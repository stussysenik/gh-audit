"""
    GHAudit — Scientific GitHub Portfolio Security Audit & Valuation Engine

    A Julia-based tool for batch security auditing, COCOMO II monetary valuation,
    NDA classification, and multi-perspective portfolio scoring of GitHub repositories.

    Usage:
        julia bin/ghaudit.jl triage --user stussysenik
        julia bin/ghaudit.jl scan --user stussysenik --workdir /tmp/gh-audit-work
        julia bin/ghaudit.jl report --input audit-results.json
        julia bin/ghaudit.jl publish --report audit-report.json --dry-run
"""
module GHAudit

using JSON3
using DataFrames
using Dates
using Statistics
using PrettyTables
using TOML
using ArgParse
using Graphs
using Distributions
import StructTypes

# --- Core modules ---
include("config.jl")
include("github.jl")
include("reporter/models.jl")

# --- Scanners ---
include("scanner/triage.jl")
include("scanner/secrets.jl")
include("scanner/ai_instructions.jl")
include("scanner/files.jl")
include("scanner/apple_meta.jl")

# --- Valuation ---
include("valuation/cocomo.jl")
include("valuation/market.jl")
include("valuation/portfolio.jl")
include("valuation/nda.jl")
include("valuation/graph_theory.jl")
include("valuation/bayesian_risk.jl")

# --- Reporter ---
include("reporter/categorizer.jl")
include("reporter/json_report.jl")
include("reporter/markdown_report.jl")

# --- Remediation ---
include("remediation/gitignore_fixer.jl")

# --- Visibility ---
include("visibility/publisher.jl")
include("visibility/scheduler.jl")

# --- CLI ---
include("cli.jl")

# --- Orchestration ---

"""
    run_full_audit(owner; exclusions_path, workdir, gitleaks_config)

Execute the complete audit pipeline:
1. List all private repos
2. API triage (no cloning)
3. Deep scan flagged repos (clone + gitleaks)
4. LOC counting + COCOMO valuation
5. Market + portfolio scoring
6. NDA classification
7. Report generation
"""
function run_full_audit(owner::String;
    exclusions_path::String = "exclusions.toml",
    workdir::String = "/tmp/gh-audit-work",
    gitleaks_config::String = "gitleaks.toml",
    output_dir::String = ".")

    timestamp = Dates.format(now(), "yyyy-mm-dd_HHMMss")
    exclusions = Config.load_exclusions(exclusions_path)

    # Step 1: List repos
    @info "📋 Listing private repos for $owner..."
    repos = GitHub.list_private_repos(owner)
    @info "Found $(length(repos)) private repos"

    # Step 2: API Triage
    @info "🔍 Phase 1: API-level triage (no cloning)..."
    triage_results = triage_all(owner, repos)

    # Categorize triage results
    clean = filter(t -> t.triage_level == TRIAGE_CLEAN, triage_results)
    review = filter(t -> t.triage_level == TRIAGE_REVIEW, triage_results)
    deep = filter(t -> t.triage_level == TRIAGE_SCAN_DEEP, triage_results)
    sensitive = filter(t -> t.triage_level == TRIAGE_SENSITIVE, triage_results)

    @info "Triage complete" clean=length(clean) review=length(review) deep=length(deep) sensitive=length(sensitive)

    # Step 3: Deep scan
    # Only deep-scan repos flagged SCAN_DEEP (not REVIEW — those are minor)
    repos_to_scan = deep
    all_findings = Dict{String, Vector{Finding}}()

    if !isempty(repos_to_scan)
        @info "🔬 Phase 2: Deep scanning $(length(repos_to_scan)) repos..."
        mkpath(workdir)

        scan_names = Set(t.name for t in repos_to_scan)
        scan_repos = filter(r -> r.name in scan_names, repos)
        findings_map = deep_scan_repos(owner, scan_repos, workdir, gitleaks_config)
        merge!(all_findings, findings_map)
    end

    # Step 3b: AI instruction scan for flagged repos
    ai_repos = filter(t -> t.has_ai_instructions, triage_results)
    if !isempty(ai_repos)
        @info "🤖 Scanning $(length(ai_repos)) repos for AI instruction vulnerabilities..."
        for tr in ai_repos
            tree = GitHub.get_file_tree(owner, tr.name)
            ai_findings = scan_ai_instructions(owner, tr.name, tree)
            if !isempty(ai_findings)
                existing = get(all_findings, tr.name, Finding[])
                all_findings[tr.name] = vcat(existing, ai_findings)
            end
        end
    end

    # Step 4: Build repo reports with valuation
    @info "💰 Calculating valuations and portfolio scores..."
    reports = RepoReport[]

    for repo in repos
        tr = findfirst(t -> t.name == repo.name, triage_results)
        triage = isnothing(tr) ? TriageResult(name=repo.name) : triage_results[tr]

        report = RepoReport(
            name = repo.name,
            triage = triage,
            findings = get(all_findings, repo.name, Finding[]),
            language = repo.language,
            disk_kb = repo.disk_kb,
        )

        # LOC estimation from disk size (heuristic when not cloned)
        # ~10 bytes per line average for source code, disk_kb includes git objects
        estimated_loc = max(1, repo.disk_kb * 1024 ÷ 30)
        report.loc = estimated_loc
        kloc = estimated_loc / 1000.0

        # COCOMO II valuation
        lang = isempty(repo.language) ? "JavaScript" : repo.language
        effort = calculate_effort(kloc, lang)
        rate = Config.get_rate_tier(lang, repo.description)
        cost = calculate_cost(effort, rate)

        # Market scoring
        tree = triage.flags  # Use triage flags as proxy for file tree
        market = calculate_market_score(lang, repo.name, repo.description, triage.flags, estimated_loc)

        # Portfolio scoring
        perspectives = calculate_perspectives(
            triage.flags, estimated_loc, lang,
            repo.name, repo.description,
            length(report.findings)
        )
        portfolio = Config.W_STAFF_ENG * perspectives.staff_engineer +
                    Config.W_DESIGN_ENG * perspectives.design_engineer +
                    Config.W_AI_ML * perspectives.ai_ml_researcher

        # Final weighted valuation
        estimated_value = Config.W_COCOMO * cost +
                         Config.W_MARKET * (market / 100.0 * cost) +
                         Config.W_PORTFOLIO * (portfolio / 100.0 * cost)

        # Leverage score: value per KLOC — diamonds create max value from minimal code
        leverage = kloc > 0.01 ? estimated_value / kloc : 0.0
        leverage_rank = if leverage > 50000; "Diamond"
            elseif leverage > 20000; "Gold"
            elseif leverage > 10000; "Silver"
            elseif leverage > 5000; "Bronze"
            else "Raw"
        end

        report.valuation = Valuation(
            kloc = kloc,
            cocomo_effort_pm = effort,
            cocomo_cost_usd = cost,
            market_score = market,
            portfolio_score = portfolio,
            estimated_value_usd = estimated_value,
            leverage_score = leverage,
            leverage_rank = leverage_rank,
        )
        report.perspectives = perspectives

        # NDA classification
        nda_score, nda_reasons = calculate_nda_score(
            repo.name, repo.description, triage.flags, exclusions
        )
        report.nda_score = nda_score
        report.nda_reasons = nda_reasons

        # Final classification
        classify_repo(report, exclusions)

        push!(reports, report)
    end

    # Sort by value descending
    sort!(reports, by=r -> r.valuation.estimated_value_usd, rev=true)

    # Build summary
    summary = AuditSummary(
        timestamp = timestamp,
        total_repos = length(reports),
        safe_count = count(r -> r.classification == SAFE, reports),
        needs_fixes_count = count(r -> r.classification == NEEDS_FIXES, reports),
        too_sensitive_count = count(r -> r.classification == TOO_SENSITIVE, reports),
        nda_count = count(r -> r.classification == NDA_REQUIRED, reports),
        total_findings = sum(r -> length(r.findings), reports),
        critical_count = sum(r -> count(f -> f.severity == CRITICAL, r.findings), reports),
        total_portfolio_value_usd = sum(r -> r.valuation.estimated_value_usd, reports),
        repos = reports,
    )

    # Step 5: Graph theory analysis
    @info "🔗 Running graph theory analysis..."
    graph_summary = Dict{String, Any}()
    try
        graph_summary = graph_analysis_summary(reports)
        @info "Graph analysis complete" clusters=length(get(graph_summary, "clusters", [])) hub_repos=length(get(graph_summary, "hub_repos", []))
    catch e
        @warn "Graph analysis failed (non-fatal)" exception=e
    end

    # Step 6: Bayesian risk propagation
    @info "📐 Running Bayesian risk propagation..."
    risk_summary = Dict{String, Any}()
    try
        risk_summary = risk_propagation_summary(reports)
        @info "Risk analysis complete"
    catch e
        @warn "Risk analysis failed (non-fatal)" exception=e
    end

    # Generate reports
    json_path = joinpath(output_dir, "gh-audit-report-$timestamp.json")
    md_path = joinpath(output_dir, "gh-audit-report-$timestamp.md")

    @info "📊 Generating reports..."
    write_json_report(summary, json_path)
    write_markdown_report(summary, md_path; graph_summary, risk_summary)

    @info "✅ Audit complete!" json=json_path markdown=md_path
    @info "Portfolio value: \$$(round(summary.total_portfolio_value_usd, digits=2))"
    @info "$(summary.safe_count) safe | $(summary.needs_fixes_count) need fixes | $(summary.too_sensitive_count) too sensitive | $(summary.nda_count) NDA"

    return summary
end

end # module GHAudit
