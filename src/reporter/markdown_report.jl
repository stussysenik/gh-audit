"""
    Markdown report writer.

    Generates a comprehensive, human-readable audit report with executive summary,
    valuation tables, NDA recommendations, portfolio rankings, critical findings,
    and a remediation checklist. Uses PrettyTables.jl for formatted tables.
"""

using PrettyTables
using Dates

# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

"""Format a number as USD with commas and `\$` prefix (e.g., \$1,234,567)."""
function _fmt_usd(val::Real)::String
    # Handle zero and negative
    val < 0 && return "-" * _fmt_usd(-val)
    rounded = round(Int, val)
    s = string(rounded)
    # Insert commas from the right
    parts = String[]
    while length(s) > 3
        pushfirst!(parts, s[end-2:end])
        s = s[1:end-3]
    end
    pushfirst!(parts, s)
    return "\$" * join(parts, ",")
end

"""Format a float to one decimal place."""
_fmt_score(val::Real)::String = string(round(val; digits=1))

"""Format LOC with commas."""
function _fmt_loc(val::Integer)::String
    s = string(val)
    parts = String[]
    while length(s) > 3
        pushfirst!(parts, s[end-2:end])
        s = s[1:end-3]
    end
    pushfirst!(parts, s)
    return join(parts, ",")
end

"""Map Classification enum to a human-readable emoji+label."""
function _classification_label(c::Classification)::String
    c == SAFE          && return "SAFE"
    c == NEEDS_FIXES   && return "NEEDS FIXES"
    c == TOO_SENSITIVE  && return "TOO SENSITIVE"
    c == NDA_REQUIRED  && return "NDA REQUIRED"
    return string(c)
end

"""Map Severity enum to a label for display."""
function _severity_label(s::Severity)::String
    s == CRITICAL && return "CRITICAL"
    s == HIGH     && return "HIGH"
    s == MEDIUM   && return "MEDIUM"
    s == LOW      && return "LOW"
    s == INFO     && return "INFO"
    return string(s)
end

# ---------------------------------------------------------------------------
# Section writers
# ---------------------------------------------------------------------------

"""Write the executive summary section."""
function _write_executive_summary(io::IO, summary::AuditSummary)
    println(io, "## Executive Summary\n")
    println(io, "| Metric | Value |")
    println(io, "|--------|-------|")
    println(io, "| Total Repositories | $(summary.total_repos) |")
    println(io, "| Safe to Publish | $(summary.safe_count) |")
    println(io, "| Needs Fixes | $(summary.needs_fixes_count) |")
    println(io, "| Too Sensitive | $(summary.too_sensitive_count) |")
    println(io, "| NDA Required | $(summary.nda_count) |")
    println(io, "| Total Portfolio Value | $(_fmt_usd(summary.total_portfolio_value_usd)) |")
    println(io, "| Critical Findings | $(summary.critical_count) |")
    println(io, "| Total Findings | $(summary.total_findings) |")
    println(io)
end

"""Write the valuation table section using PrettyTables."""
function _write_valuation_table(io::IO, summary::AuditSummary)
    println(io, "## Valuation Table\n")

    repos = sort(summary.repos; by=r -> r.valuation.estimated_value_usd, rev=true)

    if isempty(repos)
        println(io, "_No repositories to display._\n")
        return
    end

    # Build the data matrix
    header = ["Repo", "Language", "LOC", "COCOMO Cost", "Market Score",
              "Portfolio Score", "Est. Value", "Classification"]

    data = Matrix{String}(undef, length(repos), length(header))
    for (i, r) in enumerate(repos)
        data[i, 1] = r.name
        data[i, 2] = isempty(r.language) ? "-" : r.language
        data[i, 3] = _fmt_loc(r.loc)
        data[i, 4] = _fmt_usd(r.valuation.cocomo_cost_usd)
        data[i, 5] = _fmt_score(r.valuation.market_score)
        data[i, 6] = _fmt_score(r.valuation.portfolio_score)
        data[i, 7] = _fmt_usd(r.valuation.estimated_value_usd)
        data[i, 8] = _classification_label(r.classification)
    end

    # Write markdown table manually (PrettyTables v3 API changed)
    println(io, "| ", join(header, " | "), " |")
    println(io, "| ", join(fill("---", length(header)), " | "), " |")
    for i in 1:size(data, 1)
        println(io, "| ", join(data[i, :], " | "), " |")
    end
    println(io)
end

"""Write the NDA recommendations section."""
function _write_nda_recommendations(io::IO, summary::AuditSummary)
    println(io, "## NDA Recommendations\n")

    nda_repos = filter(r -> r.classification == NDA_REQUIRED, summary.repos)

    if isempty(nda_repos)
        println(io, "_No repositories require NDA protection._\n")
        return
    end

    println(io, "The following repositories are recommended for NDA protection:\n")

    for r in nda_repos
        println(io, "### $(r.name)\n")
        println(io, "- **NDA Score:** $(_fmt_score(r.nda_score))")
        if !isempty(r.nda_reasons)
            println(io, "- **Reasons:**")
            for reason in r.nda_reasons
                println(io, "  - $reason")
            end
        end
        println(io)
    end
end

"""Write the portfolio quality rankings section."""
function _write_portfolio_rankings(io::IO, summary::AuditSummary)
    println(io, "## Portfolio Quality Rankings\n")
    println(io, "Top 20 repositories by portfolio composite score:\n")

    repos = sort(summary.repos; by=r -> r.valuation.portfolio_score, rev=true)
    top_repos = first(repos, min(20, length(repos)))

    if isempty(top_repos)
        println(io, "_No repositories to display._\n")
        return
    end

    header = ["Rank", "Repo", "Portfolio Score", "Staff Eng", "Design Eng",
              "AI/ML", "Language", "Classification"]

    data = Matrix{String}(undef, length(top_repos), length(header))
    for (i, r) in enumerate(top_repos)
        data[i, 1] = string(i)
        data[i, 2] = r.name
        data[i, 3] = _fmt_score(r.valuation.portfolio_score)
        data[i, 4] = _fmt_score(r.perspectives.staff_engineer)
        data[i, 5] = _fmt_score(r.perspectives.design_engineer)
        data[i, 6] = _fmt_score(r.perspectives.ai_ml_researcher)
        data[i, 7] = isempty(r.language) ? "-" : r.language
        data[i, 8] = _classification_label(r.classification)
    end

    println(io, "| ", join(header, " | "), " |")
    println(io, "| ", join(fill("---", length(header)), " | "), " |")
    for i in 1:size(data, 1)
        println(io, "| ", join(data[i, :], " | "), " |")
    end
    println(io)
end

"""Write the critical findings section."""
function _write_critical_findings(io::IO, summary::AuditSummary)
    println(io, "## Critical Findings\n")

    # Collect all CRITICAL and HIGH findings across repos
    severe_findings = Tuple{String, Finding}[]
    for r in summary.repos
        for f in r.findings
            if f.severity == CRITICAL || f.severity == HIGH
                push!(severe_findings, (r.name, f))
            end
        end
    end

    if isempty(severe_findings)
        println(io, "_No critical or high-severity findings detected._\n")
        return
    end

    # Sort: CRITICAL first, then HIGH
    sort!(severe_findings; by=x -> Int(x[2].severity))

    println(io, "| Severity | Repo | Category | File | Description | Suggestion |")
    println(io, "|----------|------|----------|------|-------------|------------|")

    for (repo_name, f) in severe_findings
        sev = _severity_label(f.severity)
        cat = string(f.category)
        file = isempty(f.file_path) ? "-" : f.file_path
        desc = replace(f.description, "|" => "\\|")
        sugg = isempty(f.suggestion) ? "-" : replace(f.suggestion, "|" => "\\|")
        println(io, "| $sev | $repo_name | $cat | `$file` | $desc | $sugg |")
    end
    println(io)
end

"""Write the remediation checklist section."""
function _write_remediation_checklist(io::IO, summary::AuditSummary)
    println(io, "## Remediation Checklist\n")

    # Collect all auto-fixable findings
    fixable = Tuple{String, Finding}[]
    for r in summary.repos
        for f in r.findings
            if f.auto_fixable
                push!(fixable, (r.name, f))
            end
        end
    end

    if isempty(fixable)
        println(io, "_No auto-fixable items found._\n")
        return
    end

    println(io, "The following items can be automatically remediated:\n")

    # Group by repo for readability
    by_repo = Dict{String, Vector{Finding}}()
    for (repo_name, f) in fixable
        push!(get!(by_repo, repo_name, Finding[]), f)
    end

    for repo_name in sort(collect(keys(by_repo)))
        println(io, "### $repo_name\n")
        for f in by_repo[repo_name]
            sev = _severity_label(f.severity)
            file_info = isempty(f.file_path) ? "" : " (`$(f.file_path)`)"
            suggestion = isempty(f.suggestion) ? f.description : f.suggestion
            println(io, "- [ ] **[$sev]**$file_info $suggestion")
        end
        println(io)
    end
end

# ---------------------------------------------------------------------------
# Main report writer
# ---------------------------------------------------------------------------

"""
    write_markdown_report(summary::AuditSummary, output_path::String) -> String

Generate a comprehensive Markdown audit report and write it to `output_path`.
Creates parent directories if they don't exist. Returns the absolute path
of the written file.

The report contains six sections:
1. Executive Summary — key metrics at a glance
2. Valuation Table — all repos sorted by estimated value
3. NDA Recommendations — repos flagged for NDA protection
4. Portfolio Quality Rankings — top 20 by composite score
5. Critical Findings — all CRITICAL and HIGH severity items
6. Remediation Checklist — auto-fixable items as checkboxes

# Example
```julia
write_markdown_report(summary, "reports/audit-2026-03-31.md")
```
"""
function write_markdown_report(summary::AuditSummary, output_path::String;
    graph_summary::Dict{String,Any}=Dict{String,Any}(),
    risk_summary::Dict{String,Any}=Dict{String,Any}())::String
    # Ensure the output directory exists
    output_dir = dirname(output_path)
    if !isempty(output_dir) && !isdir(output_dir)
        mkpath(output_dir)
        @info "Created output directory" path=output_dir
    end

    open(output_path, "w") do io
        # Title
        timestamp = isempty(summary.timestamp) ? string(Dates.now()) : summary.timestamp
        println(io, "# GHAudit Report\n")
        println(io, "**Generated:** $timestamp\n")
        println(io, "---\n")

        _write_executive_summary(io, summary)
        _write_leverage_diamonds(io, summary)
        _write_valuation_table(io, summary)
        _write_nda_recommendations(io, summary)
        _write_portfolio_rankings(io, summary)
        _write_critical_findings(io, summary)
        _write_remediation_checklist(io, summary)
        _write_security_tooling_recs(io, summary)
        _write_graph_analysis(io, graph_summary)
        _write_risk_analysis(io, risk_summary)

        # Footer
        println(io, "---\n")
        println(io, "_Report generated by [GHAudit](https://github.com/s3nik/gh-audit)._")
    end

    file_size_kb = round(filesize(output_path) / 1024; digits=1)
    @info "Markdown report written" path=output_path size_kb=file_size_kb repos=summary.total_repos

    return abspath(output_path)
end

# --- Leverage Diamonds Section ---

"""Write the leverage diamonds section — repos that create the most value per KLOC."""
function _write_leverage_diamonds(io::IO, summary::AuditSummary)
    println(io, "## Leverage Diamonds\n")
    println(io, "Repos ranked by **value created per thousand lines of code**. Diamonds = maximum leverage.\n")

    # Sort by leverage score descending, filter out near-zero KLOC
    ranked = sort(
        filter(r -> r.valuation.kloc > 0.01, summary.repos),
        by=r -> r.valuation.leverage_score, rev=true
    )

    # Count by rank
    ranks = Dict{String,Int}()
    for r in ranked
        rank = r.valuation.leverage_rank
        ranks[rank] = get(ranks, rank, 0) + 1
    end

    println(io, "| Rank | Count |")
    println(io, "| --- | --- |")
    for rank in ["Diamond", "Gold", "Silver", "Bronze", "Raw"]
        count = get(ranks, rank, 0)
        count > 0 && println(io, "| $rank | $count |")
    end
    println(io)

    # Show top 15
    println(io, "### Top 15 Highest-Leverage Repos\n")
    println(io, "| Repo | Language | KLOC | Est. Value | Leverage (\$/KLOC) | Rank |")
    println(io, "| --- | --- | --- | --- | --- | --- |")
    for r in ranked[1:min(15, length(ranked))]
        v = r.valuation
        println(io, "| $(r.name) | $(isempty(r.language) ? "-" : r.language) | $(round(v.kloc, digits=1)) | $(_fmt_usd(v.estimated_value_usd)) | $(_fmt_usd(v.leverage_score)) | $(v.leverage_rank) |")
    end
    println(io)
end

# --- Security Tooling Recommendations ---

"""Write security tooling setup recommendations based on audit findings."""
function _write_security_tooling_recs(io::IO, summary::AuditSummary)
    println(io, "## Security Tooling Recommendations\n")
    println(io, "Based on the audit findings, here are the recommended security tools and configurations:\n")

    total = summary.total_repos
    with_findings = count(r -> !isempty(r.findings), summary.repos)
    finding_rate = total > 0 ? round(with_findings / total * 100, digits=1) : 0.0

    # Always recommend these
    println(io, "### 1. GitHub Secret Scanning (Free, Auto-enabled on Public Repos)\n")
    println(io, "GitHub automatically enables secret scanning when repos go public. No action needed.")
    println(io, "It detects 200+ secret types from major providers (AWS, Google, Stripe, etc.).\n")

    println(io, "### 2. CodeRabbit (Free for Open Source)\n")
    println(io, "**Recommendation: YES — set up globally**\n")
    println(io, "CodeRabbit provides AI-powered code review on every PR. Free for public repos.")
    println(io, "- Catches security issues, code smells, and bugs before merge")
    println(io, "- Adds credibility — shows you take code quality seriously")
    println(io, "- Setup: Add `.coderabbit.yaml` to each repo or use the GitHub App\n")
    println(io, "```yaml")
    println(io, "# .coderabbit.yaml")
    println(io, "reviews:")
    println(io, "  auto_review:")
    println(io, "    enabled: true")
    println(io, "  path_instructions:")
    println(io, "    - path: \"**/*.{ts,tsx,js,jsx}\"")
    println(io, "      instructions: \"Review for XSS, injection, and React anti-patterns\"")
    println(io, "```\n")

    println(io, "### 3. Greptile (Free Tier Available)\n")
    println(io, "**Recommendation: YES for top 20 repos by value**\n")
    println(io, "Greptile indexes your codebase and answers questions about it. Useful for:")
    println(io, "- Onboarding hiring managers who want to understand your code")
    println(io, "- Self-documentation — ask \"how does the auth flow work?\"")
    println(io, "- Free tier covers public repos\n")

    println(io, "### 4. Global GitHub Actions Workflow\n")
    println(io, "**Recommendation: YES — create a reusable workflow**\n")
    println(io, "Create a `.github` repo with shared workflows that all repos inherit:\n")
    println(io, "```yaml")
    println(io, "# .github/workflows/security-scan.yml")
    println(io, "name: Security Scan")
    println(io, "on: [push, pull_request]")
    println(io, "jobs:")
    println(io, "  gitleaks:")
    println(io, "    runs-on: ubuntu-latest")
    println(io, "    steps:")
    println(io, "      - uses: actions/checkout@v4")
    println(io, "        with:")
    println(io, "          fetch-depth: 0")
    println(io, "      - uses: gitleaks/gitleaks-action@v2")
    println(io, "        env:")
    println(io, raw"          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}")
    println(io, "```\n")

    println(io, "### 5. Pre-commit Hooks (Local)\n")
    println(io, "**Recommendation: Add to active repos**\n")
    println(io, "Prevent secrets from ever being committed:\n")
    println(io, "```bash")
    println(io, "brew install pre-commit")
    println(io, "# Add .pre-commit-config.yaml to repos:")
    println(io, "repos:")
    println(io, "  - repo: https://github.com/gitleaks/gitleaks")
    println(io, "    rev: v8.30.1")
    println(io, "    hooks:")
    println(io, "      - id: gitleaks")
    println(io, "```\n")

    # Summary table
    println(io, "### Setup Priority\n")
    println(io, "| Tool | Cost | Effort | Impact | Priority |")
    println(io, "| --- | --- | --- | --- | --- |")
    println(io, "| GitHub Secret Scanning | Free | None (auto) | High | Already done |")
    println(io, "| CodeRabbit | Free (OSS) | 5 min | High | Do today |")
    println(io, "| GitHub Actions gitleaks | Free | 15 min | High | Do today |")
    println(io, "| Greptile | Free tier | 10 min | Medium | This week |")
    println(io, "| Pre-commit hooks | Free | 5 min/repo | Medium | Active repos |")
    println(io)
end

# --- Graph Analysis Section ---

"""Write the portfolio graph analysis section."""
function _write_graph_analysis(io::IO, graph_summary::Dict{String, Any})
    isempty(graph_summary) && return

    println(io, "## Portfolio Graph Analysis\n")
    println(io, "Repos modeled as a knowledge graph. Edges = shared language, domain, tech stack.\n")

    # Clusters
    clusters = get(graph_summary, "clusters", [])
    if !isempty(clusters)
        println(io, "### Skill Domain Clusters\n")
        for (i, cluster) in enumerate(clusters)
            if cluster isa Dict
                domain = get(cluster, "domain", "Cluster $i")
                repos_list = get(cluster, "repos", String[])
            elseif cluster isa Vector
                domain = "Cluster $i"
                repos_list = String[string(x) for x in cluster]
            else
                continue
            end
            println(io, "**$(domain)** ($(length(repos_list)) repos)")
            for r in repos_list[1:min(10, length(repos_list))]
                println(io, "- $r")
            end
            if length(repos_list) > 10
                println(io, "- _...and $(length(repos_list) - 10) more_")
            end
            println(io)
        end
    end

    # Hub repos
    hub_repos = get(graph_summary, "hub_repos", [])
    if !isempty(hub_repos)
        println(io, "### Hub Repositories (Most Connected)\n")
        println(io, "These repos connect multiple skill domains — they demonstrate versatility.\n")
        println(io, "| Repo | Centrality Score |")
        println(io, "| --- | --- |")
        for h in hub_repos[1:min(10, length(hub_repos))]
            if h isa Tuple
                println(io, "| $(h[1]) | $(round(h[2], digits=3)) |")
            elseif h isa Dict
                println(io, "| $(get(h, "name", "?")) | $(round(get(h, "centrality", 0.0), digits=3)) |")
            end
        end
        println(io)
    end
end

# --- Risk Analysis Section ---

"""Write the Bayesian risk propagation section."""
function _write_risk_analysis(io::IO, risk_summary::Dict{String, Any})
    isempty(risk_summary) && return

    println(io, "## Bayesian Risk Propagation\n")
    println(io, "Probabilistic vulnerability assessment using Bayesian inference.\n")
    println(io, "If one repo has a vulnerability, repos sharing similar attributes have elevated risk.\n")

    base_rate = get(risk_summary, "base_rate", 0.0)
    println(io, "**Base vulnerability rate:** $(round(base_rate * 100, digits=1))%\n")

    # Highest risk repos
    high_risk = get(risk_summary, "highest_risk", [])
    if !isempty(high_risk)
        println(io, "### Elevated Risk Repos\n")
        println(io, "| Repo | Posterior Risk |")
        println(io, "| --- | --- |")
        for r in high_risk[1:min(10, length(high_risk))]
            if r isa Tuple && length(r) >= 2
                println(io, "| $(r[1]) | $(round(r[2] * 100, digits=1))% |")
            elseif r isa Dict
                println(io, "| $(get(r, "name", "?")) | $(round(get(r, "risk", 0.0) * 100, digits=1))% |")
            end
        end
        println(io)
    end

    # Category theory note
    println(io, "### Categorical Framework\n")
    println(io, "The risk analysis uses a functorial mapping **F: Code → Risk** where:")
    println(io, "- **Objects** in Code = repositories; objects in Risk = probability scores ∈ [0,1]")
    println(io, "- **Morphisms** in Code = shared attributes; morphisms in Risk = risk propagation edges")
    println(io, "- **Functorial law**: risk propagates transitively — if A shares attributes with B, and B with C, then A→C risk is F(g∘f) = F(g)∘F(f)")
    println(io)
end
