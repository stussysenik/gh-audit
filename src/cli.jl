"""
    CLI entrypoint using ArgParse.

    Subcommands:
      triage   — API-level scan without cloning
      scan     — Full audit (triage + deep scan + valuation)
      report   — Generate reports from existing JSON
      publish  — Make repos public
      revert   — Make repos private again
      schedule — Create GitHub Actions workflow for auto-revert
"""

function parse_args(args=ARGS)
    s = ArgParseSettings(
        prog = "ghaudit",
        description = "GHAudit — Scientific GitHub Portfolio Security Audit & Valuation Engine",
        version = "0.1.0",
    )

    @add_arg_table! s begin
        "command"
            help = "Subcommand: triage, scan, appraise, report, publish, revert, schedule"
            required = true
        "--repo", "-r"
            help = "Single repo to appraise (owner/name format)"
            default = ""
        "--user", "-u"
            help = "GitHub username"
            default = "stussysenik"
        "--workdir", "-w"
            help = "Working directory for cloning repos"
            default = "/tmp/gh-audit-work"
        "--output", "-o"
            help = "Output directory for reports"
            default = "."
        "--config", "-c"
            help = "Path to gitleaks.toml config"
            default = "gitleaks.toml"
        "--exclusions", "-e"
            help = "Path to exclusions.toml"
            default = "exclusions.toml"
        "--input", "-i"
            help = "Input JSON report (for report/publish commands)"
            default = ""
        "--dry-run"
            help = "Preview actions without executing"
            action = :store_true
        "--days"
            help = "Days until revert (for schedule command)"
            arg_type = Int
            default = 14
    end

    return ArgParse.parse_args(args, s)
end

function run_cli(args=ARGS)
    parsed = parse_args(args)
    cmd = parsed["command"]

    if cmd == "triage"
        run_triage_cmd(parsed)
    elseif cmd == "scan"
        run_scan_cmd(parsed)
    elseif cmd == "report"
        run_report_cmd(parsed)
    elseif cmd == "publish"
        run_publish_cmd(parsed)
    elseif cmd == "revert"
        run_revert_cmd(parsed)
    elseif cmd == "appraise"
        run_appraise_cmd(parsed)
    elseif cmd == "schedule"
        run_schedule_cmd(parsed)
    else
        @error "Unknown command: $cmd. Use: triage, scan, appraise, report, publish, revert, schedule"
    end
end

function run_triage_cmd(parsed)
    owner = parsed["user"]
    @info "🔍 Running API triage for $owner..."

    repos = GitHub.list_private_repos(owner)
    @info "Found $(length(repos)) private repos"

    results = triage_all(owner, repos)

    # Save results
    output_path = joinpath(parsed["output"], "triage-results.json")
    open(output_path, "w") do io
        JSON3.pretty(io, results)
    end

    # Summary
    for level in instances(TriageLevel)
        n = count(t -> t.triage_level == level, results)
        @info "  $(string(level)): $n repos"
    end

    @info "Results saved to $output_path"
end

function run_scan_cmd(parsed)
    owner = parsed["user"]
    summary = run_full_audit(
        owner;
        exclusions_path = parsed["exclusions"],
        workdir = parsed["workdir"],
        gitleaks_config = parsed["config"],
        output_dir = parsed["output"],
    )
end

function run_report_cmd(parsed)
    input = parsed["input"]
    if isempty(input)
        @error "Please specify --input with the JSON report path"
        return
    end

    @info "Generating reports from $input..."
    summary = JSON3.read(read(input, String), AuditSummary)

    timestamp = Dates.format(now(), "yyyy-mm-dd_HHMMss")
    md_path = joinpath(parsed["output"], "gh-audit-report-$timestamp.md")
    write_markdown_report(summary, md_path)
    @info "Markdown report: $md_path"
end

function run_publish_cmd(parsed)
    owner = parsed["user"]
    input = parsed["input"]
    dry_run = parsed["dry-run"]

    if isempty(input)
        @error "Please specify --input with the JSON report path"
        return
    end

    summary = JSON3.read(read(input, String), AuditSummary)

    # Only publish SAFE repos and NEEDS_FIXES repos (assuming fixes were applied)
    publishable = filter(r -> r.classification in (SAFE, NEEDS_FIXES), summary.repos)
    repo_names = [r.name for r in publishable]

    @info "Publishing $(length(repo_names)) repos (dry_run=$dry_run)..."
    publish_repos(owner, repo_names, dry_run)

    # Generate revert list
    revert_path = joinpath(parsed["output"], "repos-to-revert.txt")
    generate_revert_list(summary, revert_path)
    @info "Revert list saved to $revert_path"
end

function run_revert_cmd(parsed)
    owner = parsed["user"]
    revert_path = joinpath(parsed["output"], "repos-to-revert.txt")

    if !isfile(revert_path)
        @error "No repos-to-revert.txt found at $revert_path"
        return
    end

    repo_names = filter(!isempty, readlines(revert_path))
    @info "Reverting $(length(repo_names)) repos to private..."
    revert_repos(owner, repo_names)
end

"""Appraise a single repo — clone, scan, valuate, and print a scorecard."""
function run_appraise_cmd(parsed)
    repo_arg = parsed["repo"]
    if isempty(repo_arg)
        @error "Please specify --repo owner/name (e.g., --repo stussysenik/zig-image-carousel)"
        return
    end

    parts = split(repo_arg, '/')
    if length(parts) != 2
        @error "Repo must be in owner/name format"
        return
    end
    owner, name = String(parts[1]), String(parts[2])
    workdir = parsed["workdir"]
    config = parsed["config"]

    @info "Appraising $owner/$name..."

    # Get repo info
    repos = try
        output = GitHub.gh([
            "repo", "view", "$owner/$name",
            "--json", "name,description,primaryLanguage,diskUsage"
        ])
        raw = JSON3.read(output)
        lang = ""
        if haskey(raw, :primaryLanguage) && !isnothing(raw.primaryLanguage)
            lang_obj = raw.primaryLanguage
            lang = lang_obj isa JSON3.Object && haskey(lang_obj, :name) ? string(lang_obj.name) : ""
        end
        [GitHub.RepoInfo(
            name = string(raw.name),
            description = string(get(raw, :description, "")),
            language = lang,
            disk_kb = Int(get(raw, :diskUsage, 0)),
        )]
    catch e
        @error "Could not fetch repo info" exception=e
        return
    end

    repo = repos[1]

    # Clone and scan
    clone_path = joinpath(workdir, name)
    mkpath(workdir)

    @info "Cloning $owner/$name..."
    findings = Finding[]
    loc_total = 0
    loc_by_lang = Dict{String,Int}()

    if GitHub.clone_repo(owner, name, clone_path)
        # Run gitleaks
        @info "Running gitleaks..."
        scan_findings = scan_repo(clone_path, config)
        append!(findings, scan_findings)

        # Count LOC with tokei
        @info "Counting lines of code..."
        try
            loc_total, loc_by_lang = count_loc_tokei(clone_path)
        catch
            loc_total = max(1, repo.disk_kb * 1024 ÷ 30)
        end

        # Clean up
        rm(clone_path; recursive=true, force=true)
    else
        @warn "Clone failed, using disk estimate for LOC"
        loc_total = max(1, repo.disk_kb * 1024 ÷ 30)
    end

    # Valuate
    lang = isempty(repo.language) ? "JavaScript" : repo.language
    kloc = loc_total / 1000.0
    effort = calculate_effort(kloc, lang)
    rate = Config.get_rate_tier(lang, repo.description)
    cost = calculate_cost(effort, rate)
    market = calculate_market_score(lang, name, repo.description, String[], loc_total)
    perspectives = calculate_perspectives(String[], loc_total, lang, name, repo.description, length(findings))
    portfolio = Config.W_STAFF_ENG * perspectives.staff_engineer +
                Config.W_DESIGN_ENG * perspectives.design_engineer +
                Config.W_AI_ML * perspectives.ai_ml_researcher
    estimated_value = Config.W_COCOMO * cost +
                     Config.W_MARKET * (market / 100.0 * cost) +
                     Config.W_PORTFOLIO * (portfolio / 100.0 * cost)
    leverage = kloc > 0.01 ? estimated_value / kloc : 0.0
    leverage_rank = if leverage > 50000; "Diamond"
        elseif leverage > 20000; "Gold"
        elseif leverage > 10000; "Silver"
        elseif leverage > 5000; "Bronze"
        else "Raw"
    end

    # Print scorecard
    println()
    println("╔══════════════════════════════════════════════════════╗")
    println("║           GHAudit Repo Appraisal                    ║")
    println("╠══════════════════════════════════════════════════════╣")
    println("║  Repo:      $owner/$name")
    println("║  Language:  $lang")
    println("║  LOC:       $(loc_total) ($(round(kloc, digits=1)) KLOC)")
    println("║  Findings:  $(length(findings))")
    println("╠══════════════════════════════════════════════════════╣")
    println("║  COCOMO Effort:     $(round(effort, digits=1)) person-months")
    println("║  Development Cost:  \$$(round(Int, cost))")
    println("║  Market Score:      $(round(market, digits=1))/100")
    println("║  Portfolio Score:   $(round(portfolio, digits=1))/100")
    println("║  Est. Value:        \$$(round(Int, estimated_value))")
    println("╠══════════════════════════════════════════════════════╣")
    println("║  Leverage:          \$$(round(Int, leverage))/KLOC")
    println("║  Leverage Rank:     $leverage_rank")
    println("╠══════════════════════════════════════════════════════╣")
    println("║  Staff Engineer:    $(round(perspectives.staff_engineer, digits=1))/100")
    println("║  Design Engineer:   $(round(perspectives.design_engineer, digits=1))/100")
    println("║  AI/ML Researcher:  $(round(perspectives.ai_ml_researcher, digits=1))/100")
    println("╚══════════════════════════════════════════════════════╝")

    if !isempty(findings)
        println("\n⚠️  Security Findings:")
        for f in findings
            println("  [$(f.severity)] $(f.description)")
        end
    end
    println()
end

function run_schedule_cmd(parsed)
    owner = parsed["user"]
    days = parsed["days"]
    output_dir = parsed["output"]

    revert_path = joinpath(output_dir, "repos-to-revert.txt")
    if !isfile(revert_path)
        @error "No repos-to-revert.txt found. Run 'publish' first."
        return
    end

    repo_names = filter(!isempty, readlines(revert_path))
    generate_revert_workflow(owner, repo_names, days, output_dir)
    @info "GitHub Actions workflow generated. See $output_dir/repo-scheduler/"
end
