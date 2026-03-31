"""
    Gitleaks wrapper for full git-history secret scanning.

    Shells out to `gitleaks detect` on locally-cloned repos, parses the
    JSON report, and converts each hit into a Finding.

    Concurrency is controlled via an asyncmap + Semaphore pattern so
    we never run more than MAX_CONCURRENT clones at once.
"""

using Base: Semaphore, acquire, release

# Maximum parallel clone + scan operations
const MAX_CONCURRENT_SCANS = 5

# ---------------------------------------------------------------------------
# Gitleaks JSON output shape (one entry per detected secret)
# ---------------------------------------------------------------------------
# {
#   "RuleID":      "generic-api-key",
#   "Description": "Generic API Key",
#   "File":        "config/settings.py",
#   "StartLine":   42,
#   "Commit":      "abc123...",
#   "Secret":      "AKIA..."
# }
# ---------------------------------------------------------------------------

"""
    scan_repo(repo_path::String, config_path::String="") -> Vector{Finding}

Run `gitleaks detect` against a cloned repo at `repo_path`.

If `config_path` is non-empty, it is passed as `--config`. The function
parses the JSON report and returns a vector of `Finding`. An empty vector
means no secrets were detected (or gitleaks is not installed).
"""
function scan_repo(repo_path::String, config_path::String="")::Vector{Finding}
    findings = Finding[]

    # Build gitleaks command
    cmd_parts = ["gitleaks", "detect",
                  "--source", repo_path,
                  "--report-format", "json",
                  "--report-path", "/dev/stdout",
                  "--no-banner"]

    if !isempty(config_path) && isfile(config_path)
        push!(cmd_parts, "--config", config_path)
    end

    repo_name = basename(repo_path)

    output = try
        buf     = IOBuffer()
        err_buf = IOBuffer()
        cmd     = Cmd(Cmd(cmd_parts); ignorestatus=true)
        proc    = run(pipeline(cmd, stdout=buf, stderr=err_buf), wait=true)
        raw     = String(take!(buf))

        # gitleaks exit codes: 0 = no leaks, 1 = leaks found, >1 = error
        if proc.exitcode > 1
            err_msg = String(take!(err_buf))
            @warn "Gitleaks error on $repo_name" exitcode=proc.exitcode stderr=err_msg
            return findings
        end
        raw
    catch e
        @warn "Failed to run gitleaks on $repo_name" exception=e
        return findings
    end

    # Parse the JSON array of findings
    isempty(strip(output)) && return findings

    raw_findings = try
        JSON3.read(output)
    catch e
        @warn "Failed to parse gitleaks output for $repo_name" exception=e
        return findings
    end

    for item in raw_findings
        rule_id     = string(get(item, :RuleID, "unknown"))
        description = string(get(item, :Description, "Secret detected"))
        file_path   = string(get(item, :File, ""))
        start_line  = Int(get(item, :StartLine, 0))
        commit_sha  = string(get(item, :Commit, ""))
        secret_val  = string(get(item, :Secret, ""))

        # Severity heuristic based on rule ID
        severity = _classify_secret_severity(rule_id, file_path)

        # Redact secret in description (show first 4 chars only)
        redacted = length(secret_val) > 4 ? secret_val[1:4] * "..." : "***"

        push!(findings, Finding(
            repo        = repo_name,
            severity    = severity,
            category    = SECRET,
            file_path   = file_path,
            line_number = start_line > 0 ? start_line : nothing,
            description = "$description ($rule_id) -- redacted value: $redacted",
            suggestion  = "Rotate this secret immediately and remove from git history using git-filter-repo or BFG.",
            auto_fixable = false,
            commit_sha  = isempty(commit_sha) ? nothing : commit_sha,
        ))
    end

    @info "Gitleaks scan complete" repo=repo_name findings=length(findings)
    return findings
end

"""
    deep_scan_repos(owner, repos, workdir, config_path) -> Dict{String, Vector{Finding}}

Clone each repo in `repos` to `workdir`, run gitleaks, collect findings.

Uses asyncmap with a semaphore to limit concurrency to MAX_CONCURRENT_SCANS.
Cloned repos are removed after scanning to conserve disk space.
"""
function deep_scan_repos(
    owner::String,
    repos::Vector{GitHub.RepoInfo},
    workdir::String,
    config_path::String="",
)::Dict{String, Vector{Finding}}

    mkpath(workdir)
    sem     = Semaphore(MAX_CONCURRENT_SCANS)
    total   = length(repos)
    results = Dict{String, Vector{Finding}}()
    lock    = ReentrantLock()
    scanned = Threads.Atomic{Int}(0)

    @info "Starting deep scan of $total repos (max $MAX_CONCURRENT_SCANS concurrent)"

    tasks = map(enumerate(repos)) do (i, repo)
        Threads.@spawn begin
            acquire(sem)
            try
                Threads.atomic_add!(scanned, 1)
                n = scanned[]
                @info "[$n/$total] Cloning $(repo.name) for deep scan..."

                dest = joinpath(workdir, repo.name)

                # Clone the full history (gitleaks needs it)
                success = GitHub.clone_repo(owner, repo.name, dest)
                if !success
                    @warn "Skipping deep scan for $(repo.name) -- clone failed"
                    Base.lock(lock) do
                        results[repo.name] = Finding[]
                    end
                    return
                end

                # Run gitleaks
                repo_findings = try
                    scan_repo(dest, config_path)
                catch e
                    @warn "Gitleaks scan failed for $(repo.name)" exception=e
                    Finding[]
                end

                Base.lock(lock) do
                    results[repo.name] = repo_findings
                end

                # Cleanup cloned repo to save disk
                try
                    rm(dest; recursive=true, force=true)
                catch e
                    @warn "Failed to clean up $dest" exception=e
                end
            finally
                release(sem)
            end
        end
    end

    # Wait for all tasks
    for t in tasks
        wait(t)
    end

    total_findings = sum(length(v) for v in values(results); init=0)
    @info "Deep scan complete" repos_scanned=length(results) total_findings

    return results
end

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

"""Map gitleaks rule IDs to severity levels."""
function _classify_secret_severity(rule_id::String, file_path::String)::Severity
    rule_lower = lowercase(rule_id)
    path_lower = lowercase(file_path)

    # CRITICAL: cloud provider keys, private keys
    if any(s -> occursin(s, rule_lower), ["aws", "gcp", "azure", "private-key", "private_key"])
        return CRITICAL
    end

    # CRITICAL: anything in production config
    if occursin("production", path_lower) || occursin("prod", path_lower)
        return CRITICAL
    end

    # HIGH: API keys, tokens, passwords
    if any(s -> occursin(s, rule_lower), ["api-key", "api_key", "token", "password", "secret"])
        return HIGH
    end

    # MEDIUM: generic patterns
    if any(s -> occursin(s, rule_lower), ["generic", "entropy"])
        return MEDIUM
    end

    # Default
    return HIGH
end
