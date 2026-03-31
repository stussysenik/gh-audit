"""
    API-level triage scanner.

    Classifies repos into triage levels WITHOUT cloning by inspecting
    the file tree via GitHub's Trees API. This is the first pass in the
    audit pipeline -- cheap, fast, and sufficient to decide which repos
    need deeper analysis.

    Triage levels:
      TRIAGE_CLEAN     -- No obvious issues detected
      TRIAGE_REVIEW    -- Minor concerns worth a human glance
      TRIAGE_SCAN_DEEP -- Contains patterns that demand full git-history scanning
      TRIAGE_SENSITIVE -- Known sensitive material; flag immediately
"""

# ---------------------------------------------------------------------------
# File-name patterns that drive triage classification
# ---------------------------------------------------------------------------

# Any match here escalates directly to SCAN_DEEP
const SCAN_DEEP_EXACT_FILES = Set([
    ".env", ".env.local", ".env.production", ".env.development",
    ".env.staging", ".env.test",
    "credentials.json", "serviceAccountKey.json",
])

# Extension-based patterns that also escalate to SCAN_DEEP
const SCAN_DEEP_EXTENSIONS = Set([".pem", ".key", ".p12", ".pfx", ".jks"])

# Files that indicate an AI-assisted repo
const AI_INSTRUCTION_FILES = Set([
    "CLAUDE.md", "AGENTS.md", ".cursorrules", ".cursorignore",
    ".github/copilot-instructions.md",
])

# Presence of these files triggers REVIEW
const REVIEW_FILES = Set([
    "docker-compose.yml", "docker-compose.yaml",
])

# ---------------------------------------------------------------------------
# Core triage logic
# ---------------------------------------------------------------------------

"""
    triage_repo(owner::String, repo_info::GitHub.RepoInfo) -> TriageResult

Fetch the file tree for `repo_info` via the API and classify it.

Returns a `TriageResult` with the appropriate triage level and metadata flags.
The function never throws -- API errors result in TRIAGE_REVIEW with an
explanatory flag.
"""
function triage_repo(owner::String, repo_info::GitHub.RepoInfo)::TriageResult
    result = TriageResult(
        name        = repo_info.name,
        language    = repo_info.language,
        disk_kb     = repo_info.disk_kb,
        description = repo_info.description,
    )

    # Fetch the file tree from the GitHub API
    files = try
        GitHub.get_file_tree(owner, repo_info.name)
    catch e
        @warn "Triage: could not fetch file tree" repo=repo_info.name exception=e
        push!(result.flags, "file_tree_unavailable")
        result.triage_level = TRIAGE_REVIEW
        return result
    end

    result.file_count = length(files)

    # Empty repo -- nothing to scan
    if isempty(files)
        push!(result.flags, "empty_repository")
        return result
    end

    # Track whether we found a .gitignore
    has_gitignore = false

    for filepath in files
        basename_lower = lowercase(basename(filepath))
        basename_orig  = basename(filepath)
        _, ext         = splitext(basename_orig)

        # --- .gitignore check ---
        if basename_lower == ".gitignore"
            has_gitignore = true
        end

        # --- SCAN_DEEP: exact filename match ---
        if basename_orig in SCAN_DEEP_EXACT_FILES || basename_lower in SCAN_DEEP_EXACT_FILES
            result.triage_level = max(result.triage_level, TRIAGE_SCAN_DEEP)
            result.has_env_files    = startswith(basename_lower, ".env")  || result.has_env_files
            result.has_sensitive_files = true
            push!(result.flags, "sensitive_file:$basename_orig")
        end

        # --- SCAN_DEEP: extension match ---
        if lowercase(ext) in SCAN_DEEP_EXTENSIONS
            result.triage_level = max(result.triage_level, TRIAGE_SCAN_DEEP)
            result.has_sensitive_files = true
            push!(result.flags, "sensitive_ext:$ext")
        end

        # --- AI instruction files ---
        if basename_orig in AI_INSTRUCTION_FILES || filepath in AI_INSTRUCTION_FILES
            result.has_ai_instructions = true
            push!(result.flags, "ai_instructions:$basename_orig")
        end

        # --- Apple project files ---
        if lowercase(ext) == ".pbxproj"
            result.has_apple_project = true
            push!(result.flags, "apple_project:$basename_orig")
        end

        # --- Docker compose (REVIEW) ---
        if basename_orig in REVIEW_FILES
            result.triage_level = max(result.triage_level, TRIAGE_REVIEW)
            push!(result.flags, "docker_compose")
        end
    end

    # Missing .gitignore is a yellow flag
    if !has_gitignore && result.file_count > 0
        result.triage_level = max(result.triage_level, TRIAGE_REVIEW)
        push!(result.flags, "missing_gitignore")
    end

    @info "Triaged $(repo_info.name)" level=result.triage_level flags=length(result.flags) files=result.file_count
    return result
end

# Helper: TriageLevel ordering for `max` (higher enum value = more severe)
Base.isless(a::TriageLevel, b::TriageLevel) = Int(a) < Int(b)

"""
    triage_all(owner::String, repos::Vector{GitHub.RepoInfo}) -> Vector{TriageResult}

Triage every repo in `repos`, printing a progress counter to stdout.

Returns a vector of `TriageResult` in the same order as the input.
"""
function triage_all(owner::String, repos::Vector{GitHub.RepoInfo})::Vector{TriageResult}
    total   = length(repos)
    results = Vector{TriageResult}(undef, total)

    for (i, repo) in enumerate(repos)
        print("\r  Triaging [$i/$total] $(repo.name)" * " "^20)
        results[i] = triage_repo(owner, repo)
    end
    println()  # Newline after progress counter

    # Summary
    counts = Dict{TriageLevel, Int}()
    for r in results
        counts[r.triage_level] = get(counts, r.triage_level, 0) + 1
    end
    @info "Triage complete" total clean=get(counts, TRIAGE_CLEAN, 0) review=get(counts, TRIAGE_REVIEW, 0) deep=get(counts, TRIAGE_SCAN_DEEP, 0) sensitive=get(counts, TRIAGE_SENSITIVE, 0)

    return results
end
