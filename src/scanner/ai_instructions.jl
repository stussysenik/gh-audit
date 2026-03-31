"""
    Prompt injection scanner for AI instruction files.

    Analyzes CLAUDE.md, AGENTS.md, .cursorrules, and similar files for
    patterns that could constitute prompt injection attacks:

      - Direct instruction override attempts
      - Hidden HTML directives
      - Data exfiltration vectors (webhooks, curl, fetch)
      - Privilege escalation commands
      - Unicode homoglyph / invisible character attacks
      - Carlini Rule of Two violations (read-sensitive + mutate-state)

    Findings are returned at varying severity levels depending on the
    confidence and risk of the detected pattern.
"""

# ---------------------------------------------------------------------------
# Known AI instruction filenames (case-sensitive match on basename)
# ---------------------------------------------------------------------------

const AI_FILE_NAMES = Set([
    "CLAUDE.md", "AGENTS.md", ".cursorrules", ".cursorignore",
    "copilot-instructions.md", ".github/copilot-instructions.md",
    ".aider.conf.yml", ".continue/config.json",
])

# ---------------------------------------------------------------------------
# Detection patterns -- each tuple is (label, regex, severity, description)
# ---------------------------------------------------------------------------

const INJECTION_PATTERNS = [
    # -- Direct instruction override --
    (
        "instruction_override",
        r"(?i)(ignore\s+(all\s+)?previous\s+instructions|disregard\s+(all\s+)?(previous|above|prior)|override\s+system\s*(prompt|instructions)?|forget\s+(everything|all)\s+(above|before))"i,
        CRITICAL,
        "Prompt injection: attempts to override or disregard prior instructions",
    ),
    # -- Hidden HTML comments with instructions --
    (
        "hidden_html_instruction",
        r"<!--[^>]*?(instruction|ignore|override|inject|execute|run\s+this|system\s*prompt)[^>]*?-->"i,
        HIGH,
        "Hidden HTML comment containing instruction-like directives",
    ),
    # -- Data exfiltration: webhook / external URLs in executable context --
    (
        "exfil_webhook",
        r"(?i)(https?://[^\s\"')\]]+\.(ngrok|webhook\.site|requestbin|pipedream|hookbin|burpcollaborator)[^\s\"')\]]*)"i,
        CRITICAL,
        "Data exfiltration vector: webhook/tunnel URL detected",
    ),
    (
        "exfil_curl",
        r"(?i)curl\s+(-[a-zA-Z]+\s+)*https?://(?!localhost|127\.0\.0\.1)[^\s\"')\]]+"i,
        HIGH,
        "Data exfiltration vector: curl to external domain",
    ),
    (
        "exfil_fetch",
        r"(?i)(fetch|axios|http\.get|http\.post|requests\.(get|post))\s*\(\s*[\"']https?://(?!localhost|127\.0\.0\.1)"i,
        HIGH,
        "Data exfiltration vector: fetch/HTTP call to external domain",
    ),
    # -- Privilege escalation --
    (
        "privesc_sudo",
        r"\bsudo\s+"i,
        MEDIUM,
        "Privilege escalation: sudo usage in AI instructions",
    ),
    (
        "privesc_no_verify",
        r"--no-verify"i,
        MEDIUM,
        "Privilege escalation: --no-verify flag bypasses safety hooks",
    ),
    (
        "privesc_force_push",
        r"(git\s+push\s+--force|--force-with-lease)"i,
        MEDIUM,
        "Privilege escalation: force push in AI instructions",
    ),
    (
        "privesc_chmod_777",
        r"chmod\s+777"i,
        HIGH,
        "Privilege escalation: chmod 777 grants world-writable permissions",
    ),
    (
        "privesc_rm_rf",
        r"rm\s+-rf\s+/"i,
        CRITICAL,
        "Privilege escalation: destructive rm -rf / in AI instructions",
    ),
]

# -- Unicode / invisible character patterns --
# Zero-width space (U+200B), zero-width non-joiner (U+200C),
# zero-width joiner (U+200D), left-to-right/right-to-left marks, etc.
const INVISIBLE_CHAR_PATTERN = r"[\u200B\u200C\u200D\u200E\u200F\u2060\u2061\u2062\u2063\u2064\uFEFF\u00AD]"

# -- Carlini Rule of Two detection --
# If a file grants BOTH read-sensitive-data AND mutate-state, that
# violates the principle of least privilege.
const RULE_OF_TWO_READ_PATTERNS = [
    r"(?i)(read|access|fetch|get|load|open|cat|view)\s+(secret|credential|key|token|password|\.env|private|sensitive)"i,
    r"(?i)(secret|credential|key|token|password|\.env|private|sensitive)\s+(file|data|content|value)"i,
]

const RULE_OF_TWO_MUTATE_PATTERNS = [
    r"(?i)(write|modify|update|delete|remove|overwrite|push|deploy|execute|run|install)"i,
    r"(?i)(commit|merge|publish|release|upload)"i,
]

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

"""
    scan_ai_instructions(owner::String, repo::String, files::Vector{String}) -> Vector{Finding}

Scan all AI instruction files in `files` for prompt injection patterns.

Downloads each recognized AI instruction file via the GitHub API and runs
the full pattern suite. Returns findings sorted by severity (most severe first).
"""
function scan_ai_instructions(owner::String, repo::String, files::Vector{String})::Vector{Finding}
    findings = Finding[]

    # Filter to only AI instruction files
    ai_files = filter(files) do f
        bname = basename(f)
        bname in AI_FILE_NAMES || f in AI_FILE_NAMES
    end

    isempty(ai_files) && return findings

    @info "Scanning AI instruction files in $repo" count=length(ai_files)

    for filepath in ai_files
        content = try
            GitHub.get_file_content(owner, repo, filepath)
        catch e
            @warn "Failed to fetch AI instruction file" repo file=filepath exception=e
            continue
        end

        isnothing(content) && continue
        isempty(strip(content)) && continue

        # Run all regex-based pattern checks
        _check_injection_patterns!(findings, repo, filepath, content)

        # Check for invisible / homoglyph characters
        _check_invisible_chars!(findings, repo, filepath, content)

        # Carlini Rule of Two check
        _check_rule_of_two!(findings, repo, filepath, content)
    end

    # Sort by severity (CRITICAL first, since CRITICAL=1)
    sort!(findings, by = f -> Int(f.severity))

    @info "AI instruction scan complete" repo findings=length(findings)
    return findings
end

# ---------------------------------------------------------------------------
# Internal detection functions
# ---------------------------------------------------------------------------

"""Run each pattern in INJECTION_PATTERNS against the file content."""
function _check_injection_patterns!(findings::Vector{Finding}, repo::String, filepath::String, content::String)
    for (label, pattern, severity, description) in INJECTION_PATTERNS
        for m in eachmatch(pattern, content)
            # Find the line number of the match
            line_num = _line_number_at(content, m.offset)

            push!(findings, Finding(
                repo        = repo,
                severity    = severity,
                category    = AI_INSTRUCTION,
                file_path   = filepath,
                line_number = line_num,
                description = "$description [pattern: $label]",
                suggestion  = "Review this AI instruction file for malicious intent. Remove or sandbox the flagged pattern.",
                auto_fixable = false,
            ))
        end
    end
end

"""Detect zero-width and invisible Unicode characters that could hide instructions."""
function _check_invisible_chars!(findings::Vector{Finding}, repo::String, filepath::String, content::String)
    invisible_matches = collect(eachmatch(INVISIBLE_CHAR_PATTERN, content))

    if !isempty(invisible_matches)
        # Report once per file with the count
        line_num = _line_number_at(content, first(invisible_matches).offset)

        push!(findings, Finding(
            repo        = repo,
            severity    = HIGH,
            category    = AI_INSTRUCTION,
            file_path   = filepath,
            line_number = line_num,
            description = "Unicode homoglyph/invisible character attack: $(length(invisible_matches)) invisible characters detected",
            suggestion  = "Strip zero-width and invisible Unicode characters. These can hide malicious instructions from human reviewers.",
            auto_fixable = true,
        ))
    end
end

"""
    Carlini Rule of Two: if a single AI instruction file grants both
    read-access to sensitive data AND the ability to mutate state,
    that is a dangerous combination.
"""
function _check_rule_of_two!(findings::Vector{Finding}, repo::String, filepath::String, content::String)
    has_read   = any(p -> occursin(p, content), RULE_OF_TWO_READ_PATTERNS)
    has_mutate = any(p -> occursin(p, content), RULE_OF_TWO_MUTATE_PATTERNS)

    if has_read && has_mutate
        push!(findings, Finding(
            repo        = repo,
            severity    = HIGH,
            category    = AI_INSTRUCTION,
            file_path   = filepath,
            line_number = nothing,
            description = "Carlini Rule of Two violation: file grants both read-sensitive-data and mutate-state capabilities",
            suggestion  = "Separate read and write permissions into distinct instruction scopes. An AI agent should not hold both capabilities simultaneously.",
            auto_fixable = false,
        ))
    end
end

# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

"""Return the 1-indexed line number for a byte offset in `text`."""
function _line_number_at(text::String, offset::Int)::Int
    count('\n', SubString(text, 1, min(offset, lastindex(text)))) + 1
end
