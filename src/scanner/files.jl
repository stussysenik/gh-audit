"""
    Sensitive file pattern scanner for cloned repositories.

    Walks the local filesystem of a cloned repo looking for files that
    should never be committed: environment configs with real secrets,
    private keys, certificates, keystores, SSH keys, and databases.

    For .env files, we go a step further and check whether they contain
    actual values (not just empty placeholders, comments, or example
    templates).
"""

# ---------------------------------------------------------------------------
# File patterns
# ---------------------------------------------------------------------------

# .env variants that are expected/safe (example templates, not real secrets)
const ENV_SAFE_SUFFIXES = Set([
    ".env.example", ".env.defaults", ".env.sample", ".env.template",
    ".env.test.example", ".env.development.example",
])

# Exact basenames of sensitive files (case-insensitive comparison)
const SENSITIVE_EXACT_NAMES = Set([
    "credentials.json",
    "serviceaccountkey.json",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_dsa",
])

# Extensions that indicate sensitive key/cert/database material
const SENSITIVE_EXTENSIONS = Set([
    ".pem", ".key", ".p12", ".pfx", ".jks",
    ".sqlite", ".db",
])

# Directories to skip (version control, dependencies, build artifacts)
const SKIP_DIRS = Set([
    ".git", "node_modules", ".build", "build", "dist",
    "__pycache__", ".tox", ".venv", "venv",
    "Pods", ".dart_tool", ".pub-cache",
    "vendor", "target",
])

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

"""
    scan_sensitive_files(repo_path::String, repo_name::String="") -> Vector{Finding}

Walk the filesystem of a cloned repo at `repo_path` and return findings
for any sensitive files discovered.

For `.env` files that are not safe templates, the scanner reads the first
few KB to check whether they contain actual secret values (not just
comments or empty placeholders).
"""
function scan_sensitive_files(repo_path::String, repo_name::String="")::Vector{Finding}
    findings = Finding[]
    repo_name = isempty(repo_name) ? basename(repo_path) : repo_name

    if !isdir(repo_path)
        @warn "scan_sensitive_files: path is not a directory" path=repo_path
        return findings
    end

    _walk_directory!(findings, repo_path, repo_path, repo_name)

    @info "Sensitive file scan complete" repo=repo_name findings=length(findings)
    return findings
end

# ---------------------------------------------------------------------------
# Recursive directory walker
# ---------------------------------------------------------------------------

"""Recursively walk `dir`, checking each file against sensitive patterns."""
function _walk_directory!(findings::Vector{Finding}, root::String, dir::String, repo_name::String)
    entries = try
        readdir(dir; join=false)
    catch e
        @warn "Cannot read directory" dir exception=e
        return
    end

    for entry in entries
        full_path = joinpath(dir, entry)

        # Skip symlinks to avoid loops
        islink(full_path) && continue

        if isdir(full_path)
            # Skip known non-source directories
            entry in SKIP_DIRS && continue
            _walk_directory!(findings, root, full_path, repo_name)
        elseif isfile(full_path)
            _check_file!(findings, root, full_path, entry, repo_name)
        end
    end
end

# ---------------------------------------------------------------------------
# Per-file check
# ---------------------------------------------------------------------------

"""Check a single file against all sensitive patterns."""
function _check_file!(findings::Vector{Finding}, root::String, full_path::String, filename::String, repo_name::String)
    relative_path = relpath(full_path, root)
    name_lower    = lowercase(filename)
    _, ext        = splitext(filename)
    ext_lower     = lowercase(ext)

    # --- .env files (but not safe templates) ---
    if startswith(name_lower, ".env")
        # Check if this is a safe template file
        if _is_safe_env_name(name_lower)
            return  # Skip .env.example, .env.sample, etc.
        end

        severity = MEDIUM
        desc     = "Environment file found: $filename"

        # Inspect contents to determine if it has real values
        has_real_values = try
            _env_has_real_values(full_path)
        catch e
            @warn "Could not read .env file" path=relative_path exception=e
            false
        end

        if has_real_values
            severity = HIGH
            desc     = "Environment file with actual secret values: $filename"
        end

        push!(findings, Finding(
            repo        = repo_name,
            severity    = severity,
            category    = SENSITIVE_FILE,
            file_path   = relative_path,
            description = desc,
            suggestion  = "Add $filename to .gitignore and remove from git history. Use environment variables or a secrets manager instead.",
            auto_fixable = true,
        ))
        return
    end

    # --- Exact sensitive filenames ---
    if name_lower in SENSITIVE_EXACT_NAMES
        severity = _severity_for_exact_name(name_lower)
        push!(findings, Finding(
            repo        = repo_name,
            severity    = severity,
            category    = SENSITIVE_FILE,
            file_path   = relative_path,
            description = "Sensitive file detected: $filename",
            suggestion  = "Remove this file from the repository and rotate any associated credentials.",
            auto_fixable = false,
        ))
        return
    end

    # --- Extension-based matches ---
    if ext_lower in SENSITIVE_EXTENSIONS
        severity = _severity_for_extension(ext_lower)
        push!(findings, Finding(
            repo        = repo_name,
            severity    = severity,
            category    = SENSITIVE_FILE,
            file_path   = relative_path,
            description = "Sensitive file by extension ($ext_lower): $filename",
            suggestion  = _suggestion_for_extension(ext_lower),
            auto_fixable = false,
        ))
        return
    end
end

# ---------------------------------------------------------------------------
# .env content analysis
# ---------------------------------------------------------------------------

"""
    Check whether a `.env` file contains actual values (not just
    empty placeholders or comments).

    Reads up to 8 KB and looks for lines matching `KEY=VALUE` where
    VALUE is non-empty and not a placeholder like `changeme`, `xxx`, `TODO`.
"""
function _env_has_real_values(filepath::String)::Bool
    content = try
        # Read at most 8 KB
        open(filepath, "r") do io
            read(io, min(8192, filesize(filepath))) |> String
        end
    catch
        return false
    end

    placeholder_pattern = r"^(changeme|xxx+|TODO|FIXME|REPLACE_ME|your[_-]?.*here|<.*>|\.\.\.)$"i

    for line in eachline(IOBuffer(content))
        stripped = strip(line)
        # Skip empty lines and comments
        isempty(stripped) && continue
        startswith(stripped, "#") && continue

        # Match KEY=VALUE
        m = match(r"^[A-Za-z_][A-Za-z0-9_]*\s*=\s*(.+)$", stripped)
        isnothing(m) && continue

        value = strip(m.captures[1])
        # Remove surrounding quotes
        if length(value) >= 2
            if (startswith(value, '"') && endswith(value, '"')) ||
               (startswith(value, '\'') && endswith(value, '\''))
                value = value[2:end-1]
            end
        end

        # Skip empty or placeholder values
        isempty(value) && continue
        occursin(placeholder_pattern, value) && continue

        # Found at least one real-looking value
        return true
    end

    return false
end

"""Check if a .env filename is a known safe/template variant."""
function _is_safe_env_name(name_lower::String)::Bool
    for safe in ENV_SAFE_SUFFIXES
        if name_lower == safe
            return true
        end
    end
    # Also safe: if it ends with .example, .sample, .template, .defaults
    for suffix in [".example", ".sample", ".template", ".defaults"]
        if endswith(name_lower, suffix)
            return true
        end
    end
    return false
end

# ---------------------------------------------------------------------------
# Severity classification helpers
# ---------------------------------------------------------------------------

function _severity_for_exact_name(name_lower::String)::Severity
    if name_lower in Set(["id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"])
        return CRITICAL  # SSH private keys
    elseif name_lower == "credentials.json"
        return HIGH
    elseif name_lower == "serviceaccountkey.json"
        return CRITICAL  # GCP service account key
    end
    return HIGH
end

function _severity_for_extension(ext_lower::String)::Severity
    if ext_lower in Set([".pem", ".key", ".p12", ".pfx"])
        return HIGH  # Certificates and private keys
    elseif ext_lower == ".jks"
        return HIGH  # Java keystore
    elseif ext_lower in Set([".sqlite", ".db"])
        return MEDIUM  # Databases (may contain user data)
    end
    return MEDIUM
end

function _suggestion_for_extension(ext_lower::String)::String
    if ext_lower in Set([".pem", ".key", ".p12", ".pfx", ".jks"])
        return "Private keys and certificates should never be in version control. Use a secrets manager or certificate store."
    elseif ext_lower in Set([".sqlite", ".db"])
        return "Database files may contain user data. Add to .gitignore and use database migrations instead."
    end
    return "Review this file for sensitive content and consider adding it to .gitignore."
end
