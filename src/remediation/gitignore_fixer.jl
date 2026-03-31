"""
    Gitignore remediation utilities.

    Provides three levels of .gitignore repair:
      1. Append missing patterns to an existing .gitignore
      2. Remove already-tracked sensitive files from the git index
      3. Create a language-appropriate .gitignore from scratch

    All functions operate on a local repo clone path. They are designed to be
    called after the audit identifies missing or incomplete .gitignore coverage.
"""

# ---------------------------------------------------------------------------
# Standard .gitignore templates by language
# ---------------------------------------------------------------------------

const GITIGNORE_TEMPLATES = Dict{String, Vector{String}}(
    "Python" => [
        "# Python",
        "__pycache__/",
        "*.py[cod]",
        "*\$py.class",
        "*.so",
        ".Python",
        "env/",
        "venv/",
        ".venv/",
        "build/",
        "dist/",
        "*.egg-info/",
        ".eggs/",
        ".pytest_cache/",
        ".mypy_cache/",
        ".ruff_cache/",
        ".tox/",
        "*.egg",
        ".env",
        ".env.local",
    ],
    "JavaScript" => [
        "# JavaScript / Node.js",
        "node_modules/",
        "dist/",
        "build/",
        ".next/",
        ".nuxt/",
        "*.log",
        "npm-debug.log*",
        ".env",
        ".env.local",
        ".env.*.local",
        "coverage/",
        ".cache/",
    ],
    "TypeScript" => [
        "# TypeScript / Node.js",
        "node_modules/",
        "dist/",
        "build/",
        ".next/",
        "*.js.map",
        "*.log",
        ".env",
        ".env.local",
        ".env.*.local",
        "coverage/",
        ".cache/",
        "*.tsbuildinfo",
    ],
    "Swift" => [
        "# Swift / Xcode",
        ".build/",
        "DerivedData/",
        "*.xcuserdata/",
        "*.xcworkspace/xcuserdata/",
        "*.pbxuser",
        "*.mode1v3",
        "*.mode2v3",
        "*.perspectivev3",
        "*.hmap",
        "*.ipa",
        "*.dSYM.zip",
        "*.dSYM",
        "Pods/",
        ".env",
    ],
    "Dart" => [
        "# Dart / Flutter",
        ".dart_tool/",
        ".packages",
        "build/",
        ".flutter-plugins",
        ".flutter-plugins-dependencies",
        "*.iml",
        ".idea/",
        ".env",
    ],
    "Go" => [
        "# Go",
        "*.exe",
        "*.exe~",
        "*.dll",
        "*.so",
        "*.dylib",
        "*.test",
        "*.out",
        "vendor/",
        ".env",
    ],
    "Rust" => [
        "# Rust",
        "target/",
        "Cargo.lock",
        "*.pdb",
        ".env",
    ],
    "Julia" => [
        "# Julia",
        "Manifest.toml",
        ".env",
        "*.jl.cov",
        "*.jl.mem",
        "deps/build.log",
    ],
    "Zig" => [
        "# Zig",
        "zig-cache/",
        "zig-out/",
        ".zig-cache/",
        ".env",
    ],
    "Ruby" => [
        "# Ruby",
        "*.gem",
        "*.rbc",
        ".bundle/",
        "vendor/bundle/",
        "log/",
        "tmp/",
        ".env",
        ".env.local",
    ],
    "Elixir" => [
        "# Elixir",
        "_build/",
        "deps/",
        "*.ez",
        "*.beam",
        ".env",
    ],
)

# Common patterns that should be in every .gitignore regardless of language
const UNIVERSAL_PATTERNS = [
    "# OS files",
    ".DS_Store",
    "Thumbs.db",
    "",
    "# Editor files",
    ".vscode/",
    ".idea/",
    "*.swp",
    "*.swo",
    "*~",
    "",
    "# Secrets",
    ".env",
    ".env.local",
    ".env.*.local",
    "*.pem",
    "*.key",
    "credentials.json",
    "serviceAccountKey.json",
]

# ---------------------------------------------------------------------------
# Core remediation functions
# ---------------------------------------------------------------------------

"""
    fix_gitignore(repo_path::String, patterns::Vector{String}) -> Int

Append missing patterns to the .gitignore file at `repo_path`. If no .gitignore
exists, one is created. Returns the number of patterns added.

Each pattern is checked against existing lines to avoid duplicates. Blank lines
and comments in `patterns` are always appended as-is for formatting.

# Arguments
- `repo_path`: Path to the root of the local repository clone.
- `patterns`: Vector of gitignore patterns to ensure are present.
"""
function fix_gitignore(repo_path::String, patterns::Vector{String})::Int
    gitignore_path = joinpath(repo_path, ".gitignore")

    # Read existing patterns (empty set if file doesn't exist)
    existing = Set{String}()
    if isfile(gitignore_path)
        for line in readlines(gitignore_path)
            stripped = strip(line)
            if !isempty(stripped) && !startswith(stripped, "#")
                push!(existing, stripped)
            end
        end
    end

    # Determine which patterns to add
    to_add = String[]
    added_count = 0
    for pattern in patterns
        stripped = strip(pattern)
        # Always include blank lines and comments for formatting
        if isempty(stripped) || startswith(stripped, "#")
            push!(to_add, pattern)
        elseif stripped ∉ existing
            push!(to_add, pattern)
            added_count += 1
        end
    end

    if added_count == 0
        @info "No new patterns to add" repo_path
        return 0
    end

    # Append to .gitignore (create if needed)
    open(gitignore_path, "a") do io
        # Add a separator if the file already has content
        if isfile(gitignore_path) && filesize(gitignore_path) > 0
            println(io)
            println(io, "# Added by GHAudit")
        end
        for line in to_add
            println(io, line)
        end
    end

    @info "Updated .gitignore" repo_path patterns_added=added_count
    return added_count
end

"""
    remove_tracked_env(repo_path::String) -> Bool

Remove tracked `.env` files from the git index (without deleting them from disk).
Runs `git rm --cached` on common environment file patterns.

Returns `true` if any files were removed from tracking, `false` otherwise.
"""
function remove_tracked_env(repo_path::String)::Bool
    env_files = [".env", ".env.local", ".env.development", ".env.production",
                 ".env.staging", ".env.test"]

    removed_any = false

    for env_file in env_files
        full_path = joinpath(repo_path, env_file)
        # Only attempt removal if the file exists on disk (might be tracked)
        if isfile(full_path)
            try
                result = read(
                    Cmd(`git rm --cached $env_file`; dir=repo_path),
                    String,
                )
                @info "Removed from git index" file=env_file repo_path
                removed_any = true
            catch e
                # File exists on disk but isn't tracked — that's fine
                if occursin("did not match any files", sprint(showerror, e))
                    @info "File not tracked, skipping" file=env_file
                else
                    @warn "Failed to remove tracked file" file=env_file exception=e
                end
            end
        end
    end

    if removed_any
        @info "Tracked env files removed from index" repo_path
    else
        @info "No tracked env files found" repo_path
    end

    return removed_any
end

"""
    create_standard_gitignore(repo_path::String, language::String) -> Bool

Create a comprehensive .gitignore for `language` at `repo_path` if one doesn't
already exist. Combines language-specific patterns with universal patterns
(OS files, editor files, secrets).

Returns `true` if a new .gitignore was created, `false` if one already exists.

# Arguments
- `repo_path`: Path to the root of the local repository clone.
- `language`: Primary programming language (e.g., "Python", "TypeScript").
"""
function create_standard_gitignore(repo_path::String, language::String)::Bool
    gitignore_path = joinpath(repo_path, ".gitignore")

    if isfile(gitignore_path)
        @info "Gitignore already exists, skipping creation" repo_path
        return false
    end

    # Build the template
    lines = String[]

    # Language-specific patterns
    lang_patterns = get(GITIGNORE_TEMPLATES, language, String[])
    if !isempty(lang_patterns)
        append!(lines, lang_patterns)
        push!(lines, "")
    end

    # Universal patterns
    append!(lines, UNIVERSAL_PATTERNS)

    # Write the file
    open(gitignore_path, "w") do io
        for line in lines
            println(io, line)
        end
    end

    @info "Created standard .gitignore" repo_path language patterns=length(lines)
    return true
end
