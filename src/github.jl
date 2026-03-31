"""
    GitHub API client wrapping the `gh` CLI.

    All GitHub interactions go through the authenticated `gh` command to avoid
    managing OAuth tokens directly. Handles rate limiting and pagination.
"""

module GitHub

using JSON3

"""Repo metadata returned by `gh repo list`."""
Base.@kwdef struct RepoInfo
    name::String
    description::String = ""
    language::String = ""
    disk_kb::Int = 0
    is_private::Bool = true
    is_fork::Bool = false
    url::String = ""
    default_branch::String = "main"
end

"""Run a gh CLI command and return stdout. Retries on transient failures."""
function gh(args::Vector{String}; timeout::Int=30, retries::Int=3)::String
    for attempt in 1:retries
        cmd = Cmd(`gh $args`)
        buf = IOBuffer()
        err_buf = IOBuffer()
        try
            run(pipeline(cmd, stdout=buf, stderr=err_buf), wait=true)
            return String(take!(buf))
        catch e
            err_msg = String(take!(err_buf))
            if attempt < retries && (occursin("502", err_msg) || occursin("503", err_msg) || occursin("timeout", lowercase(err_msg)))
                @warn "gh command failed (attempt $attempt/$retries), retrying in $(attempt * 2)s..." args err_msg
                sleep(attempt * 2)
            else
                @warn "gh command failed" args err_msg
                rethrow()
            end
        end
    end
    error("gh command failed after $retries attempts")
end

"""Run gh and parse JSON output."""
function gh_json(args::Vector{String}; timeout::Int=30)
    output = gh(args; timeout)
    return JSON3.read(output)
end

"""List all private repos for a user. Fetches in batches to avoid GitHub 502 errors."""
function list_private_repos(user::String; limit::Int=200)::Vector{RepoInfo}
    # gh repo list with many fields + high limit causes GraphQL 502s
    # Use simpler fields and let gh handle pagination
    output = gh([
        "repo", "list", user,
        "--visibility", "private",
        "--json", "name,description,primaryLanguage,diskUsage",
        "--limit", string(limit)
    ]; retries=3)

    raw = JSON3.read(output)

    raw = JSON3.read(output)
    repos = RepoInfo[]

    for r in raw
        lang = ""
        if haskey(r, :primaryLanguage) && !isnothing(r.primaryLanguage)
            lang_obj = r.primaryLanguage
            if lang_obj isa JSON3.Object && haskey(lang_obj, :name)
                lang = string(lang_obj.name)
            elseif lang_obj isa AbstractString
                lang = string(lang_obj)
            end
        end

        push!(repos, RepoInfo(
            name = string(get(r, :name, "")),
            description = string(get(r, :description, "")),
            language = lang,
            disk_kb = Int(get(r, :diskUsage, 0)),
            is_private = true,
        ))
    end

    return repos
end

"""Get the file tree for a repo (recursive) via GitHub API."""
function get_file_tree(owner::String, repo::String)::Vector{String}
    try
        output = gh([
            "api", "repos/$owner/$repo/git/trees/HEAD",
            "-q", ".tree[].path",
            "--paginate"
        ]; timeout=15)
        return filter(!isempty, split(strip(output), '\n'))
    catch
        # Fallback: try with recursive flag
        try
            output = gh([
                "api", "repos/$owner/$repo/git/trees/HEAD?recursive=1",
                "-q", ".tree[].path",
            ]; timeout=15)
            return filter(!isempty, split(strip(output), '\n'))
        catch e
            @warn "Could not fetch file tree for $repo" exception=e
            return String[]
        end
    end
end

"""Get file content from a repo via GitHub API."""
function get_file_content(owner::String, repo::String, path::String)::Union{String, Nothing}
    try
        output = gh([
            "api", "repos/$owner/$repo/contents/$path",
            "-q", ".content",
        ]; timeout=10)
        content = strip(output)
        isempty(content) && return nothing
        # GitHub API returns base64-encoded content
        return String(base64decode(content))
    catch
        return nothing
    end
end

"""Clone a repo to a local path. Returns true on success."""
function clone_repo(owner::String, repo::String, dest::String; depth::Int=0)::Bool
    try
        args = ["repo", "clone", "$owner/$repo", dest]
        if depth > 0
            args = ["repo", "clone", "$owner/$repo", dest, "--", "--depth=$depth"]
        end
        gh(args; timeout=120)
        return true
    catch e
        @warn "Failed to clone $repo" exception=e
        return false
    end
end

"""Change repo visibility."""
function set_visibility(owner::String, repo::String, visibility::String)::Bool
    try
        gh([
            "repo", "edit", "$owner/$repo",
            "--visibility", visibility,
            "--accept-visibility-change-consequences",
        ]; timeout=15)
        return true
    catch e
        @warn "Failed to set $repo visibility to $visibility" exception=e
        return false
    end
end

# Base64 decode helper (Julia stdlib)
function base64decode(s::String)::Vector{UInt8}
    Base.base64decode(replace(s, r"\s" => ""))
end

end # module GitHub
