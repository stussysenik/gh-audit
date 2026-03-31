"""
    Repository visibility management.

    Handles the transition of repositories from private to public, with
    safeguards including dry-run mode, rate-limiting (1 req/sec), and
    automatic revert list generation for rollback.

    All GitHub API calls go through the `GitHub.set_visibility` wrapper,
    which uses the `gh` CLI under the hood.
"""

# ---------------------------------------------------------------------------
# Publish repos to public
# ---------------------------------------------------------------------------

"""
    publish_repos(owner::String, repos::Vector{String}, dry_run::Bool=true) -> Vector{String}

Set the visibility of `repos` to "public" under `owner`. Returns a vector of
repo names that were successfully made public.

When `dry_run=true` (the default), no changes are made — the function only
prints what it would do. This is a safety measure to prevent accidental
exposure of sensitive repositories.

Rate-limited to 1 request per second to stay within GitHub API limits.

# Arguments
- `owner`: GitHub username or org that owns the repositories.
- `repos`: Vector of repository names (not full paths) to publish.
- `dry_run`: If `true`, only print actions without executing them.
"""
function publish_repos(owner::String, repos::Vector{String}, dry_run::Bool=true)::Vector{String}
    total = length(repos)
    published = String[]

    if dry_run
        @info "DRY RUN — no changes will be made" total_repos=total
    else
        @info "Publishing repos to public" total_repos=total owner
    end

    for (i, repo) in enumerate(repos)
        if dry_run
            @info "[DRY RUN] Would publish $owner/$repo ($i/$total)"
        else
            @info "Publishing $owner/$repo ($i/$total)"
            success = GitHub.set_visibility(owner, repo, "public")
            if success
                push!(published, repo)
                @info "Published $owner/$repo"
            else
                @warn "Failed to publish $owner/$repo — skipping"
            end

            # Rate limit: 1 second between API calls (skip after last repo)
            if i < total
                sleep(1)
            end
        end
    end

    if dry_run
        @info "DRY RUN complete — $(total) repos would be published"
    else
        @info "Publishing complete" published=length(published) failed=total-length(published)
    end

    return published
end

# ---------------------------------------------------------------------------
# Revert repos to private
# ---------------------------------------------------------------------------

"""
    revert_repos(owner::String, repos::Vector{String}) -> Vector{String}

Set the visibility of `repos` back to "private" under `owner`. Returns a
vector of repo names that were successfully reverted.

Rate-limited to 1 request per second.

# Arguments
- `owner`: GitHub username or org.
- `repos`: Vector of repository names to revert to private.
"""
function revert_repos(owner::String, repos::Vector{String})::Vector{String}
    total = length(repos)
    reverted = String[]

    @info "Reverting repos to private" total_repos=total owner

    for (i, repo) in enumerate(repos)
        @info "Reverting $owner/$repo ($i/$total)"
        success = GitHub.set_visibility(owner, repo, "private")
        if success
            push!(reverted, repo)
            @info "Reverted $owner/$repo to private"
        else
            @warn "Failed to revert $owner/$repo — skipping"
        end

        # Rate limit: 1 second between API calls (skip after last repo)
        if i < total
            sleep(1)
        end
    end

    @info "Revert complete" reverted=length(reverted) failed=total-length(reverted)
    return reverted
end

# ---------------------------------------------------------------------------
# Revert list generation
# ---------------------------------------------------------------------------

"""
    generate_revert_list(summary::AuditSummary, output_path::String) -> String

Write a `repos-to-revert.txt` file containing one repo name per line for every
repository in the summary that was classified as SAFE (i.e., repos that were
changed to public and may need to be reverted).

Returns the absolute path of the written file.

# Arguments
- `summary`: The completed `AuditSummary` containing all repo reports.
- `output_path`: Path to write the revert list file.
"""
function generate_revert_list(summary::AuditSummary, output_path::String)::String
    # Ensure the output directory exists
    output_dir = dirname(output_path)
    if !isempty(output_dir) && !isdir(output_dir)
        mkpath(output_dir)
    end

    # Only include repos that were made public (SAFE classification)
    published_repos = filter(r -> r.classification == SAFE, summary.repos)

    open(output_path, "w") do io
        for r in published_repos
            println(io, r.name)
        end
    end

    @info "Revert list written" path=output_path repos=length(published_repos)
    return abspath(output_path)
end
