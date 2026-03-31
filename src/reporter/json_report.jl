"""
    JSON report writer.

    Serializes the full `AuditSummary` to a pretty-printed JSON file using
    JSON3.write. This is the machine-readable audit output — consumed by
    dashboards, CI pipelines, and downstream tooling.
"""

using JSON3

# ---------------------------------------------------------------------------
# JSON report generation
# ---------------------------------------------------------------------------

"""
    write_json_report(summary::AuditSummary, output_path::String) -> String

Serialize `summary` to a pretty-printed JSON file at `output_path`.
Creates parent directories if they don't exist. Returns the absolute
path of the written file.

# Example
```julia
write_json_report(summary, "reports/audit-2026-03-31.json")
```
"""
function write_json_report(summary::AuditSummary, output_path::String)::String
    # Ensure the output directory exists
    output_dir = dirname(output_path)
    if !isempty(output_dir) && !isdir(output_dir)
        mkpath(output_dir)
        @info "Created output directory" path=output_dir
    end

    # Convert to plain Dict for reliable serialization (avoids enum/struct issues)
    data = _summary_to_dict(summary)

    open(output_path, "w") do io
        JSON3.pretty(io, data)
        write(io, "\n")
    end

    file_size_kb = round(filesize(output_path) / 1024; digits=1)
    @info "JSON report written" path=output_path size_kb=file_size_kb repos=summary.total_repos

    return abspath(output_path)
end

# --- Conversion helpers (struct → Dict for JSON serialization) ---

function _finding_to_dict(f::Finding)
    Dict{String,Any}(
        "repo" => f.repo, "severity" => string(f.severity),
        "category" => string(f.category), "file_path" => f.file_path,
        "line_number" => f.line_number, "description" => f.description,
        "suggestion" => f.suggestion, "auto_fixable" => f.auto_fixable,
        "commit_sha" => f.commit_sha,
    )
end

function _valuation_to_dict(v::Valuation)
    Dict{String,Any}(
        "kloc" => v.kloc, "cocomo_effort_pm" => v.cocomo_effort_pm,
        "cocomo_cost_usd" => v.cocomo_cost_usd, "market_score" => v.market_score,
        "portfolio_score" => v.portfolio_score,
        "raw_estimated_value_usd" => v.raw_estimated_value_usd,
        "estimated_value_usd" => v.estimated_value_usd,
        "adjustment_factor" => v.adjustment_factor,
        "leverage_score" => v.leverage_score,
        "leverage_rank" => v.leverage_rank,
        "confidence_score" => v.confidence_score,
        "confidence_label" => v.confidence_label,
        "loc_source" => v.loc_source,
        "warning_flags" => v.warning_flags,
    )
end

function _perspectives_to_dict(p::Perspectives)
    Dict{String,Any}(
        "staff_engineer" => p.staff_engineer, "design_engineer" => p.design_engineer,
        "ai_ml_researcher" => p.ai_ml_researcher,
        "staff_eng_notes" => p.staff_eng_notes, "design_eng_notes" => p.design_eng_notes,
        "ai_ml_notes" => p.ai_ml_notes,
    )
end

function _repo_to_dict(r::RepoReport)
    Dict{String,Any}(
        "name" => r.name, "classification" => string(r.classification),
        "findings" => [_finding_to_dict(f) for f in r.findings],
        "valuation" => _valuation_to_dict(r.valuation),
        "perspectives" => _perspectives_to_dict(r.perspectives),
        "language" => r.language, "disk_kb" => r.disk_kb, "loc" => r.loc,
        "nda_score" => r.nda_score, "nda_reasons" => r.nda_reasons,
        "deep_scanned" => r.deep_scanned,
    )
end

function _summary_to_dict(s::AuditSummary)
    Dict{String,Any}(
        "timestamp" => s.timestamp, "total_repos" => s.total_repos,
        "safe_count" => s.safe_count, "needs_fixes_count" => s.needs_fixes_count,
        "too_sensitive_count" => s.too_sensitive_count, "nda_count" => s.nda_count,
        "total_findings" => s.total_findings, "critical_count" => s.critical_count,
        "total_portfolio_value_usd" => s.total_portfolio_value_usd,
        "raw_total_portfolio_value_usd" => s.raw_total_portfolio_value_usd,
        "average_confidence_score" => s.average_confidence_score,
        "repos" => [_repo_to_dict(r) for r in s.repos],
    )
end
