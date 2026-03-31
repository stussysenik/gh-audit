"""
    Core data models for GHAudit findings, valuations, and reports.

    Uses Julia's type system to enforce structure across the entire audit pipeline.
    All monetary values in USD. All scores normalized 0-100.
"""

@enum Severity CRITICAL=1 HIGH=2 MEDIUM=3 LOW=4 INFO=5
@enum Category SECRET=1 AI_INSTRUCTION=2 SENSITIVE_FILE=3 DEPENDENCY=4 APPLE_META=5
@enum Classification SAFE=1 NEEDS_FIXES=2 TOO_SENSITIVE=3 NDA_REQUIRED=4

@enum TriageLevel begin
    TRIAGE_CLEAN = 1
    TRIAGE_REVIEW = 2
    TRIAGE_SCAN_DEEP = 3
    TRIAGE_SENSITIVE = 4
end

"""A single security or quality finding in a repository."""
Base.@kwdef struct Finding
    repo::String
    severity::Severity
    category::Category
    file_path::String = ""
    line_number::Union{Int, Nothing} = nothing
    description::String
    suggestion::String = ""
    auto_fixable::Bool = false
    commit_sha::Union{String, Nothing} = nothing
end

"""COCOMO II + market-based monetary valuation of a repository."""
Base.@kwdef struct Valuation
    kloc::Float64 = 0.0
    cocomo_effort_pm::Float64 = 0.0     # Person-months
    cocomo_cost_usd::Float64 = 0.0      # Development cost estimate
    market_score::Float64 = 0.0         # 0-100
    portfolio_score::Float64 = 0.0      # 0-100
    raw_estimated_value_usd::Float64 = 0.0
    estimated_value_usd::Float64 = 0.0  # Adjusted final valuation
    adjustment_factor::Float64 = 1.0
    leverage_score::Float64 = 0.0       # Value per KLOC — higher = more efficient value creation
    leverage_rank::String = ""          # "Diamond", "Gold", "Silver", "Bronze", "Raw"
    confidence_score::Float64 = 0.0
    confidence_label::String = ""
    loc_source::String = ""
    warning_flags::Vector{String} = String[]
end

"""Multi-perspective quality assessment."""
Base.@kwdef struct Perspectives
    staff_engineer::Float64 = 0.0       # 0-100
    design_engineer::Float64 = 0.0      # 0-100
    ai_ml_researcher::Float64 = 0.0     # 0-100
    staff_eng_notes::String = ""
    design_eng_notes::String = ""
    ai_ml_notes::String = ""
end

"""API triage result for a single repository."""
Base.@kwdef mutable struct TriageResult
    name::String
    triage_level::TriageLevel = TRIAGE_CLEAN
    flags::Vector{String} = String[]
    has_ai_instructions::Bool = false
    has_apple_project::Bool = false
    has_env_files::Bool = false
    has_sensitive_files::Bool = false
    file_count::Int = 0
    language::String = ""
    disk_kb::Int = 0
    description::String = ""
end

"""Complete audit report for a single repository."""
Base.@kwdef mutable struct RepoReport
    name::String
    classification::Classification = SAFE
    triage::TriageResult = TriageResult(name=name)
    findings::Vector{Finding} = Finding[]
    valuation::Valuation = Valuation()
    perspectives::Perspectives = Perspectives()
    language::String = ""
    disk_kb::Int = 0
    loc::Int = 0
    loc_by_language::Dict{String, Int} = Dict{String, Int}()
    nda_score::Float64 = 0.0
    nda_reasons::Vector{String} = String[]
    deep_scanned::Bool = false
end

"""Summary of the entire audit run."""
Base.@kwdef mutable struct AuditSummary
    timestamp::String = ""
    total_repos::Int = 0
    safe_count::Int = 0
    needs_fixes_count::Int = 0
    too_sensitive_count::Int = 0
    nda_count::Int = 0
    total_findings::Int = 0
    critical_count::Int = 0
    total_portfolio_value_usd::Float64 = 0.0
    raw_total_portfolio_value_usd::Float64 = 0.0
    average_confidence_score::Float64 = 0.0
    repos::Vector{RepoReport} = RepoReport[]
end

# --- JSON serialization via StructTypes ---

import StructTypes

StructTypes.StructType(::Type{Finding}) = StructTypes.Struct()
StructTypes.StructType(::Type{Valuation}) = StructTypes.Struct()
StructTypes.StructType(::Type{Perspectives}) = StructTypes.Struct()
StructTypes.StructType(::Type{TriageResult}) = StructTypes.Mutable()
StructTypes.StructType(::Type{RepoReport}) = StructTypes.Mutable()
StructTypes.StructType(::Type{AuditSummary}) = StructTypes.Mutable()

# Enum serialization
for E in (Severity, Category, Classification, TriageLevel)
    StructTypes.StructType(::Type{E}) = StructTypes.StringType()
    StructTypes.construct(::Type{E}, s::String) = E(findfirst(x -> string(x) == s, instances(E)))
end

"""Count findings by severity."""
function count_by_severity(findings::Vector{Finding})
    counts = Dict{Severity, Int}()
    for f in findings
        counts[f.severity] = get(counts, f.severity, 0) + 1
    end
    return counts
end

"""Get the highest severity in a list of findings."""
function max_severity(findings::Vector{Finding})::Union{Severity, Nothing}
    isempty(findings) && return nothing
    return minimum(f -> f.severity, findings)  # CRITICAL=1 is lowest enum value
end
