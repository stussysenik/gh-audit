"""
    Repository classification engine.

    Assigns a `Classification` enum value to each `RepoReport` based on a priority
    cascade: NDA exclusions and scores take precedence, then severity-based checks,
    and finally auto-fixability of remaining findings.

    Classification priority (highest → lowest):
      1. NDA_REQUIRED  — force-listed in exclusions, or nda_score >= NDA_THRESHOLD
      2. TOO_SENSITIVE — any CRITICAL-severity finding present
      3. NEEDS_FIXES   — any HIGH-severity finding, or auto-fixable MEDIUM findings
      4. SAFE          — everything else
"""

# ---------------------------------------------------------------------------
# Main classification entry point
# ---------------------------------------------------------------------------

"""
    classify_repo(report::RepoReport, exclusions::Dict) -> Classification

Evaluate `report` against the exclusion list and its findings to assign a
`Classification`. Mutates `report.classification` in place and returns
the new value for convenience.

# Arguments
- `report`: A fully-populated `RepoReport` (findings, nda_score already set).
- `exclusions`: Dict parsed from the exclusions TOML file. Expected keys:
    - `"force_private"` → Vector of repo name strings that must stay private.
"""
function classify_repo(report::RepoReport, exclusions::Dict)::Classification
    # --- Priority 1: NDA override from exclusion list ---
    force_private_dict = get(exclusions, "force_private", Dict())
    force_private = get(force_private_dict, "repos", String[])
    if report.name in force_private
        report.classification = NDA_REQUIRED
        push!(report.nda_reasons, "Listed in force_private exclusion list")
        @info "Classified $(report.name) as NDA_REQUIRED (force_private exclusion)"
        return NDA_REQUIRED
    end

    # --- Priority 2: NDA score threshold ---
    if report.nda_score >= Config.NDA_THRESHOLD
        report.classification = NDA_REQUIRED
        @info "Classified $(report.name) as NDA_REQUIRED (nda_score=$(report.nda_score))"
        return NDA_REQUIRED
    end

    # --- Priority 3: Critical findings → too sensitive to publish ---
    has_critical = any(f -> f.severity == CRITICAL, report.findings)
    if has_critical
        report.classification = TOO_SENSITIVE
        @info "Classified $(report.name) as TOO_SENSITIVE (CRITICAL findings present)"
        return TOO_SENSITIVE
    end

    # --- Priority 4: High findings → needs remediation before publishing ---
    has_high = any(f -> f.severity == HIGH, report.findings)
    if has_high
        report.classification = NEEDS_FIXES
        @info "Classified $(report.name) as NEEDS_FIXES (HIGH findings present)"
        return NEEDS_FIXES
    end

    # --- Priority 5: Auto-fixable medium findings → still needs fixes ---
    has_fixable_medium = any(
        f -> f.severity == MEDIUM && f.auto_fixable,
        report.findings,
    )
    if has_fixable_medium
        report.classification = NEEDS_FIXES
        @info "Classified $(report.name) as NEEDS_FIXES (auto-fixable MEDIUM findings)"
        return NEEDS_FIXES
    end

    # --- Default: safe to publish ---
    report.classification = SAFE
    @info "Classified $(report.name) as SAFE"
    return SAFE
end

# ---------------------------------------------------------------------------
# Batch classification
# ---------------------------------------------------------------------------

"""
    classify_all!(reports::Vector{RepoReport}, exclusions::Dict) -> Nothing

Classify every report in the vector, mutating each in place. Also logs
a summary of classification counts when complete.
"""
function classify_all!(reports::Vector{RepoReport}, exclusions::Dict)
    counts = Dict{Classification, Int}()

    for report in reports
        cls = classify_repo(report, exclusions)
        counts[cls] = get(counts, cls, 0) + 1
    end

    @info "Classification complete" total=length(reports) safe=get(counts, SAFE, 0) needs_fixes=get(counts, NEEDS_FIXES, 0) too_sensitive=get(counts, TOO_SENSITIVE, 0) nda_required=get(counts, NDA_REQUIRED, 0)
    return nothing
end
