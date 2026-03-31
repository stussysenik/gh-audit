"""
    COCOMO II effort and cost estimation model (Boehm, 2000).

    Implements the constructive cost model to estimate development effort in
    person-months and translate that into dollar costs at multiple rate tiers.

    Core formula:
        Effort (PM) = A × (KLOC)^E × ∏(EM_i)
        Cost         = Effort × HOURS_PER_PM × hourly_rate

    The CPLX effort multiplier is adjusted per-language using complexity factors
    from Config.LANGUAGE_COMPLEXITY, reflecting the cognitive overhead of each
    tech stack. A Zig project, for instance, demands ~30% more effort than a
    nominal baseline due to manual memory management.

    References:
        Boehm, B. W. (2000). Software Cost Estimation with COCOMO II.
"""

using JSON3

# ---------------------------------------------------------------------------
# LOC counting via tokei
# ---------------------------------------------------------------------------

"""
    count_loc_tokei(repo_path::String) -> (total_loc::Int, by_language::Dict{String,Int})

Shell out to `tokei --output json` and parse per-language code line counts.
Returns a tuple of total LOC and a language→LOC dictionary.

If tokei is unavailable or the repo path is empty, returns `(0, Dict())`.

# Teaching note — why tokei?
# tokei is a fast, accurate LOC counter that understands 200+ languages and
# ignores comments/blanks by default, giving us the *code* lines that matter
# for COCOMO estimation. The `--output json` flag makes it easy to parse.
"""
function count_loc_tokei(repo_path::String)::Tuple{Int, Dict{String, Int}}
    by_language = Dict{String, Int}()
    total_loc = 0

    # Guard: no path → nothing to count
    isempty(repo_path) && return (total_loc, by_language)
    isdir(repo_path)   || return (total_loc, by_language)

    try
        raw = read(`tokei --output json $repo_path`, String)
        data = JSON3.read(raw)

        for (lang_key, lang_data) in pairs(data)
            lang_name = string(lang_key)

            # tokei's JSON nests stats under the language key; the top-level
            # object for each language carries a "code" field with total lines.
            code_lines = 0
            if lang_data isa JSON3.Object && haskey(lang_data, :code)
                code_lines = Int(lang_data.code)
            end

            if code_lines > 0
                by_language[lang_name] = code_lines
                total_loc += code_lines
            end
        end
    catch e
        @warn "tokei LOC counting failed" repo_path exception=e
    end

    return (total_loc, by_language)
end

# ---------------------------------------------------------------------------
# Effort estimation
# ---------------------------------------------------------------------------

"""
    calculate_effort(kloc::Float64, language::String) -> Float64

Compute development effort in person-months using the COCOMO II post-architecture model.

The formula is:
    Effort = A × KLOC^E × EM_product_adjusted

where the EM product is adjusted by swapping the nominal CPLX multiplier (1.0)
for the language-specific complexity factor from `Config.LANGUAGE_COMPLEXITY`.

# Teaching note — why adjust CPLX?
# COCOMO's 17 effort multipliers capture project-wide characteristics, but the
# CPLX (product complexity) driver varies dramatically by language. Writing the
# same feature in Zig vs Python involves fundamentally different cognitive loads,
# so we scale accordingly.
"""
function calculate_effort(kloc::Float64, language::String)::Float64
    # Minimum LOC guard — avoids nonsensical sub-zero estimates
    kloc <= 0.0 && return 0.0

    # Fetch language-specific complexity multiplier
    cplx_adjustment = Config.get_complexity(language)

    # The stored EM_PRODUCT was computed with CPLX = 1.0 (nominal).
    # Replace that with the actual language complexity:
    #   adjusted_em = EM_PRODUCT / 1.0 × cplx_adjustment
    # Since nominal CPLX is 1.0, this simplifies to:
    adjusted_em = Config.EM_PRODUCT * cplx_adjustment

    # COCOMO II: Effort = A × KLOC^E × ∏(EM_i)
    effort_pm = Config.COCOMO_A * (kloc ^ Config.COCOMO_E) * adjusted_em

    return effort_pm
end

# ---------------------------------------------------------------------------
# Cost estimation
# ---------------------------------------------------------------------------

"""
    calculate_cost(effort_pm::Float64, rate::Float64) -> Float64

Convert person-month effort to a dollar cost.

    Cost = effort_pm × 176 hours/month × hourly_rate

# Teaching note — 176 hours/month
# Industry standard: 22 working days × 8 hours = 176 billable hours per month.
# This is the same constant used in COCOMO II's original calibration.
"""
function calculate_cost(effort_pm::Float64, rate::Float64)::Float64
    return effort_pm * Config.HOURS_PER_PM * rate
end

# ---------------------------------------------------------------------------
# Full valuation entry point
# ---------------------------------------------------------------------------

"""
    cocomo_valuate(kloc, language, description) -> NamedTuple

Run the complete COCOMO II valuation pipeline and return a named tuple with:
- `effort_pm`    — estimated person-months of effort
- `cost_junior`  — cost at junior rate (\$$(Config.RATE_JUNIOR)/hr)
- `cost_senior`  — cost at senior rate (\$$(Config.RATE_SENIOR)/hr)
- `cost_staff`   — cost at staff rate (\$$(Config.RATE_STAFF)/hr)
- `primary_cost` — cost at the tier assigned by `Config.get_rate_tier()`

The primary cost reflects the market-appropriate rate for the repo's
tech stack and domain keywords.
"""
function cocomo_valuate(kloc::Float64, language::String, description::String)
    effort_pm = calculate_effort(kloc, language)

    cost_junior = calculate_cost(effort_pm, Config.RATE_JUNIOR)
    cost_senior = calculate_cost(effort_pm, Config.RATE_SENIOR)
    cost_staff  = calculate_cost(effort_pm, Config.RATE_STAFF)

    primary_rate = Config.get_rate_tier(language, description)
    primary_cost = calculate_cost(effort_pm, primary_rate)

    return (
        effort_pm    = effort_pm,
        cost_junior  = cost_junior,
        cost_senior  = cost_senior,
        cost_staff   = cost_staff,
        primary_cost = primary_cost,
    )
end
