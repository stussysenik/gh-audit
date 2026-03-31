"""
    Market comparable scoring (0-100).

    Estimates the market opportunity value of a repository by combining five
    independent signals into a weighted composite score:

        market_score = 0.30 × tech_demand
                     + 0.25 × uniqueness
                     + 0.20 × completeness
                     + 0.15 × stars_potential
                     + 0.10 × commercial

    Each sub-score is normalized to 0-100. The weights reflect the relative
    importance of each signal when evaluating a private portfolio repo for
    potential public release or commercialization.

    Teaching note — why market scoring?
    COCOMO tells you what it *cost* to build. Market scoring estimates what the
    market would *pay* for it. A 200-line SaaS dashboard in a hot language can
    be worth more than a 10,000-line tutorial project.
"""

# ---------------------------------------------------------------------------
# Sub-score: Technology demand
# ---------------------------------------------------------------------------

"""
    tech_demand_score(language::String) -> Float64

Lookup the market demand index (0-100) for the repo's primary language.
Falls back to 50.0 (neutral) for unknown languages.
"""
function tech_demand_score(language::String)::Float64
    return Config.get_market_demand(language)
end

# ---------------------------------------------------------------------------
# Sub-score: Uniqueness
# ---------------------------------------------------------------------------

# Words that signal low uniqueness — forks, exercises, clones
const _COMMON_WORDS = Set([
    "clone", "playground", "tutorial", "example", "demo", "test",
    "learning", "practice", "sample", "starter", "template", "boilerplate",
    "hello", "world", "todo", "todolist", "homework", "assignment",
    "exercise", "copy", "fork", "sandbox",
])

"""
    uniqueness_score(name::String, description::String) -> Float64

Heuristic uniqueness score (0-100) based on name and description signals.

Higher scores for:
- Longer, specific names (suggest purpose-built tools)
- Names free of common/generic words
- Non-empty descriptions with distinctive vocabulary

Lower scores for:
- Short generic names
- Names containing words like "clone", "tutorial", "playground"
- Empty descriptions
"""
function uniqueness_score(name::String, description::String)::Float64
    score = 50.0  # neutral baseline
    name_lower = lowercase(name)
    desc_lower = lowercase(description)

    # --- Name-based signals ---

    # Longer names tend to be more descriptive and purposeful
    name_len = length(name)
    if name_len >= 15
        score += 15.0
    elseif name_len >= 8
        score += 8.0
    elseif name_len <= 3
        score -= 15.0
    end

    # Names with hyphens/underscores suggest multi-word, specific projects
    if occursin(r"[-_]", name)
        score += 5.0
    end

    # Penalize common/generic words in the name
    name_words = Set(split(name_lower, r"[-_\s]+"))
    common_hits = length(intersect(name_words, _COMMON_WORDS))
    score -= common_hits * 12.0

    # --- Description-based signals ---
    if isempty(strip(description))
        score -= 10.0
    else
        desc_len = length(description)
        if desc_len >= 80
            score += 12.0
        elseif desc_len >= 30
            score += 6.0
        end

        # Check description for generic words too
        desc_words = Set(split(desc_lower, r"[-_\s,.:;!?]+"))
        desc_common = length(intersect(desc_words, _COMMON_WORDS))
        score -= desc_common * 5.0
    end

    return clamp(score, 0.0, 100.0)
end

# ---------------------------------------------------------------------------
# Sub-score: Completeness
# ---------------------------------------------------------------------------

"""
    completeness_score(file_tree::Vector{String}) -> Float64

Score (0-100) based on the presence of project health indicators in the file tree.

Checks:
- README.md               (+20)
- tests/ or test/          (+20)
- CI config                (+20)
- LICENSE                  (+15)
- screenshots or demo/     (+15)
- docs/                    (+10)

Teaching note — completeness as a market signal:
Repos with good structure are more likely to attract contributors, pass due
diligence, and be usable without author hand-holding. Each artifact adds to
the "production readiness" impression.
"""
function completeness_score(file_tree::Vector{String})::Float64
    isempty(file_tree) && return 0.0

    score = 0.0
    tree_lower = lowercase.(file_tree)

    # README (+20)
    if any(f -> f == "readme.md" || f == "readme.rst" || f == "readme", tree_lower)
        score += 20.0
    end

    # Tests (+20)
    if any(f -> startswith(f, "tests/") || startswith(f, "test/") ||
                startswith(f, "spec/") || startswith(f, "__tests__/"), tree_lower)
        score += 20.0
    end

    # CI/CD (+20)
    if any(f -> startswith(f, ".github/workflows/") ||
                f == ".gitlab-ci.yml" ||
                f == ".travis.yml" ||
                f == "jenkinsfile" ||
                f == ".circleci/config.yml" ||
                startswith(f, ".circleci/"), tree_lower)
        score += 20.0
    end

    # LICENSE (+15)
    if any(f -> startswith(f, "license"), tree_lower)
        score += 15.0
    end

    # Screenshots / demo (+15)
    if any(f -> startswith(f, "screenshots/") ||
                startswith(f, "demo/") ||
                occursin("screenshot", f) ||
                (endswith(f, ".gif") && !startswith(f, ".")), tree_lower)
        score += 15.0
    end

    # Docs (+10)
    if any(f -> startswith(f, "docs/") || startswith(f, "doc/"), tree_lower)
        score += 10.0
    end

    return clamp(score, 0.0, 100.0)
end

# ---------------------------------------------------------------------------
# Sub-score: Stars potential
# ---------------------------------------------------------------------------

"""
    stars_potential_score(language::String, description::String, loc::Int) -> Float64

Heuristic estimate of how many GitHub stars a repo could attract (0-100).

Factors:
- Popular language → larger audience
- Unique niche description → higher curiosity
- Substantial LOC (1000-15000) → "real" project impression
"""
function stars_potential_score(language::String, description::String, loc::Int)::Float64
    score = 30.0  # baseline

    # Language popularity lifts the ceiling
    demand = Config.get_market_demand(language)
    score += demand * 0.25  # up to +25

    # Unique description helps
    if !isempty(strip(description))
        desc_lower = lowercase(description)
        desc_words = Set(split(desc_lower, r"[-_\s,.:;!?]+"))
        common_hits = length(intersect(desc_words, _COMMON_WORDS))
        if common_hits == 0 && length(description) >= 30
            score += 15.0
        elseif common_hits == 0
            score += 8.0
        else
            score -= common_hits * 3.0
        end
    else
        score -= 10.0
    end

    # Substantial LOC sweet spot
    if 1000 <= loc <= 15000
        score += 15.0
    elseif 500 <= loc < 1000
        score += 8.0
    elseif loc > 15000
        score += 5.0  # large but may be unwieldy
    elseif loc < 200
        score -= 5.0  # too small to impress
    end

    return clamp(score, 0.0, 100.0)
end

# ---------------------------------------------------------------------------
# Sub-score: Commercial viability
# ---------------------------------------------------------------------------

# Keywords suggesting commercial potential
const _COMMERCIAL_KEYWORDS = Set([
    "saas", "app", "tool", "platform", "dashboard", "api", "service",
    "monitor", "analytics", "engine", "marketplace", "payment", "billing",
    "subscription", "enterprise", "crm", "erp", "automation", "workflow",
    "deploy", "infra", "cloud",
])

"""
    commercial_score(name::String, description::String) -> Float64

Score (0-100) based on commercial intent signals in the name and description.
Keywords like "saas", "platform", "dashboard" suggest monetization potential.
"""
function commercial_score(name::String, description::String)::Float64
    score = 20.0  # baseline — anything *could* be commercial
    combined = lowercase(name * " " * description)
    words = Set(split(combined, r"[-_\s,.:;!?/]+"))

    hits = length(intersect(words, _COMMERCIAL_KEYWORDS))

    # Each commercial keyword adds value, with diminishing returns
    if hits >= 4
        score += 60.0
    elseif hits >= 2
        score += 40.0
    elseif hits == 1
        score += 20.0
    end

    # Penalize obvious non-commercial signals
    non_commercial = Set(["tutorial", "homework", "learning", "exercise", "playground"])
    if length(intersect(words, non_commercial)) > 0
        score -= 20.0
    end

    return clamp(score, 0.0, 100.0)
end

# ---------------------------------------------------------------------------
# Composite market score
# ---------------------------------------------------------------------------

"""
    calculate_market_score(language, name, description, file_tree, loc) -> Float64

Weighted composite market score (0-100) combining all five sub-signals.

Weights:
    tech_demand     = 0.30
    uniqueness      = 0.25
    completeness    = 0.20
    stars_potential  = 0.15
    commercial      = 0.10
"""
function calculate_market_score(
    language::String,
    name::String,
    description::String,
    file_tree::Vector{String},
    loc::Int,
)::Float64
    td = tech_demand_score(language)
    uq = uniqueness_score(name, description)
    cp = completeness_score(file_tree)
    sp = stars_potential_score(language, description, loc)
    cm = commercial_score(name, description)

    weighted = 0.30 * td +
               0.25 * uq +
               0.20 * cp +
               0.15 * sp +
               0.10 * cm

    return clamp(weighted, 0.0, 100.0)
end
