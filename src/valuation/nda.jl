"""
    NDA classification engine.

    Scores each repository 0-100 for NDA sensitivity based on:
    - Name/description keyword matching against Config.NDA_KEYWORDS
    - Signal category scoring from Config.NDA_SIGNALS
    - File tree analysis for sensitive patterns
    - Force-private list from exclusions.toml

    A repo scoring >= Config.NDA_THRESHOLD (default 50) is recommended for
    NDA protection — meaning it should stay private or require an NDA before
    sharing with third parties.

    Teaching note — why NDA classification?
    Private repos often contain trade secrets, proprietary algorithms, personal
    infrastructure configs, or financial trading logic. Accidentally making these
    public can have legal and financial consequences. This engine automates the
    "should this stay private?" decision.
"""

# ---------------------------------------------------------------------------
# File-tree sensitivity signals
# ---------------------------------------------------------------------------

"""
    _check_file_tree_signals(file_tree::Vector{String}) -> (adjustment::Float64, reasons::Vector{String})

Scan the file tree for sensitivity signals that adjust the NDA score:

- `.env` files with potential secrets      → +15
- Financial keywords in filenames          → +20
- Personal data files                      → +15
- Playground/tutorial indicators           → -20 (via name check, not here)
"""
function _check_file_tree_signals(file_tree::Vector{String})::Tuple{Float64, Vector{String}}
    adjustment = 0.0
    reasons = String[]
    tree_lower = lowercase.(file_tree)

    # --- .env files → potential secrets (+15) ---
    has_env = any(f -> f == ".env" ||
                       f == ".env.local" ||
                       f == ".env.production" ||
                       (startswith(f, ".env") && !endswith(f, ".example") && !endswith(f, ".sample")),
                  tree_lower)
    if has_env
        adjustment += 15.0
        push!(reasons, "Contains .env file(s) with potential secrets")
    end

    # --- Financial keywords in filenames (+20) ---
    financial_keywords = ["trade", "trading", "market", "wallet", "payment",
                          "billing", "invoice", "ledger", "portfolio-value",
                          "arbitrage", "hedge", "stock", "crypto"]
    financial_hits = any(f -> any(kw -> occursin(kw, f), financial_keywords), tree_lower)
    if financial_hits
        adjustment += 20.0
        push!(reasons, "Financial-related filenames detected")
    end

    # --- Personal data files (+15) ---
    personal_keywords = ["contacts", "calendar", "diary", "journal",
                         "personal", "outlook", "email-export", "messages"]
    personal_hits = any(f -> any(kw -> occursin(kw, f), personal_keywords), tree_lower)
    if personal_hits
        adjustment += 15.0
        push!(reasons, "Personal data filenames detected")
    end

    return (adjustment, reasons)
end

# ---------------------------------------------------------------------------
# Name/description keyword matching
# ---------------------------------------------------------------------------

"""
    _check_nda_keywords(name::String, description::String) -> (score::Float64, reasons::Vector{String})

Match repo name and description against Config.NDA_KEYWORDS for each signal
category, then sum the corresponding Config.NDA_SIGNALS scores.
"""
function _check_nda_keywords(name::String, description::String)::Tuple{Float64, Vector{String}}
    score = 0.0
    reasons = String[]
    combined = lowercase(name * " " * description)

    for (signal, keywords) in Config.NDA_KEYWORDS
        if any(kw -> occursin(kw, combined), keywords)
            signal_score = get(Config.NDA_SIGNALS, signal, 0.0)
            score += signal_score
            push!(reasons, "Matches '$(signal)' signal ($(signal_score > 0 ? "+" : "")$(signal_score))")
        end
    end

    return (score, reasons)
end

# ---------------------------------------------------------------------------
# Playground / tutorial anti-signal
# ---------------------------------------------------------------------------

"""
    _check_learning_signal(name::String, description::String) -> (adjustment::Float64, reasons::Vector{String})

Repos that are clearly learning exercises or tutorials are less likely to need
NDA protection. Apply a negative adjustment.
"""
function _check_learning_signal(name::String, description::String)::Tuple{Float64, Vector{String}}
    adjustment = 0.0
    reasons = String[]
    combined = lowercase(name * " " * description)

    learning_words = ["playground", "tutorial", "learning", "clone", "example",
                      "homework", "exercise", "practice", "sandbox", "demo"]

    hits = count(w -> occursin(w, combined), learning_words)
    if hits > 0
        adjustment -= 20.0
        push!(reasons, "Learning/tutorial project detected (-20)")
    end

    return (adjustment, reasons)
end

# ---------------------------------------------------------------------------
# Main NDA scoring
# ---------------------------------------------------------------------------

"""
    calculate_nda_score(name, description, file_tree, exclusions) -> (score::Float64, reasons::Vector{String})

Compute the NDA sensitivity score (0-100) for a repository.

Scoring pipeline:
1. Match name/description against Config.NDA_KEYWORDS → sum NDA_SIGNALS
2. Scan file tree for sensitive patterns (.env, financial, personal data)
3. Check for learning/tutorial anti-signals
4. Check force_private list from exclusions.toml
5. Clamp to 0-100

# Arguments
- `name::String`         — repository name
- `description::String`  — GitHub description
- `file_tree::Vector{String}` — flat list of file paths in the repo
- `exclusions::Dict`     — parsed exclusions.toml (may contain "force_private" key)
"""
function calculate_nda_score(
    name::String,
    description::String,
    file_tree::Vector{String},
    exclusions::Dict,
)::Tuple{Float64, Vector{String}}
    all_reasons = String[]

    # 1. Keyword matching against NDA signal categories
    (kw_score, kw_reasons) = _check_nda_keywords(name, description)
    append!(all_reasons, kw_reasons)

    # 2. File tree signals
    (ft_adjustment, ft_reasons) = _check_file_tree_signals(file_tree)
    append!(all_reasons, ft_reasons)

    # 3. Learning/tutorial anti-signal
    (learn_adjustment, learn_reasons) = _check_learning_signal(name, description)
    append!(all_reasons, learn_reasons)

    # 4. Force-private override from exclusions.toml
    force_private_bonus = 0.0
    force_private_dict = get(exclusions, "force_private", Dict())
    force_private_list = force_private_dict isa Dict ? get(force_private_dict, "repos", String[]) : String[]
    if name in force_private_list
        force_private_bonus = 100.0
        push!(all_reasons, "Listed in force_private exclusions (auto-NDA)")
    end

    # Sum and clamp
    raw_score = kw_score + ft_adjustment + learn_adjustment + force_private_bonus
    final_score = clamp(raw_score, 0.0, 100.0)

    # Add summary if score is zero
    if isempty(all_reasons)
        push!(all_reasons, "No NDA signals detected")
    end

    return (final_score, all_reasons)
end

# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

"""
    classify_nda(score::Float64) -> Bool

Returns `true` if the NDA score meets or exceeds the threshold
(Config.NDA_THRESHOLD, default 50), indicating the repo should be
protected by an NDA or kept private.
"""
function classify_nda(score::Float64)::Bool
    return score >= Config.NDA_THRESHOLD
end
