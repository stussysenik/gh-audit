"""
    Multi-perspective portfolio quality scoring.

    Evaluates each repository through three expert lenses, each producing a
    0-100 score with explanatory notes:

    1. Staff Engineer     — code quality, testing, CI/CD, structure
    2. Design Engineer    — documentation, visual assets, developer UX
    3. AI/ML Researcher   — ML components, reproducibility, scientific rigor

    Teaching note — why three perspectives?
    A repo that scores 90 from a staff engineer (great tests, CI, clean code)
    might score 20 from a design engineer (no README, no screenshots). The
    three-lens approach surfaces blind spots and highlights repos that excel
    across disciplines — the ones worth showcasing in a portfolio.
"""

# ---------------------------------------------------------------------------
# Perspective 1: Staff Engineer
# ---------------------------------------------------------------------------

"""
    score_staff_engineer(file_tree, loc, language, findings_count) -> (score, notes)

A staff engineer evaluates production-readiness:

| Signal                 | Points |
|------------------------|--------|
| Has tests              | +25    |
| Has CI/CD              | +20    |
| Code organization      | +20    |
| Reasonable size        | +15    |
| Few security findings  | +10    |
| Has .gitignore         | +10    |
"""
function score_staff_engineer(
    file_tree::Vector{String},
    loc::Int,
    language::String,
    findings_count::Int,
)::Tuple{Float64, String}
    score = 0.0
    notes = String[]
    tree_lower = lowercase.(file_tree)

    # --- Has tests (+25) ---
    if any(f -> startswith(f, "test/") || startswith(f, "tests/") ||
                startswith(f, "spec/") || startswith(f, "__tests__/"), tree_lower)
        score += 25.0
        push!(notes, "Has test suite")
    else
        push!(notes, "No tests found")
    end

    # --- Has CI/CD (+20) ---
    if any(f -> startswith(f, ".github/workflows/") ||
                f == ".gitlab-ci.yml" ||
                f == ".travis.yml" ||
                f == "makefile" ||
                f == "justfile" ||
                startswith(f, ".circleci/"), tree_lower)
        score += 20.0
        push!(notes, "Has CI/CD pipeline")
    else
        push!(notes, "No CI/CD configuration")
    end

    # --- Code organization (+20) ---
    if any(f -> startswith(f, "src/") || startswith(f, "lib/") ||
                startswith(f, "pkg/") || startswith(f, "internal/") ||
                startswith(f, "app/"), tree_lower)
        score += 20.0
        push!(notes, "Well-organized directory structure")
    else
        push!(notes, "Flat directory structure")
    end

    # --- Reasonable size (+15) ---
    # 500-10000 LOC is the sweet spot: non-trivial but manageable
    if 500 <= loc <= 10000
        score += 15.0
        push!(notes, "Good project size ($(loc) LOC)")
    elseif 200 <= loc < 500
        score += 8.0
        push!(notes, "Small project ($(loc) LOC)")
    elseif loc > 10000
        score += 8.0
        push!(notes, "Large project ($(loc) LOC) — may need decomposition")
    else
        push!(notes, "Very small project ($(loc) LOC)")
    end

    # --- Few security findings (+10) ---
    if findings_count == 0
        score += 10.0
        push!(notes, "Clean security scan")
    elseif findings_count <= 2
        score += 5.0
        push!(notes, "$(findings_count) minor security finding(s)")
    else
        push!(notes, "$(findings_count) security findings need attention")
    end

    # --- Has .gitignore (+10) ---
    if any(f -> f == ".gitignore", tree_lower)
        score += 10.0
        push!(notes, "Has .gitignore")
    else
        push!(notes, "Missing .gitignore")
    end

    return (clamp(score, 0.0, 100.0), join(notes, "; "))
end

# ---------------------------------------------------------------------------
# Perspective 2: Design Engineer
# ---------------------------------------------------------------------------

"""
    score_design_engineer(file_tree, name, description) -> (score, notes)

A design engineer evaluates developer experience and presentation:

| Signal                    | Points |
|---------------------------|--------|
| README with content       | +25    |
| Visual assets             | +25    |
| Has description           | +15    |
| Descriptive name          | +15    |
| Has landing page          | +10    |
| Has LICENSE               | +10    |
"""
function score_design_engineer(
    file_tree::Vector{String},
    name::String,
    description::String,
)::Tuple{Float64, String}
    score = 0.0
    notes = String[]
    tree_lower = lowercase.(file_tree)

    # --- README with content (+25) ---
    # We check for presence; file size check requires content access, so we
    # award partial credit for existence and full credit if it looks substantial
    has_readme = any(f -> f == "readme.md" || f == "readme.rst" || f == "readme", tree_lower)
    if has_readme
        score += 25.0
        push!(notes, "Has README")
    else
        push!(notes, "No README found")
    end

    # --- Visual assets (+25) ---
    has_visuals = any(f -> startswith(f, "screenshots/") ||
                          startswith(f, "demo/") ||
                          startswith(f, "docs/") && (endswith(f, ".png") || endswith(f, ".gif") || endswith(f, ".jpg")) ||
                          (endswith(f, ".gif") && !startswith(f, ".")) ||
                          occursin("screenshot", f), tree_lower)
    if has_visuals
        score += 25.0
        push!(notes, "Has visual assets/demos")
    else
        push!(notes, "No screenshots or demos")
    end

    # --- Has description (+15) ---
    if !isempty(strip(description))
        score += 15.0
        push!(notes, "Has GitHub description")
    else
        push!(notes, "Missing GitHub description")
    end

    # --- Descriptive name (+15) ---
    # Longer names with hyphens suggest clarity and purpose
    name_len = length(name)
    if name_len >= 10 && occursin('-', name)
        score += 15.0
        push!(notes, "Descriptive project name")
    elseif name_len >= 6
        score += 8.0
        push!(notes, "Reasonable project name")
    else
        push!(notes, "Short/generic project name")
    end

    # --- Has landing page (+10) ---
    desc_lower = lowercase(description)
    if occursin("vercel.app", desc_lower) ||
       occursin("github.io", desc_lower) ||
       occursin("netlify.app", desc_lower) ||
       occursin("http", desc_lower)
        score += 10.0
        push!(notes, "Has landing page/URL")
    else
        push!(notes, "No landing page detected")
    end

    # --- Has LICENSE (+10) ---
    if any(f -> startswith(f, "license"), tree_lower)
        score += 10.0
        push!(notes, "Has LICENSE")
    else
        push!(notes, "Missing LICENSE")
    end

    return (clamp(score, 0.0, 100.0), join(notes, "; "))
end

# ---------------------------------------------------------------------------
# Perspective 3: AI/ML Researcher
# ---------------------------------------------------------------------------

# File patterns that signal ML/AI work
const _ML_FILE_PATTERNS = [
    "model/", "models/", "notebooks/", "notebook/",
]
const _ML_EXTENSIONS = [".ipynb", ".h5", ".onnx", ".pt", ".pth", ".pkl", ".safetensors"]
const _ML_REQUIREMENTS_KEYWORDS = [
    "torch", "tensorflow", "sklearn", "scikit", "keras", "jax",
    "transformers", "huggingface", "numpy", "pandas", "scipy",
    "mlflow", "wandb", "optuna", "xgboost", "lightgbm",
]

"""
    score_ai_ml_researcher(file_tree, language, name, description) -> (score, notes)

An AI/ML researcher evaluates scientific and research merit:

| Signal                   | Points |
|--------------------------|--------|
| ML/AI components         | +30    |
| Research references      | +20    |
| Reproducibility          | +20    |
| Novel approach           | +15    |
| Scientific rigor         | +15    |
"""
function score_ai_ml_researcher(
    file_tree::Vector{String},
    language::String,
    name::String,
    description::String,
)::Tuple{Float64, String}
    score = 0.0
    notes = String[]
    tree_lower = lowercase.(file_tree)
    desc_lower = lowercase(description)
    name_lower = lowercase(name)

    # --- ML/AI components (+30) ---
    has_ml_dirs = any(f -> any(p -> startswith(f, p), _ML_FILE_PATTERNS), tree_lower)
    has_ml_files = any(f -> any(ext -> endswith(f, ext), _ML_EXTENSIONS), tree_lower)
    has_ml_deps = any(f -> (f == "requirements.txt" || f == "pyproject.toml" || f == "setup.py"),
                       tree_lower)
    has_ml_keywords = any(kw -> occursin(kw, name_lower * " " * desc_lower),
                          ["ml", "ai", "machine-learning", "deep-learning", "neural",
                           "model", "training", "inference", "llm", "gpt", "bert",
                           "diffusion", "transformer", "classifier", "regression"])

    ml_signal_count = sum([has_ml_dirs, has_ml_files, has_ml_deps && has_ml_keywords, has_ml_keywords])
    if ml_signal_count >= 3
        score += 30.0
        push!(notes, "Strong ML/AI components detected")
    elseif ml_signal_count >= 2
        score += 20.0
        push!(notes, "Some ML/AI components present")
    elseif ml_signal_count >= 1
        score += 10.0
        push!(notes, "Possible ML/AI elements")
    else
        push!(notes, "No ML/AI components detected")
    end

    # --- Research references (+20) ---
    has_papers = any(f -> startswith(f, "papers/") || startswith(f, "references/"), tree_lower)
    has_arxiv = occursin("arxiv", desc_lower)
    has_citations = any(f -> endswith(f, ".bib") || f == "citations.md" || f == "references.md",
                        tree_lower)

    research_signals = sum([has_papers, has_arxiv, has_citations])
    if research_signals >= 2
        score += 20.0
        push!(notes, "Has research references/citations")
    elseif research_signals >= 1
        score += 10.0
        push!(notes, "Some research references")
    else
        push!(notes, "No research references found")
    end

    # --- Reproducibility (+20) ---
    repro_artifacts = [
        any(f -> f == "dockerfile" || startswith(f, "docker-compose"), tree_lower),
        any(f -> f == "environment.yml" || f == "conda.yml", tree_lower),
        any(f -> f == "requirements.txt" || f == "requirements-dev.txt", tree_lower),
        any(f -> f == "pyproject.toml" || f == "setup.py" || f == "setup.cfg", tree_lower),
        any(f -> f == "project.toml" || f == "manifest.toml", tree_lower),  # Julia
        any(f -> f == "flake.nix" || f == "shell.nix", tree_lower),
    ]
    repro_count = sum(repro_artifacts)
    if repro_count >= 3
        score += 20.0
        push!(notes, "Excellent reproducibility setup")
    elseif repro_count >= 2
        score += 14.0
        push!(notes, "Good reproducibility setup")
    elseif repro_count >= 1
        score += 7.0
        push!(notes, "Basic reproducibility (dependency file present)")
    else
        push!(notes, "No reproducibility artifacts")
    end

    # --- Novel approach (+15) ---
    generic_words = Set(["clone", "tutorial", "copy", "fork", "playground", "example",
                          "learning", "homework", "exercise"])
    combined_words = Set(split(name_lower * " " * desc_lower, r"[-_\s,.:;!?/]+"))
    generic_hits = length(intersect(combined_words, generic_words))

    if generic_hits == 0 && !isempty(strip(description))
        score += 15.0
        push!(notes, "Appears to be a novel/original approach")
    elseif generic_hits == 0
        score += 8.0
        push!(notes, "Name suggests originality (no description to confirm)")
    else
        push!(notes, "Appears derivative or educational")
    end

    # --- Scientific rigor (+15) ---
    # Having both tests AND documentation suggests disciplined research
    has_tests = any(f -> startswith(f, "test/") || startswith(f, "tests/") ||
                        startswith(f, "spec/") || startswith(f, "__tests__/"), tree_lower)
    has_docs = any(f -> startswith(f, "docs/") || startswith(f, "doc/") ||
                       f == "readme.md", tree_lower)

    if has_tests && has_docs
        score += 15.0
        push!(notes, "Has both tests and documentation (scientific rigor)")
    elseif has_tests || has_docs
        score += 7.0
        push!(notes, has_tests ? "Has tests but limited documentation" : "Has documentation but no tests")
    else
        push!(notes, "No tests or documentation")
    end

    return (clamp(score, 0.0, 100.0), join(notes, "; "))
end

# ---------------------------------------------------------------------------
# Composite perspective scoring
# ---------------------------------------------------------------------------

"""
    calculate_perspectives(file_tree, loc, language, name, description, findings_count) -> Perspectives

Run all three perspective evaluations and return a `Perspectives` struct.

The struct contains:
- `staff_engineer`   / `staff_eng_notes`
- `design_engineer`  / `design_eng_notes`
- `ai_ml_researcher` / `ai_ml_notes`

Each score is 0-100 with explanatory notes for report generation.
"""
function calculate_perspectives(
    file_tree::Vector{String},
    loc::Int,
    language::String,
    name::String,
    description::String,
    findings_count::Int,
)::Perspectives
    (se_score, se_notes) = score_staff_engineer(file_tree, loc, language, findings_count)
    (de_score, de_notes) = score_design_engineer(file_tree, name, description)
    (ai_score, ai_notes) = score_ai_ml_researcher(file_tree, language, name, description)

    return Perspectives(
        staff_engineer   = se_score,
        design_engineer  = de_score,
        ai_ml_researcher = ai_score,
        staff_eng_notes  = se_notes,
        design_eng_notes = de_notes,
        ai_ml_notes      = ai_notes,
    )
end
