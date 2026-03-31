# GHAudit.jl

Scientific GitHub portfolio security audit and valuation engine. Built in Julia.

Scans your GitHub repos for leaked secrets, estimates monetary value using COCOMO II, classifies what should stay private, and scores every repo from staff-engineer, design-engineer, and AI/ML-researcher perspectives.

## What it does

```
╔══════════════════════════════════════════════════════╗
║           GHAudit Repo Appraisal                    ║
╠══════════════════════════════════════════════════════╣
║  Repo:      stussysenik/zig-image-carousel          ║
║  Language:  Zig                                     ║
║  LOC:       4,334 (4.3 KLOC)                        ║
║  LOC Source: tokei                                  ║
║  Findings:  0                                       ║
╠══════════════════════════════════════════════════════╣
║  COCOMO Effort:     5.4 person-months               ║
║  Development Cost:  $165,189                        ║
║  Market Score:      62.6/100                        ║
║  Raw Value:         $121,356                        ║
║  Est. Value:        $121,356                        ║
║  Confidence:        high (95%)                      ║
╠══════════════════════════════════════════════════════╣
║  Leverage:          $28,001/KLOC                    ║
║  Leverage Rank:     Gold                            ║
╚══════════════════════════════════════════════════════╝
```

## Features

- **Security scanning** — gitleaks full git history scan, prompt injection detection, Apple metadata audit
- **COCOMO II valuation** — scientific effort estimation (Boehm, 2000) with language-adjusted complexity
- **Leverage scoring** — value per KLOC, ranked Diamond/Gold/Silver/Bronze/Raw
- **NDA classification** — automated detection of repos that should stay private
- **Graph theory analysis** — portfolio modeled as a knowledge graph (Graphs.jl), skill domain clustering, hub detection
- **Bayesian risk propagation** — if one repo leaks, probabilistic risk scores for similar repos (Beta-Binomial conjugate model)
- **Category theory** — functorial mapping F: Code -> Risk with verified composition laws
- **Multi-perspective review** — scored from staff engineer, design engineer, and AI/ML researcher viewpoints
- **Security tooling recommendations** — CodeRabbit, Greptile, GitHub Actions setup guidance

## Usage

### Appraise a single repo

```bash
julia bin/ghaudit.jl appraise --repo owner/repo-name
```

### Full portfolio audit

```bash
julia bin/ghaudit.jl scan --user yourusername
```

### Triage only (no cloning)

```bash
julia bin/ghaudit.jl triage --user yourusername
```

### Publish safe repos

```bash
julia bin/ghaudit.jl publish --input gh-audit-report-*.json --dry-run
julia bin/ghaudit.jl publish --input gh-audit-report-*.json  # for real
```

### Schedule auto-revert

```bash
julia bin/ghaudit.jl schedule --days 14
```

## Installation

```bash
# Dependencies
brew install juliaup gitleaks bfg tokei

# Julia packages
cd gh-audit
julia -e 'using Pkg; Pkg.activate("."); Pkg.instantiate()'

# Run tests
julia test/runtests.jl
```

## The Math

### COCOMO II (Constructive Cost Model)

Based on Boehm's 2000 model for software cost estimation:

```
Effort (person-months) = A * (KLOC)^E * Product(EM_i)

where:
  A = 2.94                              (calibration constant)
  E = 0.91 + 0.01 * Sum(SF_j) = 1.021  (scale exponent)
  SF_j = {PREC, FLEX, RESL, TEAM, PMAT} (5 scale factors)
  EM_i = 17 effort multipliers          (complexity, tools, capability, etc.)
```

**Key insight**: Language complexity adjusts the CPLX multiplier. Zig (1.30x) costs more effort than Python (0.90x) for the same KLOC because of manual memory management.

**Rate tiers**:
- Staff/specialist ($175/hr): Zig, Rust, GLSL, WebGPU, Haskell, Julia
- Senior ($100/hr): Swift, Elixir, Go, TypeScript, Kotlin
- Junior ($50/hr): Python, Ruby, Lua, HTML, CSS

### Market Comparable Score (0-100)

```
market = 0.30 * tech_demand       # Language/framework market demand index
       + 0.25 * uniqueness        # Fewer similar repos = higher score
       + 0.20 * completeness      # README + tests + CI + demo + LICENSE
       + 0.15 * stars_potential   # Niche + language + LOC heuristic
       + 0.10 * commercial_score  # SaaS/product keywords
```

### Final Valuation

```
raw_value = 0.50 * COCOMO_cost                    # Development replacement cost
          + 0.30 * (market_score/100 * cost)      # Market opportunity multiplier
          + 0.20 * (portfolio_score/100 * cost)   # Portfolio/brand premium

adjusted_value = raw_value * adjustment_factor
```

### Confidence + Adjustment

`gh-audit` now reports both `raw_estimated_value_usd` and adjusted `estimated_value_usd`.

- `raw` is the unadjusted replacement-cost style reference
- `adjusted` discounts shallow `disk_estimate` repos and very large LOC outliers
- `confidence_label` and `confidence_score` show how much trust to place in the number
- `loc_source` shows whether LOC came from real `tokei` counting or a disk-usage fallback

This makes the math better in exactly the cases that were overstating totals before:

- vendored / generated / build-heavy trees are excluded from `tokei`
- shallow repos with only disk-based LOC get lower confidence
- giant KLOC outliers are attenuated instead of dominating the portfolio total unchecked

### Leverage Score

```
leverage = estimated_value / KLOC

Diamond: > $50,000/KLOC    (maximum value from minimal code)
Gold:    > $20,000/KLOC
Silver:  > $10,000/KLOC
Bronze:  > $5,000/KLOC
Raw:     <= $5,000/KLOC
```

### Bayesian Risk Propagation

Uses a Beta-Binomial conjugate prior model:

```
Prior:      Beta(alpha, beta) where alpha = vulnerable_count + 1, beta = clean_count + 1
Posterior:  For each repo, compute P(vulnerable | shared_attributes) via noisy-OR:
            P(vuln_i) = 1 - Product(1 - similarity_j * severity_j)
            for all known-vulnerable repos j
```

### Graph Theory (Graphs.jl)

Repos are vertices. Edges weighted by:
- Same language: 0.3
- Domain overlap (Jaccard): up to 0.5
- Shared description keywords: up to 0.4

Analysis: betweenness centrality (hub detection), connected components (skill clustering).

### Category Theory

Functor **F: Code -> Risk** maps:
- Objects (repos) to risk scores in [0,1]
- Morphisms (shared attributes) to risk propagation weights
- Verifies identity and composition laws

## Architecture

```
gh-audit/
  src/
    GHAudit.jl              # Main module
    config.jl               # COCOMO II params, market demand indices
    github.jl               # gh CLI wrapper
    cli.jl                  # ArgParse CLI (triage, scan, appraise, publish)
    scanner/                # Security scanning pipeline
      triage.jl             # API-level scan (no clone needed)
      secrets.jl            # gitleaks full-history wrapper
      ai_instructions.jl    # Prompt injection detection
      files.jl              # Sensitive file pattern scanner
      apple_meta.jl         # Apple Team ID / signing scanner
    valuation/              # Mathematical analysis
      cocomo.jl             # COCOMO II effort + cost model
      market.jl             # Market comparable scoring
      portfolio.jl          # Multi-perspective quality review
      nda.jl                # NDA classification engine
      graph_theory.jl       # Portfolio graph analysis (Graphs.jl)
      bayesian_risk.jl      # Bayesian risk propagation + category theory
    reporter/               # Report generation
      models.jl             # Data structures (Finding, Valuation, RepoReport)
      categorizer.jl        # SAFE / NEEDS_FIXES / TOO_SENSITIVE / NDA
      json_report.jl        # Machine-readable JSON output
      markdown_report.jl    # Human-readable markdown with tables
    remediation/            # Auto-fix capabilities
      gitignore_fixer.jl    # .gitignore remediation
    visibility/             # GitHub repo management
      publisher.jl          # Make repos public/private
      scheduler.jl          # GitHub Actions auto-revert workflow
```

## License

MIT
