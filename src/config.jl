"""
    Configuration constants for GHAudit.

    COCOMO II parameters from Boehm (2000) "Software Cost Estimation with COCOMO II".
    Market demand indices based on 2025-2026 developer survey data.
"""

module Config

using TOML

# --- COCOMO II Parameters (Boehm, 2000) ---

# Calibration constant
const COCOMO_A = 2.94

# Base exponent
const COCOMO_B = 0.91

# Scale Factors for solo developer portfolio
const SCALE_FACTORS = Dict{String, Float64}(
    "PREC" => 2.48,   # Precedentedness: High (personal projects, familiar domain)
    "FLEX" => 1.01,   # Development Flexibility: Very High (no external constraints)
    "RESL" => 2.83,   # Risk Resolution: High (iterative approach)
    "TEAM" => 1.10,   # Team Cohesion: Very High (solo developer)
    "PMAT" => 4.68,   # Process Maturity: Nominal (informal process)
)

# E = B + 0.01 * sum(SF)
const COCOMO_E = COCOMO_B + 0.01 * sum(values(SCALE_FACTORS))

# Effort Multipliers (simplified for portfolio context)
const EFFORT_MULTIPLIERS = Dict{String, Float64}(
    "RELY" => 0.92,   # Required reliability: Low (personal projects)
    "DATA" => 1.00,   # Database size: Nominal
    "CPLX" => 1.00,   # Product complexity: Nominal (adjusted per-repo)
    "RUSE" => 1.00,   # Required reusability: Nominal
    "DOCU" => 0.91,   # Documentation: Low
    "TIME" => 1.00,   # Execution time constraint: Nominal
    "STOR" => 1.00,   # Main storage constraint: Nominal
    "PVOL" => 1.00,   # Platform volatility: Nominal
    "ACAP" => 0.85,   # Analyst capability: High
    "PCAP" => 0.88,   # Programmer capability: High
    "PCON" => 0.81,   # Personnel continuity: Very High (solo)
    "APEX" => 0.88,   # Applications experience: High
    "PLEX" => 0.91,   # Platform experience: High
    "LTEX" => 0.91,   # Language/tool experience: High
    "TOOL" => 0.90,   # Use of software tools: High (AI-assisted)
    "SITE" => 0.93,   # Multi-site development: High (single site)
    "SCED" => 1.00,   # Required schedule: Nominal
)

# Product of all effort multipliers
const EM_PRODUCT = prod(values(EFFORT_MULTIPLIERS))

# Hours per person-month
const HOURS_PER_PM = 176.0

# Hourly rate tiers (USD)
const RATE_JUNIOR = 50.0
const RATE_SENIOR = 100.0
const RATE_STAFF = 175.0

# --- Complexity multipliers by language/framework ---
# Adjusts CPLX effort multiplier based on tech stack sophistication
const LANGUAGE_COMPLEXITY = Dict{String, Float64}(
    "Zig"       => 1.30,   # Systems language, manual memory management
    "Rust"      => 1.25,   # Borrow checker, lifetime annotations
    "C++"       => 1.20,   # Templates, memory management
    "C"         => 1.15,   # Manual everything
    "Haskell"   => 1.20,   # Category theory, monads
    "OCaml"     => 1.15,   # Functional + imperative
    "Julia"     => 1.10,   # Scientific computing, multiple dispatch
    "Elixir"    => 1.10,   # Concurrent, OTP patterns
    "Swift"     => 1.05,   # Protocol-oriented, SwiftUI
    "Go"        => 0.95,   # Simple by design
    "Kotlin"    => 1.00,
    "Java"      => 0.95,
    "TypeScript" => 1.00,
    "JavaScript" => 0.95,
    "Python"    => 0.90,   # High-level, rapid development
    "Ruby"      => 0.90,
    "Dart"      => 0.95,   # Flutter
    "Lua"       => 0.90,
    "HTML"      => 0.70,   # Markup, low complexity
    "CSS"       => 0.70,
    "Shell"     => 0.80,
    "Nim"       => 1.10,
    "GLSL"      => 1.25,   # Shader programming
    "WGSL"      => 1.25,   # WebGPU shaders
)

# --- Market Demand Index (0-100) ---
# Based on 2025-2026 job market, GitHub trending, Stack Overflow surveys
const MARKET_DEMAND = Dict{String, Float64}(
    "Zig"        => 92.0,   # Hot systems language, growing fast
    "Rust"       => 90.0,   # Memory safety revolution
    "TypeScript"  => 88.0,   # Web standard
    "Python"     => 87.0,   # AI/ML dominant
    "Go"         => 85.0,   # Cloud infrastructure
    "Swift"      => 82.0,   # Apple ecosystem
    "Kotlin"     => 80.0,   # Android + server
    "Dart"       => 78.0,   # Flutter cross-platform
    "Elixir"     => 75.0,   # Real-time, scalable
    "Julia"      => 72.0,   # Scientific computing niche
    "JavaScript"  => 85.0,   # Ubiquitous
    "Ruby"       => 65.0,   # Rails still relevant
    "C++"        => 75.0,   # Systems, games
    "C"          => 70.0,   # Embedded, OS
    "Haskell"    => 55.0,   # Academic, niche
    "OCaml"      => 50.0,   # Niche functional
    "Lua"        => 60.0,   # Game scripting, LÖVE
    "HTML"       => 50.0,   # Commodity skill
    "CSS"        => 50.0,
    "Shell"      => 55.0,
    "Nim"        => 45.0,
    "GLSL"       => 70.0,   # Graphics programming
    "WGSL"       => 80.0,   # WebGPU is hot
)

# --- Valuation weights ---
const W_COCOMO = 0.50      # Development cost basis
const W_MARKET = 0.30      # Market opportunity
const W_PORTFOLIO = 0.20   # Portfolio/brand value

# --- LOC estimation / outlier controls ---
const DISK_ESTIMATE_BYTES_PER_LOC = 30
const TOKEI_EXCLUDE_PATHS = [
    ".git",
    "node_modules",
    "dist",
    "build",
    ".next",
    ".nuxt",
    "coverage",
    "vendor",
    "Pods",
    ".dart_tool",
    ".gradle",
    "DerivedData",
    "target",
    "tmp",
    "out",
    "__pycache__",
    ".cache",
    ".venv",
    "venv",
]
const LARGE_REPO_SOFT_KLOC = 250.0
const LARGE_REPO_HARD_KLOC = 1000.0
const SHALLOW_OUTLIER_MAX_DISCOUNT = 0.75
const DEEP_SCAN_OUTLIER_MAX_DISCOUNT = 0.30
const DISK_ESTIMATE_BASE_DISCOUNT = 0.80
const MIN_ADJUSTMENT_FACTOR = 0.20

# --- Portfolio perspective weights ---
const W_STAFF_ENG = 0.40
const W_DESIGN_ENG = 0.30
const W_AI_ML = 0.30

# --- NDA thresholds ---
const NDA_THRESHOLD = 50.0  # Score >= 50 → recommend NDA

# NDA signal scores
const NDA_SIGNALS = Dict{String, Float64}(
    "financial_trading"     => 55.0,
    "personal_infra"        => 30.0,
    "proprietary_algorithm" => 25.0,
    "personal_data"         => 20.0,
    "api_key_patterns"      => 15.0,
    "generic_utility"       => -20.0,
    "public_equivalent"     => -15.0,
    "learning_project"      => -10.0,
)

# Keywords that trigger NDA signals
const NDA_KEYWORDS = Dict{String, Vector{String}}(
    "financial_trading"     => ["polymarket", "trading bot", "arbitrage", "hedge fund", "stock trading", "crypto trading", "betting bot", "financial bot"],
    "personal_infra"        => ["dotfiles", "config", "setup", "nvim", "daily", "journal", "personal"],
    "proprietary_algorithm" => ["proprietary", "patent", "novel", "breakthrough"],
    "personal_data"         => ["outlook", "email", "migration", "contacts", "calendar", "diary"],
)

# --- Rate tier assignment by language/domain ---
const STAFF_RATE_LANGUAGES = Set(["Zig", "Rust", "GLSL", "WGSL", "OCaml", "Haskell", "Julia"])
const STAFF_RATE_KEYWORDS = Set(["webgpu", "wasm", "ml", "ai", "shader", "compiler", "kernel"])
const SENIOR_RATE_LANGUAGES = Set(["Swift", "Elixir", "Go", "TypeScript", "Kotlin", "Dart"])

"""Load exclusions from TOML file."""
function load_exclusions(path::String)
    isfile(path) || return Dict{String, Any}()
    return TOML.parsefile(path)
end

"""Get the hourly rate tier for a repo based on its primary language and keywords."""
function get_rate_tier(language::String, description::String="")
    desc_lower = lowercase(description)
    # Staff rate for specialized languages or domains
    if language in STAFF_RATE_LANGUAGES || any(kw -> occursin(kw, desc_lower), STAFF_RATE_KEYWORDS)
        return RATE_STAFF
    elseif language in SENIOR_RATE_LANGUAGES
        return RATE_SENIOR
    else
        return RATE_JUNIOR
    end
end

"""Get complexity multiplier for a language."""
function get_complexity(language::String)::Float64
    return get(LANGUAGE_COMPLEXITY, language, 1.0)
end

"""Get market demand score for a language."""
function get_market_demand(language::String)::Float64
    return get(MARKET_DEMAND, language, 50.0)
end

end # module Config
