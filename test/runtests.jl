using Test

# Activate project
using Pkg
Pkg.activate(joinpath(@__DIR__, ".."))

include(joinpath(@__DIR__, "..", "src", "GHAudit.jl"))
using .GHAudit
using .GHAudit: Finding, Valuation, RepoReport, Perspectives,
    CRITICAL, HIGH, MEDIUM, LOW, INFO,
    SECRET, AI_INSTRUCTION, SENSITIVE_FILE, DEPENDENCY, APPLE_META,
    SAFE, NEEDS_FIXES, TOO_SENSITIVE, NDA_REQUIRED

@testset "GHAudit Tests" begin

    @testset "Config" begin
        @test GHAudit.Config.COCOMO_A == 2.94
        @test GHAudit.Config.COCOMO_B == 0.91
        @test GHAudit.Config.COCOMO_E > 1.0  # E = B + 0.01 * sum(SF)
        @test GHAudit.Config.EM_PRODUCT > 0.0
        @test GHAudit.Config.EM_PRODUCT < 1.0  # Product of multipliers < 1 for capable team

        @test GHAudit.Config.get_rate_tier("Zig", "") == GHAudit.Config.RATE_STAFF
        @test GHAudit.Config.get_rate_tier("Python", "") == GHAudit.Config.RATE_JUNIOR
        @test GHAudit.Config.get_rate_tier("TypeScript", "") == GHAudit.Config.RATE_SENIOR
        @test GHAudit.Config.get_rate_tier("Python", "webgpu shader playground") == GHAudit.Config.RATE_STAFF
    end

    @testset "Models" begin
        f = Finding(
            repo = "test-repo",
            severity = CRITICAL,
            category = SECRET,
            description = "Found API key",
            file_path = ".env",
        )
        @test f.severity == CRITICAL
        @test f.auto_fixable == false

        v = Valuation(kloc=1.5, cocomo_effort_pm=2.0, cocomo_cost_usd=35200.0)
        @test v.kloc == 1.5

        r = RepoReport(name="test")
        @test r.classification == SAFE
        @test isempty(r.findings)
    end

    @testset "COCOMO II" begin
        # 1 KLOC project
        effort = GHAudit.calculate_effort(1.0, "Python")
        @test effort > 0.0
        @test effort < 50.0  # Should be a few person-months

        cost = GHAudit.calculate_cost(effort, 100.0)
        @test cost > 0.0
        @test cost == effort * 176.0 * 100.0

        # Zig should have higher effort than Python for same KLOC
        effort_zig = GHAudit.calculate_effort(1.0, "Zig")
        effort_py = GHAudit.calculate_effort(1.0, "Python")
        @test effort_zig > effort_py  # Zig is more complex

        # 0 KLOC edge case
        @test GHAudit.calculate_effort(0.0, "Python") == 0.0

        @test GHAudit.estimate_loc_from_disk_kb(30) == 1024

        valuation = GHAudit.build_valuation(600.0, "Python", "", 80.0, 70.0; deep_scanned=false, loc_source="disk_estimate")
        @test valuation.raw_estimated_value_usd > valuation.estimated_value_usd
        @test valuation.adjustment_factor < 1.0
        @test valuation.confidence_label in ("low", "very_low")
        @test "disk_loc_estimate" in valuation.warning_flags
    end

    @testset "Market Scoring" begin
        score = GHAudit.calculate_market_score(
            "TypeScript", "my-cool-app", "A unique tool for developers",
            ["README.md", "src/", "test/", ".github/workflows/", "LICENSE"],
            5000
        )
        @test 0.0 <= score <= 100.0

        # Playground should score lower on uniqueness
        score_playground = GHAudit.calculate_market_score(
            "Python", "python-playground", "Just a playground",
            ["README.md"],
            100
        )
        score_unique = GHAudit.calculate_market_score(
            "Python", "neural-mesh-optimizer", "Novel neural architecture search",
            ["README.md", "tests/", "LICENSE"],
            5000
        )
        @test score_unique > score_playground
    end

    @testset "NDA Classification" begin
        # Financial trading repo should score high
        score, reasons = GHAudit.calculate_nda_score(
            "polymarket-bot", "Financial trading bot",
            String[], Dict()
        )
        @test score >= GHAudit.Config.NDA_THRESHOLD
        @test !isempty(reasons)

        # Generic playground should score low
        score2, reasons2 = GHAudit.calculate_nda_score(
            "python-playground", "Learning Python",
            String[], Dict()
        )
        @test score2 < GHAudit.Config.NDA_THRESHOLD

        # Force-private should always score high
        excl = Dict("force_private" => Dict("repos" => ["secret-repo"]))
        score3, _ = GHAudit.calculate_nda_score(
            "secret-repo", "", String[], excl
        )
        @test score3 >= 100.0
    end

    @testset "Portfolio Perspectives" begin
        perspectives = GHAudit.calculate_perspectives(
            ["README.md", "src/", "test/", ".github/workflows/", "LICENSE", "screenshot.png"],
            5000, "TypeScript", "my-app", "A cool web application", 0
        )
        @test 0.0 <= perspectives.staff_engineer <= 100.0
        @test 0.0 <= perspectives.design_engineer <= 100.0
        @test 0.0 <= perspectives.ai_ml_researcher <= 100.0
    end

    @testset "Classification" begin
        # Repo with no findings → SAFE
        r = RepoReport(name="clean-repo")
        GHAudit.classify_repo(r, Dict())
        @test r.classification == SAFE

        # Repo with CRITICAL finding → TOO_SENSITIVE
        r2 = RepoReport(name="leaky-repo", findings=[
            Finding(repo="leaky-repo", severity=CRITICAL, category=SECRET,
                    description="API key found", file_path=".env")
        ])
        GHAudit.classify_repo(r2, Dict())
        @test r2.classification == TOO_SENSITIVE

        # Repo in force_private list → NDA_REQUIRED
        r3 = RepoReport(name="secret-repo")
        excl = Dict("force_private" => Dict("repos" => ["secret-repo"]))
        GHAudit.classify_repo(r3, excl)
        @test r3.classification == NDA_REQUIRED
    end
end

println("\n✅ All tests passed!")
