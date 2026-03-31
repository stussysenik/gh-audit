# GHAudit — Hypertime Ledger

## 2026-03-31: Initial Build + Full Audit

### What was built
- Complete Julia project: 22 source files, ~3,500 LOC
- COCOMO II valuation engine with language-adjusted complexity multipliers
- Gitleaks integration for full git history secret scanning
- API-level triage (scans repos without cloning — checks file trees via GitHub API)
- Prompt injection scanner for AI instruction files (CLAUDE.md, AGENTS.md)
- Apple metadata scanner (Team ID, entitlements, signing configs)
- NDA classification engine with keyword + file tree analysis
- Multi-perspective portfolio scoring (staff eng, design eng, AI/ML researcher)
- Graph theory module: portfolio as knowledge graph, skill clustering, hub detection
- Bayesian risk propagation: Beta-Binomial model, noisy-OR vulnerability spreading
- Category theory: RiskFunctor with verified identity and composition laws
- Leverage scoring: Diamond/Gold/Silver/Bronze/Raw ranking per repo
- Security tooling recommendations: CodeRabbit, Greptile, GitHub Actions guidance
- Single-repo `appraise` command with scorecard output
- Markdown + JSON report generation
- GitHub Actions workflow generator for scheduled visibility revert

### What was scanned
- 198 repos (196 private + newly discovered)
- 194 deep-scanned with gitleaks (full git history)
- 165 completely clean
- 29 repos with findings (152 total findings)

### Critical findings
| Repo | Severity | Finding |
|------|----------|---------|
| mymind-clone-web | CRITICAL | 49 findings: Supabase SERVICE_ROLE key, AWS STS tokens, API keys |
| breakdex | CRITICAL | 27 findings: Anthropic auth tokens, Brave Search API key |
| redwood-mymind-clone-web | HIGH | 11 findings: Supabase JWTs in .env.production |
| mit-ocw-reels | HIGH | 5 findings: YouTube API key, GCP API key |
| ikea, song-research-tool | MEDIUM | Google/Firebase API keys |

### Decisions made
- NDA repos (keep private): polymarket-bot, cc-config, cc-setup, codex-claude-config, daily, engineering-journal-universal, nvim-portable, outlook-exodus
- Fixed false positive: `intro-react` was incorrectly flagged (keyword "robot" matched "bot")
- Fixed `financial_trading` NDA signal from +40 to +55 (trading bots should clear threshold)
- Apple Team IDs classified as MEDIUM (semi-public info, standard for open-source iOS)

### Math validation
- COCOMO II parameters sourced from Boehm (2000)
- LOC from disk-size heuristic (repo_disk_kb * 1024 / 30) — overestimates for repos with large assets
- Real tokei counts available via `appraise` command (4,334 LOC for zig-image-carousel vs 54,988 estimated)
- Market demand indices based on 2025-2026 developer surveys
- Bayesian risk uses weakly informative Beta(1,3) prior with Laplace smoothing
