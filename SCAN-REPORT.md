# Gitleaks Deep Security Scan Report

**Date**: 2026-03-31
**Scope**: All 196 private repos for GitHub user stussysenik
**Tool**: gitleaks v8.30.1 with custom config
**Scan type**: Full git history (not shallow)

## Summary

| Metric | Count |
|--------|-------|
| Total repos scanned | 196 |
| Clean repos | 165 |
| Repos with findings | 29 |
| Failed clones | 2 (cu-spring-2025-annotations, books) |
| Total findings | 152 |

## CRITICAL Findings (Require Immediate Action)

These are real secrets that should be rotated immediately.

### 1. AWS Access Tokens
- **mymind-clone-web**: 6 occurrences of AWS access token `ASIA2F3EMEYEUH3FBFHM` in `openspec/archive/legacy-prompts/PROMPT-INSTAGRAM-CAROUSEL-01-24-26.md`
- **breakdex**: 1 occurrence of AWS access token `ASIA2F3EMEYEWMYUGZMB` in `PRD/09-24-25/49. lldb.md`
- **Action**: These are temporary STS tokens (ASIA prefix) -- likely already expired, but verify and remove from git history

### 2. Supabase Keys (Anon + Service Role)
- **mymind-clone-web**: Supabase anon key and service role key hardcoded in multiple files:
  - `extension-firefox/background.js`, `extension-firefox/popup.js`, `extension/background.js`, `extension/popup.js`
  - `openspec/archive/2026-01-09-exploration/DEPLOY.md` (contains both ANON and SERVICE_ROLE keys)
  - `openspec/archive/2026-01-09-exploration/SECURITY_SUMMARY.md`
  - `apps/web/tests/.auth/user.json` (full auth session token)
- **redwood-mymind-clone-web**: Supabase keys in `.env.production`, `scripts/deep-verify.py`, `scripts/experiment.py`, `scripts/experiment.sh`
- **Action**: ROTATE the Supabase service role key immediately. The anon key is public by design but the service role key bypasses RLS

### 3. Anthropic Auth Tokens
- **breakdex**: Two Anthropic auth tokens in `.claude/settings.json`:
  - `215d413811674f5898d57bde6488baca.mNbH5hwzXf63GO5s`
  - `99c1f11f26d84c12b18392286e96d90f.xAZ8h52ZsLxS1KNi`
- **Action**: Revoke these tokens in Anthropic dashboard

### 4. Brave Search API Key
- **breakdex**: `BRAVE_API_KEY=BSA7HMLcdXdSF422-3pYVsOh2u2uXlt` in `DOCS/PRD/10-15-25/3. brave-mcp.md`
- **breaking-computer-vision**: Same key pattern in `.claude/mcp.json`
- **Action**: Rotate the Brave API key

### 5. Google/Firebase API Keys (Hardcoded in source)
- **ikea**: Firebase API key `AIzaSyBhRonnTrapZrglXx86ehCd_Mbvb2jKa18` in `verification.html` and `stats.html`
- **song-research-tool**: YouTube API keys in `.env`:
  - `AIzaSyB-HKTIonMg2UW8f73aqzkUHmlyVNAnhQA`
  - `AIzaSyBj_75i6hA3Fqz2sbDIU4_WL5pugUEfHS4`
- **mit-ocw-reels**: Google API key `AIzaSyBOey3qhzHe0m9dILExFlGAg2SBxwhZ8Q0` in `.env.local`
- **flipmakers-comingback**: Firebase API key `AIzaSyBgc6_L2q9S7ie0dGIIXTafM1gBg0EBhCU` in `js/firebase.js`
- **Action**: Restrict these API keys in Google Cloud Console (HTTP referrer restrictions, API restrictions). Consider rotating if unrestricted

### 6. Desmos API Key
- **math-explainer-redwood**: `dcb31709b452b1cf9dc26972add0fda6` in `DesmosGraph.tsx`
- **zig-elixir-math-katex**: Same key in `config/config.exs`
- **Action**: Check if this is a free/public key or paid -- rotate if paid

### 7. OpenWeatherMap API Key
- **Capstone** and **Weather-jounal-app-UDACITY**: `df9138493452d1ff1957084c14a6d68a` in `website/app.js`
- **Action**: Low risk (likely free tier) but should still be moved to env vars

## MEDIUM Findings (Should Be Addressed)

### 8. Phoenix/Elixir Secret Key Bases (dev/test configs)
These are Phoenix framework secret_key_base values in dev/test config files. They are auto-generated and typically NOT production secrets:
- **chrono-type**, **learn-elixir**, **phoenix-fun**, **pulse**, **tennis-reserve**, **e-nable**, **ramp-sheets-zig-elixir**, **Perplexica**, **fastest-music**, **redwood-mymind-clone-web**: All have `secret_key_base` in `config/test.exs` or `config/dev.exs`
- **Action**: Low risk -- these are standard Phoenix boilerplate for dev/test. Ensure production uses environment variables

### 9. Devise Secret Key (Rails)
- **kleisli-forge**: Devise secret in `config/initializers/devise.rb`
- **Action**: Move to environment variable or Rails credentials

### 10. Searxng Secret Key
- **Perplexica**: `secret_key` in `searxng/settings.yml`
- **Action**: Move to environment variable if deployed

## LOW / False Positives

### 11. Apple Developer Team ID
- 34 findings across **breakdex** (22), **mymind-clone-web** (4), **breakdex-flutter** (3), **fastest-music** (3), **dumpling-not-dumpling** (2), **MusicBrowser** (2)
- All reference `DEVELOPMENT_TEAM = 95MF6RX2GK` in Xcode project files
- **Action**: Not a secret -- this is a public Apple Team ID. Consider adding to gitleaks allowlist

### 12. Portfolio Icon Backup Files
- **Portfolio**: Base64-encoded icon metadata in `icons/*/backup.txt` -- NOT actual JWTs
- **Action**: False positive -- add to allowlist

### 13. Podfile.lock Hashes
- **breakdex-flutter**: SHA hashes in `ios/Podfile.lock` (AppAuth, GTMAppAuth)
- **Action**: False positive -- these are CocoaPods checksums

### 14. Jupyter Lab Static Files
- **google-motion-breakdance**: Minified JS in `myenv/share/jupyter/lab/static/` matching "KeyMap" pattern
- **Action**: False positive -- committed virtualenv files

### 15. README Example Key
- **spotify-music-memorizer**: `sk-1234567890abcdef` in README
- **Action**: False positive -- example/placeholder

### 16. Financial Dashboard Password Hash
- **financial-dashboard-plaid**: SHA hash in `server/storage.ts`
- **Action**: Likely a default/demo password hash -- verify

## Priority Action Items

1. **IMMEDIATE**: Rotate Supabase service role key (mymind-clone-web, redwood-mymind-clone-web)
2. **IMMEDIATE**: Revoke Anthropic auth tokens (breakdex)
3. **HIGH**: Rotate Brave Search API key (breakdex, breaking-computer-vision)
4. **HIGH**: Restrict/rotate Google API keys (ikea, song-research-tool, mit-ocw-reels, flipmakers-comingback)
5. **HIGH**: Remove `.env.production` from redwood-mymind-clone-web (should never be committed)
6. **MEDIUM**: Remove committed AWS STS tokens from git history
7. **LOW**: Move Phoenix dev/test secret_key_base values to env vars
8. **LOW**: Update gitleaks.toml allowlist to suppress false positives (Apple Team IDs, Podfile hashes, icon backup files)

## Scan Results Location

All JSON result files: `/Users/s3nik/Desktop/gh-audit/scan-results/`
