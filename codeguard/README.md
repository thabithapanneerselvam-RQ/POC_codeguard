# CodeGuard

Multi-tool SAST pipeline with Gemini AI validation. Reads findings from Semgrep, Bearer, OSV, and Gitleaks, deduplicates them, scores confidence, and validates each through Gemini — handling rate limits automatically.

## Architecture

```
Scan tools (CI)
  ├── Semgrep    → semgrep-results.json
  ├── Bearer     → bearer-results.json
  ├── Gitleaks   → gitleaks-results.json
  └── OSV        → osv-results.json   (node scripts/osv-scan.js)
         │
         ▼
  src/readers.js     — normalise findings from each tool
  src/dedup.js       — merge same file:line:issue-type across tools
  src/confidence.js  — score 0-100 (tool count × severity)
  src/gemini.js      — validate each finding (rate-limit safe, retried)
  src/validate.js    — check Gemini response quality
  src/reporter.js    — write JSON + SARIF output
         │
         ▼
  codeguard-report.json   — full detail for dashboards
  codeguard-report.sarif  — inline PR comments in GitHub / ADO
```

## Quick start

```bash
# 1. Set your API key (never hardcode it)
export GEMINI_API_KEY=your-key-here

# 2. Run OSV dependency scan
node scripts/osv-scan.js

# 3. Run the pipeline (assumes Semgrep/Bearer/Gitleaks have already run)
node src/pipeline.js --results-dir . --out ./report.json

# Or run everything:
npm run codeguard
```

## Environment variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `GEMINI_API_KEY` | Yes | — | Gemini API key |
| `CODEGUARD_CONCURRENCY` | No | `2` | Parallel Gemini calls (increase for paid tier) |

## Rate limit handling

The Gemini caller (`src/gemini.js`) handles rate limits without fixed sleeps:

- Reads `Retry-After` header when available
- Falls back to exponential backoff: 2s → 4s → 8s → 16s → 32s
- Max 5 retries per finding
- Concurrency pool controls parallel requests (default 2 = safe for free tier)

For paid Gemini tiers set `CODEGUARD_CONCURRENCY=5` or higher.

## Output

### JSON report
```json
{
  "generated": "2025-01-01T00:00:00.000Z",
  "total": 3,
  "bySeverity": { "CRITICAL": 1, "HIGH": 2, "MEDIUM": 0, "LOW": 0 },
  "findings": [
    {
      "file": "src/services/userService.js",
      "line": 21,
      "issue": "javascript.sql-injection",
      "severity": "CRITICAL",
      "confidence": "HIGH",
      "confirmedBy": ["Semgrep", "Bearer"],
      "explanation": "...",
      "exploit": "...",
      "fix": { "before": "...", "after": "...", "explanation": "..." },
      "autoFixable": true
    }
  ]
}
```

### SARIF report
Upload `codeguard-report.sarif` as a pipeline artifact in Azure DevOps or GitHub Actions and the platform renders findings as inline PR code comments automatically.

## Azure DevOps pipeline

```yaml
trigger:
  - main
  - feature/*

pool:
  vmImage: ubuntu-latest

variables:
  - group: codeguard-secrets   # contains GEMINI_API_KEY

stages:
  - stage: Scan
    jobs:
      - job: SAST
        steps:
          - task: NodeTool@0
            inputs:
              versionSpec: '18.x'

          - script: npm ci
            displayName: Install dependencies

          - script: |
              pip install semgrep
              semgrep --config=auto --json --output=semgrep-results.json . || true
            displayName: Semgrep scan

          - script: |
              bearer scan . --format json --output bearer-results.json || true
            displayName: Bearer scan

          - script: |
              gitleaks detect --source . --report-format json --report-path gitleaks-results.json || true
            displayName: Gitleaks scan

          - script: node scripts/osv-scan.js
            displayName: OSV dependency scan

          - script: node src/pipeline.js --results-dir . --out codeguard-report.json
            displayName: CodeGuard AI validation
            env:
              GEMINI_API_KEY: $(GEMINI_API_KEY)
              CODEGUARD_CONCURRENCY: 3

          - task: PublishBuildArtifacts@1
            inputs:
              pathToPublish: codeguard-report.json
              artifactName: codeguard-report

          - task: PublishBuildArtifacts@1
            inputs:
              pathToPublish: codeguard-report.sarif
              artifactName: codeguard-sarif

          # Post SARIF as inline PR comments
          - task: PublishCodeAnalysisResult@0
            inputs:
              sarifFile: codeguard-report.sarif
            condition: always()
```

## Project structure

```
codeguard/
  scripts/
    osv-scan.js          — dependency CVE scanner
  src/
    pipeline.js          — entry point & orchestration
    readers.js           — parse tool result files
    dedup.js             — deduplicate & merge findings
    confidence.js        — pre-Gemini confidence scoring
    gemini.js            — Gemini caller (rate-limit safe)
    validate.js          — response quality checks
    reporter.js          — JSON + SARIF output
  package.json
  README.md
```

## Key improvements over v1

| Issue | v1 | v2 |
|---|---|---|
| Rate limits | Fixed 8s sleep | Retry-After + exponential backoff |
| Concurrency | Sequential only | Configurable pool (default 2) |
| API key | Hardcoded in source | Environment variable only |
| Dedup key | `file:line` (misses multi-issue) | `file:line:issue-category` |
| Output | console.log only | JSON + SARIF files |
| File reading | Synchronous (blocks event loop) | Async `fs.promises.readFile` |
| Dead code | `test-codeguard-local.js` commented out | Removed entirely |
| Demo files | `test-vuln.js`, `test-vuln-2.js` in repo | Not included |
| Error handling | Silent skip | Logged with reason, summary at end |
