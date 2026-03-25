# How to Run CodeGuard — Step by Step

## What's in this bundle

```
codeguard-testrun/          ← the vulnerable app + pre-generated scan results
  src/
    routes/
      user.js               ← SQL injection
      search.js             ← XSS
      run.js                ← Command injection
      files.js              ← Path traversal
    config/
      db.js                 ← Hardcoded password
  semgrep-results.json      ← pre-generated (Semgrep found 3 issues)
  bearer-results.json       ← pre-generated (Bearer found 3 issues)
  gitleaks-results.json     ← pre-generated (2 secrets found)
  osv-results.json          ← pre-generated (3 CVEs in dependencies)
  package.json

codeguard/                  ← the pipeline
  src/
    pipeline.js
    readers.js
    dedup.js
    confidence.js
    gemini.js
    validate.js
    reporter.js
  scripts/
    osv-scan.js
  package.json
  README.md
```

---

## Prerequisites

- Node.js 18 or higher  →  https://nodejs.org
- A Gemini API key (free)  →  https://aistudio.google.com/app/apikey

---

## Step 1 — Unzip

Unzip the bundle. You'll get two folders side by side:
```
codeguard/
codeguard-testrun/
```

---

## Step 2 — Set your Gemini API key

**Mac / Linux:**
```bash
export GEMINI_API_KEY=your-key-here
```

**Windows (Command Prompt):**
```cmd
set GEMINI_API_KEY=your-key-here
```

**Windows (PowerShell):**
```powershell
$env:GEMINI_API_KEY="your-key-here"
```

---

## Step 3 — Run the pipeline against the test app

```bash
node codeguard/src/pipeline.js \
  --results-dir codeguard-testrun \
  --out codeguard-testrun/codeguard-report.json
```

**Windows:**
```cmd
node codeguard\src\pipeline.js --results-dir codeguard-testrun --out codeguard-testrun\codeguard-report.json
```

---

## What you'll see

```
╔══════════════════════════════════╗
║  CodeGuard Security Pipeline  ║
╚══════════════════════════════════╝

[1/5] Reading scan results…
  ✓ Semgrep       3 findings
  ✓ Bearer        3 findings
  ✓ Gitleaks      2 findings
  ✓ OSV           3 findings

[2/5] Deduplicating…
  Unique findings: 9

[3/5] Scoring confidence…
  Semgrep      5 findings
  Bearer       5 findings
  ...

[4/5] Validating with Gemini…
  [1/9] src/routes/user.js:8 — sql_injection … REAL [CRITICAL]
  [2/9] src/routes/run.js:6  — command_injection … REAL [CRITICAL]
  ...

[5/5] Writing report…
  ✓ JSON   → codeguard-testrun/codeguard-report.json
  ✓ SARIF  → codeguard-testrun/codeguard-report.sarif

────────────────────────────────────────
  RESULTS
────────────────────────────────────────
  Total confirmed : 8
  🔴 CRITICAL     : 4
  🟠 HIGH         : 3
  🟡 MEDIUM       : 1
  🟢 LOW          : 0
  🔧 Auto-fixable : 5
```

---

## Output files

After running you'll find two new files in `codeguard-testrun/`:

| File | What it is |
|---|---|
| `codeguard-report.json` | Full detail — findings, explanations, before/after fixes |
| `codeguard-report.sarif` | Upload to GitHub / Azure DevOps for inline PR comments |

---

## Rate limit tips

The default runs 2 findings in parallel — safe for the Gemini **free tier** (15 req/min).

If you have a **paid Gemini key**, speed it up:
```bash
CODEGUARD_CONCURRENCY=5 node codeguard/src/pipeline.js --results-dir codeguard-testrun --out codeguard-testrun/report.json
```

If you hit rate limits, the pipeline automatically waits and retries — you don't need to do anything.

---

## Running on your own project

1. Run your scanners and point their output to a folder:
   ```bash
   semgrep --config=auto --json --output=./results/semgrep-results.json .
   bearer scan . --format json --output ./results/bearer-results.json
   gitleaks detect --source . --report-format json --report-path ./results/gitleaks-results.json
   node codeguard/scripts/osv-scan.js --lockfile package-lock.json --out ./results/osv-results.json
   ```

2. Run the pipeline against that folder:
   ```bash
   node codeguard/src/pipeline.js --results-dir ./results --out ./results/report.json
   ```

Any scanner result files that are missing are skipped gracefully — you don't need all four.
