**🛡️ CodeGuard — AI-Powered Security Scanning Pipeline**

CodeGuard is an automated security scanning pipeline for Node.js applications. It runs on every GitHub push or pull request, detects vulnerabilities, validates findings using AI, and automatically raises a fix PR — all without any manual intervention.

**How It Works**


Developer pushes code / opens PR

            │
            ▼

GitHub Actions triggers automatically

            │
            ▼

Layer 1 — Semgrep      (pattern-based SAST)
Layer 2 — Bearer       (data flow analysis)
Layer 3 — Gitleaks     (secret scanning)
Layer 3 — OSV Scanner  (dependency CVE scanning)

            │
            ▼

Deduplication Engine
(collapses duplicate findings across tools)
            │
            ▼

Gemini AI Validation
(confirms real vs false positive, generates fix)

            │
            ▼

Auto Fix PR raised
(auto-fixable vulnerabilities patched automatically)

            │
            ▼

PR Comments posted
(every vulnerability commented inline on the PR)


**Setup**

**1. Clone the repository**

git clone https://github.com/thabithapanneerselvam-RQ/POC_codeguard.git
cd your-repo
npm install

**2. Add your Gemini API key to GitHub Secrets**

Go to your repository → Settings → Secrets and variables → Actions → New repository secret
Name:  GEMINI_API_KEY
Value: your-gemini-api-key-here

**3. Enable GitHub Actions write permissions**

Go to your repository → Settings → Actions → General → Workflow permissions

Select Read and write permissions
Check Allow GitHub Actions to create and approve pull requests
Click Save

**4. Copy the workflow file**

Make sure .github/workflows/codeguard.yml exists in your repository. This is the pipeline that runs automatically on every push and PR.

**5. Push your code**

git add .
git commit -m "add CodeGuard security scanning"
git push
CodeGuard will trigger automatically.




**Output**

**GitHub Security Tab**

All findings appear inline on the vulnerable lines of code under Security → Code scanning alerts.


**Auto Fix PR**

A new PR is automatically raised titled:

**🛡️ CodeGuard: Auto-fix N vulnerabilities (from PR #X)**

Review the diff, run your tests, and merge.


**PR Comments**

Every vulnerability gets an inline comment on your PR:

   1. Auto-fixed vulnerabilities show → ✅ Fixed in PR #X
   2. Manual fix required → shows before/after code diff with explanation


**JSON Report**

Full detailed report downloadable from Actions → your run → Artifacts → codeguard-report-json

{

  "tool": "CodeGuard",
  "summary": {
    "total": 24,
    "critical": 4,
    "high": 8,
    "medium": 10,
    "autoFixable": 9
    
  },
  
  "vulnerabilities": [
    {
    
      "id": "CG-001",
      "severity": "CRITICAL",
      "file": "src/db.js",
      "line": 42,
      "explanation": "...",
      "exploitExample": "...",
      "fix": {
        "before": "...",
        "after": "...",
        "autoFixable": true
        }
        
    }
  ]
}

**Project Structure**

├── .github/

│   └── workflows/

│       └── codeguard.yml          # pipeline definition

├── codeguard/

│   └── scripts/

│       └── osv-scan.js            # OSV dependency scanner

├── test-all-layers.js             # runs all scan tools

├── test-codeguard-local.js        # AI analysis + report generation

├── raise-fix-pr.js                # auto fix PR creation

├── post-pr-comments.js            # posts PR comments

├── codeguard-report.json          # generated — full report

└── codeguard-report.sarif         # generated — GitHub Security format



**Running Locally**

You can run CodeGuard locally without GitHub Actions:

**Set your Gemini API Key:**

export GEMINI_API_KEY=your-key-here

**Run all scan layers**

node test-all-layers.js

**Run AI analysis and generate reports**

node test-codeguard-local.js
Reports will be written to codeguard-report.json and codeguard-report.sarif in your project root.

**Note: raise-fix-pr.js and post-pr-comments.js require GitHub Actions environment variables and will not work locally.**
