#!/bin/bash

# ═══════════════════════════════════════════════
#  CodeGuard — One-shot scanner + pipeline runner
#  Usage: bash run-codeguard.sh /path/to/your/project
# ═══════════════════════════════════════════════

set -e

# ── Check project path ───────────────────────
PROJECT_DIR="${1:-$(pwd)}"

if [ ! -d "$PROJECT_DIR" ]; then
  echo "❌ Folder not found: $PROJECT_DIR"
  echo "   Usage: bash run-codeguard.sh /path/to/your/project"
  exit 1
fi

# ── Check Gemini API key ─────────────────────
if [ -z "$GEMINI_API_KEY" ]; then
  echo "❌ GEMINI_API_KEY is not set."
  echo "   Run: export GEMINI_API_KEY=your-key-here"
  exit 1
fi

# ── Resolve codeguard location ───────────────
CODEGUARD_DIR="$(cd "$(dirname "$0")" && pwd)/codeguard"

if [ ! -f "$CODEGUARD_DIR/src/pipeline.js" ]; then
  echo "❌ codeguard/ folder not found next to this script."
  echo "   Make sure run-codeguard.sh is in the same folder as codeguard/"
  exit 1
fi

RESULTS_DIR="$PROJECT_DIR/codeguard-results"
mkdir -p "$RESULTS_DIR"

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║        CodeGuard Security Scanner        ║"
echo "╚══════════════════════════════════════════╝"
echo ""
echo "📁 Project : $PROJECT_DIR"
echo "📂 Results : $RESULTS_DIR"
echo ""

# ── Helper ───────────────────────────────────
run_step() {
  local name="$1"
  shift
  printf "⏳ %-12s " "$name..."
  if "$@" > /tmp/cg-step.log 2>&1; then
    echo "✅ done"
  else
    echo "⚠️  skipped (not installed or no findings)"
  fi
}

# ── Step 1: Semgrep ──────────────────────────
run_step "Semgrep" \
  semgrep --config=auto --json \
    --output="$RESULTS_DIR/semgrep-results.json" \
    "$PROJECT_DIR"

# ── Step 2: Bearer ───────────────────────────
run_step "Bearer" \
  bearer scan "$PROJECT_DIR" \
    --format json \
    --output "$RESULTS_DIR/bearer-results.json"

# ── Step 3: Gitleaks ─────────────────────────
run_step "Gitleaks" \
  gitleaks detect \
    --source "$PROJECT_DIR" \
    --report-format json \
    --report-path "$RESULTS_DIR/gitleaks-results.json"

# ── Step 4: OSV (dependency CVEs) ────────────
LOCKFILE="$PROJECT_DIR/package-lock.json"
if [ -f "$LOCKFILE" ]; then
  run_step "OSV" \
    node "$CODEGUARD_DIR/scripts/osv-scan.js" \
      --lockfile "$LOCKFILE" \
      --out "$RESULTS_DIR/osv-results.json"
else
  echo "⚠️  OSV          skipped (no package-lock.json found)"
fi

# ── Step 5: CodeGuard AI pipeline ────────────
echo ""
echo "🤖 Running Gemini AI validation..."
echo ""

node "$CODEGUARD_DIR/src/pipeline.js" \
  --results-dir "$RESULTS_DIR" \
  --out "$RESULTS_DIR/codeguard-report.json"

# ── Done ─────────────────────────────────────
echo ""
echo "════════════════════════════════════════════"
echo "✅ Scan complete!"
echo ""
echo "   📄 Full report : $RESULTS_DIR/codeguard-report.json"
echo "   📄 SARIF file  : $RESULTS_DIR/codeguard-report.sarif"
echo "════════════════════════════════════════════"
echo ""
