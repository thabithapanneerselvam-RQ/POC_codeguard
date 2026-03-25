#!/usr/bin/env node
'use strict'

/**
 * CodeGuard Pipeline
 * ------------------
 * Reads scan results from Semgrep, Bearer, OSV, Gitleaks,
 * deduplicates, scores confidence, then validates each finding
 * through Gemini with full rate-limit handling & exponential backoff.
 *
 * Usage:
 *   GEMINI_API_KEY=<key> node src/pipeline.js [--results-dir ./] [--out report.json]
 */

const fs   = require('fs')
const path = require('path')
const { readFindings }       = require('./readers')
const { deduplicate }        = require('./dedup')
const { getConfidenceScore } = require('./confidence')
const { callGemini }         = require('./gemini')
const { validateGeminiResp } = require('./validate')
const { writeReport }        = require('./reporter')

// ── Config ──────────────────────────────────────────────
const GEMINI_KEY = process.env.GEMINI_API_KEY
if (!GEMINI_KEY) {
  console.error('[CodeGuard] ERROR: Set GEMINI_API_KEY environment variable.')
  console.error('  export GEMINI_API_KEY=your-key-here')
  process.exit(1)
}

const args        = parseArgs(process.argv.slice(2))
const RESULTS_DIR = args['results-dir'] || '.'
const OUT_FILE    = args['out']         || path.join(RESULTS_DIR, 'codeguard-report.json')

// Concurrency: how many findings to process in parallel
// Gemini free tier allows ~15 RPM → safe default is 2 parallel
const CONCURRENCY = parseInt(process.env.CODEGUARD_CONCURRENCY || '2', 10)

// ── Main ─────────────────────────────────────────────────
async function main() {
  banner('CodeGuard Security Pipeline')

  // STEP 1 — Read raw findings from all tool result files
  console.log('[1/5] Reading scan results…')
  const raw = readFindings(RESULTS_DIR)
  if (raw.length === 0) {
    console.log('  No findings from any tool. Nothing to do.')
    return
  }
  console.log(`  Raw findings: ${raw.length}`)

  // STEP 2 — Deduplicate: same file+line+issue → one finding, merged confirmedBy
  console.log('\n[2/5] Deduplicating…')
  const findings = deduplicate(raw)
  console.log(`  Unique findings: ${findings.length}`)

  // STEP 3 — Score confidence pre-Gemini (used for prioritisation)
  console.log('\n[3/5] Scoring confidence…')
  findings.forEach(f => { f.confidence = getConfidenceScore(f) })
  // Sort: process highest-confidence first (most likely real)
  findings.sort((a, b) => b.confidence.score - a.confidence.score)
  printFindingsSummary(findings)

  // STEP 4 — Validate each finding via Gemini (rate-limited, retried)
  console.log('\n[4/5] Validating with Gemini…')
  console.log(`  Concurrency: ${CONCURRENCY} parallel calls`)
  const results = await runWithConcurrency(findings, CONCURRENCY, async (finding, idx) => {
    process.stdout.write(`  [${idx+1}/${findings.length}] ${finding.file}:${finding.line} — ${finding.issue} … `)
    const gemini = await callGemini(finding, GEMINI_KEY)
    const valid  = validateGeminiResp(finding, gemini)
    if (!valid) {
      console.log('FALSE POSITIVE')
      return null
    }
    console.log(`REAL [${gemini.severity}]`)
    return { finding, gemini }
  })

  const confirmed = results.filter(Boolean)

  // STEP 5 — Write report
  console.log('\n[5/5] Writing report…')
  writeReport(confirmed, OUT_FILE)

  // ── Summary ─────────────────────────────────────────────
  printSummary(confirmed)
}

// ── Concurrency pool ────────────────────────────────────
async function runWithConcurrency(items, limit, fn) {
  const results = new Array(items.length)
  let   cursor  = 0

  async function worker() {
    while (cursor < items.length) {
      const idx  = cursor++
      results[idx] = await fn(items[idx], idx)
    }
  }

  const workers = Array.from({ length: Math.min(limit, items.length) }, worker)
  await Promise.all(workers)
  return results
}

// ── Helpers ─────────────────────────────────────────────
function banner(title) {
  const line = '═'.repeat(title.length + 4)
  console.log(`\n╔${line}╗`)
  console.log(`║  ${title}  ║`)
  console.log(`╚${line}╝\n`)
}

function printFindingsSummary(findings) {
  const byTool = {}
  findings.forEach(f => f.confirmedBy.forEach(t => {
    byTool[t] = (byTool[t] || 0) + 1
  }))
  Object.entries(byTool).forEach(([t, n]) => console.log(`  ${t.padEnd(12)} ${n} findings`))
}

function printSummary(confirmed) {
  console.log('\n' + '─'.repeat(40))
  console.log('  RESULTS')
  console.log('─'.repeat(40))
  if (confirmed.length === 0) {
    console.log('  No confirmed vulnerabilities.')
    return
  }
  const sev = s => confirmed.filter(r => r.gemini.severity === s).length
  console.log(`  Total confirmed : ${confirmed.length}`)
  console.log(`  🔴 CRITICAL     : ${sev('CRITICAL')}`)
  console.log(`  🟠 HIGH         : ${sev('HIGH')}`)
  console.log(`  🟡 MEDIUM       : ${sev('MEDIUM')}`)
  console.log(`  🟢 LOW          : ${sev('LOW')}`)
  console.log(`  🔧 Auto-fixable : ${confirmed.filter(r => r.gemini.autoFixable).length}`)
  console.log(`\n  Report: ${OUT_FILE}`)

  confirmed.forEach((r, i) => {
    const e = { CRITICAL:'🔴', HIGH:'🟠', MEDIUM:'🟡', LOW:'🟢' }[r.gemini.severity] || '⚪'
    console.log(`\n  ${e} [${i+1}] ${r.gemini.severity} — ${r.finding.issue}`)
    console.log(`       ${r.finding.file}:${r.finding.line}`)
    console.log(`       Confirmed by: ${r.finding.confirmedBy.join(' + ')}`)
    console.log(`       ${r.gemini.explanation}`)
  })
}

function parseArgs(argv) {
  const out = {}
  for (let i = 0; i < argv.length; i += 2) {
    const key = argv[i].replace(/^--/, '')
    out[key] = argv[i + 1]
  }
  return out
}

main().catch(err => {
  console.error('[CodeGuard] Fatal error:', err.message)
  process.exit(1)
})
