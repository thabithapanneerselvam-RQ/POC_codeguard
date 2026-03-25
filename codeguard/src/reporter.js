'use strict'

/**
 * reporter.js
 * -----------
 * Writes the pipeline's confirmed findings to disk.
 *
 * Output formats:
 *   - codeguard-report.json  — full detail, used by CI / dashboards
 *   - codeguard-report.sarif — SARIF 2.1.0, for GitHub / ADO code scanning
 *
 * The SARIF output allows inline PR annotations in Azure DevOps and GitHub
 * without any additional tooling — just upload the .sarif file as a pipeline
 * artifact and the platform renders it as inline comments.
 */

const fs   = require('fs')
const path = require('path')

function writeReport(confirmed, outFile) {
  // ── JSON report ──────────────────────────────────────
  const report = {
    generated  : new Date().toISOString(),
    total      : confirmed.length,
    bySeverity : countBySeverity(confirmed),
    findings   : confirmed.map(r => ({
      file        : r.finding.file,
      line        : r.finding.line,
      issue       : r.finding.issue,
      severity    : r.gemini.severity,
      confidence  : r.gemini.confidence,
      confirmedBy : r.finding.confirmedBy,
      explanation : r.gemini.explanation,
      exploit     : r.gemini.exploitExample,
      fix         : r.gemini.fix,
      autoFixable : r.gemini.autoFixable,
    })),
  }

  fs.writeFileSync(outFile, JSON.stringify(report, null, 2), 'utf8')
  console.log(`  ✓ JSON   → ${outFile}`)

  // ── SARIF report ─────────────────────────────────────
  const sarifFile = outFile.replace(/\.json$/, '.sarif')
  const sarif = buildSarif(confirmed)
  fs.writeFileSync(sarifFile, JSON.stringify(sarif, null, 2), 'utf8')
  console.log(`  ✓ SARIF  → ${sarifFile}`)
}

function countBySeverity(confirmed) {
  const out = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }
  confirmed.forEach(r => {
    const s = r.gemini.severity || 'MEDIUM'
    if (s in out) out[s]++
  })
  return out
}

// ── SARIF 2.1.0 ──────────────────────────────────────────
function buildSarif(confirmed) {
  return {
    version: '2.1.0',
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    runs: [{
      tool: {
        driver: {
          name           : 'CodeGuard',
          version        : '1.0.0',
          informationUri : 'https://github.com/your-org/codeguard',
          rules          : buildRules(confirmed),
        },
      },
      results: confirmed.map(r => ({
        ruleId : r.finding.issue,
        level  : sarifLevel(r.gemini.severity),
        message: { text: r.gemini.explanation },
        locations: [{
          physicalLocation: {
            artifactLocation: { uri: r.finding.file },
            region          : { startLine: r.finding.line || 1 },
          },
        }],
        fixes: r.gemini.autoFixable && r.gemini.fix?.before ? [{
          description: { text: r.gemini.fix.explanation || 'Auto-fix available' },
          artifactChanges: [{
            artifactLocation: { uri: r.finding.file },
            replacements: [{
              deletedRegion : { startLine: r.finding.line },
              insertedContent: { text: r.gemini.fix.after || '' },
            }],
          }],
        }] : [],
        properties: {
          confirmedBy  : r.finding.confirmedBy,
          confidence   : r.gemini.confidence,
          exploitExample: r.gemini.exploitExample,
        },
      })),
    }],
  }
}

function buildRules(confirmed) {
  const seen = new Set()
  return confirmed
    .filter(r => { const k = r.finding.issue; if (seen.has(k)) return false; seen.add(k); return true })
    .map(r => ({
      id              : r.finding.issue,
      name            : r.finding.issue,
      shortDescription: { text: r.finding.message || r.finding.issue },
      defaultConfiguration: { level: sarifLevel(r.gemini.severity) },
    }))
}

function sarifLevel(severity) {
  const map = { CRITICAL: 'error', HIGH: 'error', MEDIUM: 'warning', LOW: 'note' }
  return map[(severity || '').toUpperCase()] || 'warning'
}

module.exports = { writeReport }
