'use strict'

/**
 * readers.js
 * ----------
 * Reads JSON result files from Semgrep, Bearer, OSV, and Gitleaks.
 * Each reader is isolated — one failing doesn't block the others.
 * Returns a flat array of normalised finding objects.
 */

const fs   = require('fs')
const path = require('path')

// ── Normalised finding shape ─────────────────────────────
// {
//   tool       : string          — which scanner found it
//   file       : string          — relative path to the file
//   line       : number          — line number (0 if unknown)
//   issue      : string          — rule / CVE / issue ID
//   severity   : string          — CRITICAL | HIGH | MEDIUM | LOW
//   message    : string          — human-readable description
//   code       : string          — snippet or package declaration
//   confirmedBy: string[]        — tools that found this location
//   fixedIn    : string|null     — for OSV: fixed-in version
// }

function readFindings(resultsDir) {
  const findings = []
  const readers  = [readSemgrep, readBearer, readOSV, readGitleaks]

  readers.forEach(reader => {
    try {
      const found = reader(resultsDir)
      findings.push(...found)
      console.log(`  ✓ ${reader.name.replace('read', '').padEnd(12)} ${found.length} findings`)
    } catch (err) {
      console.log(`  ✗ ${reader.name.replace('read', '').padEnd(12)} skipped (${err.message})`)
    }
  })

  return findings
}

// ── Semgrep ──────────────────────────────────────────────
function readSemgrep(dir) {
  const raw = loadJSON(dir, 'semgrep-results.json')
  return (raw.results || []).map(r => ({
    tool       : 'Semgrep',
    file       : r.path || '',
    line       : r.start?.line || 0,
    issue      : r.check_id || 'unknown',
    severity   : normaliseSeverity(r.extra?.severity),
    message    : r.extra?.message || '',
    code       : r.extra?.lines   || '',
    confirmedBy: ['Semgrep'],
    fixedIn    : null,
  }))
}

// ── Bearer ───────────────────────────────────────────────
function readBearer(dir) {
  const raw = loadJSON(dir, 'bearer-results.json')

  // Bearer can return {critical:[], high:[], ...} OR a flat array
  const flat = Array.isArray(raw)
    ? raw
    : [
        ...(raw.critical || []),
        ...(raw.high     || []),
        ...(raw.medium   || []),
        ...(raw.low      || []),
        ...(raw.findings || []),
      ]

  return flat.map(r => ({
    tool       : 'Bearer',
    file       : r.full_filename || r.filename || r.file || '',
    line       : r.line_number   || r.line     || 0,
    issue      : r.id || r.rule_id || 'unknown',
    severity   : normaliseSeverity(r.severity),
    message    : r.title || r.description || r.message || '',
    code       : r.code_extract || r.snippet || r.code || '',
    confirmedBy: ['Bearer'],
    fixedIn    : null,
  }))
}

// ── OSV (dependency CVEs) ────────────────────────────────
function readOSV(dir) {
  const raw = loadJSON(dir, 'osv-results.json')
  return (Array.isArray(raw) ? raw : []).map(r => ({
    tool       : 'OSV',
    file       : 'package.json',
    line       : 0,
    issue      : r.vulnId || 'CVE-UNKNOWN',
    severity   : normaliseSeverity(r.severity),
    message    : `Package ${r.package}@${r.version}: ${r.summary || 'Known vulnerability'}`,
    code       : `"${r.package}": "${r.version}"`,
    confirmedBy: ['OSV'],
    fixedIn    : r.fixedIn || null,
  }))
}

// ── Gitleaks (secrets) ────────────────────────────────────
function readGitleaks(dir) {
  const raw = loadJSON(dir, 'gitleaks-results.json')
  return (Array.isArray(raw) ? raw : []).map(r => ({
    tool       : 'Gitleaks',
    file       : r.File || r.file || '',
    line       : r.StartLine || r.line || 0,
    issue      : 'hardcoded_secret',
    severity   : 'CRITICAL',
    message    : `Secret — Rule: ${r.RuleID || r.rule || 'unknown'}. Match: ${r.Match || r.match || ''}`,
    code       : r.Match || r.match || '',
    confirmedBy: ['Gitleaks'],
    fixedIn    : null,
  }))
}

// ── Helpers ──────────────────────────────────────────────
function loadJSON(dir, filename) {
  const filepath = path.join(dir, filename)
  if (!fs.existsSync(filepath)) throw new Error(`${filename} not found`)
  return JSON.parse(fs.readFileSync(filepath, 'utf8'))
}

const SEV_MAP = {
  critical : 'CRITICAL',
  error    : 'CRITICAL',
  high     : 'HIGH',
  medium   : 'MEDIUM',
  warning  : 'MEDIUM',
  low      : 'LOW',
  info     : 'LOW',
}

function normaliseSeverity(raw) {
  return SEV_MAP[(raw || '').toLowerCase()] || 'MEDIUM'
}

module.exports = { readFindings }
