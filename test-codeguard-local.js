const fs = require('fs')
const https = require('https')

// ─── GEMINI KEY — use environment variable, never hardcode ───
const GEMINI_KEY = process.env.GEMINI_API_KEY
if (!GEMINI_KEY) {
  console.error('ERROR: GEMINI_API_KEY environment variable not set')
  console.error('Run: export GEMINI_API_KEY=your-key-here')
  process.exit(1)
}

const BATCH_SIZE  = 5      // findings per Gemini call
const BATCH_DELAY = 60000  // 60 seconds between batches

// ─── CONFIDENCE SCORE ─────────────────
function getConfidenceScore(finding) {
  const toolCount = finding.confirmedBy.length
  const sev = (finding.severity || '').toUpperCase()

  let score = 0

  if (toolCount >= 3)       score += 40
  else if (toolCount === 2) score += 25
  else                      score += 10

  if (sev === 'CRITICAL' || sev === 'ERROR') score += 40
  else if (sev === 'HIGH')                   score += 30
  else if (sev === 'MEDIUM' || sev === 'WARNING') score += 15
  else                                        score += 5

  score += 20

  return {
    score,
    level:
      score >= 80 ? 'VERY HIGH' :
      score >= 60 ? 'HIGH' :
      score >= 40 ? 'MEDIUM' : 'LOW'
  }
}

// ─── STEP 1: READ ALL FINDINGS ────────
function readAllFindings() {
  const findings = []

  // ── Semgrep ──
  try {
    const semgrep = JSON.parse(fs.readFileSync('semgrep-results.json', 'utf8'))
    semgrep.results?.forEach(r => {
      findings.push({
        tool: 'Semgrep',
        file: r.path,
        line: r.start.line,
        issue: r.check_id,
        severity: r.extra?.severity || 'HIGH',
        message: r.extra?.message || '',
        code: r.extra?.lines || '',
        confirmedBy: ['Semgrep']
      })
    })
    console.log(`Semgrep:  ${semgrep.results?.length || 0} findings read`)
  } catch(e) {
    console.log('Semgrep results not found:', e.message)
  }

  // ── Bearer ──
  try {
    const bearerRaw = JSON.parse(fs.readFileSync('bearer-results.json', 'utf8'))
    const bearerFindings = [
      ...(bearerRaw?.critical || []),
      ...(bearerRaw?.high     || []),
      ...(bearerRaw?.medium   || []),
      ...(bearerRaw?.low      || []),
    ]
    bearerFindings.forEach(r => {
      findings.push({
        tool: 'Bearer',
        file: r.full_filename || r.filename || r.file || '',
        line: r.line_number || r.line || 0,
        issue: r.id || r.rule_id || 'unknown',
        severity: r.severity || 'HIGH',
        message: r.title || r.description || r.message || '',
        code: r.code_extract || r.snippet || r.code || '',
        confirmedBy: ['Bearer']
      })
    })
    console.log(`Bearer:   ${bearerFindings.length} findings read`)
  } catch(e) {
    console.log('Bearer results not found:', e.message)
  }

  // ── OSV ──
  try {
    const osv = JSON.parse(fs.readFileSync('osv-results.json', 'utf8'))
    osv.forEach(r => {
      findings.push({
        tool: 'OSV',
        file: 'package.json',
        line: 0,
        issue: r.vulnId || 'CVE-UNKNOWN',
        severity: r.severity || 'HIGH',
        message: `Package: ${r.package}@${r.version} — ${r.summary || 'Known vulnerability'}`,
        code: `"${r.package}": "${r.version}"`,
        fixedIn: r.fixedIn || 'unknown',
        confirmedBy: ['OSV']
      })
    })
    console.log(`OSV:      ${osv.length} CVEs read`)
  } catch(e) {
    console.log('OSV results not found:', e.message)
  }

  // ── Gitleaks ──
  try {
    const leaks = JSON.parse(fs.readFileSync('gitleaks-results.json', 'utf8'))
    leaks.forEach(r => {
      findings.push({
        tool: 'Gitleaks',
        file: r.File || r.file || '',
        line: r.StartLine || r.line || 0,
        issue: 'hardcoded_secret',
        severity: 'CRITICAL',
        message: `Secret detected — Rule: ${r.RuleID || r.rule || 'unknown'}. Match: ${r.Match || r.match || ''}`,
        code: r.Match || r.match || '',
        confirmedBy: ['Gitleaks']
      })
    })
    console.log(`Gitleaks: ${leaks.length} secrets read`)
  } catch(e) {
    console.log('Gitleaks results not found:', e.message)
  }

  return findings
}

// ─── VULN CATEGORY MAPPER ─────────────
function getVulnCategory(issue) {
  const i = (issue || '').toLowerCase()
  if (i.includes('redirect'))                                        return 'open_redirect'
  if (i.includes('nosql') || i.includes('mongo'))                   return 'nosql_injection'
  if (i.includes('jwt') || i.includes('hardcoded-jwt'))             return 'jwt_issue'
  if (i.includes('hardcoded') || i.includes('secret'))              return 'hardcoded_secret'
  if (i.includes('xss') || i.includes('cross_site') ||
      i.includes('direct-response'))                                 return 'xss'
  if (i.includes('ssrf') || i.includes('http_url') ||
      i.includes('server_side'))                                     return 'ssrf'
  if (i.includes('deserializ'))                                      return 'deserialization'
  if (i.includes('helmet'))                                          return 'missing_helmet'
  if (i.includes('csrf') || i.includes('csurf'))                    return 'csrf'
  if (i.includes('timing') || i.includes('observable'))             return 'timing_attack'
  if (i.includes('sql'))                                             return 'sql_injection'
  if (i.includes('command') || i.includes('exec'))                  return 'command_injection'
  if (i.includes('path') || i.includes('traversal'))                return 'path_traversal'
  return i
}

// ─── STEP 2: DEDUPLICATE ──────────────
function deduplicate(findings) {
  const seen = {}

  findings.forEach(f => {
    const category = getVulnCategory(f.issue)
    const key = `${f.file}:${f.line}:${category}`

    if (!seen[key]) {
      seen[key] = { ...f }
    } else {
      if (!seen[key].confirmedBy.includes(f.tool)) {
        seen[key].confirmedBy.push(f.tool)
      }
      const sevOrder = ['CRITICAL','ERROR','HIGH','MEDIUM','WARNING','LOW','INFO']
      const existingSev = (seen[key].severity || '').toUpperCase()
      const newSev = (f.severity || '').toUpperCase()
      if (sevOrder.indexOf(newSev) < sevOrder.indexOf(existingSev)) {
        seen[key].severity = f.severity
        seen[key].issue = f.issue
        seen[key].message = f.message
        seen[key].code = f.code
      }
    }
  })

  const deduped = Object.values(seen)
  console.log(`\nAfter dedup: ${deduped.length} unique findings`)
  return deduped
}

// ─── GET CODE CONTEXT ─────────────────
function getContext(finding) {
  let context = finding.code || ''
  try {
    if (finding.file && finding.file !== 'package.json' && finding.line > 0) {
      const lines = fs.readFileSync(finding.file, 'utf8').split('\n')
      const start = Math.max(0, finding.line - 5)
      const end = Math.min(lines.length, finding.line + 5)
      context = lines
        .slice(start, end)
        .map((l, i) => `${start + i + 1}: ${l}`)
        .join('\n')
    }
  } catch(e) {
    context = finding.code || 'No context available'
  }
  return context
}

// ─── STEP 3: CALL GEMINI BATCH ────────
function callGeminiBatch(batch) {
  return new Promise((resolve) => {

    const findingsText = batch.map((finding, idx) => {
      const context = getContext(finding)
      return `
FINDING ${idx + 1}:
Tool: ${finding.tool}
Issue: ${finding.issue}
File: ${finding.file}
Line: ${finding.line}
Message: ${finding.message}
CODE CONTEXT:
${context}`
    }).join('\n\n---\n')

    const prompt = `
You are a security expert reviewing Node.js code.
Analyze ALL ${batch.length} findings below and respond with a JSON array.

${findingsText}

Respond ONLY in this exact JSON array format with no extra text or markdown.
IMPORTANT: All string values must be single-line. Replace any newlines in code with \\n. No literal line breaks inside JSON strings.
CRITICAL FOR FIX: The "before" field must be copied VERBATIM from the CODE CONTEXT above.
Do not paraphrase, reformat, or summarize it. Copy the exact characters, exact spacing, exact indentation.
[
  {
    "finding_index": 1,
    "isReal": true,
    "confidence": "HIGH",
    "severity": "CRITICAL",
    "explanation": "clear explanation here",
    "exploitExample": "how attacker exploits this",
    "fix": {
      "before": "exact vulnerable code from above",
      "after": "exact fixed code",
      "explanation": "why fix works"
    },
    "autoFixable": true
  }
]

Include one object per finding (${batch.length} total). Use finding_index 1 to ${batch.length}.`

    const body = JSON.stringify({
      contents: [{ parts: [{ text: prompt }] }]
    })

    const options = {
      hostname: 'generativelanguage.googleapis.com',
      path: `/v1beta/models/gemini-2.5-flash-preview-05-20:generateContent?key=${GEMINI_KEY}`,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body)
      }
    }

    const req = https.request(options, res => {
      let data = ''
      res.on('data', chunk => data += chunk)
      res.on('end', () => {
        try {
          const response = JSON.parse(data)

          if (response.error) {
            const msg = response.error.message || ''
            if (msg.includes('quota') || msg.includes('RESOURCE_EXHAUSTED')) {
              console.log('  ⚠️  Gemini quota hit — skipping batch')
            } else {
              console.log(`  Gemini error: ${msg.substring(0, 80)}`)
            }
            resolve(null)
            return
          }

          if (!response.candidates?.[0]) {
            console.log('  Gemini: no candidates returned')
            resolve(null)
            return
          }

          const text = response.candidates[0].content.parts[0].text
          // Step 1: Strip markdown fences and control chars
          let clean = text
            .replace(/```json\n?/g, '')
            .replace(/```\n?/g, '')
            .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '')
            .trim()

          // Step 2: Fix literal newlines/tabs inside JSON string values
          clean = clean.replace(/"((?:[^"\\]|\\.)*)"/g, (match) => {
            return match
              .replace(/\n/g, '\\n')
              .replace(/\r/g, '\\r')
              .replace(/\t/g, '\\t')
          })

          // Step 3: Fix lone backslashes not part of valid JSON escape
          clean = clean.replace(/\\(?!["\\/bfnrtu0-9])/g, '\\\\')

          let parsed
          try {
            parsed = JSON.parse(clean)
          } catch(e) {
            // Step 4: Try extracting just the array portion
            const match = clean.match(/\[[\s\S]*\]/)
            if (match) {
              let arr = match[0]
              // Apply same fixes again on extracted portion
              arr = arr.replace(/"((?:[^"\\]|\\.)*)"/g, (m) => {
                return m
                  .replace(/\n/g, '\\n')
                  .replace(/\r/g, '\\r')
                  .replace(/\t/g, '\\t')
              })
              arr = arr.replace(/\\(?!["\\/bfnrtu0-9])/g, '\\\\')
              try { parsed = JSON.parse(arr) }
              catch(e2) { console.log('  Parse error:', e2.message); resolve(null); return }
            } else {
              console.log('  Parse error: no JSON array in response')
              resolve(null)
              return
            }
          }

          if (!Array.isArray(parsed)) parsed = [parsed]
          resolve(parsed)

        } catch(e) {
          console.log('  Parse error:', e.message)
          resolve(null)
        }
      })
    })

    req.on('error', e => {
      console.log('  Request error:', e.message)
      resolve(null)
    })

    req.write(body)
    req.end()
  })
}

// ─── STEP 4: VALIDATE ─────────────────
function validate(finding, gemini) {
  if (!gemini) {
    console.log('  Skipped: Gemini did not respond')
    return false
  }
  if (!gemini.isReal) {
    console.log('  Gemini says: false positive')
    return false
  }
  if (gemini.confidence === 'LOW') {
    console.log('  Low confidence — auto fix disabled')
    gemini.autoFixable = false
  }
  if (gemini.fix?.before && finding.file !== 'package.json') {
    try {
      const content = fs.readFileSync(finding.file, 'utf8')
      if (!content.includes(gemini.fix.before)) {
        console.log('  Validation: before code not found — auto fix disabled')
        gemini.autoFixable = false
      }
    } catch(e) {
      gemini.autoFixable = false
    }
  }
  return true
}

// ─── STEP 5: DELAY HELPER ─────────────
function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms))
}

// ─── REPORT: JSON ─────────────────────
function generateJSONReport(results, meta) {
  const report = {
    tool: 'CodeGuard',
    version: '1.0.0',
    generatedAt: new Date().toISOString(),
    summary: {
      total:     results.length,
      critical:  results.filter(r => r.gemini.severity === 'CRITICAL').length,
      high:      results.filter(r => r.gemini.severity === 'HIGH').length,
      medium:    results.filter(r => r.gemini.severity === 'MEDIUM').length,
      low:       results.filter(r => r.gemini.severity === 'LOW').length,
      autoFixable: results.filter(r => r.gemini.autoFixable).length
    },
    scanMeta: meta,
    vulnerabilities: results.map((r, i) => {
      const conf = getConfidenceScore(r.finding)
      return {
        id: `CG-${String(i + 1).padStart(3, '0')}`,
        severity:      r.gemini.severity,
        confidence:    r.gemini.confidence,
        confidenceScore: conf.score,
        confidenceLevel: conf.level,
        file:          r.finding.file,
        line:          r.finding.line,
        issueType:     r.finding.issue,
        detectedBy:    r.finding.confirmedBy,
        explanation:   r.gemini.explanation,
        exploitExample: r.gemini.exploitExample,
        fix: {
          before:      r.gemini.fix?.before || '',
          after:       r.gemini.fix?.after  || '',
          explanation: r.gemini.fix?.explanation || '',
          autoFixable: r.gemini.autoFixable
        }
      }
    })
  }

  fs.writeFileSync('codeguard-report.json', JSON.stringify(report, null, 2))
  console.log('📄 JSON report saved: codeguard-report.json')
}

// ─── REPORT: SARIF ────────────────────
// SARIF 2.1.0 — standard format for GitHub, ADO, VS Code
function generateSARIFReport(results) {
  // Map severity to SARIF level
  function toSarifLevel(sev) {
    const s = (sev || '').toUpperCase()
    if (s === 'CRITICAL' || s === 'ERROR') return 'error'
    if (s === 'HIGH')                      return 'error'
    if (s === 'MEDIUM' || s === 'WARNING') return 'warning'
    return 'note'
  }

  // Build unique rules list from results
  const rulesMap = {}
  results.forEach(r => {
    const ruleId = r.finding.issue
    if (!rulesMap[ruleId]) {
      rulesMap[ruleId] = {
        id: ruleId,
        name: ruleId.split('.').pop() || ruleId,
        shortDescription: { text: r.gemini.explanation || ruleId },
        fullDescription:  { text: r.gemini.explanation || ruleId },
        helpUri: `https://owasp.org/www-project-top-ten/`,
        properties: {
          severity: r.finding.severity,
          tags: r.finding.confirmedBy
        }
      }
    }
  })

  const sarif = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'CodeGuard',
            version: '1.0.0',
            informationUri: 'https://github.com/your-org/codeguard',
            rules: Object.values(rulesMap)
          }
        },
        results: results.map((r, i) => {
          const conf = getConfidenceScore(r.finding)
          return {
            ruleId:  r.finding.issue,
            level:   toSarifLevel(r.gemini.severity),
            message: {
              text: `[${r.gemini.severity}] ${r.gemini.explanation}\n\nExploit: ${r.gemini.exploitExample}\n\nFix: ${r.gemini.fix?.explanation || ''}`
            },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: {
                    uri: r.finding.file,
                    uriBaseId: '%SRCROOT%'
                  },
                  region: {
                    startLine: Math.max(1, r.finding.line || 1)
                  }
                }
              }
            ],
            fixes: r.gemini.autoFixable ? [
              {
                description: { text: r.gemini.fix?.explanation || 'Apply suggested fix' },
                artifactChanges: [
                  {
                    artifactLocation: {
                      uri: r.finding.file,
                      uriBaseId: '%SRCROOT%'
                    },
                    replacements: [
                      {
                        deletedRegion: { startLine: Math.max(1, r.finding.line || 1) },
                        insertedContent: { text: r.gemini.fix?.after || '' }
                      }
                    ]
                  }
                ]
              }
            ] : [],
            properties: {
              confidence:      r.gemini.confidence,
              confidenceScore: conf.score,
              confidenceLevel: conf.level,
              detectedBy:      r.finding.confirmedBy,
              autoFixable:     r.gemini.autoFixable,
              issueId:         `CG-${String(i + 1).padStart(3, '0')}`
            }
          }
        })
      }
    ]
  }

  fs.writeFileSync('codeguard-report.sarif', JSON.stringify(sarif, null, 2))
  console.log('📄 SARIF report saved: codeguard-report.sarif')
}

// ─── MAIN ─────────────────────────────
async function main() {
  console.log('=============================')
  console.log('  CodeGuard Full Flow Test')
  console.log('=============================\n')

  const scanStartTime = new Date()

  console.log('Reading all tool results...')
  const raw = readAllFindings()

  if (raw.length === 0) {
    console.log('\nNo findings. Run node test-all-layers.js first!')
    return
  }

  const findings = deduplicate(raw)

  const totalBatches = Math.ceil(findings.length / BATCH_SIZE)
  console.log(`\nSending to Gemini in batches of ${BATCH_SIZE}...`)
  console.log(`Total batches: ${totalBatches}`)
  console.log('─────────────────────────────────\n')

  const results = []
  let findingCounter = 0

  for (let b = 0; b < findings.length; b += BATCH_SIZE) {
    const batch = findings.slice(b, b + BATCH_SIZE)
    const batchNum = Math.floor(b / BATCH_SIZE) + 1

    console.log(`\n📦 Batch ${batchNum}/${totalBatches} — findings ${b + 1} to ${b + batch.length}`)
    console.log('  Calling Gemini...')

    const geminiResults = await callGeminiBatch(batch)

    batch.forEach((finding, idx) => {
      findingCounter++
      const conf = getConfidenceScore(finding)
      const gemini = geminiResults
        ? geminiResults.find(r => r.finding_index === idx + 1)
        : null

      console.log(`\nFinding ${findingCounter}/${findings.length}:`)
      console.log(`  File:       ${finding.file}`)
      console.log(`  Line:       ${finding.line}`)
      console.log(`  Issue:      ${finding.issue}`)
      console.log(`  Tool:       ${finding.tool}`)
      console.log(`  Found by:   ${finding.confirmedBy.join(' + ')}`)
      console.log(`  Confidence: ${conf.level} (${conf.score}/100)`)

      if (!validate(finding, gemini)) {
        console.log(`  Result: FALSE POSITIVE — discarded\n`)
        return
      }

      console.log(`  Result:      REAL — ${gemini.severity}`)
      console.log(`  Confidence:  ${gemini.confidence}`)
      console.log(`  AutoFixable: ${gemini.autoFixable}`)
      console.log(`  Fix before:\n${gemini.fix?.before || ''}`)
      console.log(`  Fix after:\n${gemini.fix?.after || ''}\n`)

      results.push({ finding, gemini })
    })

    if (b + BATCH_SIZE < findings.length) {
      console.log(`  ⏳ Waiting ${BATCH_DELAY / 1000}s before next batch...\n`)
      await delay(BATCH_DELAY)
    }
  }

  const scanEndTime = new Date()

  // ─── CONSOLE SUMMARY ──────────────────
  console.log('=============================')
  console.log('  Final Summary')
  console.log('=============================\n')

  if (results.length === 0) {
    console.log('No confirmed vulnerabilities found.')
    return
  }

  results.forEach((r, i) => {
    const emoji =
      r.gemini.severity === 'CRITICAL' ? '🔴' :
      r.gemini.severity === 'HIGH'     ? '🟠' :
      r.gemini.severity === 'MEDIUM'   ? '🟡' : '🟢'

    const conf = getConfidenceScore(r.finding)

    console.log(`${emoji} Issue ${i + 1}: ${r.gemini.severity}`)
    console.log(`   File:         ${r.finding.file}:${r.finding.line}`)
    console.log(`   Type:         ${r.finding.issue}`)
    console.log(`   Confirmed by: ${r.finding.confirmedBy.join(' + ')}`)
    console.log(`   Confidence:   ${conf.level} (${conf.score}/100)`)
    console.log(`   Explanation:  ${r.gemini.explanation}`)
    console.log(`   Exploit:      ${r.gemini.exploitExample}`)
    console.log(`   Fix before:\n${r.gemini.fix?.before || ''}`)
    console.log(`   Fix after:\n${r.gemini.fix?.after || ''}`)
    console.log(`   Fix why:      ${r.gemini.fix?.explanation || ''}`)
    console.log(`   AutoFixable:  ${r.gemini.autoFixable}`)
    console.log()
  })

  const critical   = results.filter(r => r.gemini.severity === 'CRITICAL').length
  const high       = results.filter(r => r.gemini.severity === 'HIGH').length
  const medium     = results.filter(r => r.gemini.severity === 'MEDIUM').length
  const autofix    = results.filter(r => r.gemini.autoFixable).length

  console.log(`Total confirmed: ${results.length} vulnerabilities`)
  console.log(`  🔴 Critical:     ${critical}`)
  console.log(`  🟠 High:         ${high}`)
  console.log(`  🟡 Medium:       ${medium}`)
  console.log(`  🔧 Auto-fixable: ${autofix}`)
  console.log()
  console.log('In ADO pipeline:')
  console.log('├── These would be posted as inline PR comments')
  console.log('├── Auto fix PRs raised for autoFixable ones')
  console.log('└── Teams notification sent ✅')

  // ─── GENERATE REPORTS ─────────────────
  console.log('\n=============================')
  console.log('  Generating Reports')
  console.log('=============================\n')

  const meta = {
    scanStartTime: scanStartTime.toISOString(),
    scanEndTime:   scanEndTime.toISOString(),
    durationSeconds: Math.round((scanEndTime - scanStartTime) / 1000),
    totalRawFindings: raw.length,
    totalAfterDedup:  findings.length,
    totalConfirmed:   results.length,
    toolsUsed: ['Semgrep', 'Bearer', 'Gitleaks', 'OSV', 'Gemini AI']
  }

  generateJSONReport(results, meta)
  generateSARIFReport(results)

  console.log('\n✅ Reports ready:')
  console.log('   codeguard-report.json  — full details, AI explanations, fixes')
  console.log('   codeguard-report.sarif — import into GitHub/ADO/VS Code')
}

main().catch(console.error)