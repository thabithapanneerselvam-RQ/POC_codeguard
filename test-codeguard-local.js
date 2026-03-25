const fs = require('fs')
const https = require('https')

const GEMINI_KEY = 'AIzaSyCPBmKy6ZU4dNoeTxeIMRJxWGjWdHyaoF8'

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
    const semgrep = JSON.parse(
      fs.readFileSync('semgrep-results.json', 'utf8')
    )
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

  // ── Bearer — reads ALL severity levels ──
  try {
    const bearerRaw = JSON.parse(
      fs.readFileSync('bearer-results.json', 'utf8')
    )

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

  // ── OSV — CVE vulnerabilities ──
  try {
    const osv = JSON.parse(
      fs.readFileSync('osv-results.json', 'utf8')
    )
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

  // ── Gitleaks — secrets ──
  try {
    const leaks = JSON.parse(
      fs.readFileSync('gitleaks-results.json', 'utf8')
    )
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



// ─── STEP 2: DEDUPLICATE ──────────────
// Same file + same line = one finding
// Multiple tools finding same location
// get merged into one with higher confidence
function deduplicate(findings) {
  const seen = {}

  findings.forEach(f => {
    const key = `${f.file}:${f.line}`

    if (!seen[key]) {
      seen[key] = { ...f }
    } else {
      // Same location found by another tool
      // Merge: add tool to confirmedBy
      // Keep highest severity
      if (!seen[key].confirmedBy.includes(f.tool)) {
        seen[key].confirmedBy.push(f.tool)
      }
      // Keep most severe issue name
      const sevOrder = ['CRITICAL','ERROR','HIGH','MEDIUM','WARNING','LOW']
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

// ─── STEP 3: CALL GEMINI ──────────────
function callGemini(finding) {
  return new Promise((resolve) => {

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

    const prompt = `
You are a security expert reviewing Node.js code.

FINDING:
Tool: ${finding.tool}
Issue: ${finding.issue}
File: ${finding.file}
Line: ${finding.line}
Message: ${finding.message}

CODE CONTEXT:
${context}

Respond ONLY in this exact JSON format with no extra text or markdown:
{
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
}`

    const body = JSON.stringify({
      contents: [{ parts: [{ text: prompt }] }]
    })

    const options = {
      hostname: 'generativelanguage.googleapis.com',
      path: `/v1beta/models/gemini-2.5-flash:generateContent?key=${GEMINI_KEY}`,
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
            console.log(`  Gemini error: ${response.error.message?.substring(0, 80)}`)
            resolve(null)
            return
          }

          if (!response.candidates?.[0]) {
            console.log('  Gemini: no candidates returned')
            resolve(null)
            return
          }

          const text = response.candidates[0].content.parts[0].text

          const clean = text
            .replace(/```json\n?/g, '')
            .replace(/```\n?/g, '')
            .trim()

          let parsed
          try {
            parsed = JSON.parse(clean)
          } catch(e) {
            const match = clean.match(/\{[\s\S]*\}/)
            if (match) {
              try {
                parsed = JSON.parse(match[0])
              } catch(e2) {
                console.log('  Parse error:', e2.message)
                resolve(null)
                return
              }
            } else {
              console.log('  Parse error: no JSON in response')
              resolve(null)
              return
            }
          }

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

// ─── MAIN ─────────────────────────────
async function main() {
  console.log('=============================')
  console.log('  CodeGuard Full Flow Test')
  console.log('=============================\n')

  if (GEMINI_KEY === 'YOUR_GEMINI_KEY_HERE') {
    console.log('ERROR: Set your Gemini API key first!')
    console.log('Run: export GEMINI_API_KEY=your-key-here')
    process.exit(1)
  }

  console.log('Reading all tool results...')
  const raw = readAllFindings()

  if (raw.length === 0) {
    console.log('\nNo findings. Run node test-all-layers.js first!')
    return
  }

  const findings = deduplicate(raw)

  console.log('\nSending each finding to Gemini...')
  console.log('─────────────────────────────────\n')

  const results = []

  for (let i = 0; i < findings.length; i++) {
    const finding = findings[i]
    const conf = getConfidenceScore(finding)

    console.log(`Finding ${i + 1}/${findings.length}:`)
    console.log(`  File:       ${finding.file}`)
    console.log(`  Line:       ${finding.line}`)
    console.log(`  Issue:      ${finding.issue}`)
    console.log(`  Tool:       ${finding.tool}`)
    console.log(`  Found by:   ${finding.confirmedBy.join(' + ')}`)
    console.log(`  Confidence: ${conf.level} (${conf.score}/100)`)
    console.log(`  Calling Gemini...`)

    const gemini = await callGemini(finding)

    if (!validate(finding, gemini)) {
      console.log(`  Result: FALSE POSITIVE — discarded\n`)
      continue
    }

    console.log(`  Result:      REAL — ${gemini.severity}`)
    console.log(`  Confidence:  ${gemini.confidence}`)
    console.log(`  AutoFixable: ${gemini.autoFixable}`)
    console.log(`  Fix before:\n${gemini.fix?.before || ''}`)
    console.log(`  Fix after:\n${gemini.fix?.after || ''}\n`)

    results.push({ finding, gemini })

    if (i < findings.length - 1) {
      console.log('  Waiting 8s before next call...\n')
      await delay(8000)
    }
  }

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

  const critical = results.filter(r => r.gemini.severity === 'CRITICAL').length
  const high     = results.filter(r => r.gemini.severity === 'HIGH').length
  const medium   = results.filter(r => r.gemini.severity === 'MEDIUM').length
  const autofix  = results.filter(r => r.gemini.autoFixable).length

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
}

main().catch(console.error)