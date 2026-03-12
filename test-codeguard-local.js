// test-codeguard-local.js
// This simulates what codeguard.js does
// Reads ALL findings from all tools
// Sends EACH to Gemini
// Shows results for all 4 vulnerabilities

const fs = require('fs')
const https = require('https')

const GEMINI_KEY = 'AIzaSyDmZVv3XYh8LtIqix447Xq9DRYwpEBh7B0'

// ─── STEP 1: READ ALL FINDINGS ────────
function readAllFindings() {
  const findings = []

  // Read Semgrep results
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
        severity: r.extra.severity,
        message: r.extra.message,
        code: r.extra.lines,
        confirmedBy: ['Semgrep']
      })
    })
    console.log(`Semgrep: ${semgrep.results?.length || 0} findings read`)
  } catch(e) {
    console.log('Semgrep results not found:', e.message)
  }

  // Read Bearer results
  try {
    const bearerRaw = JSON.parse(
      fs.readFileSync('bearer-results.json', 'utf8')
    )

    // Handle different bearer output formats
    const bearerFindings =
      bearerRaw?.findings ||
      bearerRaw?.high ||
      bearerRaw?.critical ||
      (Array.isArray(bearerRaw) ? bearerRaw : [])

    bearerFindings?.forEach(r => {
      findings.push({
        tool: 'Bearer',
        file: r.filename || r.file || '',
        line: r.line_number || r.line || 0,
        issue: r.rule_id || r.id || 'unknown',
        severity: r.severity || 'HIGH',
        message: r.description || r.message || '',
        code: r.snippet || r.code || '',
        confirmedBy: ['Bearer']
      })
    })
    console.log(`Bearer: ${bearerFindings?.length || 0} findings read`)
  } catch(e) {
    console.log('Bearer results not found:', e.message)
  }

  return findings
}

// ─── STEP 2: DEDUPLICATE ──────────────
function deduplicate(findings) {
  const seen = {}

  findings.forEach(f => {
    // Same file + same line = same issue
    const key = `${f.file}:${f.line}`

    if (!seen[key]) {
      seen[key] = { ...f }
    } else {
      // Found by multiple tools
      seen[key].confirmedBy.push(f.tool)
    }
  })

  const deduped = Object.values(seen)
  console.log(`\nAfter dedup: ${deduped.length} unique findings`)
  return deduped
}

// ─── STEP 3: CALL GEMINI ──────────────
function callGemini(finding) {
  return new Promise((resolve) => {

    // Get code context around the finding
    let context = finding.code || ''
    try {
      const lines = fs.readFileSync(
        finding.file, 'utf8'
      ).split('\n')

      const start = Math.max(0, finding.line - 5)
      const end = Math.min(lines.length, finding.line + 5)

      context = lines
        .slice(start, end)
        .map((l, i) => `${start + i + 1}: ${l}`)
        .join('\n')
    } catch(e) {}

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

Respond ONLY in this exact JSON format with no extra text:
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
            console.log(`  Gemini error: ${response.error.message}`)
            resolve(null)
            return
          }

          const text = response.candidates[0]
            .content.parts[0].text

          // Strip markdown code blocks
          const clean = text
            .replace(/```json/g, '')
            .replace(/```/g, '')
            .trim()

          const parsed = JSON.parse(clean)
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
  if (!gemini) return false
  if (!gemini.isReal) return false

  // Check before code exists in file
  if (gemini.fix?.before) {
    try {
      const content = fs.readFileSync(
        finding.file, 'utf8'
      )
      if (!content.includes(gemini.fix.before)) {
        console.log(`  Validation: before code not found in file`)
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

  // Step 1: Read all findings
  console.log('Reading all tool results...')
  const raw = readAllFindings()

  if (raw.length === 0) {
    console.log('No findings found.')
    console.log('Run test-all-layers.js first!')
    return
  }

  // Step 2: Deduplicate
  const findings = deduplicate(raw)

  // Step 3: Send each to Gemini
  console.log('\nSending each finding to Gemini...')
  console.log('─────────────────────────────────\n')

  const results = []

  for (let i = 0; i < findings.length; i++) {
    const finding = findings[i]

    console.log(`Finding ${i + 1}/${findings.length}:`)
    console.log(`  File: ${finding.file}`)
    console.log(`  Line: ${finding.line}`)
    console.log(`  Issue: ${finding.issue}`)
    console.log(`  Found by: ${finding.confirmedBy.join(' + ')}`)

    // Call Gemini
    console.log(`  Calling Gemini...`)
    const gemini = await callGemini(finding)

    // Validate
    if (!validate(finding, gemini)) {
      console.log(`  Result: FALSE POSITIVE — discarded\n`)
      continue
    }

    console.log(`  Result: REAL — ${gemini.severity}`)
    console.log(`  AutoFixable: ${gemini.autoFixable}`)
    console.log(`  Fix: ${gemini.fix?.before}`)
    console.log(`       → ${gemini.fix?.after}\n`)

    results.push({ finding, gemini })

    // Wait 3 seconds between calls
    // Avoid rate limiting
    if (i < findings.length - 1) {
      console.log('  Waiting 3s before next call...\n')
      await delay(3000)
    }
  }

  // Step 4: Summary
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

    console.log(`${emoji} Issue ${i + 1}: ${r.gemini.severity}`)
    console.log(`   File: ${r.finding.file}:${r.finding.line}`)
    console.log(`   Type: ${r.finding.issue}`)
    console.log(`   Confirmed by: ${r.finding.confirmedBy.join(' + ')}`)
    console.log(`   Explanation: ${r.gemini.explanation?.substring(0, 80)}...`)
    console.log(`   Fix: ${r.gemini.fix?.before}`)
    console.log(`        → ${r.gemini.fix?.after}`)
    console.log(`   AutoFixable: ${r.gemini.autoFixable}`)
    console.log()
  })

  console.log(`Total confirmed: ${results.length} vulnerabilities`)
  console.log('\nIn ADO pipeline:')
  console.log('├── These would be posted as PR comments')
  console.log('├── Auto fix PRs raised for autoFixable ones')
  console.log('└── Teams notification sent ✅')
}

main().catch(console.error)