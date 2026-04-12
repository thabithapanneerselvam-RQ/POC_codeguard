const https = require('https')
const fs    = require('fs')

// ─── ENV ──────────────────────────────────────────────────────────────
const GITHUB_TOKEN  = process.env.GITHUB_TOKEN
const REPO          = process.env.GITHUB_REPOSITORY        // "owner/repo"
const PR_NUMBER     = process.env.PR_NUMBER
const COMMIT_SHA    = process.env.GITHUB_SHA

if (!GITHUB_TOKEN || !REPO || !PR_NUMBER || !COMMIT_SHA) {
  console.error('Missing required env vars: GITHUB_TOKEN, GITHUB_REPOSITORY, PR_NUMBER, GITHUB_SHA')
  process.exit(1)
}

const [OWNER, REPO_NAME] = REPO.split('/')

// ─── HELPER: GitHub API request ───────────────────────────────────────
function githubRequest(method, path, body) {
  return new Promise((resolve, reject) => {
    const payload = body ? JSON.stringify(body) : null

    const options = {
      hostname: 'api.github.com',
      path,
      method,
      headers: {
        'Authorization': `Bearer ${GITHUB_TOKEN}`,
        'Accept':        'application/vnd.github+json',
        'User-Agent':    'CodeGuard-Bot',
        'X-GitHub-Api-Version': '2022-11-28',
        ...(payload && { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) })
      }
    }

    const req = https.request(options, res => {
      let data = ''
      res.on('data', chunk => data += chunk)
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(data) }) }
        catch { resolve({ status: res.statusCode, body: data }) }
      })
    })

    req.on('error', reject)
    if (payload) req.write(payload)
    req.end()
  })
}

// ─── HELPER: Severity emoji ───────────────────────────────────────────
function severityEmoji(sev) {
  return { CRITICAL: '🔴', HIGH: '🟠', MEDIUM: '🟡', LOW: '🟢' }[sev] || '⚪'
}

// ─── STEP A: Get list of files changed in the PR ──────────────────────
async function getPRFiles() {
  const res = await githubRequest('GET', `/repos/${OWNER}/${REPO_NAME}/pulls/${PR_NUMBER}/files?per_page=100`)
  if (res.status !== 200) {
    console.error('Failed to fetch PR files:', res.body)
    return []
  }
  // Returns array of { filename, patch, ... }
  return res.body
}

// ─── STEP B: Get changed line numbers for a specific file ─────────────
// GitHub only allows comments on lines that are part of the diff (the "+lines")
// We parse the patch to find which lines are valid comment targets.
function getChangedLines(patch) {
  const lines = new Set()
  if (!patch) return lines

  let currentLine = 0
  for (const line of patch.split('\n')) {
    const hunkMatch = line.match(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/)
    if (hunkMatch) {
      currentLine = parseInt(hunkMatch[1], 10) - 1
      continue
    }
    if (line.startsWith('-')) continue   // deleted line, skip
    currentLine++
    if (line.startsWith('+')) lines.add(currentLine)  // added line = valid target
  }
  return lines
}

// ─── STEP C: Build comment body ───────────────────────────────────────
function buildComment(vuln) {
  const emoji = severityEmoji(vuln.severity)
  const fixBlock = vuln.fix.before
    ? `
**Before:**
\`\`\`js
${vuln.fix.before}
\`\`\`
**After:**
\`\`\`js
${vuln.fix.after}
\`\`\`
> ${vuln.fix.explanation}`
    : '_No auto-fix available_'

  return `## ${emoji} CodeGuard — ${vuln.severity} \`${vuln.issueType}\`

**ID:** \`${vuln.id}\`  
**Detected by:** ${vuln.detectedBy.join(', ')}  
**Confidence:** ${vuln.confidenceLevel} (${vuln.confidenceScore}/100)

### 🔍 Explanation
${vuln.explanation}

### 💣 Exploit Example
${vuln.exploitExample}

### 🔧 Suggested Fix
${fixBlock}

---
<sub>🤖 Posted by [CodeGuard](https://github.com/${OWNER}/${REPO_NAME}) · ${vuln.autoFixable ? '✅ Auto-fix PR will be raised' : '🔨 Manual fix required'}</sub>`
}

// ─── STEP D: Post a single inline comment ─────────────────────────────
async function postInlineComment(vuln, line) {
  const body = {
    body:      buildComment(vuln),
    commit_id: COMMIT_SHA,
    path:      vuln.file,
    line:      line,
    side:      'RIGHT'
  }

  const res = await githubRequest(
    'POST',
    `/repos/${OWNER}/${REPO_NAME}/pulls/${PR_NUMBER}/comments`,
    body
  )

  if (res.status === 201) {
    console.log(`  ✅ Inline comment posted → ${vuln.file}:${line}`)
  } else {
    console.log(`  ⚠️  Inline comment failed (${res.status}) — falling back to PR-level comment`)
    return false
  }
  return true
}

// ─── STEP E: Post a PR-level comment (fallback) ───────────────────────
async function postPRComment(vuln) {
  const body = {
    body: `> **File:** \`${vuln.file}:${vuln.line}\` _(line not in diff — general comment)_\n\n` + buildComment(vuln)
  }

  const res = await githubRequest(
    'POST',
    `/repos/${OWNER}/${REPO_NAME}/issues/${PR_NUMBER}/comments`,
    body
  )

  if (res.status === 201) {
    console.log(`  ✅ PR-level comment posted → ${vuln.file}:${vuln.line}`)
  } else {
    console.error(`  ❌ PR comment failed (${res.status}):`, JSON.stringify(res.body))
  }
}

// ─── STEP F: Post a PR summary comment ───────────────────────────────
async function postSummaryComment(report) {
  const { summary } = report

  const rows = report.vulnerabilities.map(v =>
    `| ${severityEmoji(v.severity)} ${v.severity} | \`${v.id}\` | \`${v.file}:${v.line}\` | ${v.issueType} | ${v.fix.autoFixable ? '✅' : '❌'} |`
  ).join('\n')

  const body = {
    body: `## 🛡️ CodeGuard Security Scan Results

| Metric | Count |
|--------|-------|
| 🔴 Critical | ${summary.critical} |
| 🟠 High | ${summary.high} |
| 🟡 Medium | ${summary.medium} |
| 🟢 Low | ${summary.low} |
| 🔧 Auto-fixable | ${summary.autoFixable} |

### Findings

| Severity | ID | Location | Type | Auto-Fix |
|----------|----|----------|------|----------|
${rows}

---
<sub>🤖 Scan completed at ${report.generatedAt} · Tools: ${report.scanMeta.toolsUsed.join(', ')}</sub>`
  }

  const res = await githubRequest(
    'POST',
    `/repos/${OWNER}/${REPO_NAME}/issues/${PR_NUMBER}/comments`,
    body
  )

  if (res.status === 201) console.log('✅ Summary comment posted')
  else console.error('❌ Summary comment failed:', res.body?.message)
}

// ─── MAIN ─────────────────────────────────────────────────────────────
async function main() {
  console.log('=================================')
  console.log('  CodeGuard — Post PR Comments')
  console.log('=================================\n')

  // 1. Read report
  if (!fs.existsSync('codeguard-report.json')) {
    console.log('No codeguard-report.json found — nothing to post')
    return
  }

  const report = JSON.parse(fs.readFileSync('codeguard-report.json', 'utf8'))
  const vulns  = report.vulnerabilities || []

  if (vulns.length === 0) {
    console.log('No vulnerabilities in report — nothing to post')
    return
  }

  console.log(`Found ${vulns.length} vulnerabilities to post\n`)

  // 2. Get PR diff info so we know which lines are valid inline targets
  console.log('Fetching PR diff...')
  const prFiles = await getPRFiles()

  // Build a map: filename → Set of valid line numbers
  const diffMap = {}
  prFiles.forEach(f => {
    diffMap[f.filename] = getChangedLines(f.patch)
  })

  // 3. Post summary comment first
  await postSummaryComment(report)

  // 4. Post one comment per finding
  for (const vuln of vulns) {
    console.log(`\nPosting: ${vuln.id} → ${vuln.file}:${vuln.line}`)

    const validLines = diffMap[vuln.file]

    if (validLines && validLines.has(vuln.line)) {
      // Line is in the diff — post inline
      const ok = await postInlineComment(vuln, vuln.line)
      if (!ok) await postPRComment(vuln)
    } else {
      // Line not in diff — fall back to PR-level comment
      console.log(`  ℹ️  Line ${vuln.line} not in diff — using PR comment`)
      await postPRComment(vuln)
    }

    // Small delay to avoid GitHub secondary rate limits
    await new Promise(r => setTimeout(r, 500))
  }

  console.log('\n✅ All comments posted!')
}

main().catch(err => {
  console.error('Fatal error:', err)
  process.exit(1)
})