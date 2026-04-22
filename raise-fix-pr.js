const https = require('https')
const fs    = require('fs')

const GITHUB_TOKEN   = process.env.GITHUB_TOKEN
const REPO           = process.env.GITHUB_REPOSITORY
const PR_NUMBER      = process.env.PR_NUMBER
const SOURCE_BRANCH  = process.env.SOURCE_BRANCH

if (!GITHUB_TOKEN || !REPO || !PR_NUMBER || !SOURCE_BRANCH) {
  console.error('Missing: GITHUB_TOKEN, GITHUB_REPOSITORY, PR_NUMBER, SOURCE_BRANCH')
  process.exit(1)
}

const [OWNER, REPO_NAME] = REPO.split('/')

// ─── GitHub API helper ────────────────────────────────────────────────
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
        ...(payload && {
          'Content-Type':   'application/json',
          'Content-Length': Buffer.byteLength(payload)
        })
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

// ─── Apply fix.before → fix.after in file content ────────────────────
function applyFix(content, before, after) {
  if (!content.includes(before)) return null
  return content.replace(before, after)
}

// ─── MAIN ─────────────────────────────────────────────────────────────
async function main() {
  console.log('=================================')
  console.log('  CodeGuard — Raise Fix PR')
  console.log('=================================\n')

  // 1. Read report
  if (!fs.existsSync('codeguard-report.json')) {
    console.log('No report found — skipping fix PR')
    fs.writeFileSync('fix-pr-result.json', JSON.stringify({ raised: false, fixedCount: 0 }))
    return
  }

  const report  = JSON.parse(fs.readFileSync('codeguard-report.json', 'utf8'))
  const fixable = report.vulnerabilities.filter(v =>
    v.fix.autoFixable &&
    v.fix.before      &&
    v.fix.after       &&
    v.file !== 'package.json'
  )

  if (fixable.length === 0) {
    console.log('No auto-fixable vulnerabilities — skipping fix PR')
    fs.writeFileSync('fix-pr-result.json', JSON.stringify({ raised: false, fixedCount: 0 }))
    return
  }

  console.log(`Found ${fixable.length} auto-fixable vulnerabilities\n`)

  // 2. Get current branch tip SHA
  const refRes = await githubRequest(
    'GET',
    `/repos/${OWNER}/${REPO_NAME}/git/refs/heads/${SOURCE_BRANCH}`
  )
  if (refRes.status !== 200) {
    console.error('Failed to get branch ref:', refRes.body?.message)
    process.exit(1)
  }
  const baseSHA = refRes.body.object.sha
  console.log(`Base SHA: ${baseSHA}\n`)

  // 3. Fetch each file from GitHub and collect fixes
  const fileFixMap = {}

  for (const vuln of fixable) {
    if (!fileFixMap[vuln.file]) {
      const fileRes = await githubRequest(
        'GET',
        `/repos/${OWNER}/${REPO_NAME}/contents/${vuln.file}?ref=${SOURCE_BRANCH}`
      )
      if (fileRes.status !== 200) {
        console.log(`  ⚠️  Could not fetch ${vuln.file} — skipping`)
        continue
      }
      const content = Buffer.from(fileRes.body.content, 'base64').toString('utf8')
      fileFixMap[vuln.file] = { content, fixes: [] }
    }
    fileFixMap[vuln.file].fixes.push(vuln)
  }

  // 4. Apply all fixes per file, create blobs
  const treeItems      = []
  const appliedVulnIds = []
  const skippedVulnIds = []

  for (const [filePath, { content, fixes }] of Object.entries(fileFixMap)) {
    let updatedContent = content

    for (const vuln of fixes) {
      const result = applyFix(updatedContent, vuln.fix.before, vuln.fix.after)
      if (result) {
        updatedContent = result
        appliedVulnIds.push(vuln.id)
        console.log(`  ✅ Fixed ${vuln.id} — ${vuln.file}:${vuln.line}`)
      } else {
        skippedVulnIds.push(vuln.id)
        console.log(`  ⚠️  ${vuln.id} — fix.before not found in file, skipped`)
      }
    }

    // Only create blob if at least one fix was applied to this file
    if (appliedVulnIds.length > 0) {
      const blobRes = await githubRequest(
        'POST',
        `/repos/${OWNER}/${REPO_NAME}/git/blobs`,
        { content: updatedContent, encoding: 'utf-8' }
      )
      if (blobRes.status !== 201) {
        console.error(`  ❌ Blob creation failed for ${filePath}`)
        continue
      }
      treeItems.push({
        path: filePath,
        mode: '100644',
        type: 'blob',
        sha:  blobRes.body.sha
      })
    }
  }

  if (appliedVulnIds.length === 0) {
    console.log('\nNo fixes could be applied — fix.before strings not found in files')
    fs.writeFileSync('fix-pr-result.json', JSON.stringify({
      raised: false, fixedCount: 0, skippedVulnIds
    }))
    return
  }

  // 5. Create tree
  const treeRes = await githubRequest(
    'POST',
    `/repos/${OWNER}/${REPO_NAME}/git/trees`,
    { base_tree: baseSHA, tree: treeItems }
  )
  if (treeRes.status !== 201) {
    console.error('Tree creation failed:', treeRes.body?.message)
    process.exit(1)
  }

  // 6. Create commit
  const commitMessage =
    `fix(security): CodeGuard auto-fix ${appliedVulnIds.length} vulnerabilities\n\n` +
    `Fixed: ${appliedVulnIds.join(', ')}\n` +
    `Source PR: #${PR_NUMBER}\n` +
    `Auto-generated by CodeGuard`

  const commitRes = await githubRequest(
    'POST',
    `/repos/${OWNER}/${REPO_NAME}/git/commits`,
    {
      message: commitMessage,
      tree:    treeRes.body.sha,
      parents: [baseSHA]
    }
  )
  if (commitRes.status !== 201) {
    console.error('Commit creation failed:', commitRes.body?.message)
    process.exit(1)
  }

  // 7. Create fix branch — delete first if it already exists from a previous run
  const fixBranch     = `codeguard/fix-pr-${PR_NUMBER}`
  const existingBranch = await githubRequest(
    'GET',
    `/repos/${OWNER}/${REPO_NAME}/git/refs/heads/${fixBranch}`
  )
  if (existingBranch.status === 200) {
    console.log(`Branch ${fixBranch} already exists — deleting and recreating`)
    await githubRequest(
      'DELETE',
      `/repos/${OWNER}/${REPO_NAME}/git/refs/heads/${fixBranch}`
    )
  }

  const branchRes = await githubRequest(
    'POST',
    `/repos/${OWNER}/${REPO_NAME}/git/refs`,
    { ref: `refs/heads/${fixBranch}`, sha: commitRes.body.sha }
  )
  if (branchRes.status !== 201) {
    console.error('Branch creation failed:', branchRes.body?.message)
    process.exit(1)
  }
  console.log(`\n✅ Branch created: ${fixBranch}`)

  // 8. Check if fix PR already exists — reuse it if so
  const existingPRs = await githubRequest(
    'GET',
    `/repos/${OWNER}/${REPO_NAME}/pulls?head=${OWNER}:${fixBranch}&state=open`
  )
  if (existingPRs.status === 200 && existingPRs.body.length > 0) {
    const existingPR = existingPRs.body[0]
    console.log(`Fix PR already exists: #${existingPR.number} — ${existingPR.html_url}`)
    fs.writeFileSync('fix-pr-result.json', JSON.stringify({
      raised:        true,
      fixPRNumber:   existingPR.number,
      fixPRUrl:      existingPR.html_url,
      fixedCount:    appliedVulnIds.length,
      fixedVulnIds:  appliedVulnIds,
      skippedVulnIds
    }, null, 2))
    return
  }

  // 9. Raise new PR
  const fixedSummary = appliedVulnIds.map(id => {
    const v = fixable.find(f => f.id === id)
    return `- \`${id}\` — ${v.severity} \`${v.issueType}\` in \`${v.file}:${v.line}\``
  }).join('\n')

  const skippedNote = skippedVulnIds.length > 0
    ? `\n### ⚠️ Could Not Auto-Fix (manual fix required)\n${skippedVulnIds.map(id => `- \`${id}\``).join('\n')}`
    : ''

  const prRes = await githubRequest(
    'POST',
    `/repos/${OWNER}/${REPO_NAME}/pulls`,
    {
      title: `🛡️ CodeGuard: Auto-fix ${appliedVulnIds.length} vulnerabilities (from PR #${PR_NUMBER})`,
      body:
`## CodeGuard Auto-Fix

This PR was automatically generated by CodeGuard to fix security vulnerabilities found in PR #${PR_NUMBER}.

### ✅ Fixed Vulnerabilities
${fixedSummary}
${skippedNote}

### Review Checklist
- [ ] Verify each fix looks correct
- [ ] Run your test suite
- [ ] Merge this PR before or alongside PR #${PR_NUMBER}

> ⚠️ Auto-generated fixes should always be reviewed before merging.
> Generated by CodeGuard at ${new Date().toISOString()}`,
      head: fixBranch,
      base: SOURCE_BRANCH
    }
  )

  if (prRes.status !== 201) {
    console.error('PR creation failed:', prRes.body?.message)
    process.exit(1)
  }

  const fixPRNumber = prRes.body.number
  const fixPRUrl    = prRes.body.html_url
  console.log(`✅ Fix PR raised: #${fixPRNumber} — ${fixPRUrl}`)

  // 10. Write result for post-pr-comments.js to read
  fs.writeFileSync('fix-pr-result.json', JSON.stringify({
    raised:        true,
    fixPRNumber,
    fixPRUrl,
    fixedCount:    appliedVulnIds.length,
    fixedVulnIds:  appliedVulnIds,
    skippedVulnIds
  }, null, 2))

  console.log('✅ fix-pr-result.json written')
}

main().catch(err => {
  console.error('Fatal:', err)
  process.exit(1)
})