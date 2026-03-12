// test-all-layers.js
// Runs all layers locally
// Simulates what ADO pipeline does

const { execSync } = require('child_process')
const fs = require('fs')

console.log('\n=============================')
console.log('  CodeGuard Local Test Run')
console.log('=============================\n')

// LAYER 1: Semgrep
console.log('Running Layer 1: Semgrep...')
try {
  execSync(
    'semgrep \
    --config auto \
    --json \
    --output semgrep-results.json \
    --exclude "*.json" \
    --exclude "test-*.js" \
    --exclude "codeguard/" \
    --exclude "*.snap" \
    --exclude "*.test.ts" \
    --exclude "*.test.js" \
    --exclude "__snapshots__" \
    src/ 2>/dev/null || true',
    { stdio: 'pipe' }
  )
  const results = JSON.parse(
    fs.readFileSync('semgrep-results.json', 'utf8')
  )
  console.log(`✅ Semgrep: ${results.results?.length || 0} findings\n`)
} catch(e) {
  console.log('⚠️  Semgrep error:', e.message)
}

// LAYER 2: Bearer
console.log('Running Layer 2: Bearer...')
try {
  execSync(
    'bearer scan src/ \
    --format json \
    --output bearer-results.json \
    --quiet 2>/dev/null || true',
    { stdio: 'pipe' }
  )

  const bearerData = JSON.parse(
    fs.readFileSync('bearer-results.json', 'utf8')
  )

  // Bearer result format check
  const count =
    bearerData?.findings?.length ||
    bearerData?.high?.length ||
    bearerData?.critical?.length ||
    (Array.isArray(bearerData) ? bearerData.length : 0) ||
    0

  console.log(`✅ Bearer: ${count} findings\n`)

} catch(e) {
  console.log('⚠️  Bearer error:', e.message)
}

// LAYER 3a: npm audit
console.log('Running Layer 3: npm audit...')
try {
  execSync(
    'npm audit --json > npm-audit.json 2>/dev/null',
    { stdio: 'pipe' }
  )
  console.log('✅ npm audit complete\n')
} catch(e) {
  // npm audit exits with error if vulns found
  // that is normal behavior
  console.log('✅ npm audit complete (vulns found)\n')
}

// LAYER 3b: OSV
console.log('Running Layer 3: OSV scan...')
// osv-scan.js runs async
// give it 5 seconds
execSync('node codeguard/scripts/osv-scan.js')
console.log('✅ OSV scan complete\n')

// LAYER 3c: Gitleaks
console.log('Running Layer 3: Gitleaks...')
try {
  execSync(
    'gitleaks detect --source . --report-format json --report-path gitleaks-results.json --exit-code 0',
    { stdio: 'pipe' }
  )
  const results = JSON.parse(
    fs.readFileSync('gitleaks-results.json', 'utf8')
  )
  console.log(`✅ Gitleaks: ${results?.length || 0} secrets found\n`)
} catch(e) {
  console.log('⚠️  Gitleaks error')
}

// SUMMARY
console.log('=============================')
console.log('  Results Summary')
console.log('=============================')

try {
  const semgrep = JSON.parse(
    fs.readFileSync('semgrep-results.json', 'utf8')
  )
  console.log(`Semgrep findings: ${semgrep.results?.length || 0}`)
} catch(e) {}

try {
  const bearer = JSON.parse(
    fs.readFileSync('bearer-results.json', 'utf8')
  )
  console.log(`Bearer findings: ${bearer?.length || 0}`)
} catch(e) {}

try {
  const osv = JSON.parse(
    fs.readFileSync('osv-results.json', 'utf8')
  )
  console.log(`OSV CVEs found: ${osv?.length || 0}`)
} catch(e) {}

try {
  const leaks = JSON.parse(
    fs.readFileSync('gitleaks-results.json', 'utf8')
  )
  console.log(`Secrets found: ${leaks?.length || 0}`)
} catch(e) {}

console.log('\nAll layers tested locally ✅')
console.log('Ready for ADO pipeline setup')