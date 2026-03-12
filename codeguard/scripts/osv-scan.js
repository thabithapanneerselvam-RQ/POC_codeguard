// codeguard/scripts/osv-scan.js

const fs = require('fs')
const https = require('https')

// Check if package-lock.json exists
if (!fs.existsSync('package-lock.json')) {
  console.log('No package-lock.json found')
  fs.writeFileSync(
    'osv-results.json',
    JSON.stringify([], null, 2)
  )
  process.exit(0)
}

const lockfile = JSON.parse(
  fs.readFileSync('package-lock.json', 'utf8')
)

// Extract packages
const packages = []
const deps = lockfile.packages || {}

Object.entries(deps).forEach(([name, info]) => {
  if (name && info.version) {
    packages.push({
      name: name.replace('node_modules/', ''),
      version: info.version
    })
  }
})

console.log(`Checking ${packages.length} packages...`)

// Call OSV API
const body = JSON.stringify({
  queries: packages.map(pkg => ({
    package: {
      name: pkg.name,
      ecosystem: 'npm'
    },
    version: pkg.version
  }))
})

const options = {
  hostname: 'api.osv.dev',
  path: '/v1/querybatch',
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
      const results = []

      response.results?.forEach((result, i) => {
        if (result.vulns?.length > 0) {
          result.vulns.forEach(vuln => {
            results.push({
              tool: 'OSV',
              package: packages[i].name,
              version: packages[i].version,
              vulnId: vuln.id,
              severity: vuln.database_specific
                ?.severity || 'MEDIUM',
              summary: vuln.summary,
              fixedIn: vuln.affected?.[0]
                ?.ranges?.[0]
                ?.events
                ?.find(e => e.fixed)?.fixed
            })
          })
        }
      })

      fs.writeFileSync(
        'osv-results.json',
        JSON.stringify(results, null, 2)
      )
      console.log(
        `OSV: found ${results.length} vulnerabilities`
      )
    } catch(e) {
      console.log('OSV parse error:', e.message)
      fs.writeFileSync(
        'osv-results.json',
        JSON.stringify([], null, 2)
      )
    }
  })
})

req.on('error', e => {
  console.log('OSV API error:', e.message)
  fs.writeFileSync(
    'osv-results.json',
    JSON.stringify([], null, 2)
  )
})

req.write(body)
req.end()