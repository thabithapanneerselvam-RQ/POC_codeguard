#!/usr/bin/env node
'use strict'

/**
 * scripts/osv-scan.js
 * -------------------
 * Queries the OSV API for known CVEs in your npm dependencies.
 * Reads package-lock.json, batches all packages in a single API call,
 * writes osv-results.json.
 *
 * Usage: node scripts/osv-scan.js [--lockfile package-lock.json] [--out osv-results.json]
 */

const fs    = require('fs')
const https = require('https')
const path  = require('path')

const args     = parseArgs(process.argv.slice(2))
const LOCKFILE = args.lockfile || 'package-lock.json'
const OUT_FILE = args.out      || 'osv-results.json'

function main() {
  if (!fs.existsSync(LOCKFILE)) {
    console.log(`[OSV] ${LOCKFILE} not found — writing empty results`)
    write([])
    return
  }

  let lockfile
  try {
    lockfile = JSON.parse(fs.readFileSync(LOCKFILE, 'utf8'))
  } catch (err) {
    console.error(`[OSV] Failed to parse ${LOCKFILE}:`, err.message)
    write([])
    return
  }

  // Extract packages from packages map (npm v7+) or dependencies (npm v6)
  const packages = []
  const deps = lockfile.packages || lockfile.dependencies || {}

  Object.entries(deps).forEach(([name, info]) => {
    const cleanName = name.replace(/^node_modules\//, '')
    const version   = info.version
    if (cleanName && version) {
      packages.push({ name: cleanName, version })
    }
  })

  if (packages.length === 0) {
    console.log('[OSV] No packages found in lockfile')
    write([])
    return
  }

  console.log(`[OSV] Checking ${packages.length} packages…`)

  const body = JSON.stringify({
    queries: packages.map(pkg => ({
      package: { name: pkg.name, ecosystem: 'npm' },
      version : pkg.version,
    })),
  })

  const options = {
    hostname: 'api.osv.dev',
    path    : '/v1/querybatch',
    method  : 'POST',
    headers : {
      'Content-Type'  : 'application/json',
      'Content-Length': Buffer.byteLength(body),
    },
  }

  const req = https.request(options, res => {
    let data = ''
    res.on('data', chunk => { data += chunk })
    res.on('end', () => {
      try {
        const response = JSON.parse(data)
        const results  = []

        ;(response.results || []).forEach((result, i) => {
          ;(result.vulns || []).forEach(vuln => {
            results.push({
              tool    : 'OSV',
              package : packages[i].name,
              version : packages[i].version,
              vulnId  : vuln.id,
              severity: vuln.database_specific?.severity || 'MEDIUM',
              summary : vuln.summary || '',
              fixedIn : vuln.affected?.[0]?.ranges?.[0]?.events?.find(e => e.fixed)?.fixed || null,
            })
          })
        })

        write(results)
        console.log(`[OSV] Done — ${results.length} CVEs found`)
      } catch (err) {
        console.error('[OSV] Parse error:', err.message)
        write([])
      }
    })
  })

  req.on('error', err => {
    console.error('[OSV] API error:', err.message)
    write([])
  })

  req.write(body)
  req.end()
}

function write(results) {
  fs.writeFileSync(OUT_FILE, JSON.stringify(results, null, 2), 'utf8')
}

function parseArgs(argv) {
  const out = {}
  for (let i = 0; i < argv.length; i += 2) {
    const key = argv[i].replace(/^--/, '')
    out[key] = argv[i + 1]
  }
  return out
}

main()
