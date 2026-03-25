'use strict'

/**
 * dedup.js
 * --------
 * Merges findings that refer to the same vulnerability.
 *
 * Key strategy: file + line + issue-type
 *   → same physical location AND same class of issue = one finding
 *   → multiple tools confirming same location get merged into confirmedBy[]
 *   → severity is always escalated to the highest seen
 *
 * Why not just file:line?
 *   A file may have a SQL injection on line 10 AND a secret on line 10.
 *   Those are two different vulnerabilities — they should not be merged.
 *
 * Why not file:line:exact-issue-id?
 *   Semgrep might call it "javascript.sql-injection" and Bearer might call
 *   it "ruby_lang_sql_injection" for the same code. We normalise to a
 *   broad category so cross-tool confirmation still works.
 */

const SEV_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

function deduplicate(findings) {
  const seen = new Map()

  findings.forEach(f => {
    const key = `${f.file}::${f.line}::${categorise(f.issue)}`

    if (!seen.has(key)) {
      seen.set(key, { ...f, confirmedBy: [...f.confirmedBy] })
    } else {
      const existing = seen.get(key)

      // Merge confirmedBy (no duplicates)
      f.confirmedBy.forEach(tool => {
        if (!existing.confirmedBy.includes(tool)) {
          existing.confirmedBy.push(tool)
        }
      })

      // Escalate severity if the new finding is more severe
      if (SEV_ORDER.indexOf(f.severity) < SEV_ORDER.indexOf(existing.severity)) {
        existing.severity = f.severity
        existing.message  = f.message
        existing.code     = f.code
        existing.issue    = f.issue
      }

      // Use the richer code snippet
      if (!existing.code && f.code) existing.code = f.code
    }
  })

  return Array.from(seen.values())
}

// Broad category mapping for cross-tool dedup
const ISSUE_CATEGORIES = [
  { pattern: /sql.inject|sqli/i,        category: 'sql_injection'      },
  { pattern: /command.inject|exec|rce/i, category: 'command_injection'  },
  { pattern: /xss|cross.site.script/i,  category: 'xss'                },
  { pattern: /path.travers|dir.travers/i,category: 'path_traversal'    },
  { pattern: /secret|hardcode|api.key/i, category: 'hardcoded_secret'  },
  { pattern: /cve-\d{4}-\d+/i,          category: 'cve'                },
  { pattern: /open.redirect/i,           category: 'open_redirect'     },
  { pattern: /ssrf/i,                    category: 'ssrf'               },
  { pattern: /xxe/i,                     category: 'xxe'                },
  { pattern: /deserializ/i,              category: 'deserialization'    },
]

function categorise(issue) {
  for (const { pattern, category } of ISSUE_CATEGORIES) {
    if (pattern.test(issue)) return category
  }
  return issue.toLowerCase().replace(/[^a-z0-9]+/g, '_')
}

module.exports = { deduplicate }
