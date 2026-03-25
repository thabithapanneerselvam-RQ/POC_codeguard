'use strict'

/**
 * validate.js
 * -----------
 * Validates and sanitises the Gemini response before it's used.
 *
 * Checks:
 *   1. Gemini returned a response at all
 *   2. Gemini believes it's a real vulnerability (isReal)
 *   3. Confidence is not LOW (too uncertain to auto-fix)
 *   4. If autoFixable is true, the "before" snippet actually exists in the file
 *      (prevents applying patches to wrong code)
 *
 * Side effects:
 *   - May downgrade autoFixable to false
 *   - Fills in defaults for missing fields
 */

const fs = require('fs')

function validateGeminiResp(finding, gemini) {
  // No response from Gemini
  if (!gemini) return false

  // Gemini flagged as false positive
  if (!gemini.isReal) return false

  // Fill in defaults for optional fields
  gemini.severity     = gemini.severity     || finding.severity || 'MEDIUM'
  gemini.confidence   = gemini.confidence   || 'MEDIUM'
  gemini.explanation  = gemini.explanation  || ''
  gemini.exploitExample = gemini.exploitExample || ''
  gemini.fix          = gemini.fix          || { before: '', after: '', explanation: '' }
  gemini.autoFixable  = !!gemini.autoFixable

  // Disable auto-fix for LOW confidence findings
  if (gemini.confidence === 'LOW') {
    gemini.autoFixable = false
  }

  // Verify the "before" snippet actually exists in the file before marking auto-fixable
  if (gemini.autoFixable && gemini.fix.before && finding.file !== 'package.json') {
    try {
      const content = fs.readFileSync(finding.file, 'utf8')
      if (!content.includes(gemini.fix.before)) {
        gemini.autoFixable = false
      }
    } catch {
      gemini.autoFixable = false
    }
  }

  return true
}

module.exports = { validateGeminiResp }
