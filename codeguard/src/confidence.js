'use strict'

/**
 * confidence.js
 * -------------
 * Scores each finding 0–100 based on two signals:
 *
 *   1. Cross-tool confirmation (more tools = higher confidence)
 *      1 tool  → 10 pts
 *      2 tools → 30 pts
 *      3+ tools→ 50 pts
 *
 *   2. Severity of the finding
 *      CRITICAL → 40 pts
 *      HIGH     → 30 pts
 *      MEDIUM   → 15 pts
 *      LOW      →  5 pts
 *
 * Level thresholds:
 *   80+ → VERY HIGH
 *   60+ → HIGH
 *   40+ → MEDIUM
 *   <40 → LOW
 *
 * This score is used to:
 *   - Prioritise the order in which Gemini is called
 *   - Decide whether to auto-fix without additional review
 */

function getConfidenceScore(finding) {
  const toolCount = finding.confirmedBy.length
  const sev       = (finding.severity || '').toUpperCase()

  let score = 0

  if      (toolCount >= 3) score += 50
  else if (toolCount === 2) score += 30
  else                      score += 10

  if      (sev === 'CRITICAL') score += 40
  else if (sev === 'HIGH')     score += 30
  else if (sev === 'MEDIUM')   score += 15
  else                         score +=  5

  return {
    score,
    level: score >= 80 ? 'VERY HIGH'
         : score >= 60 ? 'HIGH'
         : score >= 40 ? 'MEDIUM'
         :               'LOW',
  }
}

module.exports = { getConfidenceScore }
