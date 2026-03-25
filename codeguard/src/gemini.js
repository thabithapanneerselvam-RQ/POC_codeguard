'use strict'

/**
 * gemini.js
 * ---------
 * Calls Gemini Flash to validate a finding.
 *
 * Rate-limit strategy:
 *   - Respects Retry-After header when returned (429)
 *   - Falls back to exponential backoff: 2s → 4s → 8s → 16s → 32s
 *   - Max 5 retries per finding; gives up and returns null after that
 *   - Does NOT use a fixed sleep — adapts to actual API signals
 *
 * Context extraction:
 *   - Reads ±10 lines around the finding's line number from disk (async)
 *   - Falls back to the stored code snippet if file is unreadable
 *
 * Prompt design:
 *   - Instructs Gemini to respond ONLY in JSON (no markdown fences)
 *   - Requests: isReal, confidence, severity, explanation,
 *     exploitExample, fix {before, after, explanation}, autoFixable
 */

const https = require('https')
const fs    = require('fs')

const MAX_RETRIES   = 5
const BASE_DELAY_MS = 2000
const MODEL         = 'gemini-2.5-flash'
const API_HOST      = 'generativelanguage.googleapis.com'
const CONTEXT_LINES = 10   // lines above and below the finding

async function callGemini(finding, apiKey) {
  const context = await extractContext(finding)
  const prompt  = buildPrompt(finding, context)

  for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
    const result = await httpPost(apiKey, prompt)

    if (result.rateLimited) {
      const wait = result.retryAfter
        ? result.retryAfter * 1000
        : BASE_DELAY_MS * Math.pow(2, attempt)
      process.stdout.write(`[rate-limited, waiting ${Math.round(wait/1000)}s] `)
      await sleep(wait)
      continue
    }

    if (result.error) {
      if (attempt < MAX_RETRIES) {
        const wait = BASE_DELAY_MS * Math.pow(2, attempt)
        process.stdout.write(`[retry ${attempt+1}] `)
        await sleep(wait)
        continue
      }
      return null
    }

    return result.data
  }

  return null
}

// ── HTTP POST ────────────────────────────────────────────
function httpPost(apiKey, prompt) {
  return new Promise(resolve => {
    const body = JSON.stringify({
      contents: [{ parts: [{ text: prompt }] }],
      generationConfig: {
        temperature    : 0.1,
        responseMimeType: 'application/json',
      },
    })

    const options = {
      hostname: API_HOST,
      path    : `/v1beta/models/${MODEL}:generateContent?key=${apiKey}`,
      method  : 'POST',
      headers : {
        'Content-Type'  : 'application/json',
        'Content-Length': Buffer.byteLength(body),
      },
    }

    const req = https.request(options, res => {
      // Check for rate limit immediately from status
      if (res.statusCode === 429) {
        const retryAfter = parseInt(res.headers['retry-after'] || '0', 10) || null
        resolve({ rateLimited: true, retryAfter })
        res.resume()
        return
      }

      let raw = ''
      res.on('data', chunk => { raw += chunk })
      res.on('end', () => {
        try {
          const response = JSON.parse(raw)

          if (response.error) {
            // Check for quota-related errors in body
            const isQuota = /quota|rate/i.test(response.error.message || '')
            if (isQuota) {
              resolve({ rateLimited: true, retryAfter: null })
            } else {
              resolve({ error: response.error.message })
            }
            return
          }

          const text = response.candidates?.[0]?.content?.parts?.[0]?.text
          if (!text) {
            resolve({ error: 'Empty response from Gemini' })
            return
          }

          // Strip markdown code fences if Gemini adds them despite responseMimeType
          const clean = text
            .replace(/^```json\s*/i, '')
            .replace(/```\s*$/,      '')
            .trim()

          try {
            resolve({ data: JSON.parse(clean) })
          } catch {
            // Try to extract JSON from mixed response
            const match = clean.match(/\{[\s\S]*\}/)
            if (match) {
              try {
                resolve({ data: JSON.parse(match[0]) })
              } catch {
                resolve({ error: 'Could not parse Gemini JSON response' })
              }
            } else {
              resolve({ error: 'No JSON found in Gemini response' })
            }
          }
        } catch (err) {
          resolve({ error: `HTTP parse error: ${err.message}` })
        }
      })
    })

    req.on('error', err => resolve({ error: err.message }))
    req.write(body)
    req.end()
  })
}

// ── Context extraction (async, non-blocking) ─────────────
async function extractContext(finding) {
  if (!finding.file || finding.file === 'package.json' || finding.line <= 0) {
    return finding.code || 'No source context available'
  }

  try {
    const content = await fs.promises.readFile(finding.file, 'utf8')
    const lines   = content.split('\n')
    const start   = Math.max(0, finding.line - 1 - CONTEXT_LINES)
    const end     = Math.min(lines.length, finding.line + CONTEXT_LINES)
    return lines
      .slice(start, end)
      .map((l, i) => `${start + i + 1}: ${l}`)
      .join('\n')
  } catch {
    return finding.code || 'No source context available'
  }
}

// ── Prompt ───────────────────────────────────────────────
function buildPrompt(finding, context) {
  return `You are a senior application security engineer reviewing a SAST finding.

FINDING DETAILS:
Tool:     ${finding.tool}
Issue:    ${finding.issue}
File:     ${finding.file}
Line:     ${finding.line}
Severity: ${finding.severity}
Message:  ${finding.message}
Confirmed by: ${finding.confirmedBy.join(', ')}

CODE CONTEXT:
${context}

Analyse this finding carefully. Consider:
- Is this a real, exploitable vulnerability or a false positive?
- What is the actual risk in this specific code context?
- What is the minimal, correct fix?

Respond ONLY with valid JSON matching this exact schema (no markdown, no extra text):
{
  "isReal": true,
  "confidence": "HIGH",
  "severity": "CRITICAL",
  "explanation": "Concise explanation of why this is or isn't a vulnerability",
  "exploitExample": "How an attacker would exploit this (or empty string if false positive)",
  "fix": {
    "before": "The exact vulnerable code to replace",
    "after": "The exact fixed code",
    "explanation": "Why this fix eliminates the vulnerability"
  },
  "autoFixable": true
}

For isReal: set false if this is a false positive (e.g. unreachable code, test-only file, already sanitised).
For severity: CRITICAL | HIGH | MEDIUM | LOW
For confidence: HIGH | MEDIUM | LOW
For autoFixable: true only if the fix.before/after is complete and safe to apply mechanically.`
}

// ── Util ─────────────────────────────────────────────────
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms))
}

module.exports = { callGemini }
