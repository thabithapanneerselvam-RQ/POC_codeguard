// test-gemini.js
// Run this to verify Gemini works

const https = require('https')

const GEMINI_KEY = 'AIzaSyBYR0xfnLCVgpkV_VH24vHQBAQDxrEsecA'

const prompt = `
You are a security expert.

FINDING:
Tool: Semgrep
Issue: SQL Injection
File: test-vuln.js
Line: 8
Code: db.query("SELECT * WHERE id = " + id)

Is this real? Respond in JSON only:
{
  "isReal": true or false,
  "confidence": "HIGH/MEDIUM/LOW",
  "severity": "CRITICAL/HIGH/MEDIUM/LOW",
  "explanation": "...",
  "fix": {
    "before": "...",
    "after": "..."
  },
  "autoFixable": true or false
}
`

const body = JSON.stringify({
  contents: [{
    parts: [{ text: prompt }]
  }]
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
 // test-gemini.js
// Replace the res.on('end') part with this:

res.on('end', () => {
  try {
    const response = JSON.parse(data)

    // ADD THIS — see full response first
    console.log('Full response:')
    console.log(JSON.stringify(response, null, 2))

    // Check for error
    if (response.error) {
      console.log('API Error:', response.error.message)
      return
    }

    // Check candidates exists
    if (!response.candidates) {
      console.log('No candidates in response')
      console.log('Response was:', response)
      return
    }

    const text = response.candidates[0]
      .content.parts[0].text
    console.log('Gemini response:')
    console.log(text)

  } catch(e) {
    console.log('Parse error:', e.message)
    console.log('Raw data:', data)
  }
})
})

req.write(body)
req.end()