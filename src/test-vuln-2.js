// Vulnerability test scenarios for CodeGuard POC
// Scenarios:
//   1. Hardcoded Secrets         (Gitleaks + Bearer)
//   2. SQL Injection              (Semgrep + Bearer)
//   3. Command Injection          (Semgrep + Bearer)
//   4. XSS                        (Semgrep + Bearer)
//   5. Path Traversal             (Bearer)
//   6. Sensitive Data Exposure    (Semgrep + Bearer)
//   7. JWT Vulnerabilities        (Semgrep + Bearer + Gitleaks)
//   8. NoSQL Injection            (Semgrep + Bearer)
//   9. SSRF                       (Semgrep + Bearer)
//  10. Timing Attack              (Bearer)
//  11. No Password Hashing        (Semgrep)
//  12. JWT No Expiry              (Semgrep)

const express = require('express')
const { exec } = require('child_process')
const fs = require('fs')
const mysql = require('mysql')
const jwt = require('jsonwebtoken')
const axios = require('axios')
const mongoose = require('mongoose')

const helmet = require('helmet'); // Add this line at the top of your file
const app = express()
app.disable('x-powered-by') // Disable the X-Powered-By header
app.use(helmet()) // Use Helmet middleware to set security headers
app.use(express.json())
app.use(express.urlencoded({ extended: true }))

/* =========================
   SCENARIO 1: HARDCODED SECRETS
   Caught by: Gitleaks + Bearer
========================= */

const API_KEY     = 'sk_test_123456789abcdef'
const DB_PASSWORD = 'SuperSecretPassword123'
const JWT_SECRET  = 'mysecretkey123'

/* =========================
   SCENARIO 2: SQL INJECTION
   Caught by: Semgrep + Bearer
========================= */

app.get('/user', (req, res) => {
  const id = req.query.id
  const query = 'SELECT * FROM users WHERE id = ?'

  const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: DB_PASSWORD,
    database: 'users'
  })

  db.query(query, [id], (err, result) => {
    if (err) { res.send(err); return }
    res.send(result)
  })
})

/* =========================
   SCENARIO 3: COMMAND INJECTION
   Caught by: Semgrep + Bearer
========================= */

app.get('/run', (req, res) => {
  const command = req.query.cmd

  exec(command, (err, stdout) => {
    if (err) { res.send(err); return }
    res.send(stdout)
  })
})

/* =========================
   SCENARIO 4: XSS
   (Cross-Site Scripting)
   Caught by: Semgrep + Bearer
========================= */

const { escapeHtml } = require('escape-goat'); // Example: Use a trusted HTML escaping library

app.get('/search', (req, res) => {
  const query = req.query.q;
  res.send('<h1>' + escapeHtml(query) + '</h1>');
});

/* =========================
   SCENARIO 5: PATH TRAVERSAL
   Caught by: Bearer
========================= */

app.get('/read', (req, res) => {
  const file = req.query.file

  fs.readFile(file, 'utf8', (err, data) => {
    if (err) { res.send(err); return }
    res.send(data)
  })
})

/* =========================
   SCENARIO 6: SENSITIVE DATA EXPOSURE
   Caught by: Semgrep + Bearer
========================= */

app.get('/config', (req, res) => {
  res.json({
    apiKey: API_KEY,
    password: DB_PASSWORD
  })
})

/* =========================
   SCENARIO 7: JWT VULNERABILITIES
   Caught by: Semgrep + Bearer + Gitleaks
========================= */

// VULN 1: Signing with weak hardcoded secret + no expiry
app.post('/login', (req, res) => {
  const { username } = req.body
  const token = jwt.sign(
    { userId: 1, username },
    process.env.JWT_SECRET // Use an environment variable for the secret
    // Recommended: add an 'expiresIn' option for token expiration
  )
  res.json({ token })
})

// VULN 2: Verifying with algorithm none allowed
app.get('/profile', (req, res) => {
  const token = req.headers.authorization
  // Ensure a strong, secret key is used from environment variables.
  // Do not allow 'none' and specify the actual algorithm(s) used for signing.
  const decoded = jwt.verify(token, process.env.JWT_SECRET, {
    algorithms: ['HS256'] // Example: Use HS256 or RS256, but never 'none'.
  })
  res.json(decoded)
})

// VULN 3: Insecure token verification — uses hardcoded JWT_SECRET
app.get('/me', (req, res) => {
  const token = req.headers.authorization
  // Load the JWT secret from a secure source, such as an environment variable.
  // Replace 'JWT_SECRET' with a variable like process.env.JWT_SECRET
  const decoded = jwt.verify(token, process.env.JWT_SECRET)
  res.json(decoded)
})

/* =========================
   SCENARIO 8: NOSQL INJECTION
   Caught by: Semgrep + Bearer
========================= */

// VULN 1: User input directly in MongoDB query
app.post('/user/login', (req, res) => {
  const username = req.body.username
  const password = req.body.password

  mongoose.model('User').findOne({
    username: username,
    password: password
  }).then(user => {
    if (user) {
      res.json({ success: true })
    } else {
      res.status(401).json({ success: false })
    }
  })
})

// VULN 2: Direct query object from user input
app.get('/users/search', (req, res) => {
  const filter = req.query.filter
  mongoose.model('User').find(
    JSON.parse(filter)
  )
})

/* =========================
   SCENARIO 9: SSRF
   (Server Side Request Forgery)
   Caught by: Semgrep + Bearer
========================= */

// VULN 1: Fetching user controlled URL
app.get('/fetch', async (req, res) => {
  const url = req.query.url
  const response = await axios.get(url)
  res.send(response.data)
})

// VULN 2: Webhook with user controlled URL
app.post('/webhook', async (req, res) => {
  const webhookUrl = req.body.url
  await axios.post(webhookUrl, {
    event: 'payment_success'
  })
  res.json({ sent: true })
})

/* =========================
   SCENARIO 10: TIMING ATTACK
   Caught by: Bearer
========================= */

// VULN 1: Direct string comparison for token
const crypto = require('crypto');

app.post('/verify', (req, res) => {
  const token = req.body.token;
  const storedToken = process.env.API_TOKEN;

  // Ensure both token and storedToken are strings before creating buffers.
  // If not, treat as invalid to prevent Buffer.from errors and potential timing differences
  // from error handling.
  if (typeof token !== 'string' || typeof storedToken !== 'string') {
    return res.json({ valid: false });
  }

  const tokenBuffer = Buffer.from(token);
  const storedTokenBuffer = Buffer.from(storedToken);

  // Use crypto.timingSafeEqual for constant-time comparison to prevent timing attacks.
  if (crypto.timingSafeEqual(tokenBuffer, storedTokenBuffer)) {
    res.json({ valid: true });
  } else {
    res.json({ valid: false });
  }
});

// VULN 2: Direct comparison for API key
app.post('/api/authenticate', (req, res) => {
  const providedKey = req.headers['x-api-key']
  const validKey = process.env.API_KEY

  if (providedKey === validKey) {
    res.json({ authenticated: true })
  } else {
    res.status(401).json({ authenticated: false })
  }
})

/* =========================
   SCENARIO 11: NO PASSWORD HASHING
   Caught by: Semgrep
========================= */

app.post('/register', (req, res) => {
  const { username, password } = req.body
  // password stored as plaintext — no hashing
  const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: DB_PASSWORD,
    database: 'users'
  })
  db.query(
    `INSERT INTO users VALUES ('${username}', '${password}')`
  )
  res.json({ created: true })
})

app.listen(3000, () => {
  console.log('Test scenarios app running on port 3000')
})
