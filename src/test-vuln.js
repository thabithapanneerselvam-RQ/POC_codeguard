// test-vuln.js
const express = require('express')
const app = express()

// VULNERABILITY 1: SQL Injection
app.get('/user', (req, res) => {
  const id = req.query.id
  db.query(
    "SELECT * FROM users WHERE id = " + id
  )
})

// VULNERABILITY 2: Hardcoded secret
const API_KEY = "sk-abc123secretkey"

// VULNERABILITY 3: Command injection
app.get('/run', (req, res) => {
  const cmd = req.query.cmd
  require('child_process').exec(cmd)
})

// VULNERABILITY 4: XSS
app.get('/search', (req, res) => {
  const query = req.query.q
  res.send('<h1>' + query + '</h1>')
})




const jwt = require('jsonwebtoken')
app.use(express.json())

// VULN 1: Weak JWT Secret
const JWT_SECRET = "secret123"

// VULN 2: No password hashing
app.post('/register', (req, res) => {
  const { username, password } = req.body
  db.query(
    `INSERT INTO users VALUES ('${username}', '${password}')`
  )
})

// VULN 3: JWT with no expiry
app.post('/login', (req, res) => {
  const token = jwt.sign(
    { user: req.body.username },
    JWT_SECRET
    // no expiresIn ← vulnerable
  )
  res.json({ token })
})

// VULN 4: Insecure token verification
app.get('/profile', (req, res) => {
  const token = req.headers.authorization
  const decoded = jwt.verify(token, JWT_SECRET)
  res.json(decoded)
})

// VULN 5: Timing attack on password compare
app.post('/verify', (req, res) => {
  const stored = "admin123"
  if (req.body.password === stored) {
    res.send('ok')
  }
})
EOF