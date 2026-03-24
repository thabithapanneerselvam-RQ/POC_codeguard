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