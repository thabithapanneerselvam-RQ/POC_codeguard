const express = require("express");
const { exec } = require("child_process");
const fs = require("fs");
const mysql = require("mysql");
const jwt = require('jsonwebtoken')
const axios = require('axios')
const mongoose = require('mongoose')

const app = express();
app.use(express.json())
app.use(express.urlencoded({ extended: true }))

/* =========================
   GITLEAKS SECRET
========================= */

/* =========================
   HARDCODED CREDENTIAL
========================= */
const API_KEY = "sk_test_123456789abcdef";
const DB_PASSWORD = "SuperSecretPassword123";

/* =========================
   SQL INJECTION
   (Semgrep + Bearer)
========================= */

app.get("/user", (req, res) => {
  const id = req.query.id;

  const query = "SELECT * FROM users WHERE id = " + id;

  const db = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: DB_PASSWORD,
    database: "users"
  });

  db.query(query, (err, result) => {
    if (err) {
      res.send(err);
      return;
    }

    res.send(result);
  });
});

/* =========================
   COMMAND INJECTION
   (Semgrep + Bearer)
========================= */

app.get("/run", (req, res) => {
  const command = req.query.cmd;

  exec(command, (err, stdout) => {
    if (err) {
      res.send(err);
      return;
    }

    res.send(stdout);
  });
});

/* =========================
   XSS VULNERABILITY
   (Semgrep + Bearer)
========================= */

app.get("/search", (req, res) => {
  const query = req.query.q;

  res.send("<h1>" + query + "</h1>");
});

/* =========================
   PATH TRAVERSAL
   (Bearer)
========================= */

app.get("/read", (req, res) => {
  const file = req.query.file;

  fs.readFile(file, "utf8", (err, data) => {
    if (err) {
      res.send(err);
      return;
    }

    res.send(data);
  });
});

/* =========================
   SENSITIVE DATA EXPOSURE
========================= */

app.get("/config", (req, res) => {
  res.json({
    apiKey: API_KEY,
    password: DB_PASSWORD
  });
});

app.listen(3000, () => {
  console.log("Test vulnerable app running on port 3000");
});



/* =========================
   SCENARIO 1: JWT VULNERABILITIES
========================= */

// VULN 1: Weak JWT secret hardcoded
const JWT_SECRET = 'mysecretkey123'

// VULN 2: Signing with weak secret
app.post('/login', (req, res) => {
  const { username } = req.body
  const token = jwt.sign(
    { userId: 1, username },
    'secret'
  )
  res.json({ token })
})

// VULN 3: Verifying with algorithm none allowed
app.get('/profile', (req, res) => {
  const token = req.headers.authorization
  const decoded = jwt.verify(token, '', {
    algorithms: ['none']
  })
  res.json(decoded)
})

/* =========================
   SCENARIO 2: NOSQL INJECTION
========================= */

// VULN: User input directly in MongoDB query
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

// VULN: Direct query object from user
app.get('/users/search', (req, res) => {
  const filter = req.query.filter
  mongoose.model('User').find(
    JSON.parse(filter)
  )
})

/* =========================
   SCENARIO 4: SSRF
   (Server Side Request Forgery)
========================= */

// VULN: Fetching user controlled URL
app.get('/fetch', async (req, res) => {
  const url = req.query.url
  const response = await axios.get(url)
  res.send(response.data)
})

// VULN: Webhook with user controlled URL
app.post('/webhook', async (req, res) => {
  const webhookUrl = req.body.url
  await axios.post(webhookUrl, {
    event: 'payment_success'
  })
  res.json({ sent: true })
})

/* =========================
   SCENARIO 10: TIMING ATTACK
========================= */

// VULN: Direct string comparison for password
app.post('/verify', (req, res) => {
  const token = req.body.token
  const storedToken = process.env.API_TOKEN

  if (token === storedToken) {
    res.json({ valid: true })
  } else {
    res.json({ valid: false })
  }
})

// VULN: Direct comparison for API key
app.post('/api/authenticate', (req, res) => {
  const providedKey = req.headers['x-api-key']
  const validKey = process.env.API_KEY

  if (providedKey === validKey) {
    res.json({ authenticated: true })
  } else {
    res.status(401).json({ authenticated: false })
  }
})

app.listen(3000, () => {
  console.log('Test scenarios app running on port 3000')
})