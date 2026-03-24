// test-vulnerable.js
const express = require("express");
const { exec } = require("child_process");
const fs = require("fs");
const mysql = require("mysql");
const path = require("path");

const app = express();

/* =========================
   GITLEAKS SECRET
========================= */

// Fake AWS key (secret detection)test-vuln.js
const AWS_SECRET_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";
const API_KEY = "sk_test_123456789abcdef";

/* =========================
   HARDCODED CREDENTIAL
========================= */

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