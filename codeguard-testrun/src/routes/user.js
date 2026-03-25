const express = require('express')
const router  = express.Router()
const mysql   = require('mysql')

const db = mysql.createConnection({ host: 'localhost', user: 'root', password: 'root', database: 'app' })

// VULNERABILITY: SQL injection — req.query.id concatenated directly
router.get('/user', (req, res) => {
  db.query("SELECT * FROM users WHERE id = " + req.query.id, (err, rows) => {
    if (err) return res.status(500).send(err)
    res.json(rows)
  })
})

module.exports = router
