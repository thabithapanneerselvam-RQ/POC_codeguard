const express = require('express')
const fs      = require('fs')
const router  = express.Router()

// VULNERABILITY: Path traversal — req.query.file used without sanitization
router.get('/read', (req, res) => {
  fs.readFile(req.query.file, 'utf8', (err, data) => {
    if (err) return res.status(500).send(err.message)
    res.send(data)
  })
})

module.exports = router
