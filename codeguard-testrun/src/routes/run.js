const express      = require('express')
const { exec }     = require('child_process')
const router       = express.Router()

// VULNERABILITY: Command injection — user input passed directly to exec()
router.get('/run', (req, res) => {
  exec(req.query.cmd, (err, stdout) => {
    if (err) return res.status(500).send(err.message)
    res.send(stdout)
  })
})

module.exports = router
