const express = require('express')
const router  = express.Router()

// VULNERABILITY: Reflected XSS — query param written directly into HTML response
router.get('/search', (req, res) => {
  const query = req.query.q
  res.send('<h1>' + query + '</h1>')
})

module.exports = router
