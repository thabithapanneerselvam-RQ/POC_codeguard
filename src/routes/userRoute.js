const express = require('express')
const router = express.Router()
const userController = require('../controllers/userController')

router.get('/user', (req, res) => {
  const id = req.query.id   // ← USER INPUT ENTERS
  userController.getUser(id, res)
})

module.exports = router