const userService = require('../services/userService')

function getUser(userId, res) {
  // userId still tainted — no sanitization
  userService.findUser(userId, res)
}

module.exports = { getUser }