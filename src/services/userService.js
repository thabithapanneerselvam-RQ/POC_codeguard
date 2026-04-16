const mysql = require('mysql')

function findUser(input, res) {
  const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: process.env.DB_PASSWORD,
    database: 'users'
  })

  // input came from req.query.id
  // 3 files away!
  db.query(
    "SELECT * FROM users WHERE id = ?", [input]
  )
}

module.exports = { findUser }