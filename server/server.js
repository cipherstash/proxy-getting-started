const express = require('express')
const bodyParser = require('body-parser')
const cors = require('cors')
const app = express()
const port = process.env.PORT || 3000
const fs = require('fs');

const Pool = require('pg').Pool
const pool = new Pool({
  user: 'postgres',
  host: 'tandem',
  database: 'stash',
  password: 'password',
  port: 5432,
})

const getUsers = (request, response) => {
  pool.query('SELECT id, name, email FROM users ORDER BY name ASC', (error, results) => {
    if (error) {
      response.status(500).json({ error: error })
      return
    }
    response.status(200).json(results?.rows)
  })
}

// This example application expects 2 users in the database:
// 1	Anakin	anakin@skywalker.com
// 2	Luke	luke@skywalker.com
const encryptData = async (request, response) => {
  try {
    await pool.query("UPDATE users SET name = 'Luke', email = 'luke@skywalker.com' WHERE id = 2")
    await pool.query("UPDATE users SET name = 'Anakin', email = 'anakin@skywalker.com' WHERE id = 1")
    response.status(200).json({ message: 'Data encrypted!' })
  } catch (e) {
    response.status(500).json({ error: e })
    return
  }
}

app.use(cors())
app.use(bodyParser.json())
app.use(
  bodyParser.urlencoded({
    extended: true,
  })
)

app.get('/users', getUsers)
app.post('/encrypt-data', encryptData)

app.get('/', (request, response) => {
  response.json({ message: 'Welcome!' })
})

app.listen(port, () => {
  console.log(`App running on port ${port}.`)
})