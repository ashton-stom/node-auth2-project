const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const users = require('../users/users-model.js')
const token = require('jsonwebtoken')
const bcrypt = require('bcrypt')
const { JWT_SECRET } = require("../secrets"); // use this secret!

router.post("/register", validateRoleName, async (req, res, next) => {
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
  let { username, password, role_name } = req.body;
  password = bcrypt.hashSync(password, 10)
  console.log(password)
  try {
    const createdUser = await users.add({ username, password, role_name })
    console.log(`Created user ${createdUser.username}`)
    res.status(201).json({ message: 'Welcome to the club!' })
  } catch (err) {
    res.status(500).json({ message: 'Unable to create account' })
    console.log(err)
  }
});


router.post("/login", checkUsernameExists, async (req, res, next) => {
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
  let { username, password } = req.body;
  try {
    console.log(password)
    const loginUser = await users.findBy(user => user.username == username )
    console.log(loginUser)
    if (loginUser.length == 0) {
      res.status(400).json({ message: 'Login error' })
    } else {
      if (!bcrypt.compareSync(password, loginUser[0].password)) {
        res.status(400).json({ message: 'Incorrect credentials' })
        return
      }
      let jwt = token.sign({ user_id: loginUser[0].user_id, username: loginUser[0].username }, JWT_SECRET)
      res.status(200).json({ message: 'Welcome back!', token: jwt })
    }
  } catch (err) {
    res.status(500).json({ message: 'Cannot login' })
    console.log(err);
  }
});

module.exports = router;
