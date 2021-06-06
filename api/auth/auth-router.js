const router = require("express").Router();
const Users = require('../users/users-model');
const bcrypt = require('bcryptjs');
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const jwt = require('jsonwebtoken');
const { JWT_SECRET } = require("../secrets"); // use this secret!

router.post("/register", /*validateRoleName,*/ async (req, res, next) => {
  const user = req.body;
  const hash = bcrypt.hashSync(user.password, 8);
  try {
    user.password = hash;
    const newUser = await Users.add(user);
    res.status(201).json(newUser);
  } catch(err) {
    next();
  }
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
});


router.post("/login", /*checkUsernameExists,*/ async (req, res, next) => {
  const {username, password} = req.body;
  const user = await Users.findBy({username});
  try {
    if (user && bcrypt.compareSync(password, user.password)) {
      const token = makeToken(user);
      res.json({ message: `${username} is back!`, token });
    } else {
      console.log(user, password, user.password);
      res.status(401).json('invalid credentials');
    }
  } catch(err) {
    res.json(err.message)
    //next();
  }
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
});

function makeToken(user) {
  const payload = {
    subject: user.user_id,
    username: user.username,
    role: user.role_name
  }
  const options = {
    expiresIn: "1d"
  }
  return jwt.sign(payload, JWT_SECRET, options)
}


module.exports = router;
