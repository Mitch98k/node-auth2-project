const router = require("express").Router();
const Users = require('../users/users-model');
const bcrypt = require('bcryptjs');
const { checkUsernameExists, validateRoleName, vrn2, vrn3 } = require('./auth-middleware');
const jwt = require('jsonwebtoken');
const { JWT_SECRET } = require("../secrets"); // use this secret!

router.post("/register", validateRoleName, vrn2, vrn3, async (req, res, next) => {
  const user = req.body;
  const hash = bcrypt.hashSync(user.password, 8);
  try {
    user.password = hash;
    const newUser = await Users.add(user);
    res.status(201).json(newUser);
  } catch(err) {
    res.json(err.message)
    next();
  }
});


router.post("/login", checkUsernameExists, async (req, res, next) => {
  const {username, password} = req.body;
  const user = req.user;
  try {
    if (bcrypt.compareSync(password, user.password)) {
      const token = makeToken(user);
      res.json({ message: `${username} is back!`, token });
    } else {
      res.status(401).json({ message: 'invalid credentials' });
    }
  } catch(err) {
    res.json(err.message)
    next();
  }
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
