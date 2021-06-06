const Users = require('../users/users-model');

const { JWT_SECRET } = require("../secrets"); // use this secret!
const jwt = require('jsonwebtoken');

const restricted = (req, res, next) => {
  const token = req.headers.authorization;
  if (!token) {
    res.status(401).json({ message: "Token required" });
  } else {
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
      if (err) {
        res.status(401).json({ message: "Token invalid" });
      } else {
        req.decodedToken = decoded;
        next();
      }
    })
  }
}

const only = role_name => (req, res, next) => {
  if (req.decodedToken.role === role_name) {
    next();
  } else {
    res.status(403).json({ message: 'This is not for you' });
  }
}


const checkUsernameExists = async (req, res, next) => {
  const {username} = req.body;
  const user = await Users.findBy({username});
  if (!user) {
    res.status(401).json({ message: "Invalid credentials" });
  } else {
    req.user = user;
    next();
  }
}


const validateRoleName = (req, res, next) => {
  const {role_name} = req.body;
  if (role_name) {
    req.body.role_name = role_name.trim();
    next();
  } else {
    req.role_name = 'student';
    next();
  }
}
  const vrn2 = (req, res, next) => {
    if (req.body.role_name === 'admin') {
      res.status(422).json({ message: "Role name can not be admin" });
    } else {
      next();
    }
  }
  
  const vrn3 = (req, res, next) => {
    if (req.body.role_name.length > 32) {
      res.status(422).json({ message: "Role name can not be longer than 32 chars" });
    } else {
      next();
    }
  }


module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  vrn2,
  vrn3,
  only,
}
