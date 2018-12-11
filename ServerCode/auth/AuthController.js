// Authentication logic
var express = require('express');
var router = express.Router();
var bodyParser = require('body-parser');
var jwt = require('jsonwebtoken');
var bcrypt = require('bcryptjs');
var config = require('../config');
var VerifyToken = require('./VerifyToken');

router.use(bodyParser.urlencoded({ extended: false }));
router.use(bodyParser.json());
var User = require('../user/User');
var MessageToken = require('./MessageToken');


// Creates a new user with hashed password
router.post('/register', function(req, res) {
  var hashedPassword = bcrypt.hashSync(req.body.password, 8);

    // Check the email before creating a new user
    User.findOne({ email: req.body.email }, function (err, user) {
      if (err) {
        return res.status(500).send("Error on the server.");
      }
      // If the email isn't found under any users, then create the new user
      if (!user) {
        User.create({
          name : req.body.name,
          email : req.body.email,
          password : hashedPassword
        },
        function (err, user) {
          if (err) {
            return res.status(500).send("There was a problem registering the user.");
          }

          // If user is registered without errors
          // Create a token
          var token = jwt.sign({ id: user._id }, config.secret, {
            expiresIn: 86400 // expires in 24 hours
          });

          MessageToken.create({email: req.body.email, token: token});
          res.status(200).send({auth: true, token: token});
        });
      }
      // If the user was found with the same email, return an error
      else {
        return res.status(404).send("User found with same email.");
      }
    });
});


router.post('/login', function(req, res) {
  User.findOne({ email: req.body.email }, function (err, user) {
    if (err) {
      return res.status(500).send('Error on the server.');
    }
    if (!user) {
      return res.status(404).send('No user found.');
    }

    // Check if password is valid
    var passwordIsValid = bcrypt.compareSync(req.body.password, user.password);
    if (!passwordIsValid) {
      return res.status(401).send({auth: false, token: null});
    }

    // if user is found and password is valid
    // create token
    var token = jwt.sign({id: user._id}, config.secret, {
      expiresIn: 86400 //expires in 24 hours
    });

    MessageToken.create({email: req.body.email, token: token});

    // return the information including token as JSON
    res.status(200).send({auth: true, token: token});
  });
});


// Gets user id based on the token we got back from the register endpoint
router.get('/me', VerifyToken, function(req, res, next) {
  User.findById(req.userId, {password: 0}, function (err, user) {
    if (err) {
      return res.status(500).send("There was a problem finding the user.");
    }
    if (!user) {
      return res.status(404).send("No user found.");
    }
    res.status(200).send(user);
  });
});


router.get('/logout', function(req, res) {
  res.status(200).send({auth: false, token: null});
});


// middleware function
router.use(function (user, req, res, next) {
  res.status(200).send(user);
});


module.exports = router;
