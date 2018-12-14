var express = require('express');
var router = express.Router();
var bodyParser = require('body-parser');
var jwt = require('jsonwebtoken');
var bcrypt = require('bcryptjs');
var config = require('../config');
var VerifyToken = require('../auth/VerifyToken');

router.use(bodyParser.urlencoded({ extended: false }));
router.use(bodyParser.json());
var User = require('../user/User');
var Message = require('./Message');
var MessageToken = require('../auth/MessageToken');


// create a message
// VerifyToken is used to verify whether you are able to send a message or not
router.post('/send', VerifyToken, function(req, res, next) {
  MessageToken.findOne({token: req.headers['x-access-token']}, (err, user) => {
    Message.create({
      sender: user.email,
      recipient: req.body.recipient,
      AES: req.body.AES,
      RSA: req.body.RSA,
      Tag: req.body.Tag
    },
    function(err) {
      if (err) {
        res.status(500).send("Error sending the message.");
      }
    });
    res.status(200).send(req.body.content);
  });
});


// Get a message
router.get('/receive', VerifyToken, function(req, res) {
  MessageToken.findOne({token: req.headers['x-access-token']}, (err, user) => {
    if (err) {
      res.status(500).send("There was a problem finding the token.");
    }
    Message.find({recipient: user.email}, (err, message) => {
      if (err) {
        res.status(500).send("There was a problem finding the message.");
      }
      res.status(200).send(message);
    });
    Message.find({recipient: user.email}).remove().exec();
  });
});


module.exports = router;
