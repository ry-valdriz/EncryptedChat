var mongoose = require('mongoose');


var MessageSchema = new mongoose.Schema({
  sender: String, //email
  recipient: String, //email or username
  //content: String
  AES: String,
  RSA: String,
  Tag: String
});

mongoose.model('Message', MessageSchema);

module.exports = mongoose.model('Message');
