var mongoose = require('mongoose');

var MessageTokenSchema = new mongoose.Schema({
  email: String,
  token: String
});

mongoose.model('MessageToken', MessageTokenSchema);

module.exports = mongoose.model('MessageToken');
