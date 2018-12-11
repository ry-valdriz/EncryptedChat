var app = require('./app');
const bodyParser = require("body-parser");

var port = process.env.PORT || 3000;
app.use(bodyParser.urlencoded({extended: true}));
app.use(bodyParser.json());

var server = app.listen(port, function() {
  console.log('Express server listening on port ' + port);
});
