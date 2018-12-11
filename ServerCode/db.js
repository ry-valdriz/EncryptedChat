const mongoose = require('mongoose');

const dbURI = "mongodb://duodolo:3bPNBm_E5rnPJG@cluster0-shard-00-00-4xwi0.mongodb.net:27017,cluster0-shard-00-01-4xwi0.mongodb.net:27017,cluster0-shard-00-02-4xwi0.mongodb.net:27017/test?ssl=true&replicaSet=Cluster0-shard-0&authSource=admin&retryWrites=true";
const options = {
  useNewUrlParser: true,
  reconnectTries: Number.MAX_VALUE,
  poolSize: 10
};

mongoose.connect(dbURI, options).then(
  function res() {
    console.log("Database connection established!");
  },
  function err() {
    console.log("Error connecting Database instance.");
  }
);
