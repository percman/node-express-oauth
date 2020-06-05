const express = require("express");
const bodyParser = require("body-parser");
const fs = require("fs");
const { timeout } = require("./utils");
const jwt = require("jsonwebtoken");

const config = {
  port: 9002,
  publicKey: fs.readFileSync("assets/public_key.pem"),
};

const users = {
  user1: {
    username: "user1",
    name: "User 1",
    date_of_birth: "7th October 1990",
    weight: 57,
  },
  john: {
    username: "john",
    name: "John Appleseed",
    date_of_birth: "12th September 1998",
    weight: 87,
  },
};

const app = express();
app.use(timeout);
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.get("/user-info", (req, res) => {
  if (req.headers.authorization) {
    let payload = req.headers.authorization.slice(7);
    let token;
    jwt.verify(
      payload,
      config.publicKey,
      {
        algorithms: ["RS256"],
      },
      (err, decoded) => {
        if (err) {
          res.status(401).send();
          return;
        }
        token = decoded;
      }
    );

    if (token) {
      let scopes = token.scope.split(" ");

      let permissions = [];
      scopes.forEach((scope) => {
        permissions.push(scope.slice(11));
      });

      console.log(permissions);
      let response = {};

      permissions.forEach((permission) => {
        response[permission] = users[token.userName][permission];
      });

      res.json(response);
    }
  } else {
    res.status(401).send();
  }
});

const server = app.listen(config.port, "localhost", function () {
  var host = server.address().address;
  var port = server.address().port;
});

// for testing purposes
module.exports = {
  app,
  server,
};
