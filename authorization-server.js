const fs = require("fs");
const express = require("express");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const { URL } = require("url");
const {
  randomString,
  containsAll,
  decodeAuthCredentials,
  timeout,
} = require("./utils");

const config = {
  port: 9001,
  privateKey: fs.readFileSync("assets/private_key.pem"),

  clientId: "my-client",
  clientSecret: "zETqHgl0d7ThysUqPnaFuLOmG1E=",
  redirectUri: "http://localhost:9000/callback",

  authorizationEndpoint: "http://localhost:9001/authorize",
};

const clients = {
  "my-client": {
    name: "Sample Client",
    clientSecret: "zETqHgl0d7ThysUqPnaFuLOmG1E=",
    scopes: ["permission:name", "permission:date_of_birth"],
  },
  "test-client": {
    name: "Test Client",
    clientSecret: "TestSecret",
    scopes: ["permission:name"],
  },
};

const users = {
  user1: "password1",
  john: "appleseed",
};

const requests = {};
const authorizationCodes = {};

let state = "";

const app = express();
app.set("view engine", "ejs");
app.set("views", "assets/authorization-server");
app.use(timeout);
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.get("/authorize", (req, res) => {
  let clientId = req.query.client_id;
  if (clients[clientId]) {
    let allowedScopes = clients[clientId].scopes;
    let requestedScopes = req.query.scope.split(" ");

    if (containsAll(allowedScopes, requestedScopes)) {
      let rndmString = randomString();
      requests[rndmString] = req.query;
      res.render("login", {
        client: clients[clientId],
        scope: req.query.scope,
        requestId: rndmString,
      });
    } else {
      res.status(401).send();
    }
  } else {
    res.status(401).send();
  }
});

app.post("/approve", (req, res) => {
  if (users[req.body.userName] === req.body.password) {
    if (requests[req.body.requestId]) {
      let request = requests[req.body.requestId];
      delete requests[req.body.requestId];

      let rndmString = randomString();
      authorizationCodes[rndmString] = {
        clientReq: request,
        userName: req.body.userName,
      };

      let redirectUri = new URL(request.redirect_uri);
      redirectUri.searchParams.set("code", rndmString);
      redirectUri.searchParams.set("state", request.state);

      res.redirect(redirectUri);
    } else {
      res.status(401).send();
    }
  } else {
    res.status(401).send();
  }
});

app.post("/token", (req, res) => {
  if (req.headers.authorization) {
    let creds = decodeAuthCredentials(req.headers.authorization);
    if (clients[creds.clientId].clientSecret === creds.clientSecret) {
      if (authorizationCodes[req.body.code]) {
        let auth = authorizationCodes[req.body.code];
        delete authorizationCodes[req.body.code];

        let payload = {
          userName: auth.userName,
          scope: auth.clientReq.scope,
        };

        var token = jwt.sign(payload, config.privateKey, {
          algorithm: "RS256",
        });

        res.json({
          access_token: token,
          token_type: "Bearer",
        });
      } else {
        res.status(401).send();
      }
    } else {
      res.status(401).send();
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

module.exports = { app, requests, authorizationCodes, server };
