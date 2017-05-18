let fs = require('fs');
const mime = require('mime-kind');

const uuidV1 = require('uuid/v1');
let config = require('../libs/config');
let path = require('path');
let log = require('../libs/log')(module);
let express = require('express');
let CryptoJS = require("crypto-js");
let session = require('express-session');
let UserModel = require('../libs/mongoose').UserModel;
let mongooseConnection = require('../libs/mongoose').db;
const MongoStore = require('connect-mongo')(session);

let app = express();

/* =========== Setting up middleware options */

let sess = {
  genid: function(req) {
    return uuidV1();
  },
  secret: 'keyboard cat',
  resave: true,
  saveUninitialized: true,
  store: new MongoStore({mongooseConnection})
};

/* =========== Including middleware */

app.use(session(sess));

function checkUser(req, res, next) {
  let sess = req.session;
  if (sess.user_id) {
    log.info('searching for session id ' + sess.user_id);
    UserModel.findById(sess.user_id, function(err, useracc) {
      /* Checking user id in session */
      if (useracc && req.headers['authorization']) {
        const jwtKey = 'JoelAndEllie';
        let receivedToken = req.headers['authorization'].split(' ');
        const decodedJwt = receivedToken[1].split('.');
        const jwtSignature = CryptoJS.SHA256(decodedJwt[0] + '.' + decodedJwt[1], jwtKey);
        let isValid = false;
        decodedJwt.map(function(decItem, index) {
          if (new Buffer(decItem, 'base64').toString('ascii') === JSON.stringify(jwtSignature)) {
            isValid = true;
          }
        });
        if (isValid) {
          res.status(200);
          next();
        }
        else {
          log.warn('invalid token');
          res.status(403).send('access denied');
        }
      } else {
        log.warn('no matched user');
        res.status(403).send('access denied');
      }
    });
  } else {
    log.warn('no user_id available in session');
    res.status(200);
    next();
  }
}

module.exports = checkUser;
