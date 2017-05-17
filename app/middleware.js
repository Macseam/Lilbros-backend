let fs = require('fs');
const mime = require('mime-kind');

const uuidV1 = require('uuid/v1');
let config = require('../libs/config');
let path = require('path');
let log = require('../libs/log')(module);
let express = require('express');

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
      if (useracc && sess.token && req.headers['x-csrf-token'] && (sess.token === req.headers['x-csrf-token'])) {
        res.status(200);
        next();
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
