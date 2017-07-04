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

/* =========== Настраиваем middleware */

let sess = {
  genid: function(req) {
    return uuidV1();
  },
  secret: 'keyboard cat',
  resave: true,
  saveUninitialized: true,
  store: new MongoStore({mongooseConnection})
};

/* =========== Применяем middleware */

app.use(session(sess));

function checkUser(req, res, next) {
  let sess = req.session;
  if (sess.user_id) {
    log.info('ищем айдишник пользователя ' + sess.user_id);
    UserModel.findById(sess.user_id)
      .then(function(useracc){
        log.info('есть совпадение айдишника с данными в базе');

        // Проверяем user id в сессии и JWT в шапке запроса
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
            log.info('токен ок');
            res.status(200);
            next();
          }
          else {
            log.warn('неверный токен');
            res.status(403).send('доступ закрыт');
          }
        } else {
          log.warn('пользователь не найден');
          res.status(403).send('доступ закрыт');
        }
      })
      .catch(next);
  } else {
    log.warn('В сессии не найдено информации о пользователе');
    res.status(200);
    next();
  }
}

module.exports = checkUser;
