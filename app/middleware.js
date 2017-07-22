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
    UserModel.findById(sess.user_id).exec()
      .then(function(useracc){
        log.info('есть совпадение айдишника с данными в базе');

        // Проверяем user id в сессии и JWT в куки
        let secretCookie = req.cookies['Authorization'];
        if (useracc && secretCookie) {
          const jwtKey = 'JoelAndEllie';
          let receivedToken = secretCookie.split(' ');
          const decodedJwt = receivedToken[1].split('.');
          const jwtSignature = CryptoJS.SHA256(decodedJwt[0] + '.' + decodedJwt[1], jwtKey);
          let isValid = false;
          decodedJwt.map(function(decItem, index) {
            if (new Buffer(decItem, 'base64').toString('ascii') === JSON.stringify(jwtSignature)) {
              isValid = true;
            }
          });
          if (isValid) {
            log.info('проверка токена успешно пройдена');
            res.status(200);
            //return next();
            return new Promise(function (resolve) {
              resolve(next());
            });
          }
          else {
            log.warn('неверный токен');
            return res.status(403).send('доступ закрыт');
          }
        } else {
          log.warn('пользователь не найден');
          return res.status(403).send('доступ закрыт');
        }
      })
      .catch(next);
  } else {
    log.warn('В сессии не найдено информации о пользователе');
    return res.status(403).send('доступ закрыт');
  }
}

module.exports = checkUser;
