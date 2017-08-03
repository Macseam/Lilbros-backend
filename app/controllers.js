'use strict';
let P = require('bluebird');
let _ = require('lodash');
let fs = require('fs');
let statAsync = P.promisify(fs.statSync);
let cookieParser = require('cookie-parser');
const mime = require('mime-kind');
let compression = require('compression');
const uuidV1 = require('uuid/v1');
let moment = require('moment');
let config = require('../libs/config');
let path = require('path');
let log = require('../libs/log')(module);
let express = require('express');
let cors = require('cors');
let CryptoJS = require("crypto-js");
let session = require('express-session');
let ExpressBrute = require('express-brute');
let BruteMongooseStore = require('express-brute-mongoose');
let bodyParser = require('body-parser');
let multer  = require('multer');
let helmet = require('helmet');
let upload = multer({
  storage: multer.diskStorage(
    {
      destination: function (req, file, cb) {
        cb(null, 'public/uploads')
      },
      filename: function (req, file, cb) {
        cb(null, file.fieldname + '-' + Date.now() + '.jpg')
      }
    }
  )
});
let thumb = require('node-thumbnail').thumb;
let UserModel = require('../libs/mongoose').UserModel;
let ArticleModel = require('../libs/mongoose').ArticleModel;
let BruteForceModel = require('../libs/mongoose').BruteForceModel;
let mongooseConnection = require('../libs/mongoose').db;
const MongoStore = require('connect-mongo')(session);

let BruteForceStore = new BruteMongooseStore(BruteForceModel);

let app = express();

/* =========== Выставляем начальные настройки */

let maxUsersCount = 1;

let corsOptions = {
  origin: true,
  optionsSuccessStatus: 200,
  credentials: true
};

let parseJson = bodyParser.json();
let parseUrlencoded = bodyParser.urlencoded({ extended: true });
let parseBody = [parseJson, parseUrlencoded];

let sess = {
  genid: function(req) {
    return uuidV1();
  },
  secret: 'JoelAndEllie',
  resave: true,
  saveUninitialized: true,
  store: new MongoStore({mongooseConnection})
};

moment.locale('ru');

// Функция проверки формата изображения

const checkImages = function(req, res, next, receivedFile, realMimeType, article) {

  // Создаём стрим файла
  let readStream = fs.createReadStream(receivedFile);

// Если есть ошибка - выводим её
  readStream.on('error', function(err) {
    log.error(err);
  });

// Если стрим готов для чтения, читаем его и проверяем на данные, которые могут дать информацию о формате файла
  readStream.on('readable', function() {
    let data = readStream.read();
    if (!realMimeType) {
      realMimeType = mime(data);
    }
  });

// При завершении чтения стрима при правильном mime-type создаём миниатюру и сохраняем в images
// Если mime-type не подходит, удаляем изображение
  readStream.on('end', ()=> {
    if (realMimeType) {
      log.info('mime-type файла: ' + realMimeType.mime);
    }
    if (realMimeType && (realMimeType.mime === 'image/jpeg' || realMimeType.mime === 'image/png')) {

      if (!_.isEmpty(article.images)) {
        article.images.map(function(imgObj){
          statAsync(path.join(__dirname, '../public/uploads/' + imgObj.url))
            .then(function() {
              return fs.unlink(
                path.join(__dirname, '../public/uploads/' + imgObj.url),
                log.info(imgObj.url + ' - файл удалён, заменён новым')
              );
            })
            .catch(next);
        });
        article.images = [{kind: 'cover', url: req.file.filename}];
      }

      thumb({
        source: receivedFile,
        width: 400,
        'destination': path.join(__dirname, '../public/uploads')
      })
      .then(function(files) {
        article.images.push({kind: 'thumb', url: files[0].dstPath.split('/').slice(-1).join('')});
        log.info('Миниатюра успешно создана');
        return saveArticle(req, res, next, article);
      })
      .catch(next);
    }
    else {
      fs.unlink(receivedFile, log.warn(receivedFile + ' - файл удален, формат не jpeg/png'));
      return saveArticle(req, res, next, article);
    }
    readStream.destroy();
  });
};

const saveArticle = function(req, res, next, article) {
  return article.save()
    .then(function (article) {
      log.info("Запись '" + article.title + "' успешно обновлена");
      return res.send("Запись '" + article.title + "' успешно обновлена");
    })
    .catch(next);
};

let failCallback = function (req, res, next, nextValidRequestDate) {
  res.status(403).send("Превышено допустимое количество попыток входа, следующая попытка " + moment(nextValidRequestDate).fromNow());
};

let bruteforce = new ExpressBrute(BruteForceStore, {freeRetries: 5, failCallback: failCallback});
app.use(cors(corsOptions));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(session(sess));
app.use(helmet());
app.use(compression());

let checkUser = require('./middleware');

/* =========== Роутинг */

// Завершение сессии пользователя

app.get('/logout', function (req, res) {
  let sess = req.session;
  let userId = sess.user_id;
  if (sess.user_id && res.statusCode === 200) {
    req.session.regenerate(function(err) {
      if (!err) {
        res.clearCookie('Authorization', { path: '/' });
        res.redirect('/api');
        log.info('удаление айди пользователя ' + userId + ' из сессии выполнено успешно');
      }
      else {
        res.send('сессию удалить не удалось: ' + err);
      }
    });
  }
  else if (res.statusCode === 200) {
    res.send('в сессии и так нет данных о пользователе');
  }
  else {
    res.status(403).send('доступ закрыт');
  }
});

// Проверяем, есть ли в сессии инфа о пользователе

app.get('/api', function (req, res, next) {
  let sess = req.session;
  if (sess.user_id && res.statusCode === 200) {
    UserModel.findById(sess.user_id)
      .then(function(useracc) {
        return res.send(useracc.username);
      })
      .catch(next);
  }
  else if (res.statusCode === 200) {
    res.end();
  }
  else {
    res.status(403).send('Доступ закрыт');
  }
});

// Получаем список всех пользователей

app.get('/api/getuserslist', function (req, res, next) {
  UserModel.find()
    .then(function(users) {
      return res.send(users);
    })
    .catch(next);
});

// Заводим нового пользователя (если пользователей меньше, чем maxUsersCount)

app.post('/api/setnewuser', function (req, res, next) {
  UserModel.find()
    .then(function(userAccount) {
      if (userAccount && userAccount.length < maxUsersCount) {
        let useracc = new UserModel({
          username: req.body.username || null,
          email: req.body.email || null,
          password: req.body.password || null,
        });
        return useracc.save()
          .then(function (user) {
            log.info("Пользователь " + user.username + " успешно создан");
            return res.send("Пользователь " + user.username + " успешно создан");
          })
          .catch(next);
      }
      else if (userAccount && userAccount.length >= maxUsersCount) {
        log.info('Достигнуто максимальное количество пользователей');
        return res.status(500).send('Достигнуто максимальное количество пользователей');
      }
      else {
        log.info('Что-то пошло не так');
        return res.status(500).send('Что-то пошло не так');
      }
    })
    .catch(next);
});

// Удаляем пользователя по id

app.delete('/api/deleteuser/:id', function (req, res, next) {
  return UserModel.findById(req.params.id)
    .then(function(useracc) {
      if(!useracc) {
        res.statusCode = 404;
        return res.send('Данного пользователя и так не существует');
      }
      else {
        return useracc.remove()
          .then(function(user) {
            log.info("Пользователь " + user.username + " успешно удалён");
            return res.send("Пользователь " + user.username + " успешно удалён");
          })
          .catch(next);
      }
    })
    .catch(next);
});

// Получаем с фронта логин-пароль, если совпадают с данными из базы, то создаём сессию и токен

app.post('/api/sendauthinfo', /*bruteforce.prevent,*/ parseBody, function (req, res, next) {
  let sess = req.session;
  let receivedAuthHeader = req.header('Authorization');
  if (receivedAuthHeader) {
    receivedAuthHeader = new Buffer(receivedAuthHeader, 'base64').toString('ascii').split(':');
    return UserModel.findOne({
      username: receivedAuthHeader[0]
    })
      .then(function(useracc) {
        if(!useracc) {
          log.error('В базе нет такой пары логин/пароль: ' + receivedAuthHeader[0] + ' / ' + receivedAuthHeader[1]);
          return res.status(403).send('Неверный логин/пароль');
        }
        else {
          log.info('Пользователь с именем ' + useracc.username + ' найден в базе');

          // Сравниваем хэши пароля найденного у данного пользователя в базе и введённого в форму пароля

          return useracc.comparePassword(receivedAuthHeader[1], useracc.password)
            .then(function() {
              sess.user_id = useracc._id;

              // Создаём JWT

              const jwtHeader = {
                "alg": "HS256",
                "typ": "JWT"
              };
              const jwtPayload = {
                "loggedUserId": sess.user_id,
                "iat": Date.now()
              };
              const jwtKey = 'JoelAndEllie';
              const jwtUnsigned = new Buffer(JSON.stringify(jwtHeader)).toString('base64')
                + '.' + new Buffer(JSON.stringify(jwtPayload)).toString('base64');
              const jwtSignature = CryptoJS.SHA256(jwtUnsigned, jwtKey);

              const jwtResult = new Buffer(JSON.stringify(jwtHeader)).toString('base64')
                + '.' + new Buffer(JSON.stringify(jwtPayload)).toString('base64')
                + '.' + new Buffer(JSON.stringify(jwtSignature)).toString('base64');

              res.cookie('Authorization', 'Bearer ' + jwtResult,
                {
                  httpOnly: true
                }
              );
              return res.send(useracc.username);
            })
            .catch(function() {
              return res.status(403).send('Неверный логин/пароль');
            });
        }
      })
      .catch(next);
  }
  else {
    return res.status(403).send('Неверный логин/пароль');
  }
});

// Отладочный роут для получения всех записей

app.get('/api/articles', function (req, res) {
  let sess = req.session;
  return ArticleModel.find().lean().exec(function(err, data){
    if (sess.user_id) {
      data.forEach(function(item){
        item.deleteLink = 'api/articles/' + item._id;
      });
    }
    return res.send(data);
  });
});

// Получение всех записей верхнего уровня

app.get('/api/toparticles', function (req, res, next) {
  return ArticleModel.find({"parent": null})
    .then(function (articles) {
      return res.send(articles);
    })
    .catch(next);
});

// Получение всех записей у конкретного родителя

app.get('/api/articles/:id', function (req, res, next) {
  return ArticleModel.find({"slug": req.params.id})
    .then(function (article) {
      if(!article || _.isEmpty(article)) {
        res.statusCode = 404;
        return res.send('Такие статьи не найдены');
      }
      return ArticleModel.find({"parent": article[0]['_id']})
    })
    .then(function (childArticle) {
      if(!childArticle || _.isEmpty(childArticle)) {
        return res.send([]);
      }
      return res.send(childArticle);
    })
    .catch(next);
});

// Получение одной записи по id

app.get('/api/details/:id', function (req, res, next) {
  return ArticleModel.findOne({"slug": req.params.id})
    .then(function (article) {
      if(!article || _.isEmpty(article)) {
        res.statusCode = 404;
        return res.send('Запись не найдена');
      }
      return res.send(article);
    })
    .catch(next);
});

// Отправка и сохранение в базу новой записи

app.post('/api/articles', checkUser, upload.single('cover'), function (req, res, next) {
  let receivedBody;
  if (req.body && req.body.body) {
    receivedBody = JSON.parse(req.body.body);
  }
  else {
    receivedBody = req.body;
  }
  let article = new ArticleModel({
    title: receivedBody.title || null,
    author: receivedBody.author || null,
    parent: receivedBody.parent || null,
    slug: receivedBody.slug || null,
    description: receivedBody.description || null,
    images: []
  });
  if (req.file) {
    let realMimeType = null;
    article.images = [{kind: 'cover', url: req.file.filename}];
    let receivedFile = path.join(__dirname, '../public/uploads/' + req.file.filename);
    checkImages(req, res, next, receivedFile, realMimeType, article);
  }
  else {
    saveArticle(req, res, next, article);
  }
});

// Редактирование и сохранение в базу записи

app.put('/api/articles/:id', checkUser, upload.single('cover'), function (req, res, next) {
  let receivedBody;
  if (req.body && req.body.body) {
    receivedBody = JSON.parse(req.body.body);
  }
  else {
    receivedBody = req.body;
  }
  return ArticleModel.findById(req.params.id)
    .then(function (article) {
      if(!article) {
        res.statusCode = 404;
        return res.send('Запись не найдена');
      }
      article.title = receivedBody.title || article.title;
      article.description = receivedBody.description || article.description;
      article.author = receivedBody.author || article.author;
      article.parent = receivedBody.parent || article.parent;
      article.slug = receivedBody.slug || article.slug;

      if (req.file) {
        let realMimeType = null;
        let receivedFile = path.join(__dirname, '../public/uploads/' + req.file.filename);
        return checkImages(req, res, next, receivedFile, realMimeType, article);
      }

      // Если при сохранении не приходит изображение, значит, пользователь его удалил и надо удалять из папки
      else if (req.body.cover === 'null' && !_.isEmpty(article.images)) {
        article.images.map(function(imgObj){
          statAsync(path.join(__dirname, '../public/uploads/' + imgObj.url))
            .then(function() {
              fs.unlink(
                path.join(__dirname, '../public/uploads/' + imgObj.url),
                log.info(imgObj.url + ' - файл удалён пользователем через интерфейс')
              );
            })
            .catch(next);
        });
        article.images = [];
        return saveArticle(req, res, next, article);
      }
      else {
        return saveArticle(req, res, next, article);
      }

    })
    .catch(next);
});

app.delete('/api/articles/:id', checkUser, function (req, res, next) {
  if (req.params.id) {
    return ArticleModel.findByIdAndRemove(req.params.id)
      .then(function(article) {
        article.images.map(function(imgObj){
          fs.unlink(
            path.join(__dirname, '../public/uploads/' + imgObj.url),
            log.info(imgObj.url + ' - файл удалён, потому что удалена родительская запись')
          );
        });
        log.info("Запись '" + article.title + "' успешно удалена");
        return res.send("Запись '" + article.title + "' успешно удалена");
      })
      .catch(next);
  } else {
    res.statusCode = 500;
    log.error('Internal error(%d): %s',res.statusCode,'no id supplied');
    return res.send('Неверно составленный запрос');
  }
});

// Отладочный роут для тестирования ошибок

app.get('/ErrorExample', function (req, res, next) {
  next(new Error('Random error!'));
});

// Обработка статики (кэширование)

app.get('/*', function (req, res, next) {
  if (req.url.indexOf("/uploads/") !== -1) {
    res.setHeader("Cache-Control", "public, max-age=2592000");
    res.setHeader("Expires", new Date(Date.now() + 2592000000).toUTCString());
  }
  next();
});

app.use(express.static(path.join(__dirname, '../public')));

/* =========== Обработка ошибок */

app.use(function (err, req, res) {
  console.log(err);
  res.status(404);
  log.debug('Not found URL: %s', req.url);
  res.send('Путь не найден');
});

app.use(function (err, req, res) {
  res.status(err.status || 500);
  log.error('Internal error(%d): %s', res.statusCode, err.message);
  res.send(err.message);
});

module.exports = app;