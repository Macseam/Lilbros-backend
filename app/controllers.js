let _ = require('lodash');
let fs = require('fs');
const mime = require('mime-kind');

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
  ),
  fileFilter: (req, file, cb)=>{
    cb(null, file.mimetype.indexOf('image/') !== -1);
    if (file.mimetype.indexOf('image/') === -1) {
      cb(new Error('Attempt to upload non-image file'));
    }
  }
});
let thumb = require('node-thumbnail').thumb;
let UserModel = require('../libs/mongoose').UserModel;
let ArticleModel = require('../libs/mongoose').ArticleModel;
let BruteForceModel = require('../libs/mongoose').BruteForceModel;
let mongooseConnection = require('../libs/mongoose').db;
const MongoStore = require('connect-mongo')(session);

let BruteForceStore = new BruteMongooseStore(BruteForceModel);

let app = express();

/* =========== Setting up middleware options */

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

let failCallback = function (req, res, next, nextValidRequestDate) {
  res.status(403).send({error: "Превышено допустимое количество попыток входа, следующая попытка "+ moment(nextValidRequestDate).fromNow()});
};

let bruteforce = new ExpressBrute(BruteForceStore, {freeRetries: 5, failCallback: failCallback});
app.use(cors(corsOptions));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(session(sess));
app.use(express.static(path.join(__dirname, '../public')));
app.use(helmet());

let checkUser = require('./middleware');

/* =========== Setting up routing */

app.get('/logout', function (req, res) {
  let sess = req.session;
  if (sess.user_id && res.statusCode === 200) {
    req.session.regenerate(function(err) {
      if (!err) {
        res.redirect('/api');
      }
      else {
        res.send('unable to destroy session: ' + err);
      }
    });
  }
  else if (res.statusCode === 200) {
    res.send('no logged user to log out');
  }
  else {
    res.status(403).send('access denied');
  }
});

app.get('/api', function (req, res) {
  let sess = req.session;
  if (sess.user_id && res.statusCode === 200) {
    UserModel.findById(sess.user_id, function(err, useracc) {
      if (!err) {
        res.send(useracc.username);
      }
      else {
        res.status(403).send('access denied');
      }
    });
  }
  else if (res.statusCode === 200) {
    res.end();
  }
  else {
    res.status(403).send('access denied');
  }
});

app.get('/api/getuserslist', function (req, res) {
  return UserModel.find(function (err, users) {
    if (!err) {
      return res.send(users);
    }
    else {
      res.statusCode = 500;
      log.error('Internal error(%d): %s', res.statusCode, err.message);
      return res.send({error: 'Server error'});
    }
  });
});

app.post('/api/setnewuser', bruteforce.prevent, function (req, res) {
  return UserModel.find(function (err, userAccount) {
    if (!err && userAccount && userAccount.length === 0) {
      let useracc = new UserModel({
        username: req.body.username || null,
        email: req.body.email || null,
        password: req.body.password || null,
      });
      useracc.save(function (err) {
        if (!err) {
          log.info('user created');
          return res.send({status: 'OK', useracc: useracc});
        }
        else {
          log.error(err);
          if (err.name === 'ValidationError') {
            res.statusCode = 400;
            res.send({error: 'Validation error'});
          }
          else {
            res.statusCode = 500;
            res.send({error: 'Server error'});
          }
          log.error('Internal error(%d): %s', res.statusCode, err.message);
        }
      });
    }
    else if (!err && userAccount && userAccount.length > 0) {
      res.statusCode = 500;
      res.send({error: 'Server error'});
    }
    else {
      log.error(err);
      if (err.name === 'ValidationError') {
        res.statusCode = 400;
        res.send({error: 'Validation error'});
      }
      else {
        res.statusCode = 500;
        res.send({error: 'Server error'});
      }
      log.error('Internal error(%d): %s', res.statusCode, err.message);
    }
  });
});

app.delete('/api/deleteuser/:id', bruteforce.prevent, checkUser, function (req, res) {
  return UserModel.findById(req.params.id, function (err, useracc) {
    if(!useracc) {
      res.statusCode = 404;
      return res.send({ error: 'Not found' });
    }
    return useracc.remove(function (err) {
      if (!err) {
        log.info("article removed");
        return res.send({ status: 'OK' });
      } else {
        res.statusCode = 500;
        log.error('Internal error(%d): %s',res.statusCode,err.message);
        return res.send({ error: 'Server error' });
      }
    });
  });
});

app.post('/api/sendauthinfo', bruteforce.prevent, parseBody, function (req, res) {
  let sess = req.session;
  return UserModel.findOne({ username: req.body.username }, function (err, useracc) {
    if(!useracc) {
      log.error('access denied, wrong login/password! ' + req.body.username + ' : ' + req.body.password);
      res.statusCode = 403;
      return res.send({ error: 'Неверный логин/пароль' });
    }
    else {
      log.info('user named ' + useracc.username + ' is found');
      useracc.comparePassword(req.body.password, function(err, isMatch) {
        if (err) throw err;
        if (isMatch) {
          sess.user_id = useracc._id;

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

          res.cookie('auth',jwtResult);

          return res.send(useracc.username);
        }
        else {
          log.error('access denied, wrong login/password! ' + req.body.username + ' : ' + req.body.password);
          res.status(403).send('access denied, wrong login/password');
        }
      });
    }
  });
});

app.get('/api/articles', function (req, res) {
  let sess = req.session;
  return ArticleModel.find(function (err, articles) {
    if (!err) {
      //return res.send(articles);
    }
    else {
      res.statusCode = 500;
      log.error('Internal error(%d): %s', res.statusCode, err.message);
      return res.send({error: 'Server error'});
    }
  }).lean().exec(function(err, data){
    if (sess.user_id) {
      data.forEach(function(item){
        item.deleteLink = 'api/articles/' + item._id;
      });
    }
    return res.send(data);
  });
});

app.get('/api/toparticles', function (req, res) {
  return ArticleModel.find({"parent": null},function (err, articles) {
    if (!err) {
      return res.send(articles);
    }
    else {
      res.statusCode = 500;
      log.error('Internal error(%d): %s', res.statusCode, err.message);
      return res.send({error: 'Server error'});
    }
  });
});

app.get('/sesstest', function (req, res) {
  let resSess = req.session;
  if (resSess.views) {
    resSess.views++;
    res.send('views: ' + resSess.views + ', ' + 'expires in: ' + (resSess.cookie.maxAge / 1000) + 's');
  } else {
    resSess.views = 1;
    res.send('welcome to the session demo. refresh!');
  }
});

app.get('/api/articles/:id', function (req, res) {
  return ArticleModel.find({"slug": req.params.id}, function (err, article) {
    if(!article) {
      res.statusCode = 404;
      return res.send({ error: 'Not found' });
    }
    if (!err) {
      return ArticleModel.find({"parent": article[0]['_id']}, function (childErr, childArticle) {
        if(!childArticle) {
          res.statusCode = 404;
          return res.send({ error: 'Not found' });
        }
        if (!childErr) {
          return res.send(childArticle);
        }
        else {
          res.statusCode = 500;
          log.error('Internal error(%d): %s',res.statusCode,childErr.message);
          return res.send({ error: 'Server error' });
        }
      })
    } else {
      res.statusCode = 500;
      log.error('Internal error(%d): %s',res.statusCode,err.message);
      return res.send({ error: 'Server error' });
    }
  });
});

app.get('/api/details/:id', function (req, res) {
  return ArticleModel.findOne({"slug": req.params.id}, function (err, article) {
    if(!article) {
      res.statusCode = 404;
      return res.send({ error: 'Not found' });
    }
    if (!err) {
      return res.send(article);
    } else {
      res.statusCode = 500;
      log.error('Internal error(%d): %s',res.statusCode,err.message);
      return res.send({ error: 'Server error' });
    }
  });
});

app.post('/api/articles', checkUser, upload.single('cover'), function (req, res) {
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

    // Create stream from image file
    let readStream = fs.createReadStream(receivedFile);

    // On stream error - output error message
    readStream.on('error', function(err) {
      log.error(err);
    });

    // If stream is readable, read it and try to get mime type
    readStream.on('readable', function() {
      let data = readStream.read();
      if (!realMimeType) {
        realMimeType = mime(data);
      }
    });

    // On stream end - if mime is right, create thumbnail and save article images
    // if mime is wrong, delete image and do not save
    readStream.on('end', ()=> {
      if (realMimeType) {
        log.info('final mime: ' + realMimeType.mime);
      }
      if (realMimeType && (realMimeType.mime === 'image/jpeg' || realMimeType.mime === 'image/png')) {
        thumb({
          source: receivedFile,
          width: 400,
          'destination': path.join(__dirname, '../public/uploads')
        }).then(function(files) {
          article.images.push({kind: 'thumb', url: files[0].dstPath.split('/').slice(-1).join('')});
          article.save(function (err) {
            if (!err) {
              log.info('article created');
              return res.send({status: 'OK', article: article});
            }
            else {
              log.error(err);
              if (err.name === 'ValidationError') {
                res.statusCode = 400;
                res.send({error: 'Validation error'});
              }
              else {
                res.statusCode = 500;
                res.send({error: 'Server error'});
              }
              log.error('Internal error(%d): %s', res.statusCode, err.message);
            }
          });
          log.info('Successfully thumbnailed');
        }).catch(function(e) {
          log.error('Error while thumbnailing', e.toString());
        });
      }
      else {
        fs.unlink(receivedFile, log.warn(receivedFile + ' deleted because it was not a jpeg/png image'));
      }
      readStream.destroy();
    });
  }
  else {
    article.save(function (err) {
      if (!err) {
        log.info('article created');
        return res.send({status: 'OK', article: article});
      }
      else {
        log.error(err);
        if (err.name === 'ValidationError') {
          res.statusCode = 400;
          res.send({error: 'Validation error'});
        }
        else {
          res.statusCode = 500;
          res.send({error: 'Server error'});
        }
        log.error('Internal error(%d): %s', res.statusCode, err.message);
      }
    });
  }
});

app.put('/api/articles/:id', checkUser, upload.single('cover'), function (req, res) {
  let receivedBody;
  if (req.body && req.body.body) {
    receivedBody = JSON.parse(req.body.body);
  }
  else {
    receivedBody = req.body;
  }
  return ArticleModel.findById(req.params.id, function (err, article) {
    if(!article) {
      res.statusCode = 404;
      return res.send({ error: 'Not found' });
    }
    article.title = receivedBody.title || article.title;
    article.description = receivedBody.description || article.description;
    article.author = receivedBody.author || article.author;
    article.parent = receivedBody.parent || article.parent;
    article.slug = receivedBody.slug || article.slug;

    if (req.file) {

      // Save article with new image
      let realMimeType = null;

      let receivedFile = path.join(__dirname, '../public/uploads/' + req.file.filename);

      // Create stream from image file
      let readStream = fs.createReadStream(receivedFile);

      // On stream error - output error message
      readStream.on('error', function(err) {
        log.error(err);
      });

      // If stream is readable, read it and try to get mime type
      readStream.on('readable', function() {
        let data = readStream.read();
        if (!realMimeType) {
          realMimeType = mime(data);
        }
      });

      // On stream end - if mime is right, create thumbnail and save article images
      // if mime is wrong, delete image and do not save
      readStream.on('end', ()=> {
        if (realMimeType) {
          log.info('final mime: ' + realMimeType.mime);
        }
        if (realMimeType && (realMimeType.mime === 'image/jpeg' || realMimeType.mime === 'image/png')) {

          // If cover image exists, delete it
          if (!_.isEmpty(article.images)) {
            article.images.map(function(imgObj){
              fs.stat(path.join(__dirname, '../public/uploads/' + imgObj.url), function (err, stats) {
                if (err) {
                  return console.error(err);
                }
                fs.unlink(path.join(__dirname, '../public/uploads/' + imgObj.url), log.info(imgObj.url + ' deleted because of overwriting'));
              });
            });
          }

          article.images = [{kind: 'cover', url: req.file.filename}];

          thumb({
            source: receivedFile,
            width: 400,
            'destination': path.join(__dirname, '../public/uploads')
          }).then(function(files) {
            article.images.push({kind: 'thumb', url: files[0].dstPath.split('/').slice(-1).join('')});
            article.save(function (err) {
              if (!err) {
                log.info('article saved');
                return res.send({status: 'OK', article: article});
              }
              else {
                log.error(err);
                if (err.name === 'ValidationError') {
                  res.statusCode = 400;
                  res.send({error: 'Validation error'});
                }
                else {
                  res.statusCode = 500;
                  res.send({error: 'Server error'});
                }
                log.error('Internal error(%d): %s', res.statusCode, err.message);
              }
            });
            log.info('Successfully thumbnailed');
          }).catch(function(e) {
            log.error('Error while thumbnailing', e.toString());
          });
        }
        else {
          fs.unlink(receivedFile, log.warn(receivedFile + ' deleted because it was not a jpeg/png image'));
        }
        readStream.destroy();
      });
    }

    // If there is no new image, delete existing image
    else if (req.body.cover === 'null' && !_.isEmpty(article.images)) {
      article.images.map(function(imgObj){
        fs.stat(path.join(__dirname, '../public/uploads/' + imgObj.url), function (err, stats) {
          if (err) {
            return console.error(err);
          }
          fs.unlink(path.join(__dirname, '../public/uploads/' + imgObj.url), log.info(imgObj.url + ' deleted because an image deleted from ui'));
        });
      });
      article.images = [];
      article.save(function (err) {
        if (!err) {
          log.info('article saved');
          return res.send({status: 'OK', article: article});
        }
        else {
          log.error(err);
          if (err.name === 'ValidationError') {
            res.statusCode = 400;
            res.send({error: 'Validation error'});
          }
          else {
            res.statusCode = 500;
            res.send({error: 'Server error'});
          }
          log.error('Internal error(%d): %s', res.statusCode, err.message);
        }
      });
    }

  });
});

app.delete('/api/articles/:id', checkUser, function (req, res) {
  if (req.params.id) {
    return ArticleModel.findById(req.params.id, function (err, article) {
      if(!article) {
        res.statusCode = 404;
        return res.send({ error: 'Not found' });
      }
      return article.remove(function (err) {
        article.images.map(function(imgObj){
          fs.unlink(path.join(__dirname, '../public/uploads/' + imgObj.url), log.info(imgObj.url + ' deleted with its parent article'));
        });
        if (!err) {
          log.info("article removed");
          return res.send({ status: 'OK' });
        } else {
          res.statusCode = 500;
          log.error('Internal error(%d): %s',res.statusCode,err.message);
          return res.send({ error: 'Server error' });
        }
      });
    });
  } else {
    res.statusCode = 500;
    log.error('Internal error(%d): %s',res.statusCode,'no id supplied');
    return res.send({ error: 'Server error' });
  }
});

app.get('/ErrorExample', function (req, res, next) {
  next(new Error('Random error!'));
});

/* =========== Error handling */

app.use(function (req, res, next) {
  res.status(404);
  log.debug('Not found URL: %s', req.url);
  res.send({error: 'Not found'});
});

app.use(function (err, req, res, next) {
  if (err.code !== 'EBADCSRFTOKEN') {
    return next(err);
  }
  log.error('Form tampered with(%d): %s', res.statusCode, err.message);
  res.status(403);
  res.send('form tampered with');
});

app.use(function (err, req, res, next) {
  res.status(err.status || 500);
  log.error('Internal error(%d): %s', res.statusCode, err.message);
  res.send({error: err.message});
});

module.exports = app;