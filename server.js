/* =========== Importing modules */

let config = require('./libs/config');
let path = require('path');
let log = require('./libs/log')(module);
let express = require('express');
let cors = require('cors');
let bcrypt = require('bcrypt');
let SALT_WORK_FACTOR = 10;
let session = require('express-session');
let bodyParser = require('body-parser');
let UserModel = require('./libs/mongoose').UserModel;
let ArticleModel = require('./libs/mongoose').ArticleModel;
let mongooseConnection = require('./libs/mongoose').db;
const MongoStore = require('connect-mongo')(session);

let app = express();

/* =========== Setting up middleware options */

let corsOptions = {
  origin: 'http://localhost:8090',
  //methods: ['OPTIONS','HEAD','GET','POST'],
  optionsSuccessStatus: 200,
  credentials: true
};

let parseJson = bodyParser.json();
let parseUrlencoded = bodyParser.urlencoded({ extended: true });
let parseBody = [parseJson, parseUrlencoded];

let sess = {
  secret: 'keyboard cat',
  resave: false,
  saveUninitialized: true,
  store: new MongoStore({mongooseConnection})
};

/* =========== Including middleware */

app.use(cors(corsOptions));

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use(session(sess));

let router = express.Router();
app.use(router);

app.use(express.static(path.join(__dirname, 'public')));

function checkUser(req, res, next) {
  if (req.session.user_id) {
    UserModel.findById(req.session.user_id, function(err, useracc) {
      if (useracc) {
        console.log(useracc.username + ' is logged in');
        console.log(req.session);
        req.currentUser = useracc;
        next();
      } else {
        console.log('no matched user');
        res.send('redirect to login');
      }
    });
  } else {
    console.log('no user_id');
    res.send('redirect to login');
  }
}

/* =========== Setting up routing */

router.get('/api', checkUser, function (req, res) {
  let sess = req.session;
  let saltValue = bcrypt.genSaltSync(SALT_WORK_FACTOR);
  let tokenValue = bcrypt.hashSync((saltValue + ":" + req.session.secretkey), saltValue);
  console.log('salt generated: ' + saltValue);
  console.log('token saved: ' + tokenValue);
  sess.token = tokenValue;
  res.cookie('CSRF-TOKEN',tokenValue, { httpOnly: true });
  res.send('API is running');
});

router.get('/apitherapy', checkUser, function (req, res) {
  let sess = req.session;
  let saltValue = sess.token.substr(0,29);
  console.log('salt calculated: ' + saltValue);
  let tokenValue = bcrypt.hashSync((saltValue + ":" + sess.secretkey), saltValue);
  console.log('token generated: ' + tokenValue);
  console.log('hashes match: ' + (sess.token === tokenValue));
  res.send('APITherapy is running');
});

router.get('/api/getuserslist', function (req, res) {
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

router.post('/api/setnewuser', function (req, res) {
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
          console.log(err);
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
      console.log(err);
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

router.delete('/api/deleteuser/:id', function (req, res) {
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

router.post('/api/sendauthinfo', parseBody, function (req, res) {
  let sess = req.session;
  return UserModel.findOne({ username: req.body.username }, function (err, useracc) {
    if(!useracc) {
      res.statusCode = 404;
      return res.send({ error: 'User not found' });
    }
    useracc.comparePassword(req.body.password, function(err, isMatch) {
      if (err) throw err;
      if (isMatch) {
        sess.user_id = useracc._id;

        // TODO: Разобраться, как пихать соль в сессию асинхронно

        if (!sess.secretkey) {
          sess.secretkey = bcrypt.genSaltSync(SALT_WORK_FACTOR);
        }

        return res.send('session created');
      }
      else {
        return res.send('password doesnt match');
      }
    });
  });
});

router.get('/api/articles', function (req, res) {
  return ArticleModel.find(function (err, articles) {
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

router.post('/api/articles', function (req, res) {
  let article = new ArticleModel({
    title: req.body.title || null,
    author: req.body.author || null,
    parent: req.body.parent || null,
    slug: req.body.slug || null,
    description: req.body.description || null,
    images: req.body.images || []
  });
  article.save(function (err) {
    if (!err) {
      log.info('article created');
      return res.send({status: 'OK', article: article});
    }
    else {
      console.log(err);
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

router.get('/sesstest', function (req, res) {
  let resSess = req.session;
  if (resSess.views) {
    resSess.views++;
    res.send('views: ' + resSess.views + ', ' + 'expires in: ' + (resSess.cookie.maxAge / 1000) + 's');
  } else {
    resSess.views = 1;
    res.send('welcome to the session demo. refresh!');
  }
});

router.get('/api/articles/:id', function (req, res) {
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

router.get('/api/details/:id', function (req, res) {
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

router.put('/api/articles/:id', function (req, res) {
  return ArticleModel.findById(req.params.id, function (err, article) {
    if(!article) {
      res.statusCode = 404;
      return res.send({ error: 'Not found' });
    }

    article.title = req.body.title;
    article.description = req.body.description;
    article.author = req.body.author;
    article.parent = req.body.parent;
    article.slug = req.body.slug;
    article.images = req.body.images;
    return article.save(function (err) {
      if (!err) {
        log.info("article updated");
        return res.send({ status: 'OK', article:article });
      } else {
        if(err.name === 'ValidationError') {
          res.statusCode = 400;
          res.send({ error: 'Validation error' });
        } else {
          res.statusCode = 500;
          res.send({ error: 'Server error' });
        }
        log.error('Internal error(%d): %s',res.statusCode,err.message);
      }
    });
  });
});

router.delete('/api/articles/:id', function (req, res) {
  return ArticleModel.findById(req.params.id, function (err, article) {
    if(!article) {
      res.statusCode = 404;
      return res.send({ error: 'Not found' });
    }
    return article.remove(function (err) {
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

router.get('/ErrorExample', function (req, res, next) {
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

/* =========== Listening for incoming connections */

app.listen(config.get('port'), function () {
  log.info('Express server listening on port ' + config.get('port'));
});
