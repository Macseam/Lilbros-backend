/* =========== Importing modules */

let config = require('./libs/config');
let path = require('path');
let log = require('./libs/log')(module);
let express = require('express');
let cors = require('cors');
let session = require('express-session');
let bodyParser = require('body-parser');
let csrf = require('csurf');
let UserModel = require('./libs/mongoose').UserModel;
let ArticleModel = require('./libs/mongoose').ArticleModel;
let mongooseConnection = require('./libs/mongoose').db;
const MongoStore = require('connect-mongo')(session);

let app = express();
app.set('view engine', 'ejs');

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

let csrfProtection = csrf({ cookie: false });

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
app.use(csrfProtection);

let router = express.Router();
app.use(router);

//app.use(express.static(path.join(__dirname, 'public')));

function checkUser(req, res, next) {
  if (req.session.user_id) {
    User.findById(req.session.user_id, function(user) {
      if (user) {
        req.currentUser = user;
        next();
      } else {
        res.redirect('/login');
      }
    });
  } else {
    res.redirect('/login');
  }
}

/* =========== Setting up routing */

router.get('/api', function (req, res) {
  res.send('API is running');
});

router.get('/form', function (req, res) {
  res.send(req.csrfToken());
});

router.get('/testform', function(req, res) {
  res.render('index', { csrfToken: req.csrfToken() })
});

router.post('/testprocess', parseBody, function(req, res){
  res.send('<p>Your favorite color is "' + req.body.favoriteColor + '".');
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
  return UserModel.findOne({ username: req.body.username }, function (err, useracc) {
    if(!useracc) {
      res.statusCode = 404;
      return res.send({ error: 'User not found' });
    }
    useracc.comparePassword(req.body.password, function(err, isMatch) {
      if (err) throw err;
      if (isMatch) {
        return res.send(req.csrfToken());
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
