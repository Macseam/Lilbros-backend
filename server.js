/* =========== Importing modules */

const uuidV1 = require('uuid/v1');
let config = require('./libs/config');
let path = require('path');
let log = require('./libs/log')(module);
let express = require('express');
let cors = require('cors');
let bcrypt = require('bcrypt');
let SALT_WORK_FACTOR = 10;
let session = require('express-session');
let ExpressBrute = require('express-brute');
let BruteMongooseStore = require('express-brute-mongoose');
let bodyParser = require('body-parser');
let UserModel = require('./libs/mongoose').UserModel;
let ArticleModel = require('./libs/mongoose').ArticleModel;
let BruteForceModel = require('./libs/mongoose').BruteForceModel;
let mongooseConnection = require('./libs/mongoose').db;
const MongoStore = require('connect-mongo')(session);

let BruteForceStore = new BruteMongooseStore(BruteForceModel);

let app = express();

/* =========== Setting up middleware options */

let corsOptions = {
  origin: true,
  //methods: ['OPTIONS','HEAD','GET','POST'],
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
  secret: 'keyboard cat',
  resave: true,
  saveUninitialized: true,
  store: new MongoStore({mongooseConnection})
};

let bruteforce = new ExpressBrute(BruteForceStore);

/* =========== Including middleware */

/app.use(cors(corsOptions));

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use(session(sess));

/*let router = express.Router();
app.use(router);*/

app.use(express.static(path.join(__dirname, 'public')));

/*app.use(function(req, res, next) {
  console.log('mid session info:');
  console.log(req.session);
  console.log(req.sessionID);
  next();
});*/

function checkUser(req, res, next) {
  let sess = req.session;
  if (sess.user_id) {
    console.log('searching for ' + sess.user_id);
    UserModel.findById(sess.user_id, function(err, useracc) {

      /* Checking user id in session */
      if (useracc && sess.token && req.headers['x-csrf-token'] && (sess.token === req.headers['x-csrf-token'])) {
        console.log(useracc.username + ' is logged in');
        req.currentUser = useracc;

        /* Checking and renewing token */
        if (sess.token) {
          let saltValue = sess.token.substr(0,29);
          console.log('salt calculated: ' + saltValue);
          let tokenValue = bcrypt.hashSync((saltValue + ":" + sess.secretkey), saltValue);
          console.log('token generated: ' + tokenValue);
          console.log('hashes match: ' + (sess.token === tokenValue));

          if (sess.token === tokenValue) {
            console.log('authorized user, all ok');
          }

          saltValue = bcrypt.genSaltSync(SALT_WORK_FACTOR);
          tokenValue = bcrypt.hashSync((saltValue + ":" + sess.secretkey), saltValue);
          sess.token = tokenValue;
          res.cookie('CSRF-TOKEN',tokenValue);
        }
        else {
          console.log('no token found, generating a new one');
          let saltValue = bcrypt.genSaltSync(SALT_WORK_FACTOR);
          let tokenValue = bcrypt.hashSync((saltValue + ":" + req.session.secretkey), saltValue);
          console.log('salt generated: ' + saltValue);
          console.log('token saved: ' + tokenValue);
          sess.token = tokenValue;
          res.cookie('CSRF-TOKEN',tokenValue);
        }
        res.status(200);
        next();
      } else {
        console.log('no matched user');
        res.status(403).send('access denied');
      }
    });
  } else {
    console.log('no user_id available in session');
    res.status(200);
    next();
  }
}

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
    res.send('guest user');
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
      res.statusCode = 404;
      return res.send({ error: 'User not found' });
    }
    else {
      console.log('user named ' + useracc.username + ' is found');
    }
    useracc.comparePassword(req.body.password, function(err, isMatch) {
      if (err) throw err;
      if (isMatch) {
        sess.user_id = useracc._id;

        // TODO: Разобраться, как пихать соль в сессию асинхронно

        if (!sess.secretkey) {
          sess.secretkey = bcrypt.genSaltSync(SALT_WORK_FACTOR);
          let tokenValue = bcrypt.hashSync((sess.secretkey + ":" + req.session.secretkey), sess.secretkey);
          sess.token = tokenValue;
          res.cookie('CSRF-TOKEN',tokenValue);
        }
        else {
          let tokenValue = bcrypt.hashSync((sess.secretkey + ":" + req.session.secretkey), sess.secretkey);
          sess.token = tokenValue;
          res.cookie('CSRF-TOKEN',tokenValue);
        }

        req.session = sess;
        req.session.save( function(err) {
          req.session.reload( function (err) {
            console.log('session saved');
          });
        });

        return res.send(useracc.username);
      }
      else {
        res.status(403).send('access denied, wrong login/password');
      }
    });
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

app.post('/api/articles', bruteforce.prevent, checkUser, function (req, res) {
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

app.put('/api/articles/:id', bruteforce.prevent, checkUser, function (req, res) {
  return ArticleModel.findById(req.params.id, function (err, article) {
    if(!article) {
      res.statusCode = 404;
      return res.send({ error: 'Not found' });
    }

    article.title = req.body.title || article.title;
    article.description = req.body.description || article.description;
    article.author = req.body.author || article.author;
    article.parent = req.body.parent || article.parent;
    article.slug = req.body.slug || article.slug;
    article.images = req.body.images || article.images;
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

app.delete('/api/articles/:id', bruteforce.prevent, checkUser, function (req, res) {
  if (req.params.id) {
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

/* =========== Listening for incoming connections */

app.listen(config.get('port'), function () {
  log.info('Express server listening on port ' + config.get('port'));
});
