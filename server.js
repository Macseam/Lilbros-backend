/* =========== Importing modules */

let csrf = require('csurf');
let bodyParser = require('body-parser');
let config = require('./libs/config');
let express = require('express');
let cors = require('cors');
let path = require('path');
let cookieParser = require('cookie-parser');
let log = require('./libs/log')(module);
let ArticleModel = require('./libs/mongoose').ArticleModel;
let session = require('express-session');
let app = express();

/* =========== Setting up middleware options */

let corsOptions = {
  origin: 'http://localhost:8080',
  optionsSuccessStatus: 200
};

app.set('view engine', 'ejs');

let parseJson = bodyParser.json();
let parseUrlencoded = bodyParser.urlencoded({extended: true});
let parseBody = [parseJson, parseUrlencoded];

let csrfProtection = csrf({
  cookie: true,
  ignoreMethods: ['GET','POST','PUT','DELETE']
});

let sess = {
  secret: 'keyboard cat',
  cookie: {},
  resave: true,
  saveUninitialized: true
};

if (app.get('env') !== 'development') {
  app.set('trust proxy', 1);
  sess.cookie.secure = true;
}

/* =========== Including middleware */

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}));

app.use(session(sess));
app.use(cookieParser());
app.use(csrfProtection);

app.use(cors(corsOptions));

app.use(express.static(path.join(__dirname, 'public')));

app.use(function (req, res, next) {
  res.locals._csrf = req.csrfToken();
  next();
});

/* =========== Setting up routing */

app.get('/api', function (req, res) {
  res.send('API is running');
});

app.get('/form', csrfProtection, function (req, res) {
  /*let tkn = req.csrfToken();
   res.render('index', { csrfToken: tkn })*/
  res.send(req.csrfToken());
});

app.post('/process', parseBody, csrfProtection, function (req, res) {
  res.send('<p>Your favorite color is "' + req.body.favoriteColor + '".');
});

app.get('/api/articles', function (req, res) {
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

app.post('/api/articles', function (req, res) {
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
    res.setHeader('Content-Type', 'text/html');
    res.write('<p>views: ' + resSess.views + '</p>');
    res.write('<p>expires in: ' + (resSess.cookie.maxAge / 1000) + 's</p>');
    res.end();
  } else {
    resSess.views = 1;
    res.end('welcome to the session demo. refresh!');
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
  return ArticleModel.find({"slug": req.params.id}, function (err, article) {
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

app.put('/api/articles/:id', function (req, res) {
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

app.delete('/api/articles/:id', function (req, res) {
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
