let config = require('./config');

let mongoose = require('mongoose'),
Schema = mongoose.Schema,
bcrypt = require('bcrypt'),
SALT_WORK_FACTOR = 10;

let BruteForceSchema = require('express-brute-mongoose/dist/schema');

mongoose.Promise = require('bluebird');
let log = require('./log')(module);

mongoose.connect(config.get('mongoose:uri'));
let db = mongoose.connection;

const salt = config.get('mongoose:salt');

db.on('error', function (err) {
  log.error('connection error: ', err.message);
});

db.once('open', function callback() {
  log.info('Connected to DB!');
});

let Images = new Schema({
  kind: {
    type: String,
    required: true
  },
  url: {
    type: String,
    required: true
  }
});

let Article = new Schema({
  title: {
    type: String,
    required: true
  },
  author: {
    type: String,
    required: false
  },
  description: {
    type: String,
    required: true
  },
  parent: {
    type: String,
    required: false
  },
  slug: {
    type: String,
    required: true
  },
  images: [Images],
  modified: {
    type: Date,
    default: Date.now
  }
});

let User = new Schema({
  username: {
    type: String,
    index: { unique: true },
    required: true
  },
  email: {
    type: String,
    index: { unique: true },
    required: true
  },
  password: {
    type: String,
    //set: encryptPassword,
    required: true
  },
  registered: {
    type: Date,
    default: Date.now
  }
});

User.pre('save', function(next) {
  let user = this;
  if (!user.isModified('password')) return next();

  bcrypt.genSalt(SALT_WORK_FACTOR, function(err, salt) {
    if (err) return next(err);

    bcrypt.hash(user.password, salt, function(err, hash) {
      if (err) return next(err);

      user.password = hash;
      next();
    });
  });
});

User.methods.comparePassword = function(candidatePassword, basePassword) {
  return new Promise(function (resolve, reject) {
    bcrypt.compare(candidatePassword, basePassword, function (err, isMatch) {
      if (err || !isMatch) {
        let error = new Error('Неверный пароль');
        error.code = 403;
        return reject(error);
      }
      resolve(isMatch);
    });
  });
};

Article.path('title').validate(function (v) {
  return v.length > 3 && v.length < 70;
});

let UserModel = mongoose.model('User', User);
let ArticleModel = mongoose.model('Article', Article);
let BruteForceModel = mongoose.model('bruteforce', BruteForceSchema);

module.exports.BruteForceModel = BruteForceModel;
module.exports.UserModel = UserModel;
module.exports.ArticleModel = ArticleModel;
module.exports.db = db;
