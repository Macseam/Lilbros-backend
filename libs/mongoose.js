let config = require('./config');
let mongoose = require('mongoose');
mongoose.Promise = require('bluebird');
let log = require('./log')(module);

mongoose.connect(config.get('mongoose:uri'));
let db = mongoose.connection;

db.on('error', function (err) {
  log.error('connection error: ', err.message);
});

db.once('open', function callback() {
  log.info('Connected to DB!');
});

let Schema = mongoose.Schema;

let Images = new Schema({
  kind: {
    type: String,
    enum: ['thumbnail', 'detail'],
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
    type: Number,
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

Article.path('title').validate(function (v) {
  return v.length > 3 && v.length < 70;
});

let ArticleModel = mongoose.model('Article', Article);

module.exports.ArticleModel = ArticleModel;
