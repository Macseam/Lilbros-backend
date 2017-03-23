let config = require('./libs/config');
let express = require('express');
let path = require('path');
let bodyParser = require('body-parser');
let log = require('./libs/log')(module);
let ArticleModel = require('./libs/mongoose').ArticleModel;
let app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static(path.join(__dirname, 'public')));

app.get('/api', function(req, res){
res.send('API is running');
});

app.get('/api/articles', function(req, res){
return ArticleModel.find(function(err, articles){
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

app.post('/api/articles', function(req, res){
let article = new ArticleModel({
title: req.body.title,
author: req.body.author,
description: req.body.description,
images: req.body.images
});
article.save(function(err){
if (!err) {
log.info('article created');
return res.send({status: 'OK', article: article});
}
else {
console.log(err);
if (err.name == 'ValidationError') {
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

app.get('/api/articles/:id', function(req, res){
res.send('This GET with id is not implemented yet');
});

app.put('/api/articles/:id', function(req, res){
res.send('This PUT with id is not implemented yet');
});

app.delete('/api/articles/:id', function(req, res){
res.send('This DELETE with id is not implemented yet');
});

app.get('/ErrorExample', function(req, res, next){
next(new Error('Random error!'));
});

app.use(function(req, res, next){
res.status(404);
log.debug('Not found URL: %s', req.url);
res.send({error: 'Not found'});
return;
});

app.use(function(err, req, res, next){
res.status(err.status || 500);
log.error('Internal error(%d): %s', res.statusCode, err.message);
res.send({error: err.message});
return;
});

app.listen(config.get('port'), function(){
log.info('Express server listening on port ' + config.get('port'));
});
