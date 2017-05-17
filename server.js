/* =========== Importing modules */

let express = require('express');
let config = require('./libs/config');
let log = require('./libs/log')(module);
let app = express();
app.use(require('./app/controllers'));

/* =========== Listening for incoming connections */

app.listen(config.get('port'), function () {
  log.info('Express server listening on port ' + config.get('port'));
});