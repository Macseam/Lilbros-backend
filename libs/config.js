let nconf = require('nconf');
nconf.env().argv().file('development',{file: './config.json'});

module.exports = nconf;
