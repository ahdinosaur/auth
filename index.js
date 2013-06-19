var resource = require('resource'),
    http = resource.use('http'),
    user = resource.use('user'),
    logger = resource.logger,
    auth = resource.define('auth');

auth.schema.description = "for integrating authentication";

auth.persist('memory');

auth.providers = {};
auth.setup = false;

function start(options, callback) {
  var async = require('async');

  logger.info("using", options.provider.name, "as auth middleware");
  async.parallel([
    // add auth provider to providers object
    function(callback) {
      auth.providers[options.provider.name] = options.provider;
      callback(null);
    },
    // add property to store provider instance ids
    function(callback) {
      var providerName = options.provider.name.replace('auth-', '');
      logger.info("defining", providerName, "of auth");
      user.property(providerName, {
        description: "instance id of " + options.provider.name,
        type: 'string'
      });
      // TODO remove
      user.persist('memory');
      callback(null);
    }],
    function(err, results) {
      if (err) { return callback(err); }

      // auth only needs to be setup once
      if (auth.setup) {
        return callback(null);
      }
      // set setup so we don't try to start again
      auth.setup = true;

      var passport = require('passport');

      async.parallel([
        // setup .view convention
        function(callback) {
          var view = resource.use('view');
          view.create({ path: __dirname + '/view' }, function(err, _view) {
              if (err) { callback(err); }
              auth.view = _view;
              callback(null, _view);
          });
        },
        // setup passport serialization
        function(callback) {
          passport.serializeUser(user.serialize);
          callback(null);
        },
        // setup passport deserialization
        function(callback) {
          passport.deserializeUser(user.deserialize);
          callback(null);
        },
        // add auth to http middleware
        function(callback) {
          http.app.after('session').use(passport.initialize()).as('auth-init');
          http.app.after('auth-init').use(passport.session()).as('auth-session');
          callback(null);
        },
        // setup logout route
        function(callback) {
          http.app.get('/logout', function(req, res){
            req.logout();
            res.redirect('/');
          });
          callback(null);
        }],
      function(err, results) {
        callback(err);
      });
    });
}
auth.method('start', start, {
  description: 'start authentication in an app'
});

function authenticate(provider, options, middleware) {
  var passport = require('passport');
  return passport.authenticate(provider, options, middleware);
}
auth.method('authenticate', authenticate, {
  description: 'authenticate the auth provider',
  properties: {
    provider: {
      type: 'string'
    },
    options: {
      type: 'object'
    },
    middleware: {
      type: 'function'
    }
  }
});

function authorize(provider, options, middleware) {
  var passport = require('passport');
  return passport.authorize(provider, options, middleware);
}
auth.method('authorize', authorize, {
  description: 'authorize the auth provider',
  properties: {
    provider: {
      type: 'string'
    },
    options: {
      type: 'object'
    },
    middleware: {
      type: 'function'
    }
  }
});

function use(strategy, callback) {
  var passport = require('passport');
  passport.use(strategy);
  callback(null);
}
auth.method('use', use, {
  description: 'use an auth strategy',
  properties: {
    strategy: {
      type: 'any'
    },
    callback: {
      type: 'function'
    }
  }
});

auth.dependencies = {
  'passport': '*',
  'async': '*'
};
auth.license = 'MIT';
exports.auth = auth;
