var resource = require('resource'),
    http = resource.use('http'),
    logger = resource.logger,
    auth = resource.define('auth');

auth.schema.description = "for integrating authentication";

auth.persist('memory');

// TODO remove
auth.property('browserid', {
  description: "instance id of browserid",
  type: 'string'
});

function serialize(auth, done) {
  done(null, auth.id);
}
auth.method('serialize', serialize, {
  description: "serialize auth",
  properties: {
    auth: {
      type: 'object'
    },
    done: {
      type: 'function'
    }
  }
});

function deserialize(id, done) {
  auth.get(id, function(err, _auth) {
    if (err) { throw err; }
    done(null, _auth);
  });
}
auth.method('deserialize', deserialize, {
  description: "deserialize auth",
  properties: {
    id: {
      type: 'string'
    },
    done: {
      type: 'function'
    }
  }
});

function start(options, callback) {
  var passport = require('passport'),
      async = require('async');

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
      passport.serializeUser(auth.serialize);
      callback(null);
    },
    // setup passport deserialization
    function(callback) {
      passport.deserializeUser(auth.deserialize);
      callback(null);
    },
    // setup auth providers
    function(callback) {
      //
      // feature detection of which auth providers to use
      //
      auth.providers = {};
      // regex of the resource name of an auth provider
      var authRe = /auth-(.*)/;
      // for each resource already .use'd, or possible auth provider
      async.each(Object.keys(resource),
        function(possibleAuthProvider) {
          // test if auth provider
          if (authRe.test(possibleAuthProvider)) {
            // we found an auth provider, use it
            var authProvider = resource[possibleAuthProvider];
            logger.info("using", authProvider.name, "as auth middleware");

            // get name of auth provider
            var providerName = authRe.exec(authProvider.name)[1];
            async.parallel([
              // add provider to list of providers
              function(callback) {
                auth.providers[providerName] = authProvider;
                callback(null);
              },
              // add property to store provider instance ids
              function(callback) {
                logger.info("defining", providerName, "of auth");
                auth.property(providerName, {
                  description: "instance id of " + authProvider.name,
                  type: 'string'
                });
                callback(null);
              },
              function(callback) {
              // use auth strategy of provider
              authProvider.strategy(function(err, strategy) {
                if (err) { return callback(err); }
                passport.use(strategy);
                // use route of provider
                authProvider.routes(options[providerName], callback);
              });
            }],
            function(err) {
              return callback(err);
            });
          }
      });
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

auth.dependencies = {
  'passport': '*',
  'async': '*'
};
auth.license = 'MIT';
exports.auth = auth;
