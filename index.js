var resource = require('resource'),
    http = resource.use('http'),
    logger = resource.logger,
    auth = resource.define('auth');

auth.schema.description = "for integrating authentication";

auth.persist('memory');

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

function start() {
  passport = require('passport');

  passport.serializeUser(auth.serialize);
  passport.deserializeUser(auth.deserialize);

  // feature detection of which auth providers to use
  auth.providers = [];
  var authRe = /auth-(.)*/;
  Object.keys(resource).forEach(function(possibleAuthProvider) {
    if (authRe.test(possibleAuthProvider)) {
      // we found an auth provider, use it
      var authProvider = resource[possibleAuthProvider];
      logger.info("using", authProvider.name, "as auth middleware");

      // add provider to list of providers
      auth.providers.push(authProvider);
      // add property to store provider instance ids
      auth.property(authRe.exec(authProvider.name)[1], {
        description: "instance id of " + authProvider.name,
        type: 'string'
      });
      // use auth strategy of provider
      authProvider.strategy(function(err, strategy) {
        passport.use(strategy);
      });
    }
  });

  http.connectr.after('session').use(passport.initialize()).as('auth-init');
  http.connectr.after('auth-init').use(passport.session()).as('auth-session');
}
auth.method('start', start, {
  description: 'start authentication in an app'
});

function routes() {
  // logout route
  http.app.get('/logout', function(req, res){
    req.logout();
    res.redirect('/');
  });

  // auth providers can add more routes
  auth.providers.forEach(function(authProvider) {
    authProvider.routes();
  });
}
auth.method('routes', routes, {
  description: 'sets up auth routes'
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
  'passport': '*'
};
auth.license = 'MIT';
exports.auth = auth;