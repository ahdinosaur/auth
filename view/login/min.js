var resource = require('resource');

module['exports'] = function(options, callback) {

  var $ = this.$,
      self = this,
      async = require('async'),
      auth = resource.use('auth');

  // for each provider
  async.each(Object.keys(auth.providers),
    // append provider present to dom
    function(providerName, callback) {
      auth.providers[providerName].view.login.min.present(options, function(err, result) {
        if (err) { return callback(err); }
        $('.authProviders').append(result);
        return callback(null);
      });
    },
    // return dom
    function(err) {
      if (err) { return callback(err); }
      return callback(null, $.html());
    });
};
