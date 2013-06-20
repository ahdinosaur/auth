var resource = require('resource');

module['exports'] = function(options, callback) {

  var $ = this.$,
      async = require('async'),
      auth = resource.use('auth');

  // for each auth provider
  async.each(Object.keys(auth.providers),
    // append provider login to dropdown
    function(providerName, callback) {
      auth.providers[providerName].view.login.min.present(options, function(err, result) {
        if (err) { return callback(err); }
        $('#authProviders').append("<li>"+result+"</li>");
        return callback(null);
      });
    },
    // return dom
    function(err) {
      if (err) { return callback(err); }
      return callback(null, $.html());
    });
};
