var resource = require('resource');

module['exports'] = function(options, callback) {

  var $ = this.$,
      async = require('async'),
      auth = resource.use('auth');

  // option to anchor dropdown to right or left
  if (options.anchor === 'left') {
    // defaults to left
  } else if (options.anchor === 'right') {
    $('#authDropdown').addClass('dropdown-anchor-right');
  }

  if (options.text) {
    $('#authButton').text(options.text);
  }

  // for each auth provider
  async.each(Object.keys(auth.providers),
    // append provider login to dropdown
    function(providerName, callback) {
      auth.providers[providerName].view.login.present(options, function(err, result) {
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
