/**
 * Module dependencies.
 */
var passport = require('passport-strategy')
  , util = require('util')
  , request = require('request')
  , crypto = require('crypto-js');


/**
 * `Strategy` constructor.
 *
 * The local authentication strategy authenticates requests based on the
 * credentials submitted through an HTML-based login form.
 *
 * Applications must supply a `verify` callback which accepts `username` and
 * `password` credentials, and then calls the `done` callback supplying a
 * `user`, which should be set to `false` if the credentials are not valid.
 * If an exception occurred, `err` should be set.
 *
 * Optionally, `options` can be used to change the fields in which the
 * credentials are found.
 *
 * Options:
 *   - `usernameField`  field name where the username is found, defaults to _username_
 *   - `passwordField`  field name where the password is found, defaults to _password_
 *   - `passReqToCallback`  when `true`, `req` is the first argument to the verify callback (default: `false`)
 *
 * Examples:
 *
 *     passport.use(new LocalStrategy(
 *       function(username, password, done) {
 *         User.findOne({ username: username, password: password }, function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {

  passport.Strategy.call(this);
  this.name = 'two-legged';
  this._verify = verify;
  this._options = options;
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate request based on the contents of a form submission.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function(req, options) {
  var options = this._options
  var verify = this._verify;

  if (!options.tokenURL || !options.clientID || !options.clientSecret || !options.scope) {
    return this.fail({ message: options.badRequestMessage || 'Missing parameters' }, 400);
  }

  var encoded = crypto.enc.Utf8.parse(options.clientID + ':' + options.clientSecret);
  var hashed = crypto.enc.Base64.stringify(encoded);

  var self = this;
  request.post({
    uri: options.tokenURL,
    headers: {Authorization: 'Basic ' + hashed },
    form: {grant_type: 'client_credentials', scope: options.scope}
  }, function(error, response, body){
    verify(error, JSON.parse(body).access_token);
  })



  /*
  function verified(err, user, info) {
    if (err) { return self.error(err); }
    if (!user) { return self.fail(info); }
    self.success(user, info);
  }

  try {
    if (self._passReqToCallback) {
      this._verify(req, username, password, verified);
    } else {
      this._verify(username, password, verified);
    }
  } catch (ex) {
    return self.error(ex);
  }
  */
};


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
