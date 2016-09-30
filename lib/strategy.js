// Load modules.
var OAuth2Strategy = require('passport-oauth2')
  , util = require('util')
  , url = require('url')
	, InternalOAuthError = require('passport-oauth2').InternalOAuthError


/**
 * `Strategy` constructor.
 *
 * Options:
 *   - `clientID`      identifies client to service provider
 *   - `clientSecret`  secret used to establish ownership of the client identifier
 *   - `callbackURL`   URL to which service provider will redirect the user after granting authorization
 *
 * Examples:
 *
 *     passport.use(new ARTIKCloudStrategy({
 *         clientID: '123-456-789',
 *         clientSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/auth/example/callback'
 *       },
 *       function(accessToken, refreshToken, profile, cb) {
 *         User.findOrCreate(..., function (err, user) {
 *           cb(err, user);
 *         });
 *       }
 *     ));
 *
 * @constructor
 * @param {object} options
 * @param {function} verify
 * @access public
 */
function Strategy(options, verify) {
  options = options || {};
  options.authorizationURL = options.authorizationURL || 'https://accounts.artik.cloud/authorize';
  options.tokenURL = options.tokenURL || 'https://accounts.artik.cloud/token';
  options.tokenType = options.tokenType || 'authorization code';

  OAuth2Strategy.call(this, options, verify);
  this.name = 'artikcloud';
  this._profileURL = options.profileURL || 'https://api.artik.cloud/v1.1/users/self';
  this._logoutURL = options.logoutURL || 'https://api.artik.cloud/v1.1/logout';
	this._basicAuth = (new Buffer(options.clientID + ":" + options.clientSecret)).toString('base64');
	this._oauth2._useAuthorizationHeaderForGET = true;
}

// Inherit from `OAuth2Strategy`.
util.inherits(Strategy, OAuth2Strategy);


function isEmpty(obj) {
	for (var prop in obj) {
		if (obj.hasOwnProperty(prop))
			return false;
	}

	return true;
}

/**
 * Authenticate request by delegating to ARTIK Cloud using OAuth 2.0.
 *
 * @param {http.IncomingMessage} req
 * @param {object} options
 * @access protected
 */
Strategy.prototype.authenticate = function (req, options) {
	if (url.parse(this._callbackURL).pathname == req._parsedOriginalUrl.pathname) {
		if (isEmpty(req.query)) {
			this.pass();
			return;
		}
	}

	if (options.authType == 'implicit') {
		var params = this.authorizationParams(options);
		var location = this._oauth2.getAuthorizeUrl(params);
		this.redirect(location);
	}
	else if (options.authType == 'client_credentials') {
		var self = this;

		this._oauth2._request("POST", this._oauth2._getAccessTokenUrl(),
			{
				'Content-Type': 'application/x-www-form-urlencoded',
				'Authorization': 'Basic ' + this._basicAuth
			},
			"grant_type=client_credentials", null,
			function (error, data, response) {
				if (error)
					return self.error(error);

				var result = JSON.parse(data);
				self.success(result, data);
				self.pass();
			});
	}
	else {
		OAuth2Strategy.prototype.authenticate.call(this, req, options);
	}
};

/**
 * Return extra ARTIK Cloud-specific parameters to be included in the authorization
 * request.
 *
 * Options:
 *  - `display`  Display mode to render dialog, { `page`, `popup`, `touch` }.
 *
 * @param {object} options
 * @return {object}
 * @access protected
 */
Strategy.prototype.authorizationParams = function (options) {
	var params = {};

	if (options.authType == 'implicit') {
		params.response_type = 'token';
	}

	return params;
};

/**
 * Retrieve user profile from ARTIK Cloud.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 * @param {string} accessToken
 * @param {function} done
 * @access protected
 */
Strategy.prototype.userProfile = function (accessToken, done) {
	this._oauth2.get(this._profileURL, accessToken, function (err, body, res) {
		var json;

		if (err) {
			console.dir(err);
			if (err.data) {
				try {
					json = JSON.parse(err.data);
				} catch (_) { }
			}

			return done(new InternalOAuthError('Failed to fetch user profile', err));
		}

		try {
			json = JSON.parse(body);
		} catch (ex) {
			return done(new Error('Failed to parse user profile'));
		}

		json.data.accessToken = accessToken;
		done(null, json.data);
	});
};

Strategy.prototype.refreshToken = function (refreshToken, params, done) {
	params = params || {};
	params.grant_type = 'refresh_token';

	this._oauth2.getOAuthAccessToken(refreshToken, params, done);
};

// Expose constructor.
module.exports = Strategy;
