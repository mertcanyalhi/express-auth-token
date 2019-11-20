/**
 * Module dependencies
 */
var jwt = require('jsonwebtoken');

/**
 * `Auth` constructor
 *
 * @api public
 */
function Auth() {
    this._key = 'auth';
    this._options = {};
    this._jwtVerifyOptions = {};
    this._jwtSignOptions = {};
    this._parsers = [];
    this._verify = null;
}

/**
 * Callback function, which will be called after the user data is verified.
 *
 * @callback verifyCompletedCallback
 * @param {String=} error - Error message, which will be used to set req.auth.error when the verification fails.
 * @param {Boolean} status - Verification result status (true: verified, false: not verified).
 * @param {Object=} data - Data object, which will be used to set `req.auth.data`. If not set, decoded token data will be used.
 */

/**
 * Callback function, which will be called to verify the user data.
 *
 * @callback verifyCallback
 * @param {String} token - Token, which was parsed from the request.
 * @param {Object} decoded - Decoded token data.
 * @param {verifyCompletedCallback} callback - Callback function, which will should called after the user is verified.
 */

/**
 * Callback function, which will be called when the authentication/authorization fails.
 *
 * @callback authFailureCallback
 * @param {Object} req - Express request object.
 * @param {Object} res - Express response object.
 * @param {Function} next - Express next callback.
 */

/**
 * Initializes the library for the given options. Uses JWT for token signing and verification.
 *
 * Examples:
 *
 *     // Initialize with secret
 *     app.use(expressAuthToken.init({
 *         parsers: [ expressAuthToken.parsers.AuthHeader ],
 *         secret: 'VerySecretKey'
 *     }));
 *
 *     // Initialize with private/public key
 *     app.use(expressAuthToken.init({
 *         parsers: [ expressAuthToken.parsers.AuthHeader ],
 *         publicKey: fs.readFileSync('./public.pem'),
 *         privateKey: fs.readFileSync('./private.key'),
 *         jwtOptions: {
 *             sign: {
 *                 algorithm: 'RS256',
 *                 expiresIn: 60 * 60 * 24 * 365 // 1 year
 *             }
 *         }
 *     }));
 *
 *     // Set failureCallback
 *     app.use(expressAuthToken.init({
 *         parsers: [ expressAuthToken.parsers.AuthHeader ],
 *         secret: 'VerySecretKey',
 *         failureCallback: function(req, res, next) {
 *             res.json({
 *                 success: false,
 *                 error: req.auth.error
 *             });
 *         }
 *     }));
 *
 * Options:
 *   - `parsers`           Array of token parsers, which will be used to parse the token from the request.
 *   - `secret`            Secret for JWT HMAC algorithms, which is either string, buffer, or object.
 *   - `privateKey`        PEM encoded private key for RSA and ECDSA for JWT.
 *   - `publicKey`         PEM encoded public key for RSA and ECDSA for JWT.
 *   - `jwtOptions`        JWT options, which will be passed to the JWT `verify` and `sign` functions.
 *   - `jwtOptions.verify` Options for the `verify` JWT function. Please refer to the JWT library for the options.
 *   - `jwtOptions.sign`   Options for the `sign` JWT function. Please refer to the JWT library for the options.
 *   - `rolesKey`          Key for roles within the signed data. When the `authorize` middleware is added to the Express route,
 *                         roles will be retrieved from the value of the key under the signed data.
 *   - `userKey`           Key for the user (user id/username/etc.) within the signed data. If used, req.user will be set to the value of
 *                         the key under the signed data.
 *   - `failureRedirect`   Redirection path, which will be used for redirecting the failed authentications/authorizations.
 *   - `failureCallback`   Callback function, which will be used for the failed authentications/authorizations.
 *
 * An optional `verifyCallback` can be supplied, which will allow you to perform user verification for the parsed token. express-auth-token will
 * always extract the signed data from the provided token, but it may be required to verify the user and/or token session in the application logic.
 *
 * Example:
 *
 *     app.use(expressAuthToken.init({
 *         parsers: [ expressAuthToken.parsers.AuthHeader ],
 *         secret: 'VerySecretKey'
 *     }, function(token, decoded, callback) {
 *         Session.findOne({
 *             userId: decoded.userId,
 *             token: token
 *         }, function(err, session) {
 *             if (!session) {
 *                 return callback('SessionNotFound', false);
 *             }
 *
 *             return callback(null, true);
 *         });
 *     }));
 *
 * Notes:
 *   - Either `secret` or `publicKey`/`privateKey` pair should be given during initialization.
 *   - At least one token parser should be given under `parsers` option.
 *   - In case if there are multiple token parsers:
 *     - Parsers will be used in the given order.
 *     - If a parser successfuly parses the token from the request, following parsers will not be used for the current request.
 *     - If the `rolesKey` option is set, corresponding key in the token data should contain an array of roles.
 *     - If the `userKey` option is set, corresponding key in the token data should contain the user information (user id/username/etc.).
 *
 * @param {Object} options - Options
 * @param {Array} options.parsers - Token parser(s), which will be used to parse token from the request.
 * @param {String=} options.secret - Secret for JWT HMAC algorithms, which is either string, buffer, or object.
 * @param {String=} options.privateKey - PEM encoded private key for RSA and ECDSA for JWT.
 * @param {String=} options.publicKey - PEM encoded public key for RSA and ECDSA for JWT.
 * @param {Object} options.jwtOptions - JWT options
 * @param {Object=} options.jwtOptions.verify - Options for the `verify` JWT function.
 * @param {Object=} options.jwtOptions.sign -  Options for the `sign` JWT function.
 * @param {String=} options.rolesKey - Key for roles within the signed data. If set, roles will be retrieved from the value of the key under the signed data.
 * @param {String=} options.userKey - Key for the user within the signed data. If set, req.user will be set to the value of the key under the signed data.
 * @param {String=} options.failureRedirect - Redirection path, which will be used for redirecting the failed authentications/authorizations.
 * @param {authFailureCallback=} options.failureCallback - Callback function, which will be used for the failed authentications/authorizations.
 * @param {verifyCallback=} verifyCallback - User Verification function, which will be called after the token is verified.
 *
 * @returns {Function} Middleware
 * @api public
 */
Auth.prototype.init = function(options, verifyCallback) {
    this._verify = verifyCallback || this._verify;

    this._options = options || {};
    this._jwtVerifyOptions = (this._options.jwtOptions && this._options.jwtOptions.verify) || {};
    this._jwtSignOptions = (this._options.jwtOptions && this._options.jwtOptions.sign) || {};

    if (!this._options.secret && (!this._options.privateKey || !this._options.publicKey)) {
        throw new TypeError('Secret or private/public keys not set');
    }

    this._parsers = this._options.parsers;

    if (!this._parsers || !this._parsers.length) {
        throw new TypeError('No parsers found');
    }

    return authMiddleware.call(this);
};

/**
 * Authentication middleware
 */
var authMiddleware = function() {
    var self = this;

    return function Auth(req, res, next) {
        // Set context
        self._req = req;
        self._res = res;
        self._next = next;

        // Module already initialized
        if (self._req.auth) { return next(); }

        // Initialize `auth` object
        self._req.auth = {
            error: 'TokenNotSet'
        };

        // Initialize `req` properties
        self._req.isAuthenticated = false;
        self._req.isAuthorized = false;

        // Parse token
        self._token = parseToken.call(self);

        // Verify token if found
        if (self._token) {
            // Token found
            return jwt.verify(self._token, self._options.secret || self._options.publicKey, self._jwtVerifyOptions, function(err, decoded) {
                verifyCallback.call(self, err, decoded);
            });
        }

        // Token not found
        return authResult.call(self, false);
    };
}

/**
 * Callback for JWT verify
 */
var verifyCallback = function(err, decoded) {
    var self = this;

    if (err) {
        // Token could not be verified
        self._req.auth.error = err.name;

        // Set underlying JWT error
        self._req.auth.jwtError = err;

        return authResult.call(self, false);
    }

    // Token verified

    if (self._verify) {
        // Call verification function
        return self._verify(self._token, decoded, function(error, status, data) {
            if (!status) {
                self._req.auth.error = error || self._req.auth.error;

                return authResult.call(self, false);
            }

            return authResult.call(self, true, data || decoded);
        });
    }

    return authResult.call(self, true, decoded);
};

/**
 * Auth result handler
 */
var authResult = function(status, data) {
    var self = this;

    if (status) {
        self._req.isAuthenticated = true;
        self._req.isAuthorized = true;

        self._req.auth.error = undefined;
        self._req.auth.token = self._token;
        self._req.auth.data = data;

        // Set `req.auth.roles` if key is given
        if (self._options.rolesKey) { self._req.auth.roles = data[self._options.rolesKey]; }

        // Set `req.user` if key is given
        if (self._options.userKey) { self._req.user = data[self._options.userKey]; }
    }

    return self._next();
};

/**
 * Try parsing token by using the defined parsers
 */
var parseToken = function() {
    var self = this;

    // Try parse token by using the defined parsers
    var token;

    self._parsers.some(function(parser) {
        token = parser.parse(self._req);

        return token !== null;
    });

    return token;
}

/**
 * Middleware for express routes which require authentication. When used, will require the request to be authenticated.
 *
 * If the authentication fails:
 *  - If `callback` parameter is given or if the `failureCallback` option is set, will call the callback function and will return 401 response.
 *  - If `callback` parameter is not given and the `failureCallback` option is set, will return 401 response.
 *  - If no callback is available and the `failureRedirect` option is set, will redirect the request to the given path.
 *
 * Example:
 *
 *     app.get('/private', expressAuthToken.authenticate(function(req, res, next) { res.json({ success: false, error: 'Access denied!' }); }));
 *
 * @param {authFailureCallback=} callback - Callback function, which will be called if the authentication fails.
 *
 * @returns {Function} Middleware
 * @api public
 */
Auth.prototype.authenticate = function(callback) {
    var self = this;

    return function(req, res, next) {
        if (req.isAuthenticated) {
            return next();
        }

        // Set error to 'NotAuthenticated'
        req.auth.error = 'NotAuthenticated';

        // Set status to Unauthorized
        res.status(401);

        return authFailed.call(self, req, res, next, callback);
    }
};

/**
 * Middleware for express routes which require role based authorization. When used, will require the request to be authenticated, and the token to have the
 * given role. Roles for the token will be retrieved from the token properties by using the given 'rolesKey' option while initalizing the middleware.
 *
 * If the authorization fails:
 *  - If `failureRedirect` option is set, will redirect the request to the given path.
 *  - If `callback` parameter is given or if the `failureCallback` option is set, will call the callback function and will return 403 response.
 *  - If `callback` parameter is not given and the `failureCallback` option is set, will return 403 response.
 *
 * Example:
 *
 *     app.get('/private', expressAuthToken.authorize('administrator', function(req, res, next) { res.json({ success: false, error: 'You are not an admin!' }); }));
 *
 * @param {String} role - Role to be used for authorization.
 * @param {authFailureCallback=} callback - Callback function, which will be called if the authorization fails.
 *
 * @returns {Function} Middleware
 * @api public
 */
Auth.prototype.authorize = function(role, callback) {
    var self = this;

    return function(req, res, next) {
        var roleMatch = req.auth &&
            req.auth.roles &&
            req.auth.roles.some(function(r) {
                return role === r;
            });

        if (roleMatch) {
            return next();
        }

        // Set error to 'NotAuthorized'
        req.auth.error = 'NotAuthorized';

        // Set status to Forbidden
        res.status(403);

        return authFailed.call(self, req, res, next, callback);
    }
};

/**
 * Handles failed authentication/authorization calls.
 */
var authFailed = function(req, res, next, callback) {
    var self = this;

    if (callback || self._options.failureCallback) {
        var _func = callback || self._options.failureCallback;

        _func(req, res, next);
    } else if (self._options.failureRedirect) {
        return res.redirect(self._options.failureRedirect);
    }

    return res.end();
};

/**
 * Initializes user verification function callback. Will replace the verification function callback in case if it was set while initializing express-auth-token.
 *
 * @param {verifyCallback=} verifyCallback - User Verification function, which will be called after the token is verified.
 *
 * Example:
 *
 *     expressAuthToken.verify(function(token, decoded, callback) {
 *         Session.findOne({
 *             userId: decoded.userId,
 *             token: token
 *         }, (err, session) => {
 *             if (!session) {
 *                 return callback('SessionNotFound', false);
 *             }
 *
 *             return callback(null, true);
 *         });
 *     });
 *
 * @api public
 */
Auth.prototype.verify = function(verifyCallback) {
    this._verify = verifyCallback || this._verify;
};

/**
 * Callback function, which will be called when the token creation is completed.
 *
 * @callback tokenCallback
 * @param {Error} error - Error object.
 * @param {String} token - Token which was created for the given data object.
 */

/**
 * Creates authentication token for the given data.
 *
 * Example:
 *
 *     expressAuthToken.createToken({
 *         userId: user.id,
 *         email: user.email,
 *         name: user.name
 *     }, function(err, token) {
 *
 *     });
 *
 * @param {Object} data - Data object, which contains user information. If `options.rolesKey` or `options.userKey` are set, it should contain corresponding keys.
 * @param {tokenCallback} callback - Token creation callback.
 *
 * @api public
 */
Auth.prototype.createToken = function(data, callback) {
    var self = this;

    return jwt.sign(data, self._options.secret || self._options.privateKey, self._jwtSignOptions, callback);
};

/**
 * Expose `Auth`
 */
exports = module.exports = Auth;
