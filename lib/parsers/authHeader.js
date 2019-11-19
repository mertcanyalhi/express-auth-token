
/**
 * Parser options:
 *  - `authScheme` Scheme to be matched within the authorization header
 */
var options = {
    authScheme: 'Bearer'
};

/**
 * Parses request object and returns token
 *
 * @param {Object} req Express request object
 */
var parse = function(req) {
    var authScheme = options.authScheme.toLowerCase();

    if (req.headers &&
        req.headers.authorization) {
        var authHeader = req.headers.authorization.match(/(\S+)\s+(\S+)/);

        if (authHeader &&
            authHeader.length === 3 &&
            authHeader[1].toLowerCase() === authScheme) {

            return authHeader[2];
        }
    }

    return null;
};

module.exports = {
    parse,
    options
};
