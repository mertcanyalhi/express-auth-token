
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
        var authHeader = req.headers.authorization.split(' ');

        if (authHeader.length === 2 &&
            authHeader[0].toLowerCase() === authScheme) {

            return authHeader[1];
        }
    }

    return null;
};

module.exports = {
    parse,
    options
};
