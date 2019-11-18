/**
 * Module dependencies
 */
var Auth = require('./auth'),
    AuthHeader = require('./parsers/authHeader');

/**
 * Expose auth middleware
 */
exports = module.exports = new Auth();

/**
 * Expose constructor
 */
exports.Auth = Auth;

/**
 * Export parsers
 */
exports.parsers = {};
exports.parsers.AuthHeader = AuthHeader;
