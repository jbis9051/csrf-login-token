const {SHA3} = require('sha3');
const createError = require('http-errors');
const compare = require('tsscmp');

function csurf_login_token(cookieName, options) {
    const opts = options || {};

    const value = opts.value || defaultValue;

    if (!cookieName || typeof cookieName !== "string") {
        throw new TypeError('cookieName must be a string')
    }
    // ignored methods
    const ignoreMethods = opts.ignoreMethods === undefined
        ? ['GET', 'HEAD', 'OPTIONS']
        : opts.ignoreMethods;

    if (!Array.isArray(ignoreMethods)) {
        throw new TypeError('option ignoreMethods must be an array')
    }

    // generate lookup
    const ignoreMethod = getIgnoredMethods(ignoreMethods);

    return (req, res, next) => {
        req.csrfToken = () => {
            if (!req.cookie[cookieName]) {
                throw new Error('No login token found. Please check that the login token exists (which should be done anyway since its a login token).')
            }
            return getHash(req.cookie[cookieName]);
        };
        if (!ignoreMethod[req.method] && !verify(cookieName, value, req)) {
            return next(createError(403, 'invalid csrf token', {
                code: 'EBADCSRFTOKEN'
            }))
        }
        next();
    }

}

/**
 * Default value function, checking the `req.body`
 * and `req.query` for the CSRF token.
 *
 * @param {IncomingMessage} req
 * @return {String}
 * @api private
 */

function defaultValue(req) {
    return (req.body && req.body._csrf) ||
        (req.query && req.query._csrf) ||
        (req.headers['csrf-token']) ||
        (req.headers['xsrf-token']) ||
        (req.headers['x-csrf-token']) ||
        (req.headers['x-xsrf-token']);
}

/**
 * Get a lookup of ignored methods.
 *
 * @param {array} methods
 * @returns {object}
 * @api private
 */

function getIgnoredMethods(methods) {
    const obj = Object.create(null);

    for (let i = 0; i < methods.length; i++) {
        const method = methods[i].toUpperCase();
        obj[method] = true;
    }
    return obj;
}

/**
 *  Get a hash of a string val
 *
 * @param val - string
 * @return {string}
 */
function getHash(val) {
    const hash = new SHA3(512);
    hash.update(val);
    return hash.digest('hex');
}

/**
 * Verifies that a request has valid csrf token
 *
 * @param cookieName - name of the login cookie
 * @param value - function to find the csrf token
 * @param req - request
 * @return {boolean}
 */
function verify(cookieName, value, req) {
    const submitToken = value(req);
    if (!submitToken) {
        return false;
    }
    const loginToken = req.cookie[cookieName];
    if (!loginToken) {
        return false;
    }
    return compare(getHash(loginToken), submitToken);
}


module.exports = csurf_login_token;
