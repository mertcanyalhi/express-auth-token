# express-auth-token

[![Build](https://travis-ci.org/mertcanyalhi/express-auth-token.svg?branch=master)](https://travis-ci.org/mertcanyalhi/express-auth-token)
[![Coverage](https://coveralls.io/repos/mertcanyalhi/express-auth-token/badge.svg?branch=master)](https://coveralls.io/r/mertcanyalhi/express-auth-token)
[![Quality](https://codeclimate.com/github/mertcanyalhi/express-auth-token/badges/gpa.svg)](https://codeclimate.com/github/mertcanyalhi/express-auth-token)
[![Dependencies](https://david-dm.org/mertcanyalhi/express-auth-token.svg)](https://david-dm.org/mertcanyalhi/express-auth-token)

express-auth-token is an [Express](http://expressjs.com/) middleware, which authenticates users by using [JSON Web Token](http://jwt.io).

## Install

```sh
npm install express-auth-token
```

## Usage

### Initializing

**Options:**

- `parsers`           Array of token parsers, which will be used to parse the token from the request.
- `secret`            Secret for JWT HMAC algorithms, which is either string, buffer, or object.
- `privateKey`        PEM encoded private key for RSA and ECDSA for JWT.
- `publicKey`         PEM encoded public key for RSA and ECDSA for JWT.
- `jwtOptions`        JWT options, which will be passed to the JWT `verify` and `sign` functions.
- `jwtOptions.verify` Options for the `verify` JWT function. Please refer to the JWT library for the options.
- `jwtOptions.sign`   Options for the `sign` JWT function. Please refer to the JWT library for the options.
- `rolesKey`          Key for roles within the signed data. When the `authorize` middleware is added to the Express route,
                      roles will be retrieved from the value of the key under the signed data.
- `userKey`           Key for the user (user id/username/etc.) within the signed data. If used, req.user will be set to the value of
                      the key under the signed data.
- `failureRedirect`   Redirection path, which will be used for redirecting the failed authentications/authorizations.
- `failureCallback`   Callback function, which will be used for the failed authentications/authorizations.

**Notes:**

- Either `secret` or `publicKey`/`privateKey` pair should be given during initialization.
- At least one token parser should be given under `parsers` option.
- In case if there are multiple token parsers:
  - Parsers will be used in the given order.
  - If a parser successfuly parses the token from the request, following parsers will not be used for the current request.
  - If the `rolesKey` option is set, corresponding key in the token data should contain an array of roles.
  - If the `userKey` option is set, corresponding key in the token data should contain the user information (user id/username/etc.).

Including the library:

```javascript
var expressAuthToken = require('express-auth-token');
```

Initializing with secret:

```javascript
app.use(expressAuthToken.init({
    parsers: [ expressAuthToken.parsers.AuthHeader ],
    secret: 'VerySecretKey'
}));
```

Initializing with private/public key:

```javascript
app.use(expressAuthToken.init({
    parsers: [ expressAuthToken.parsers.AuthHeader ],
    publicKey: fs.readFileSync('./public.pem'),
    privateKey: fs.readFileSync('./private.key'),
    jwtOptions: {
        sign: {
            algorithm: 'RS256',
            expiresIn: 60 * 60 * 24 * 365 // 1 year
        }
    }
}));
```

Setting `failureCallback`:

```javascript
app.use(expressAuthToken.init({
    parsers: [ expressAuthToken.parsers.AuthHeader ],
    secret: 'VerySecretKey',
    failureCallback: function(req, res, next) {
        res.json({
            status: false,
            error: req.auth.error
        });
    }
}));
```

An optional `verifyCallback` can be supplied, which will allow you to perform user verification for the parsed token. express-auth-token will
always extract the signed data from the provided token, but it may be required to verify the user and/or token session in the application logic.

```javascript
app.use(expressAuthToken.init({
    parsers: [ expressAuthToken.parsers.AuthHeader ],
    secret: 'VerySecretKey'
}, function(token, decoded, callback) {
    Session.findOne({
        userId: decoded.userId,
        token: token
    }, function(err, session) {
        if (!session) {
            return callback('SessionNotFound', false);
        }
        return callback(null, true);
    });
}));
```

`verifyCallback` can also be set after the initialization. This will replace the `verifyCallback` defined during the initialization in case if it was set.

```javascript
expressAuthToken.verify(function(token, decoded, callback) {
    Session.findOne({
        userId: decoded.userId,
        token: token
    }, (err, session) => {
        if (!session) {
            return callback('SessionNotFound', false);
        }

        return callback(null, true);
    });
});
```

### Authenticating/Authorizing requests

By default, all requests are allowed. express-auth-token will only try to parse the request, and extract the signed data within the token. In case if you want to authenticate
or authorize a request, you can use the `authenticate` or `authorize` middlewares.

`authenticate` middleware will only allow authenticated users to access the Express route. If the user is not authenticated, a `401` response code will be returned.

```javascript
app.get('/private', expressAuthToken.authenticate());
```

A custom callback can be defined for the failed requests:

```javascript
app.get('/private', expressAuthToken.authenticate(function(req, res, next) {
    res.json({
        message: 'Access denied!'
    });
}));
```

`authorize` middleware will only allow users having the defined role. If the user does not have the required role, a `403` response code will be returned.

```javascript
app.get('/private', expressAuthToken.authorize('administrator'));
```

A custom callback can be defined for the failed requests:

```javascript
app.get('/private', expressAuthToken.authorize('administrator', function(req, res, next) {
    res.json({
        message: 'Access denied!'
    });
}));
```

**Notes:**

- If the callback is defined under the `authenticate`/`authorize` call, `failureCallback` callback will not be called.
- If the `failureRedirect` option is set while initializing express-auth-token, failed requests will be redirected to the given path unless there is a callback.

### Parsers

express-auth-token uses parsers to parse the token from the incoming request. Parsers are extendable; you can create your own parser to parse the token from the request.

Currently supported parsers:

- **Authentication Header**
  - Parses the token from the authentication header. By default, it uses the `Bearer` scheme.
    ```Authorization: Bearer <TOKEN>```
  - Scheme can be easily modified:

    ```javascript
    expressAuthToken.parsers.AuthHeader.options.authScheme = 'MyScheme';
    ```

    ```Authorization: MyScheme <TOKEN>```

### Writing a custom parser

You can create a custom parser by using the following template. express-auth-token will call the `parse` function, and will provide the Express request object as a parameter.

```javascript
var options = {
    headerKey: 'authkey'
};

var parse = function(req) {
    return req.headers[options.headerKey];
};

module.exports = {
    parse,
    options
};
```

You can include your custom parser while initializing express-auth-token:

```javascript
app.use(expressAuthToken.init({
    parsers: [
        expressAuthToken.parsers.AuthHeader,
        myCustomParser
    ],
    secret: 'VerySecretKey'
}));
```

## Tests

```sh
npm install
npm test
```

To generate test-coverage reports:

```sh
npm install -g istanbul
npm run-script coverage
istanbul report
```

## License

The [MIT License](http://opensource.org/licenses/MIT)

Copyright (c) 2019 Mert Can Yalhi <[http://mert.co](http://mert.co)>
