var rewire = require('rewire');
var sinon = require('sinon');

var Auth = require('../lib/auth');

describe('Auth.constructor', function() {
    it('Should initialize with default values', function() {
        // Act
        var auth = new Auth();

        // Assert
        expect(auth._key).to.equal('auth');
        expect(auth._options).to.be.an('object');
        expect(auth._jwtVerifyOptions).to.be.an('object');
        expect(auth._jwtSignOptions).to.be.an('object');
        expect(auth._verify).to.be.null;
        expect(auth._parsers).to.be.an('array');
    });
});

describe('Auth.init', function() {
    it('Should set jwtOptions.verify', function() {
        // Arrange
        var jwtVerifyOptions = {
            a: 'foo'
        };
        var auth = new Auth();

        // Act
        auth.init({
            parsers: [null],
            secret: 'dummy',
            jwtOptions: {
                verify: jwtVerifyOptions
            }
        });

        // Assert
        expect(auth._jwtVerifyOptions).to.deep.equal(jwtVerifyOptions);
    });

    it('Should set jwtOptions.sign', function() {
        // Arrange
        var options = {
            parsers: [null],
            secret: 'dummy',
            jwtOptions: {
                sign: {
                    a: 'foo'
                }
            }
        };
        var auth = new Auth();

        // Act
        auth.init(options);

        // Assert
        expect(auth._jwtSignOptions).to.deep.equal(options.jwtOptions.sign);
    });

    it('Should require secret or keys', function() {
        // Arrange
        var auth = new Auth();

        // Act && Assert
        expect(auth.init).to.throw('Secret or private/public keys not set');
    });

    it('Should require private/public keys', function() {
        // Arrange
        var auth = new Auth();
        var options = {
            privateKey: 'dummy'
        };
        var initFunc = function() {
            return auth.init(options);
        };

        // Act && Assert
        expect(initFunc).to.throw('Secret or private/public keys not set');
    });

    it('Should require at least 1 parser', function() {
        // Arrange
        var auth = new Auth();
        var initFunc = function() {
            return auth.init({
                secret: 'dummy'
            });
        };

        // Act && Assert
        expect(initFunc).to.throw('No parsers found');
    });
});

describe('Auth.authMiddleware', function() {
    var rAuth = rewire('../lib/auth');
    var authMiddleware = rAuth.__get__('authMiddleware');

    it('Should initialize middleware', function() {
        // Act
        var middleware = authMiddleware();

        // Assert
        expect(middleware).to.be.a('function');
    });

    it('Should not re-initialize auth', function() {
        // Arrange
        var middleware = authMiddleware();
        var mockAuth = {};
        var mockReq = {
            auth: mockAuth
        };
        var spyNext = sinon.spy();

        // Act
        middleware(mockReq, null, spyNext);

        // Assert
        expect(spyNext).to.have.been.called;
        expect(mockReq.auth).to.deep.equal(mockAuth);
    });

    it('Should fail if token not found', function() {
        // Arrange
        var stubParseToken = sinon.stub().returns(null);
        var spyAuthResult = sinon.spy();
        rAuth.__set__('parseToken', stubParseToken);
        rAuth.__set__('authResult', spyAuthResult);

        var middleware = authMiddleware();

        // Act
        middleware.call(this, {}, null, null);

        // Assert
        expect(spyAuthResult).to.be.calledWith(false);
    });

    it('Should pass if token found', function() {
        // Arrange
        var stubParseToken = sinon.stub().returns('dummy');
        var spyVerifyCallback = sinon.spy();

        rAuth.__set__('parseToken', stubParseToken);
        rAuth.__set__('jwt', {
            verify: function(token, secret, options, callback) {
                callback();
            }
        });
        rAuth.__set__('verifyCallback', spyVerifyCallback);

        var middleware = authMiddleware();

        // Act
        middleware.call(this, {}, null, null);

        // Assert
        expect(spyVerifyCallback).to.have.been.called;
    });
});

describe('Auth.verifyCallback', function() {
    var rAuth = rewire('../lib/auth');
    var verifyCallback = rAuth.__get__('verifyCallback');

    it('Should fail if error received', function() {
        // Arrange
        var spyAuthResult = sinon.spy();

        rAuth.__set__('authResult', spyAuthResult);

        var context = {
            _req: {
                auth: {
                    error: null,
                    jwtError: null
                }
            }
        };
        var errorValue = {
            name: 'Error'
        };
        var decodedValue = null;

        // Act
        verifyCallback.call(context, errorValue, decodedValue);

        // Assert
        expect(spyAuthResult).to.be.calledWith(false);
        expect(context._req.auth.error).to.be.equal(errorValue.name);
        expect(context._req.auth.jwtError).to.deep.equal(errorValue);
    });

    it('Should pass if no error received', function() {
        // Arrange
        var spyAuthResult = sinon.spy();

        rAuth.__set__('authResult', spyAuthResult);

        var context = {};
        var errorValue = null;
        var decodedValue = {
            id: 1
        };

        // Act
        verifyCallback.call(context, errorValue, decodedValue);

        // Assert
        expect(spyAuthResult).to.be.calledWith(true, decodedValue);
    });

    it('Should call verification function', function() {
        // Arrange
        var spyAuthResult = sinon.spy();
        var spyVerify = sinon.spy();

        rAuth.__set__('authResult', spyAuthResult);

        var context = {
            _verify: spyVerify,
            _token: 'dummy'
        };
        var errorValue = null;
        var decodedValue = {
            id: 1
        };

        // Act
        verifyCallback.call(context, errorValue, decodedValue);

        // Assert
        expect(spyVerify).to.be.calledWith(context._token, decodedValue);
    });

    it('Should pass if verification function passes', function() {
        // Arrange
        var spyAuthResult = sinon.spy();

        rAuth.__set__('authResult', spyAuthResult);

        var decodedValue = {
            id: 1
        };
        var context = {
            _verify: function(token, decoded, callback) {
                callback(null, true);
            },
            _token: 'dummy'
        };
        var errorValue = null;

        // Act
        verifyCallback.call(context, errorValue, decodedValue);

        // Assert
        expect(spyAuthResult).to.be.calledWith(true, decodedValue);
    });

    it('Should fail if verification function fails', function() {
        // Arrange
        var spyAuthResult = sinon.spy();

        rAuth.__set__('authResult', spyAuthResult);

        var context = {
            _verify: function(token, decoded, callback) {
                callback(null, false);
            },
            _token: 'dummy',
            _req: {
                auth: {
                    error: 'TestError'
                }
            }
        };

        // Act
        verifyCallback.call(context, null);

        // Assert
        expect(spyAuthResult).to.be.calledWith(false);
    });
});

describe('Auth.authResult', function() {
    var rAuth = rewire('../lib/auth');
    var authResult = rAuth.__get__('authResult');

    it('Should continue if the status is not okay', function() {
        // Arrange
        var spyNext = sinon.spy();
        var context = {
            _next: spyNext,
            _req: {
                isAuthenticated: false,
                isAuthorized: false,
                auth: {
                    error: 'TestError',
                    token: null,
                    data: null
                },
                rolesKey: null,
                userKey: null
            },
            _token: 'dummy'
        };
        var contextCopy = Object.assign({}, context);

        // Act
        authResult.call(context, false);

        // Assert
        expect(context).to.deep.equal(contextCopy);
        expect(spyNext).to.be.called;
    });

    it('Should set request parameters if the status is okay', function() {
        // Arrange
        var spyNext = sinon.spy();
        var context = {
            _next: spyNext,
            _req: {
                isAuthenticated: false,
                isAuthorized: false,
                auth: {
                    error: 'TestError',
                    token: null,
                    data: null
                }
            },
            _options: {
                rolesKey: null,
                userKey: null
            },
            _token: 'dummy'
        };
        var data = {
            id: 1
        };

        // Act
        authResult.call(context, true, data);

        // Assert
        expect(context._req.isAuthenticated).to.equal(true);
        expect(context._req.isAuthorized).to.equal(true);
        expect(context._req.auth.error).to.equal(undefined);
        expect(context._req.auth.token).to.equal(context._token);
        expect(context._req.auth.data).to.deep.equal(data);
        expect(context._req.auth.roles).to.equal(undefined);
        expect(context._req.user).to.equal(undefined);
        expect(spyNext).to.be.called;
    });

    it('Should set roles if the roles key is given', function() {
        // Arrange
        var spyNext = sinon.spy();
        var context = {
            _next: spyNext,
            _req: {
                isAuthenticated: false,
                isAuthorized: false,
                auth: {
                    error: 'TestError',
                    token: null,
                    data: null
                }
            },
            _options: {
                rolesKey: 'roles',
                userKey: null
            },
            _token: 'dummy'
        };
        var data = {
            id: 1,
            roles: ['a', 'b', 'c']
        };

        // Act
        authResult.call(context, true, data);

        // Assert
        expect(context._req.auth.roles).to.deep.equal(data.roles);
    });

    it('Should set user if the roles key is given', function() {
        // Arrange
        var spyNext = sinon.spy();
        var context = {
            _next: spyNext,
            _req: {
                isAuthenticated: false,
                isAuthorized: false,
                auth: {
                    error: 'TestError',
                    token: null,
                    data: null
                }
            },
            _options: {
                rolesKey: null,
                userKey: 'id'
            },
            _token: 'dummy'
        };
        var data = {
            id: 1,
            roles: ['a', 'b', 'c']
        };

        // Act
        authResult.call(context, true, data);

        // Assert
        expect(context._req.user).to.equal(data.id);
    });
});

describe('Auth.parseToken', function() {
    var rAuth = rewire('../lib/auth');
    var parseToken = rAuth.__get__('parseToken');

    it('Should iterate through the parsers', function() {
        // Arrange
        var spyParse1 = sinon.stub().returns(null);
        var spyParse2 = sinon.stub().returns(null);
        var context = {
            _parsers: [
                { parse: spyParse1 },
                { parse: spyParse2 }
            ],
            _req: {}
        };

        // Act
        var result = parseToken.call(context);

        // Assert
        expect(result).to.equal(null);
        expect(spyParse1).to.be.calledWith(context._req);
        expect(spyParse2).to.be.calledWith(context._req);
    });

    it('Should iterate through the parsers', function() {
        // Arrange
        var tokenVal = 'token';
        var spyParse1 = sinon.stub().returns(tokenVal);
        var spyParse2 = sinon.stub().returns(null);
        var context = {
            _parsers: [
                { parse: spyParse1 },
                { parse: spyParse2 }
            ],
            _req: {}
        };

        // Act
        var result = parseToken.call(context);

        // Assert
        expect(result).to.equal(tokenVal);
        expect(spyParse1).to.be.calledWith(context._req);
        expect(spyParse2).not.to.be.called;
    });
});

describe('Auth.authFailed', function() {
    var rAuth = rewire('../lib/auth');
    var authFailed = rAuth.__get__('authFailed');

    it('Should end response if no callback/redirect is available', function() {
        // Arrange
        var spyRedirect = sinon.spy();
        var spyEnd = sinon.spy();
        var mockReq = {};
        var mockRes = {
            redirect: spyRedirect,
            end: spyEnd
        };
        var mockNext = {};
        var context = {
            _options: {
                failureCallback: null,
                failureRedirect: null
            }
        };

        // Act
        authFailed.call(context, mockReq, mockRes, mockNext, null);

        // Assert
        expect(spyEnd).to.be.called;
        expect(spyRedirect).not.to.be.called;
    });

    it('Should redirect request if no callback is given and redirection path is set', function() {
        // Arrange
        var spyEnd = sinon.stub();
        var spyRedirect = sinon.stub();
        var mockReq = {};
        var mockRes = {
            redirect: spyRedirect,
            end: spyEnd
        };
        var mockNext = {};
        var context = {
            _options: {
                failureCallback: null,
                failureRedirect: '/path'
            }
        };

        // Act
        var result = authFailed.call(context, mockReq, mockRes, mockNext, null);

        // Assert
        expect(spyRedirect).to.be.calledWith(context._options.failureRedirect);
        expect(spyEnd).not.to.be.called;
    });

    it('Should call default callback', function() {
        // Arrange
        var spyRedirect = sinon.spy();
        var spyEnd = sinon.spy();
        var spyCallback = sinon.spy();
        var mockReq = {};
        var mockRes = {
            redirect: spyRedirect,
            end: spyEnd
        };
        var mockNext = {};
        var context = {
            _options: {
                failureCallback: spyCallback,
                failureRedirect: null
            }
        };

        // Act
        authFailed.call(context, mockReq, mockRes, mockNext, null);

        // Assert
        expect(spyEnd).to.be.called;
        expect(spyRedirect).not.to.be.called;
        expect(spyCallback).to.be.calledWith(mockReq, mockRes, mockNext);
    });

    it('Should call given callback', function() {
        // Arrange
        var spyRedirect = sinon.spy();
        var spyEnd = sinon.spy();
        var spyCallbackDefault = sinon.spy();
        var spyCallback = sinon.spy();
        var mockReq = {};
        var mockRes = {
            redirect: spyRedirect,
            end: spyEnd
        };
        var mockNext = {};
        var context = {
            _options: {
                failureCallback: spyCallbackDefault,
                failureRedirect: null
            }
        };

        // Act
        authFailed.call(context, mockReq, mockRes, mockNext, spyCallback);

        // Assert
        expect(spyEnd).to.be.called;
        expect(spyRedirect).not.to.be.called;
        expect(spyCallbackDefault).not.to.be.called;
        expect(spyCallback).to.be.calledWith(mockReq, mockRes, mockNext);
    });
});

describe('Auth.verify', function() {
    var auth = new Auth();

    it('Should set verify callback', function() {
        // Arrange
        var mockVerifyCallback = 'dummy';
        var context = {
            _verify: null
        };

        // Act
        auth.verify.call(context, mockVerifyCallback);

        // Assert
        expect(context._verify).to.be.equal(mockVerifyCallback);
    });

    it('Should not be changed if no callback is given', function() {
        // Arrange
        var verifyValue = 'dummy';
        var context = {
            _verify: verifyValue
        };

        // Act
        auth.verify.call(context, null);

        // Assert
        expect(context._verify).to.be.equal(verifyValue);
    });
});

describe('Auth.createToken', function() {
    var rAuth = rewire('../lib/auth');
    var auth = new rAuth();

    it('Should call JWT sign with secret', function() {
        // Arrange
        var spyJwtSign = sinon.spy();
        var context = {
            _options: {
                secret: 'dummy',
                privateKey: 'key'
            },
            _jwtSignOptions: {
                algorithm: 'RS256'
            }
        };
        var mockData = 'data';
        var mockCallback = 'callback';

        rAuth.__set__('jwt', {
            sign: spyJwtSign
        });

        // Act
        auth.createToken.call(context, mockData, mockCallback);

        // Assert
        expect(spyJwtSign).to.have.been.calledWith(mockData, context._options.secret, context._jwtSignOptions, mockCallback);
    });

    it('Should call JWT sign with private key', function() {
        // Arrange
        var spyJwtSign = sinon.spy();
        var context = {
            _options: {
                secret: null,
                privateKey: 'key'
            },
            _jwtSignOptions: {
                algorithm: 'RS256'
            }
        };
        var mockData = 'data';
        var mockCallback = 'callback';

        rAuth.__set__('jwt', {
            sign: spyJwtSign
        });

        // Act
        auth.createToken.call(context, mockData, mockCallback);

        // Assert
        expect(spyJwtSign).to.have.been.calledWith(mockData, context._options.privateKey, context._jwtSignOptions, mockCallback);
    });
});

describe('Auth.authenticate', function() {
    var rAuth = rewire('../lib/auth');

    it('Should call next if user is authenticated', function() {
        // Arrange
        var auth = new rAuth();
        var middleware = auth.authenticate();

        var context = {};
        var mockReq = {
            isAuthenticated: true
        };
        var mockRes = {};
        var spyNext = sinon.spy();

        // Act
        middleware.call(context, mockReq, mockRes, spyNext);

        // Assert
        expect(spyNext).to.have.been.called;
    });

    it('Should fail if user is not authenticated', function() {
        // Arrange
        var mockCallback = {};

        var auth = new rAuth();
        var middleware = auth.authenticate(mockCallback);

        var spyAuthFailed = sinon.spy();
        var spyStatus = sinon.spy();
        var context = {};
        var mockReq = {
            isAuthenticated: false
        };
        var mockRes = {
            status: spyStatus
        };
        var mockNext = {};

        rAuth.__set__('authFailed', spyAuthFailed);

        // Act
        middleware.call(context, mockReq, mockRes, mockNext);

        // Assert
        expect(spyStatus).to.have.been.calledWith(401);
        expect(spyAuthFailed).to.have.been.calledWith(mockReq, mockRes, mockNext, mockCallback);
    });
});

describe('Auth.authorize', function() {
    var rAuth = rewire('../lib/auth');

    it('Should call next if user is authorized', function() {
        // Arrange
        var auth = new rAuth();
        var middleware = auth.authorize('role1');

        var context = {};
        var mockReq = {
            auth: {
                roles: ['role1']
            }
        };
        var mockRes = {};
        var spyNext = sinon.spy();

        // Act
        middleware.call(context, mockReq, mockRes, spyNext);

        // Assert
        expect(spyNext).to.have.been.called;
    });

    it('Should fail if user is not authenticated', function() {
        // Arrange
        var mockCallback = {};

        var auth = new rAuth();
        var middleware = auth.authorize('role1', mockCallback);

        var spyAuthFailed = sinon.spy();
        var spyStatus = sinon.spy();
        var context = {};
        var mockReq = {
            auth: {
                roles: [],
                error: null
            }
        };
        var mockRes = {
            status: spyStatus
        };
        var mockNext = {};

        rAuth.__set__('authFailed', spyAuthFailed);

        // Act
        middleware.call(context, mockReq, mockRes, mockNext);

        // Assert
        expect(mockReq.auth.error).to.equal('NotAuthorized');
        expect(spyStatus).to.have.been.calledWith(403);
        expect(spyAuthFailed).to.have.been.calledWith(mockReq, mockRes, mockNext, mockCallback);
    });
});
