var authHeader = require('../../lib/parsers/authHeader');

describe('Parsing Authentication Header', function() {
    it('Should parse single-space', function() {
        // Arrange
        var token = '0123456789abcdef';
        var req = {
            headers: {
                authorization: 'Bearer ' + token
            }
        };

        // Act
        var result = authHeader.parse(req);

        // Assert
        expect(result).to.equal(token);
    });

    it('Should parse multi-space', function() {
        // Arrange
        var token = '0123456789abcdef';
        var req = {
            headers: {
                authorization: 'Bearer  ' + token
            }
        };

        // Act
        var result = authHeader.parse(req);

        // Assert
        expect(result).to.equal(token);
    });

    it('Should parse line-break separator', function() {
        // Arrange
        var token = '0123456789abcdef';
        var req = {
            headers: {
                authorization: 'Bearer\n' + token
            }
        };

        // Act
        var result = authHeader.parse(req);

        // Assert
        expect(result).to.equal(token);
    });

    it('Should not parse invalid value', function() {
        // Arrange
        var req = {
            headers: {
                authorization: 'Bla'
            }
        };

        // Act
        var result = authHeader.parse(req);

        // Assert
        expect(result).to.be.null;
    });

    it('Should parse custom scheme', function() {
        // Arrange
        var scheme = 'CustomScheme';
        var token = '0123456789abcdef';
        var req = {
            headers: {
                authorization: scheme + ' ' + token
            }
        };

        authHeader.options.authScheme = scheme;

        // Act
        var result = authHeader.parse(req);

        // Assert
        expect(result).to.equal(token);
    });

    it('Should not parse if headers not set', function() {
        // Arrange
        var req = {};

        // Act
        var result = authHeader.parse(req);

        // Assert
        expect(result).to.be.null;
    });

    it('Should not parse if authorization header not set', function() {
        // Arrange
        var req = {
            headers: {}
        };

        // Act
        var result = authHeader.parse(req);

        // Assert
        expect(result).to.be.null;
    });
});
