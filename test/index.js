var fs = require('fs');

var expect = require('chai').expect;
var forsake = require('../index');

var fixtures = __dirname + '/fixtures',
    pkey_a = fs.readFileSync(fixtures + '/a.key'),
    pubkey_a = fs.readFileSync(fixtures + '/a.pub'),
    pkey_a_locked = fs.readFileSync(fixtures + '/a_helloworld.key'),
    pkey_b = fs.readFileSync(fixtures + '/b.key'),
    pubkey_b = fs.readFileSync(fixtures + '/b.pub');

describe('forsake', function() {

    describe('as a module', function () {

        it('should have the rsautl functions', function () {
            ['encrypt', 'decrypt', 'sign', 'verify'].forEach(function (fn) {
                expect(forsake).to.have.property(fn).and.be.a('function');
            });
        });

        it('should have the RSA padding constants', function () {
            ['RSA_NO_PADDING', 'RSA_PKCS1_OAEP_PADDING', 'RSA_PKCS1_PADDING',
                'RSA_SSLV23_PADDING', 'RSA_X931_PADDING'].forEach(function (ct) {
                expect(forsake).to.have.property(ct).and.be.a('number');
            });
        });

    });

    describe('when not specifying padding', function () {

        it('should support encrypting', function () {
            var out = forsake.encrypt('lolcats', pubkey_a);
            expect(out).to.have.length(256);
        });

        it('should support decrypting', function () {
            var payload = fs.readFileSync(fixtures + '/encrypted.txt');
            var out = forsake.decrypt(payload, pkey_a).toString('utf8');
            expect(out).to.equal('encrypted lolcats');
        });

        it('should support signing', function () {
            var payload = fs.readFileSync(fixtures + '/signed.txt');
            var out = forsake.sign('signed lolcats', pkey_a);
            expect(out.toString()).to.equal(payload.toString());
        });

        it('should support verifying', function () {
            var payload = fs.readFileSync(fixtures + '/signed.txt');
            var out = forsake.verify(payload, pubkey_a).toString('utf8');
            expect(out).to.equal('signed lolcats');
        });

    });

    describe('when explicitly using padding', function () {

        it('should support decrypting using OAEP', function () {
            var payload = fs.readFileSync(fixtures + '/encrypted_oaep.txt');
            var opts = { padding: forsake.RSA_PKCS1_OAEP_PADDING };
            var out = forsake.decrypt(payload, pkey_a, opts).toString('utf8');
            expect(out).to.equal('lolcats with oaep');
        });

        it('should support signing using X9.31', function () {
            var payload = fs.readFileSync(fixtures + '/signed_x931.txt');
            var opts = { padding: forsake.RSA_X931_PADDING };
            var out = forsake.sign('lolcats with x9.31', pkey_a, opts);
            expect(out.toString()).to.equal(payload.toString());
        });

        it('should throw for verifying using OAEP', function () {
            var payload = fs.readFileSync(fixtures + '/encrypted_oaep.txt');
            var opts = { padding: forsake.RSA_PKCS1_OAEP_PADDING };
            var fn = function () { forsake.verify(payload, pubkey_a, opts); };
            expect(fn).to.throw(Error, /\bunknown padding type\b/);
        });

        it('should throw for encrypting using X9.31', function () {
            var opts = { padding: forsake.RSA_X931_PADDING };
            var fn = function () { forsake.encrypt('cats', pubkey_a, opts); };
            expect(fn).to.throw(Error, /\bunknown padding type\b/);
        });

    });

    describe('when mixing up key types', function () {

        it('should throw for an unexpected private key', function () {
            var fn = function () { forsake.encrypt('lolcats', pkey_a); };
            expect(fn).to.throw(Error, /\bPEM_read_bio\b/);
        });

        it('should throw for an unexpected public key', function () {
            var fn = function () { forsake.sign('lolcats', pubkey_a); };
            expect(fn).to.throw(Error, /\bPEM_read_bio\b/);
        });

    });

    describe('when using passphrase protected keys', function () {

        var correct = { key: pkey_a_locked, passphrase: 'helloworld' };

        it('should support decrypting', function () {
            var payload = fs.readFileSync(fixtures + '/encrypted.txt');
            var out = forsake.decrypt(payload, correct).toString('utf8');
            expect(out).to.equal('encrypted lolcats');
        });

        it('should support signing', function () {
            var payload = fs.readFileSync(fixtures + '/signed.txt');
            var out = forsake.sign('signed lolcats', correct);
            expect(out.toString()).to.equal(payload.toString());
        });

        it('should throw for an incorrect passphrase', function () {
            var lies = { key: pkey_a_locked, passphrase: 'goodbyeworld' };
            var payload = fs.readFileSync(fixtures + '/encrypted.txt');
            var fn = function () { forsake.decrypt(payload, lies); };
            expect(fn).to.throw(Error, /\bbad decrypt\b/);
        });

        it('should throw for a missing passphrase', function () {
            var payload = fs.readFileSync(fixtures + '/encrypted.txt');
            var fn = function () { forsake.decrypt(payload, pkey_a_locked); };
            expect(fn).to.throw(Error, /\bbad decrypt\b/);
        });

    });

    describe('when using the wrong keys', function () {

        it('should throw while decrypting', function () {
            var payload = fs.readFileSync(fixtures + '/encrypted.txt');
            var fn = function () { forsake.decrypt(payload, pkey_b); };
            expect(fn).to.throw(Error, /\bRSA_padding_check_PKCS1_type_2\b/);
        });

        it('should throw while verifying', function () {
            var payload = fs.readFileSync(fixtures + '/signed.txt');
            var fn = function () { forsake.verify(payload, pubkey_b); };
            expect(fn).to.throw(Error, /\bRSA_padding_check_PKCS1_type_1\b/);
        });

        it('should throw while decrypting with OAEP', function () {
            var payload = fs.readFileSync(fixtures + '/encrypted_oaep.txt');
            var opts = { padding: forsake.RSA_PKCS1_OAEP_PADDING };
            var fn = function () { forsake.decrypt(payload, pkey_b, opts); };
            expect(fn).to.throw(Error, /\bdata too large for modulus\b/);
        });

        it('should throw while verifying with X9.31', function () {
            var payload = fs.readFileSync(fixtures + '/signed_x931.txt');
            var opts = { padding: forsake.RSA_X931_PADDING };
            var fn = function () { forsake.verify(payload, pubkey_b, opts); };
            expect(fn).to.throw(Error, /\bRSA_padding_check_X931\b/);
        });

    });

});
