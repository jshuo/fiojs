"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var encryption_check_1 = require("./encryption-check");
var ser = require("./chain-serialize");
var _a = require('./ecc'), PublicKey = _a.PublicKey, PrivateKey = _a.PrivateKey;
var fioAbi = require('../src/encryption-fio.abi.json');
var createHmac = require('create-hmac');
var fioTypes = ser.getTypesFromAbi(ser.createInitialTypes(), fioAbi);
/** Convert `value` to binary form. `type` must be a built-in abi type. */
function serialize(serialBuffer, type, value) {
    fioTypes.get(type).serialize(serialBuffer, value);
}
exports.serialize = serialize;
/** Convert data in `buffer` to structured form. `type` must be a built-in abi type. */
function deserialize(serialBuffer, type) {
    return fioTypes.get(type).deserialize(serialBuffer);
}
exports.deserialize = deserialize;
function createSharedCipher(_a) {
    var _b = _a === void 0 ? {} : _a, privateKey = _b.privateKey, publicKey = _b.publicKey, textEncoder = _b.textEncoder, textDecoder = _b.textDecoder;
    privateKey = PrivateKey(privateKey);
    publicKey = PublicKey(publicKey);
    var sharedSecret = privateKey.getSharedSecret(publicKey);
    return new SharedCipher({ sharedSecret: sharedSecret, textEncoder: textEncoder, textDecoder: textDecoder });
}
exports.createSharedCipher = createSharedCipher;
var SharedCipher = /** @class */ (function () {
    function SharedCipher(_a) {
        var _b = _a === void 0 ? {} : _a, sharedSecret = _b.sharedSecret, textEncoder = _b.textEncoder, textDecoder = _b.textDecoder;
        this.sharedSecret = sharedSecret;
        this.textEncoder = textEncoder;
        this.textDecoder = textDecoder;
    }
    /**
        Encrypt the content of a FIO message.

        @arg {string} fioContentType - `new_funds_content`, etc
        @arg {object} content
        @arg {Buffer} [IV = randomBytes(16)] - An unpredictable strong random value
            is required and supplied by default.  Unit tests may provide a static value
            to achieve predictable results.
        @return {string} cipher base64
    */
    SharedCipher.prototype.encrypt = function (fioContentType, content, IV) {
        var buffer = new ser.SerialBuffer({ textEncoder: this.textEncoder, textDecoder: this.textDecoder });
        serialize(buffer, fioContentType, content);
        var message = Buffer.from(buffer.asUint8Array());
        var cipherbuffer = encryption_check_1.checkEncrypt(this.sharedSecret, message, IV);
        // checkDecrypt(this.sharedSecret, cipherbuffer);
        return cipherbuffer.toString('base64');
    };
    /**
        Decrypt the content of a FIO message.

        @arg {string} fioContentType - `new_funds_content`, etc
        @arg {object} content - cipher base64
        @return {object} decrypted FIO object
    */
    SharedCipher.prototype.decrypt = function (fioContentType, content) {
        var message = encryption_check_1.checkDecrypt(this.sharedSecret, Buffer.from(content, 'base64'));
        var messageArray = Uint8Array.from(message);
        var buffer = new ser.SerialBuffer({ array: messageArray, textEncoder: this.textEncoder, textDecoder: this.textDecoder });
        return deserialize(buffer, fioContentType);
    };
    /**
        @example hashA(PublicKey.toBuffer())
        @arg {string|Buffer} key buffer
        @return {string} hex, one-way hash unique to this SharedCipher and key
    */
    SharedCipher.prototype.hashA = function (key) {
        var hash = createHmac('sha1', this.sharedSecret).update(key).digest();
        return '0x' + hash.slice(0, 16).toString('hex');
    };
    return SharedCipher;
}());
