"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.eccDecrypt = exports.eccEncrypt = void 0;
var encryption_check_1 = require("./encryption-check");
var _a = require('./ecc'), PublicKey = _a.PublicKey, PrivateKey = _a.PrivateKey;
function eccEncrypt(privateKey, publicKey, message, IV) {
    privateKey = PrivateKey(privateKey);
    publicKey = PublicKey(publicKey);
    var sharedSecret = privateKey.getSharedSecret(publicKey);
    return (0, encryption_check_1.checkEncrypt)(sharedSecret, message, IV);
}
exports.eccEncrypt = eccEncrypt;
function eccDecrypt(privateKey, publicKey, message) {
    privateKey = PrivateKey(privateKey);
    publicKey = PublicKey(publicKey);
    var sharedSecret = privateKey.getSharedSecret(publicKey);
    return (0, encryption_check_1.checkDecrypt)(sharedSecret, message);
}
exports.eccDecrypt = eccDecrypt;
//# sourceMappingURL=encryption-ecc.js.map