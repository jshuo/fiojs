"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var encryption_check_1 = require("../encryption-check");
var randomBytes = require('randombytes');
var secret = Buffer.from('02332627b9325cb70510a70f0f6be4bcb008fbbc7893ca51dedf5bf46aa740c0fc9d3fbd737d09a3c4046d221f4f1a323f515332c3fef46e7f075db561b1a2c9', 'hex');
var plaintext = Buffer.from('secret message');
var IV = Buffer.from('f300888ca4f512cebdc0020ff0f7224c', 'hex');
var cipherBuffer = Buffer.from('f300888ca4f512cebdc0020ff0f7224c7f896315e90e172bed65d005138f224da7301d5563614e3955750e4480aabf7753f44b4975308aeb8e23c31e114962ab', 'hex');
describe('Encryption', function () {
    it('checkEncrypt validates', function () {
        expect(function () {
            (0, encryption_check_1.checkEncrypt)(secret, plaintext, Buffer.concat([IV, Buffer.alloc(1)]));
        }).toThrow('IV must be 16 bytes');
    });
    it('checkDecrypt validates', function () {
        expect(function () {
            (0, encryption_check_1.checkDecrypt)(secret, Buffer.concat([cipherBuffer, Buffer.alloc(1)]));
        }).toThrow('decrypt failed');
    });
    it('checkEncrypt', function () {
        var c = (0, encryption_check_1.checkEncrypt)(secret, plaintext, IV);
        expect(c).toEqual(cipherBuffer);
    });
    it('checkDecrypt', function () {
        var c = (0, encryption_check_1.checkDecrypt)(secret, cipherBuffer);
        expect(c).toEqual(plaintext);
    });
    it('Random IV', function () {
        var message = Buffer.from(randomBytes(32));
        var c = (0, encryption_check_1.checkEncrypt)(secret, message);
        var p = (0, encryption_check_1.checkDecrypt)(secret, c);
        expect(p).toEqual(message);
    });
});
//# sourceMappingURL=encryption-check.test.js.map