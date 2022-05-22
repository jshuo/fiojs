"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var text_encoding_1 = require("text-encoding");
var ser = require("../chain-serialize");
var PrivateKey = require('../ecc').PrivateKey;
var _a = require('../encryption-fio'), serialize = _a.serialize, deserialize = _a.deserialize, createSharedCipher = _a.createSharedCipher;
var textEncoder = new text_encoding_1.TextEncoder();
var textDecoder = new text_encoding_1.TextDecoder();
describe('Encryption FIO', function () {
    var newFundsContent = {
        payee_public_address: 'purse.alice',
        amount: '1',
        chain_code: 'FIO',
        token_code: 'FIO',
        memo: null,
        hash: null,
        offline_url: null
    };
    var newFundsContentHex = '0B70757273652E616C69636501310346494F0346494F000000';
    it('serialize', function () {
        var buffer = new ser.SerialBuffer({ textEncoder: textEncoder, textDecoder: textDecoder });
        serialize(buffer, 'new_funds_content', newFundsContent);
        expect(ser.arrayToHex(buffer.asUint8Array())).toEqual(newFundsContentHex);
    });
    it('deserialize', function () {
        var array = ser.hexToUint8Array(newFundsContentHex);
        var buffer = new ser.SerialBuffer({ array: array, textEncoder: textEncoder, textDecoder: textDecoder });
        var newFundsContentRes = deserialize(buffer, 'new_funds_content');
        expect(newFundsContentRes).toEqual(newFundsContent);
    });
    describe('Diffie Cipher', function () {
        var privateKeyAlice = PrivateKey.fromSeed('alice');
        var publicKeyAlice = privateKeyAlice.toPublic();
        var privateKeyBob = PrivateKey.fromSeed('bob');
        var publicKeyBob = privateKeyBob.toPublic();
        var IV = Buffer.from('f300888ca4f512cebdc0020ff0f7224c', 'hex');
        var newFundsContentCipherBase64 = '8wCIjKT1Es69wAIP8PciTOB8F09qqDGdsq0XriIWcOkqpZe9q4FwKu3SGILtnAWtJGETbcAqd3zX7NDptPUQsS1ZfEPiK6Hv0nJyNbxwiQc=';
        it('encrypt', function () {
            var cipherAlice = createSharedCipher({ privateKey: privateKeyAlice, publicKey: publicKeyBob, textEncoder: textEncoder, textDecoder: textDecoder });
            var cipherAliceBase64 = cipherAlice.encrypt('new_funds_content', newFundsContent, IV);
            expect(cipherAliceBase64).toEqual(newFundsContentCipherBase64);
            var cipherBob = createSharedCipher({ privateKey: privateKeyBob, publicKey: publicKeyAlice, textEncoder: textEncoder, textDecoder: textDecoder });
            var cipherBobBase64 = cipherBob.encrypt('new_funds_content', newFundsContent, IV);
            expect(cipherBobBase64).toEqual(newFundsContentCipherBase64);
        });
        it('decrypt', function () {
            var cipherAlice = createSharedCipher({ privateKey: privateKeyAlice, publicKey: publicKeyBob, textEncoder: textEncoder, textDecoder: textDecoder });
            var newFundsContentAlice = cipherAlice.decrypt('new_funds_content', newFundsContentCipherBase64);
            expect(newFundsContentAlice).toEqual(newFundsContent);
            var cipherBob = createSharedCipher({ privateKey: privateKeyBob, publicKey: publicKeyAlice, textEncoder: textEncoder, textDecoder: textDecoder });
            var newFundsContentBob = cipherBob.decrypt('new_funds_content', newFundsContentCipherBase64);
            expect(newFundsContentBob).toEqual(newFundsContent);
        });
        it('hashA', function () {
            var privateKey = PrivateKey.fromSeed('');
            var publicKey = privateKey.toPublic();
            var cipher = createSharedCipher({ privateKey: privateKey, publicKey: publicKey });
            expect(cipher.hashA('')).toEqual('0x7a5de2d59c72b94c67a192a9009484ef');
            expect(cipher.hashA(Buffer.from(''))).toEqual('0x7a5de2d59c72b94c67a192a9009484ef');
            expect(cipher.hashA(publicKey.toBuffer())).toEqual('0x2521bccef77d48793a7a80716e79a46d');
        });
    });
});
//# sourceMappingURL=encryption-fio.test.js.map