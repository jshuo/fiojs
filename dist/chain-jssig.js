"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (_) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
var __read = (this && this.__read) || function (o, n) {
    var m = typeof Symbol === "function" && o[Symbol.iterator];
    if (!m) return o;
    var i = m.call(o), r, ar = [], e;
    try {
        while ((n === void 0 || n-- > 0) && !(r = i.next()).done) ar.push(r.value);
    }
    catch (error) { e = { error: error }; }
    finally {
        try {
            if (r && !r.done && (m = i["return"])) m.call(i);
        }
        finally { if (e) throw e.error; }
    }
    return ar;
};
var __spread = (this && this.__spread) || function () {
    for (var ar = [], i = 0; i < arguments.length; i++) ar = ar.concat(__read(arguments[i]));
    return ar;
};
Object.defineProperty(exports, "__esModule", { value: true });
var ecc = require('./ecc');
var createHash = require('create-hash');
var bippath = require('bip32-path');
var FIO_ACCOUNT_PATH = "m/44'/235'/0'/0/0";
//@ts-ignore
function buildTxBuffer(bip32path, message, tp, chainId) {
    if (tp === void 0) { tp = 0; }
    if (chainId === void 0) { chainId = 0; }
    var head = [], data = [];
    var headerBuffer = Buffer.alloc(4);
    headerBuffer.writeUInt16LE(tp, 0);
    headerBuffer.writeUInt16LE(chainId, 2);
    var patharrary = bippath.fromString(bip32path).toPathArray();
    var pathBuffer = Buffer.alloc(4 * patharrary.length);
    for (var i = 0; i < patharrary.length; i++) {
        pathBuffer.writeUInt32LE(patharrary[i], i * 4);
    }
    head.push(Buffer.concat([Buffer.from([patharrary.length * 4 + 4]), headerBuffer, pathBuffer]));
    // fixed 2 byte length
    var preparedTxLenBuf = Buffer.alloc(2);
    preparedTxLenBuf.writeUInt16BE(message.length, 0);
    //@ts-ignore
    data.push(Buffer.concat([preparedTxLenBuf, message]));
    var singlepath = 1;
    return Buffer.concat(__spread([Buffer.from([singlepath])], head, data));
}
function hexToUint8Array(hex) {
    if (typeof hex !== 'string') {
        throw new Error('Expected string containing hex digits');
    }
    if (hex.length % 2) {
        throw new Error('Odd number of hex digits');
    }
    var l = hex.length / 2;
    var result = new Uint8Array(l);
    for (var i = 0; i < l; ++i) {
        var x = parseInt(hex.substr(i * 2, 2), 16);
        if (Number.isNaN(x)) {
            throw new Error('Expected hex string');
        }
        result[i] = x;
    }
    return result;
}
/** Signs transactions using in-process private keys */
var JsSignatureProvider = /** @class */ (function () {
    /** @param privateKeys private keys to sign with */
    function JsSignatureProvider(privateKeys, transport) {
        /** map public to private keys */
        this.keys = new Map();
        /** public keys */
        this.availableKeys = [];
        this.transport = transport;
    }
    /** Public keys associated with the private keys that the `SignatureProvider` holds */
    JsSignatureProvider.prototype.getAvailableKeys = function () {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                return [2 /*return*/, this.availableKeys];
            });
        });
    };
    /** Sign a transaction */
    JsSignatureProvider.prototype.sign = function (_a) {
        var chainId = _a.chainId, requiredKeys = _a.requiredKeys, serializedTransaction = _a.serializedTransaction, serializedContextFreeData = _a.serializedContextFreeData;
        return __awaiter(this, void 0, void 0, function () {
            var signBuf, SIGNATURE_LENGTH, hashedTx, txBuffer, rsp, buf, signatures;
            return __generator(this, function (_b) {
                switch (_b.label) {
                    case 0:
                        signBuf = Buffer.concat([
                            new Buffer(chainId, 'hex'),
                            new Buffer(serializedTransaction),
                            new Buffer(serializedContextFreeData ? hexToUint8Array(ecc.sha256(serializedContextFreeData)) : new Uint8Array(32))
                        ]);
                        SIGNATURE_LENGTH = 65;
                        hashedTx = Buffer.from(createHash('sha256').update(signBuf).digest());
                        txBuffer = buildTxBuffer(FIO_ACCOUNT_PATH, hashedTx);
                        return [4 /*yield*/, this.transport.Send(0x70, 0xa4, 0, 0, Buffer.concat([txBuffer]))];
                    case 1:
                        rsp = _b.sent();
                        console.log(rsp.data.toString('hex'));
                        buf = Buffer.concat([Buffer.from((rsp.data[64] + 31).toString(16), 'hex'), rsp.data.slice(0, 64)]);
                        console.log(ecc.Signature.fromBuffer(buf).toString());
                        signatures = [ecc.Signature.fromBuffer(buf).toString()];
                        return [2 /*return*/, { signatures: signatures, serializedTransaction: serializedTransaction, serializedContextFreeData: serializedContextFreeData }];
                }
            });
        });
    };
    return JsSignatureProvider;
}());
exports.JsSignatureProvider = JsSignatureProvider;
