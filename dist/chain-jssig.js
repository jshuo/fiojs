"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
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
var __spreadArray = (this && this.__spreadArray) || function (to, from, pack) {
    if (pack || arguments.length === 2) for (var i = 0, l = from.length, ar; i < l; i++) {
        if (ar || !(i in from)) {
            if (!ar) ar = Array.prototype.slice.call(from, 0, i);
            ar[i] = from[i];
        }
    }
    return to.concat(ar || Array.prototype.slice.call(from));
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.JsSignatureProvider = void 0;
var ecc = require('./ecc');
var createHash = require('create-hash');
var HD_HARDENED = 0x80000000;
var fromHardened = function (n) { return (n & ~HD_HARDENED) >>> 0; };
//@ts-ignore
function splitPath(path) {
    var elements = path.split('/');
    var pathLen = elements.length;
    if (pathLen < 2 || pathLen > 6)
        throw Error('Invalid Path, only support 1 to 5 depth path');
    var pathProps = {};
    //@ts-ignore
    pathProps.pathNum = pathLen - 1;
    //@ts-ignore
    elements.forEach(function (element, index) {
        if (index === 0)
            return;
        var props = {};
        var isHardened = element.length > 1 && element[element.length - 1] === "'";
        if (isHardened) {
            //@ts-ignore
            props.value = parseInt(element.slice(0, -1), 10);
        }
        else {
            //@ts-ignore
            props.value = parseInt(element, 10);
        }
        props.isHardened = isHardened;
        props.depth = index;
        switch (index) {
            case 1:
                pathProps.purpose = props;
                break;
            case 2:
                pathProps.coinType = props;
                break;
            case 3:
                pathProps.accountId = props;
                break;
            case 4:
                pathProps.change = props;
                break;
            case 5:
                pathProps.addressIndex = props;
                break;
        }
    });
    return pathProps;
}
var HARDENED_OFFSET = 0x80000000;
function buildPathBuffer(path, num) {
    //@ts-ignore
    var getHardenedValue = function (pathLevel) {
        if (pathLevel && pathLevel.isHardened)
            return pathLevel.value + HARDENED_OFFSET;
        else if (pathLevel && !pathLevel.isHardened)
            return pathLevel.value;
        else
            throw Error('Build path error');
    };
    var pathProps = splitPath(path);
    var pathNum = num && num >= 1 && num < 6 ? num : pathProps.pathNum;
    var buf = Buffer.alloc(4 * pathNum);
    //@ts-ignore
    var purpose = pathProps.purpose, coinType = pathProps.coinType, accountId = pathProps.accountId, change = pathProps.change, addressIndex = pathProps.addressIndex;
    for (var i = 0; i < pathNum; i++) {
        // buffer need to start from 0 bytes
        switch (i) {
            case 0:
                buf.writeUInt32LE(getHardenedValue(purpose), i * 4);
                break;
            case 1:
                buf.writeUInt32LE(getHardenedValue(coinType), i * 4);
                break;
            case 2:
                buf.writeUInt32LE(getHardenedValue(accountId), i * 4);
                break;
            case 3:
                buf.writeUInt32LE(getHardenedValue(change), i * 4);
                break;
            case 4:
                buf.writeUInt32LE(getHardenedValue(addressIndex), i * 4);
                break;
        }
    }
    return { pathNum: pathNum, pathBuffer: buf };
}
//@ts-ignore
function buildTxBuffer(paths, txs, tp, chainId) {
    if (paths.length != txs.length)
        throw Error('Inconsistent length of paths and txs');
    var head = [], data = [];
    for (var i = 0; i < paths.length; i++) {
        var headerBuffer = Buffer.alloc(4);
        headerBuffer.writeUInt16LE(tp, 0);
        headerBuffer.writeUInt16LE(chainId, 2);
        var path = paths[i];
        var _a = buildPathBuffer(path), pathNum = _a.pathNum, pathBuffer = _a.pathBuffer;
        // generic prepare can use 3 or 5 path level key to sign
        if (pathNum !== 5 && pathNum !== 3)
            throw Error('Invalid Path for Signing Transaction');
        //@ts-ignore
        head.push(Buffer.concat([Buffer.from([pathNum * 4 + 4]), headerBuffer, pathBuffer]));
        // fixed 2 byte length
        var preparedTxLenBuf = Buffer.alloc(2);
        preparedTxLenBuf.writeUInt16BE(txs[i].length, 0);
        //@ts-ignore
        data.push(Buffer.concat([preparedTxLenBuf, txs[i]]));
    }
    return Buffer.concat(__spreadArray(__spreadArray([Buffer.from([paths.length])], __read(head), false), __read(data), false));
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
            var signBuf, SIGNATURE_LENGTH, hashedTx, FIO_ACCOUNT_PATH, txBuffer, rsp, buf, signatures;
            return __generator(this, function (_b) {
                switch (_b.label) {
                    case 0:
                        signBuf = Buffer.concat([
                            new Buffer(chainId, 'hex'),
                            new Buffer(serializedTransaction),
                            new Buffer(serializedContextFreeData ?
                                hexToUint8Array(ecc.sha256(serializedContextFreeData)) :
                                new Uint8Array(32)),
                        ]);
                        SIGNATURE_LENGTH = 65;
                        hashedTx = [];
                        FIO_ACCOUNT_PATH = "m/44'/235'/0'/0/0";
                        hashedTx.push(Buffer.from(createHash('sha256').update(signBuf).digest()));
                        txBuffer = buildTxBuffer([FIO_ACCOUNT_PATH], hashedTx);
                        return [4 /*yield*/, this.transport.Send(0x70, 0xa4, 0, 0, Buffer.concat([txBuffer]))];
                    case 1:
                        rsp = _b.sent();
                        console.log(rsp.data.toString('hex'));
                        buf = Buffer.concat([Buffer.from((rsp.data[64] + 31).toString(16), 'hex'), rsp.data.slice(0, 63)]);
                        console.log(ecc.Signature.fromBuffer(buf));
                        signatures = [rsp.data];
                        return [2 /*return*/, { signatures: signatures, serializedTransaction: serializedTransaction, serializedContextFreeData: serializedContextFreeData }];
                }
            });
        });
    };
    return JsSignatureProvider;
}());
exports.JsSignatureProvider = JsSignatureProvider;
