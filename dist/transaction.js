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
Object.defineProperty(exports, "__esModule", { value: true });
var chain_api_1 = require("./chain-api");
var chain_jssig_1 = require("./chain-jssig");
var chain_numeric_1 = require("./chain-numeric");
/** @return a packed and signed transaction formatted ready to be pushed to chain. */
function prepareTransaction(_a) {
    var transaction = _a.transaction, chainId = _a.chainId, privateKeys = _a.privateKeys, abiMap = _a.abiMap, textDecoder = _a.textDecoder, textEncoder = _a.textEncoder;
    return __awaiter(this, void 0, void 0, function () {
        var signatureProvider, authorityProvider, abiProvider, api, _b, signatures, serializedTransaction, serializedContextFreeData;
        return __generator(this, function (_c) {
            switch (_c.label) {
                case 0:
                    signatureProvider = new chain_jssig_1.JsSignatureProvider(privateKeys);
                    authorityProvider = chain_api_1.signAllAuthorityProvider;
                    abiProvider = {
                        getRawAbi: function (accountName) {
                            return __awaiter(this, void 0, void 0, function () {
                                var rawAbi, abi, binaryAbi;
                                return __generator(this, function (_a) {
                                    rawAbi = abiMap.get(accountName);
                                    if (!rawAbi) {
                                        throw new Error("Missing ABI for account " + accountName);
                                    }
                                    abi = chain_numeric_1.base64ToBinary(rawAbi.abi);
                                    binaryAbi = { accountName: rawAbi.account_name, abi: abi };
                                    return [2 /*return*/, binaryAbi];
                                });
                            });
                        }
                    };
                    api = new chain_api_1.Api({
                        signatureProvider: signatureProvider, authorityProvider: authorityProvider, abiProvider: abiProvider, chainId: chainId, textDecoder: textDecoder, textEncoder: textEncoder
                    });
                    return [4 /*yield*/, api.transact(transaction)];
                case 1:
                    _b = _c.sent(), signatures = _b.signatures, serializedTransaction = _b.serializedTransaction, serializedContextFreeData = _b.serializedContextFreeData;
                    return [2 /*return*/, {
                            signatures: signatures,
                            compression: 0,
                            packed_context_free_data: chain_numeric_1.arrayToHex(serializedContextFreeData || new Uint8Array(0)),
                            packed_trx: chain_numeric_1.arrayToHex(serializedTransaction),
                        }];
            }
        });
    });
}
exports.prepareTransaction = prepareTransaction;
function prepareTransactionWithHardwareSign(_a) {
    var transaction = _a.transaction, chainId = _a.chainId, privateKeys = _a.privateKeys, transport = _a.transport, abiMap = _a.abiMap, textDecoder = _a.textDecoder, textEncoder = _a.textEncoder;
    return __awaiter(this, void 0, void 0, function () {
        var signatureProvider, authorityProvider, abiProvider, api, _b, signatures, serializedTransaction, serializedContextFreeData;
        return __generator(this, function (_c) {
            switch (_c.label) {
                case 0:
                    signatureProvider = new chain_jssig_1.JsSignatureProvider(privateKeys, transport);
                    authorityProvider = chain_api_1.signAllAuthorityProvider;
                    abiProvider = {
                        getRawAbi: function (accountName) {
                            return __awaiter(this, void 0, void 0, function () {
                                var rawAbi, abi, binaryAbi;
                                return __generator(this, function (_a) {
                                    rawAbi = abiMap.get(accountName);
                                    if (!rawAbi) {
                                        throw new Error("Missing ABI for account " + accountName);
                                    }
                                    abi = chain_numeric_1.base64ToBinary(rawAbi.abi);
                                    binaryAbi = { accountName: rawAbi.account_name, abi: abi };
                                    return [2 /*return*/, binaryAbi];
                                });
                            });
                        }
                    };
                    api = new chain_api_1.Api({
                        signatureProvider: signatureProvider, authorityProvider: authorityProvider, abiProvider: abiProvider, chainId: chainId, textDecoder: textDecoder, textEncoder: textEncoder
                    });
                    return [4 /*yield*/, api.transact(transaction)];
                case 1:
                    _b = _c.sent(), signatures = _b.signatures, serializedTransaction = _b.serializedTransaction, serializedContextFreeData = _b.serializedContextFreeData;
                    return [2 /*return*/, {
                            signatures: signatures,
                            compression: 0,
                            packed_context_free_data: chain_numeric_1.arrayToHex(serializedContextFreeData || new Uint8Array(0)),
                            packed_trx: chain_numeric_1.arrayToHex(serializedTransaction),
                        }];
            }
        });
    });
}
exports.prepareTransactionWithHardwareSign = prepareTransactionWithHardwareSign;
