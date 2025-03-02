"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
/**
 * @module AccountName
 */
var bs58 = require("bs58");
var Long = require("long");
var PublicKey = require('./ecc').PublicKey;
/**
    Hashes a public key to a valid FIOIO account name.

    @arg {string} pubkey
    @return {string} valid FIOIO account name
*/
function accountHash(pubkey) {
    if (!PublicKey.isValid(pubkey, 'FIO')) {
        throw new TypeError('invalid public key');
    }
    pubkey = pubkey.substring('FIO'.length, pubkey.length);
    var decoded58 = bs58.decode(pubkey);
    var long = shortenKey(decoded58);
    var output = stringFromUInt64T(long);
    return output;
}
exports.accountHash = accountHash;
function shortenKey(key) {
    var res = Long.fromValue(0, true);
    var temp = Long.fromValue(0, true);
    var toShift = 0;
    var i = 1;
    var len = 0;
    while (len <= 12) {
        //assert(i < 33, "Means the key has > 20 bytes with trailing zeroes...")
        temp = Long.fromValue(key[i], true).and(len == 12 ? 0x0f : 0x1f);
        if (temp == 0) {
            i += 1;
            continue;
        }
        if (len == 12) {
            toShift = 0;
        }
        else {
            toShift = (5 * (12 - len) - 1);
        }
        temp = Long.fromValue(temp, true).shiftLeft(toShift);
        res = Long.fromValue(res, true).or(temp);
        len += 1;
        i += 1;
    }
    return res;
}
function stringFromUInt64T(temp) {
    var charmap = ".12345abcdefghijklmnopqrstuvwxyz".split('');
    var str = new Array(13);
    str[12] = charmap[Long.fromValue(temp, true).and(0x0f)];
    temp = Long.fromValue(temp, true).shiftRight(4);
    for (var i = 1; i <= 12; i++) {
        var c = charmap[Long.fromValue(temp, true).and(0x1f)];
        str[12 - i] = c;
        temp = Long.fromValue(temp, true).shiftRight(5);
    }
    var result = str.join('');
    if (result.length > 12) {
        result = result.substring(0, 12);
    }
    return result;
}
