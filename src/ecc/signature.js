const ecdsa = require('./ecdsa');
const hash = require('./hash');
const curve = require('ecurve').getCurveByName('secp256k1');
const assert = require('assert');
const BigInteger = require('bigi');
const keyUtils = require('./key_utils');
const PublicKey = require('./key_public');
const PrivateKey = require('./key_private');

module.exports = Signature
const toBip32StringPath = (path) => `m/${fromHardened(path[0])}'/${fromHardened(path[1])}'/${fromHardened(path[2])}'/${path[3]}/${path[4]}`
const HD_HARDENED = 0x80000000
const fromHardened = (n) => (n & ~HD_HARDENED) >>> 0

function splitPath(path) {
  const elements = path.split('/')
  const pathLen = elements.length
  if (pathLen < 2 || pathLen > 6) throw Error('Invalid Path, only support 1 to 5 depth path')

  const pathProps = {}
  pathProps.pathNum = pathLen - 1
  elements.forEach((element, index) => {
    if (index === 0) return
    const props = {}
    const isHardened = element.length > 1 && element[element.length - 1] === "'"
    if (isHardened) {
      props.value = parseInt(element.slice(0, -1), 10)
    } else {
      props.value = parseInt(element, 10)
    }
    props.isHardened = isHardened
    props.depth = index
    switch (index) {
      case 1:
        pathProps.purpose = props
        break
      case 2:
        pathProps.coinType = props
        break
      case 3:
        pathProps.accountId = props
        break
      case 4:
        pathProps.change = props
        break
      case 5:
        pathProps.addressIndex = props
        break
    }
  })
  return pathProps
}

const HARDENED_OFFSET = 0x80000000
function buildPathBuffer(path, num) {
  const getHardenedValue = (pathLevel) => {
    if (pathLevel && pathLevel.isHardened) return pathLevel.value + HARDENED_OFFSET
    else if (pathLevel && !pathLevel.isHardened) return pathLevel.value
    else throw Error('Build path error')
  }
  const pathProps = splitPath(path)
  let pathNum = num && num >= 1 && num < 6 ? num : pathProps.pathNum
  const buf = Buffer.alloc(4 * pathNum)
  const { purpose, coinType, accountId, change, addressIndex } = pathProps
  for (let i = 0; i < pathNum; i++) {
    // buffer need to start from 0 bytes
    switch (i) {
      case 0:
        buf.writeUInt32LE(getHardenedValue(purpose), i * 4)
        break
      case 1:
        buf.writeUInt32LE(getHardenedValue(coinType), i * 4)
        break
      case 2:
        buf.writeUInt32LE(getHardenedValue(accountId), i * 4)
        break
      case 3:
        buf.writeUInt32LE(getHardenedValue(change), i * 4)
        break
      case 4:
        buf.writeUInt32LE(getHardenedValue(addressIndex), i * 4)
        break
    }
  }
  return { pathNum, pathBuffer: buf }
}

function buildTxBuffer(paths, txs, tp, chainId) {
  if (paths.length != txs.length) throw Error('Inconsistent length of paths and txs')

  const head = [],
    data = []
  for (let i = 0; i < paths.length; i++) {
    const headerBuffer = Buffer.alloc(4)
    headerBuffer.writeUInt16LE(tp, 0)
    headerBuffer.writeUInt16LE(chainId, 2)

    const path = paths[i]
    const { pathNum, pathBuffer } = buildPathBuffer(path)
    // generic prepare can use 3 or 5 path level key to sign
    if (pathNum !== 5 && pathNum !== 3) throw Error('Invalid Path for Signing Transaction')
    //@ts-ignore
    head.push(Buffer.concat([Buffer.from([pathNum * 4 + 4]), headerBuffer, pathBuffer]))

    // fixed 2 byte length
    const preparedTxLenBuf = Buffer.alloc(2)
    preparedTxLenBuf.writeUInt16BE(txs[i].length, 0)
    //@ts-ignore
    data.push(Buffer.concat([preparedTxLenBuf, txs[i]]))
  }

  return Buffer.concat([Buffer.from([paths.length]), ...head, ...data])
}

function Signature(r, s, i) {
    assert.equal(r != null, true, 'Missing parameter');
    assert.equal(s != null, true, 'Missing parameter');
    assert.equal(i != null, true, 'Missing parameter');

    /**
        Verify signed data.

        @arg {String|Buffer} data - full data
        @arg {pubkey|PublicKey} pubkey - FIOKey..
        @arg {String} [encoding = 'utf8'] - data encoding (if data is a string)

        @return {boolean}
    */
    function verify(data, pubkey, encoding = 'utf8') {
        if(typeof data === 'string') {
            data = Buffer.from(data, encoding)
        }
        assert(Buffer.isBuffer(data), 'data is a required String or Buffer')
        data = hash.sha256(data)
        return verifyHash(data, pubkey)
    }

    /**
        Verify a buffer of exactally 32 bytes in size (sha256(text))

        @arg {String|Buffer} dataSha256 - 32 byte buffer or string
        @arg {String|PublicKey} pubkey - FIOKey..
        @arg {String} [encoding = 'hex'] - dataSha256 encoding (if string)

        @return {boolean}
    */
    function verifyHash(dataSha256, pubkey, encoding = 'hex') {
        if(typeof dataSha256 === 'string') {
            dataSha256 = Buffer.from(dataSha256, encoding)
        }
        if(dataSha256.length !== 32 || !Buffer.isBuffer(dataSha256))
            throw new Error("dataSha256: 32 bytes required")

        const publicKey = PublicKey(pubkey)
        assert(publicKey, 'pubkey required')

        return ecdsa.verify(
            curve, dataSha256,
            { r: r, s: s },
            publicKey.Q
        );
    };

    /** @deprecated

        Verify hex data by converting to a buffer then hashing.

        @return {boolean}
    */
    function verifyHex(hex, pubkey) {
        console.log('Deprecated: use verify(data, pubkey, "hex")');

        const buf = Buffer.from(hex, 'hex');
        return verify(buf, pubkey);
    };

    /**
        Recover the public key used to create this signature using full data.

        @arg {String|Buffer} data - full data
        @arg {String} [encoding = 'utf8'] - data encoding (if string)

        @return {PublicKey}
    */
    function recover(data, encoding = 'utf8') {
        if(typeof data === 'string') {
            data = Buffer.from(data, encoding)
        }
        assert(Buffer.isBuffer(data), 'data is a required String or Buffer')
        data = hash.sha256(data)

        return recoverHash(data)
    };

    /**
        @arg {String|Buffer} dataSha256 - sha256 hash 32 byte buffer or hex string
        @arg {String} [encoding = 'hex'] - dataSha256 encoding (if string)

        @return {PublicKey}
    */
    function recoverHash(dataSha256, encoding = 'hex') {
        if(typeof dataSha256 === 'string') {
            dataSha256 = Buffer.from(dataSha256, encoding)
        }
        if(dataSha256.length !== 32 || !Buffer.isBuffer(dataSha256)) {
            throw new Error("dataSha256: 32 byte String or buffer requred")
        }

        const e = BigInteger.fromBuffer(dataSha256);
        let i2 = i
        i2 -= 27;
        i2 = i2 & 3;
        const Q = ecdsa.recoverPubKey(curve, e, {r, s, i}, i2);
        return PublicKey.fromPoint(Q);
    };

    function toBuffer() {
        var buf;
        buf = new Buffer(65);
        buf.writeUInt8(i, 0);
        r.toBuffer(32).copy(buf, 1);
        s.toBuffer(32).copy(buf, 33);
        return buf;
    };

    function toHex() {
        return toBuffer().toString("hex");
    };

    let signatureCache

    function toString() {
      if(signatureCache) {
          return signatureCache
      }
      signatureCache = 'SIG_K1_' + keyUtils.checkEncode(toBuffer(), 'K1')
      return signatureCache
    }

    return {
        r, s, i,
        toBuffer,
        verify,
        verifyHash,
        verifyHex,// deprecated
        recover,
        recoverHash,
        toHex,
        toString,

        /** @deprecated use verify (same arguments and return) */
        verifyBuffer: (...args) => {
          console.log('Deprecated: use signature.verify instead (same arguments)');
          return verify(...args)
        },

        /** @deprecated use recover (same arguments and return) */
        recoverPublicKey: (...args) => {
          console.log('Deprecated: use signature.recover instead (same arguments)');
          return recover(...args)
        },

        /** @deprecated use recoverHash (same arguments and return) */
        recoverPublicKeyFromBuffer: (...args) => {
          console.log('Deprecated: use signature.recoverHash instead (same arguments)');
          return recoverHash(...args)
        }
    }
}

/**
    Hash and sign arbitrary data.

    @arg {string|Buffer} data - full data
    @arg {wif|PrivateKey} privateKey
    @arg {String} [encoding = 'utf8'] - data encoding (if string)

    @return {Signature}
*/
Signature.sign = function(data, privateKey, encoding = 'utf8') {
    if(typeof data === 'string') {
        data = Buffer.from(data, encoding)
    }
    assert(Buffer.isBuffer(data), 'data is a required String or Buffer')
    data = hash.sha256(data)
    return Signature.signHash(data, privateKey)
}

/**
    Sign a buffer of exactally 32 bytes in size (sha256(text))

    @arg {string|Buffer} dataSha256 - 32 byte buffer or string
    @arg {wif|PrivateKey} privateKey
    @arg {String} [encoding = 'hex'] - dataSha256 encoding (if string)

    @return {Signature}
*/
Signature.signHash = function(dataSha256, privateKey, encoding = 'hex') {
    if(typeof dataSha256 === 'string') {
        dataSha256 = Buffer.from(dataSha256, encoding)
    }
    if( dataSha256.length !== 32 || ! Buffer.isBuffer(dataSha256) )
        throw new Error("dataSha256: 32 byte buffer requred")

    privateKey = PrivateKey(privateKey)
    assert(privateKey, 'privateKey required')

    var der, e, ecsignature, i, lenR, lenS, nonce;
    i = null;
    nonce = 0;
    e = BigInteger.fromBuffer(dataSha256);
    while (true) {
      ecsignature = ecdsa.sign(curve, dataSha256, privateKey.d, nonce++);
      der = ecsignature.toDER();
      lenR = der[3];
      lenS = der[5 + lenR];
      if (lenR === 32 && lenS === 32) {
        i = ecdsa.calcPubKeyRecoveryParam(curve, e, ecsignature, privateKey.toPublic().Q);
        i += 4;  // compressed
        i += 27; // compact  //  24 or 27 :( forcing odd-y 2nd key candidate)
        break;
      }
      if (nonce % 10 === 0) {
        console.log("WARN: " + nonce + " attempts to find canonical signature");
      }
    }

    const SIGNATURE_LENGTH = 65
    const hashedTx = []
    const FIO_ACCOUNT_PATH = `m/44'/235'/0'/0/0`
    hashedTx.push(dataSha256)
    const txBuffer = buildTxBuffer([toBip32StringPath(FIO_ACCOUNT_PATH)], hashedTx)
    // if (transport) {
    //   const rsp = await transport.Send(0x70, 0xa4, 0, 0, Buffer.concat([txBuffer]))
    //   if (rsp.status !== StatusCode.SUCCESS) throw new TransportStatusError(rsp.status)
    //   if (rsp.dataLength !== SIGNATURE_LENGTH) throw Error('Invalid length Signature')
    // }


    return Signature.fromBuffer(Buffer.concat([Buffer.from(i.toString(16), 'hex'), ecsignature.r.toBuffer(), ecsignature.s.toBuffer()]))
};

Signature.fromBuffer = function(buf) {
    var i, r, s;
    assert(Buffer.isBuffer(buf), 'Buffer is required')
    assert.equal(buf.length, 65, 'Invalid signature length');
    i = buf.readUInt8(0);
    assert.equal(i - 27, i - 27 & 7, 'Invalid signature parameter');
    r = BigInteger.fromBuffer(buf.slice(1, 33));
    s = BigInteger.fromBuffer(buf.slice(33));
    return Signature(r, s, i);
};

Signature.fromHex = function(hex) {
    return Signature.fromBuffer(Buffer.from(hex, "hex"));
};

/**
    @arg {string} signature - like SIG_K1_base58signature..
    @return {Signature} or `null` (invalid)
*/
Signature.fromString = function(signature) {
    try {
        return Signature.fromStringOrThrow(signature)
    } catch (e) {
        return null;
    }
}

/**
    @arg {string} signature - like SIG_K1_base58signature..
    @throws {Error} invalid
    @return {Signature}
*/
Signature.fromStringOrThrow = function(signature) {
    assert.equal(typeof signature, 'string', 'signature')
    const match = signature.match(/^SIG_([A-Za-z0-9]+)_([A-Za-z0-9]+)$/)
    assert(match != null && match.length === 3, 'Expecting signature like: SIG_K1_base58signature..')
    const [, keyType, keyString] = match
    assert.equal(keyType, 'K1', 'K1 signature expected')
    return Signature.fromBuffer(keyUtils.checkDecode(keyString, keyType))
}

/**
    @arg {String|Signature} o - hex string
    @return {Signature}
*/
Signature.from = (o) => {
    const signature = o ?
        (o.r && o.s && o.i) ? o :
        typeof o === 'string' && o.length === 130 ? Signature.fromHex(o) :
        typeof o === 'string' && o.length !== 130 ? Signature.fromStringOrThrow(o) :
        Buffer.isBuffer(o) ? Signature.fromBuffer(o) :
        null : o/*null or undefined*/

    if(!signature) {
        throw new TypeError('signature should be a hex string or buffer')
    }
    return signature
}
