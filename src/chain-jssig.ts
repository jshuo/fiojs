/**
 * @module JS-Sig
 */
// copyright defined in fiojs/LICENSE.txt
// @ts-nocheck
import { SignatureProvider, SignatureProviderArgs } from './chain-api-interfaces';
const ecc = require('./ecc');
var createHash = require('create-hash')

const HD_HARDENED = 0x80000000
const fromHardened = (n) => (n & ~HD_HARDENED) >>> 0
 //@ts-ignore
function splitPath(path) {
  const elements = path.split('/')
  const pathLen = elements.length
  if (pathLen < 2 || pathLen > 6) throw Error('Invalid Path, only support 1 to 5 depth path')

  const pathProps = {}
   //@ts-ignore
  pathProps.pathNum = pathLen - 1
   //@ts-ignore
  elements.forEach((element, index) => {
    if (index === 0) return
    const props = {}
    const isHardened = element.length > 1 && element[element.length - 1] === "'"
    if (isHardened) {
      //@ts-ignore
      props.value = parseInt(element.slice(0, -1), 10)
    } else {
         //@ts-ignore
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
     //@ts-ignore
  const getHardenedValue = (pathLevel) => {
    if (pathLevel && pathLevel.isHardened) return pathLevel.value + HARDENED_OFFSET
    else if (pathLevel && !pathLevel.isHardened) return pathLevel.value
    else throw Error('Build path error')
  }
  const pathProps = splitPath(path)
  let pathNum = num && num >= 1 && num < 6 ? num : pathProps.pathNum
  const buf = Buffer.alloc(4 * pathNum)
   //@ts-ignore
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
 //@ts-ignore
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


function hexToUint8Array(hex: string) {
    if (typeof hex !== 'string') {
        throw new Error('Expected string containing hex digits');
    }
    if (hex.length % 2) {
        throw new Error('Odd number of hex digits');
    }
    const l = hex.length / 2;
    const result = new Uint8Array(l);
    for (let i = 0; i < l; ++i) {
        const x = parseInt(hex.substr(i * 2, 2), 16);
        if (Number.isNaN(x)) {
            throw new Error('Expected hex string');
        }
        result[i] = x;
    }
    return result;
}

/** Signs transactions using in-process private keys */
export class JsSignatureProvider implements SignatureProvider {
    /** map public to private keys */
    public keys = new Map<string, string>();

    /** public keys */
    public availableKeys = [] as string[];    
    public transport: object

    /** @param privateKeys private keys to sign with */
    constructor(privateKeys: string[], transport?: object) {
        this.transport = transport
    }

    /** Public keys associated with the private keys that the `SignatureProvider` holds */
    public async getAvailableKeys() {
        return this.availableKeys;
    }

    /** Sign a transaction */
    public async sign(
        { chainId, requiredKeys, serializedTransaction, serializedContextFreeData }: SignatureProviderArgs
    ) {
        const signBuf = Buffer.concat([
            new Buffer(chainId, 'hex'),
            new Buffer(serializedTransaction),
            new Buffer(
                serializedContextFreeData ?
                    hexToUint8Array(ecc.sha256(serializedContextFreeData)) :
                    new Uint8Array(32)
            ),
        ]);
        const SIGNATURE_LENGTH = 65
        const hashedTx = []
        const FIO_ACCOUNT_PATH = `m/44'/235'/0'/0/0`
        hashedTx.push(Buffer.from(createHash('sha256').update(signBuf).digest()))

        const txBuffer = buildTxBuffer([FIO_ACCOUNT_PATH], hashedTx)
        const rsp = await this.transport.Send(0x70, 0xa4, 0, 0, Buffer.concat([txBuffer]))
        console.log(rsp.data.toString('hex'))
        buf = Buffer.concat([Buffer.from((rsp.data[64] + 31).toString(16), 'hex'), rsp.data.slice(0, 64)]);
        console.log(ecc.Signature.fromBuffer(buf).toString());
        signatures = [ecc.Signature.fromBuffer(buf).toString()];
        return { signatures, serializedTransaction, serializedContextFreeData };
    }
}