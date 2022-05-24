/**
 * @module JS-Sig
 */
// copyright defined in fiojs/LICENSE.txt
// @ts-nocheck
import { SignatureProvider, SignatureProviderArgs } from './chain-api-interfaces'
const ecc = require('./ecc')
var createHash = require('create-hash')
var bippath = require('bip32-path')

//@ts-ignore
const FIO_ACCOUNT_PATH = `m/44'/235'/0'/0/0`
function buildTxBuffer(bip32path, message, tp, chainId) {
  const head = [],
    data = []
  const headerBuffer = Buffer.alloc(4)
  headerBuffer.writeUInt16LE(tp, 0)
  headerBuffer.writeUInt16LE(chainId, 2)
  let patharrary = bippath.fromString(bip32path).toPathArray()
  const pathBuffer = Buffer.alloc(4 * patharrary.length)
  for (let i = 0; i < patharrary.length; i++) {
    pathBuffer.writeUInt32LE(patharrary[i], i * 4)
  }
  head.push(Buffer.concat([Buffer.from([patharrary.length * 4 + 4]), headerBuffer, pathBuffer]))

  // fixed 2 byte length
  const preparedTxLenBuf = Buffer.alloc(2)
  preparedTxLenBuf.writeUInt16BE(message.length, 0)
  //@ts-ignore
  data.push(Buffer.concat([preparedTxLenBuf, message]))
  const singlepath = 1 
  return Buffer.concat([Buffer.from([singlepath]), ...head, ...data])
}

function hexToUint8Array(hex: string) {
  if (typeof hex !== 'string') {
    throw new Error('Expected string containing hex digits')
  }
  if (hex.length % 2) {
    throw new Error('Odd number of hex digits')
  }
  const l = hex.length / 2
  const result = new Uint8Array(l)
  for (let i = 0; i < l; ++i) {
    const x = parseInt(hex.substr(i * 2, 2), 16)
    if (Number.isNaN(x)) {
      throw new Error('Expected hex string')
    }
    result[i] = x
  }
  return result
}

/** Signs transactions using in-process private keys */
export class JsSignatureProvider implements SignatureProvider {
  /** map public to private keys */
  public keys = new Map<string, string>()

  /** public keys */
  public availableKeys = [] as string[]
  public transport: object

  /** @param privateKeys private keys to sign with */
  constructor(privateKeys: string[], transport?: object) {
    this.transport = transport
  }

  /** Public keys associated with the private keys that the `SignatureProvider` holds */
  public async getAvailableKeys() {
    return this.availableKeys
  }

  /** Sign a transaction */
  public async sign({ chainId, requiredKeys, serializedTransaction, serializedContextFreeData }: SignatureProviderArgs) {
    const signBuf = Buffer.concat([
      new Buffer(chainId, 'hex'),
      new Buffer(serializedTransaction),
      new Buffer(serializedContextFreeData ? hexToUint8Array(ecc.sha256(serializedContextFreeData)) : new Uint8Array(32))
    ])
    const SIGNATURE_LENGTH = 65
    const hashedTx = Buffer.from(createHash('sha256').update(signBuf).digest())
    const txBuffer = buildTxBuffer(FIO_ACCOUNT_PATH, hashedTx)
    const rsp = await this.transport.Send(0x70, 0xa4, 0, 0, Buffer.concat([txBuffer]))
    console.log(rsp.data.toString('hex'))
    const buf = Buffer.concat([Buffer.from((rsp.data[64] + 31).toString(16), 'hex'), rsp.data.slice(0, 64)])
    console.log(ecc.Signature.fromBuffer(buf).toString())
    const signatures = [ecc.Signature.fromBuffer(buf).toString()]
    return { signatures, serializedTransaction, serializedContextFreeData }
  }
}
