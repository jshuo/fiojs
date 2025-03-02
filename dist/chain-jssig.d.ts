/**
 * @module JS-Sig
 */
import { SignatureProvider, SignatureProviderArgs } from './chain-api-interfaces';
/** Signs transactions using in-process private keys */
export declare class JsSignatureProvider implements SignatureProvider {
    /** map public to private keys */
    keys: Map<string, string>;
    /** public keys */
    availableKeys: string[];
    transport: object;
    /** @param privateKeys private keys to sign with */
    constructor(privateKeys: string[], transport?: object);
    /** Public keys associated with the private keys that the `SignatureProvider` holds */
    getAvailableKeys(): Promise<string[]>;
    /** Sign a transaction */
    sign({ chainId, requiredKeys, serializedTransaction, serializedContextFreeData }: SignatureProviderArgs): Promise<{
        signatures: any[];
        serializedTransaction: Uint8Array;
        serializedContextFreeData: Uint8Array;
    }>;
}
