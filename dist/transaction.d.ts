/** @return a packed and signed transaction formatted ready to be pushed to chain. */
export declare function prepareTransaction({ transaction, chainId, privateKeys, abiMap, textDecoder, textEncoder }: {
    transaction: any;
    chainId: string;
    privateKeys: string[];
    abiMap: Map<string, any>;
    textDecoder?: TextDecoder;
    textEncoder?: TextEncoder;
}): Promise<{
    signatures: any;
    compression: number;
    packed_context_free_data: string;
    packed_trx: string;
}>;
export declare function prepareTransactionWithHardwareSign({ transaction, chainId, privateKeys, transport, abiMap, textDecoder, textEncoder }: {
    transaction: any;
    chainId: string;
    transport: object;
    privateKeys: string[];
    abiMap: Map<string, any>;
    textDecoder?: TextDecoder;
    textEncoder?: TextEncoder;
}): Promise<{
    signatures: any;
    compression: number;
    packed_context_free_data: string;
    packed_trx: string;
}>;
