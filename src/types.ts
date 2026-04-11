export interface Base58CheckDecodeResult {
  data: Uint8Array;
  version: number;
}

export interface Bech32DecodeResult {
  hrp: string;
  data: Uint8Array;
}

export interface AddressInfo {
  address: string;
  type:
    | 'p2pkh'
    | 'p2sh'
    | 'p2wpkh'
    | 'p2wsh'
    | 'p2tr'
    | 'p2pk'
    | 'unknown';
  scriptAddress: Uint8Array;
  isForNet: boolean;
  hash160?: Uint8Array;
  witnessVersion?: number;
  witnessProgram?: Uint8Array;
  pubKeyFormat?: number;
}

export interface WifDecodeResult {
  privateKey: Uint8Array;
  compressPubKey: boolean;
  publicKey: Uint8Array;
  network: string;
}

export interface ExtendedKeyInfo {
  key: string;
  isPrivate: boolean;
  depth: number;
  childIndex: number;
  parentFingerprint: number;
  chainCode: Uint8Array;
  version: Uint8Array;
  publicKey: Uint8Array;
}

export interface VerifyResult {
  valid: boolean;
  error?: string;
}

export interface TxInput {
  txid: string;
  vout: number;
  scriptSig: Uint8Array;
  sequence: number;
  witness: Uint8Array[];
}

export interface TxOutput {
  value: number;
  scriptPubKey: Uint8Array;
}

export interface TxDecodeResult {
  txid: string;
  wtxid: string;
  version: number;
  locktime: number;
  inputs: TxInput[];
  outputs: TxOutput[];
}

export interface PsbtInputInfo {
  previousTxid: string;
  previousVout: number;
  hasNonWitnessUtxo: boolean;
  hasFinalScriptSig: boolean;
  hasFinalScriptWitness: boolean;
  partialSigCount: number;
  witnessUtxoValue?: number;
  witnessUtxoScript?: Uint8Array;
}

export interface PsbtOutputInfo {
  value: number;
  scriptPubKey: Uint8Array;
}

export interface PsbtDecodeResult {
  version: number;
  locktime: number;
  inputCount: number;
  outputCount: number;
  isComplete: boolean;
  fee: number;
  inputs: PsbtInputInfo[];
  outputs: PsbtOutputInfo[];
}

export interface GcsFilterResult {
  filter: Uint8Array;
  n: number;
}

export type Network =
  | 'mainnet'
  | 'testnet'
  | 'testnet3'
  | 'testnet4'
  | 'signet'
  | 'regtest'
  | 'simnet';
