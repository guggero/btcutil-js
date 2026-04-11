export interface Base58CheckDecodeResult {
  data: string;
  version: number;
}

export interface Bech32DecodeResult {
  hrp: string;
  data: string;
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
  scriptAddress: string;
  isForNet: boolean;
  hash160?: string;
  witnessVersion?: number;
  witnessProgram?: string;
  pubKeyFormat?: number;
}

export interface WifDecodeResult {
  privateKey: string;
  compressPubKey: boolean;
  publicKey: string;
  network: string;
}

export interface ExtendedKeyInfo {
  key: string;
  isPrivate: boolean;
  depth: number;
  childIndex: number;
  parentFingerprint: number;
  chainCode: string;
  version: string;
  publicKey: string;
}

export interface VerifyResult {
  valid: boolean;
  error?: string;
}

export interface TxInput {
  txid: string;
  vout: number;
  scriptSig: string;
  sequence: number;
  witness: string[];
}

export interface TxOutput {
  value: number;
  scriptPubKey: string;
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
  witnessUtxoScript?: string;
}

export interface PsbtOutputInfo {
  value: number;
  scriptPubKey: string;
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
  filter: string;
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
