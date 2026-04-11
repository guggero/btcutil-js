/** Byte data: hex-encoded string or raw Uint8Array. */
export type Bytes = string | Uint8Array;

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

export interface PartialSigInfo {
  pubKey: Uint8Array;
  signature: Uint8Array;
}

export interface Bip32DerivationInfo {
  pubKey: Uint8Array;
  masterKeyFingerprint: number;
  path: number[];
}

export interface TaprootScriptSpendSigInfo {
  xOnlyPubKey: Uint8Array;
  leafHash: Uint8Array;
  signature: Uint8Array;
  sigHash: number;
}

export interface TaprootLeafScriptInfo {
  controlBlock: Uint8Array;
  script: Uint8Array;
  leafVersion: number;
}

export interface TaprootBip32DerivationInfo {
  xOnlyPubKey: Uint8Array;
  leafHashes: Uint8Array[];
  masterKeyFingerprint: number;
  path: number[];
}

export interface PsbtInputInfo {
  previousTxid: string;
  previousVout: number;
  sequence: number;
  sighashType: number;
  redeemScript: Uint8Array;
  witnessScript: Uint8Array;
  hasNonWitnessUtxo: boolean;
  nonWitnessUtxo?: Uint8Array;
  witnessUtxoValue?: number;
  witnessUtxoScript?: Uint8Array;
  partialSigs: PartialSigInfo[];
  finalScriptSig: Uint8Array;
  finalScriptWitness: Uint8Array;
  bip32Derivation: Bip32DerivationInfo[];
  taprootKeySpendSig: Uint8Array;
  taprootInternalKey: Uint8Array;
  taprootMerkleRoot: Uint8Array;
  taprootScriptSpendSigs: TaprootScriptSpendSigInfo[];
  taprootLeafScripts: TaprootLeafScriptInfo[];
  taprootBip32Derivation: TaprootBip32DerivationInfo[];
}

export interface PsbtOutputInfo {
  value: number;
  scriptPubKey: Uint8Array;
  redeemScript: Uint8Array;
  witnessScript: Uint8Array;
  bip32Derivation: Bip32DerivationInfo[];
  taprootInternalKey: Uint8Array;
  taprootTapTree: Uint8Array;
  taprootBip32Derivation: TaprootBip32DerivationInfo[];
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
