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

// ---------------------------------------------------------------------------
// Transaction shapes — split into encode-input (TxData) and decode-output
// (TxDecodeResult, which extends TxData with derived txid/wtxid).
// ---------------------------------------------------------------------------

export interface TxInput {
  /** Previous outpoint txid (display form, big-endian hex). */
  txid: string;
  vout: number;
  /** scriptSig — required slot, may be empty. Accepts hex string or bytes. */
  scriptSig?: Bytes;
  sequence: number;
  witness?: Bytes[];
}

export interface TxOutput {
  value: number;
  scriptPubKey?: Bytes;
}

/** Encode-input shape for `tx.encode`. */
export interface TxData {
  version: number;
  locktime: number;
  inputs: TxInput[];
  outputs: TxOutput[];
}

/** Decode-output shape from `tx.decode`. Includes derived txid/wtxid. */
export interface TxDecodeResult extends TxData {
  txid: string;
  wtxid: string;
  inputs: TxInputDecoded[];
  outputs: TxOutputDecoded[];
}

/** TxInput as returned by `tx.decode`: byte fields are concrete `Uint8Array`. */
export interface TxInputDecoded extends TxInput {
  scriptSig: Uint8Array;
  witness: Uint8Array[];
}

export interface TxOutputDecoded extends TxOutput {
  scriptPubKey: Uint8Array;
}

// ---------------------------------------------------------------------------
// PSBT shapes
// ---------------------------------------------------------------------------

export interface PartialSigInfo {
  pubKey: Bytes;
  signature: Bytes;
}

export interface Bip32DerivationInfo {
  pubKey: Bytes;
  /** Master key fingerprint as 8-char lowercase hex (e.g. "12345678"). */
  masterKeyFingerprint: string;
  /** Numeric path (canonical). */
  path?: number[];
  /** Display path string (e.g. "m/84'/0'/0'/0/0"). On encode, used as a
   *  fallback if `path` is empty/absent. On decode, always populated. */
  pathStr?: string;
}

export interface TaprootScriptSpendSigInfo {
  xOnlyPubKey: Bytes;
  leafHash: Bytes;
  signature: Bytes;
  sigHash: number;
}

export interface TaprootLeafScriptInfo {
  controlBlock: Bytes;
  script: Bytes;
  leafVersion: number;
}

export interface TaprootBip32DerivationInfo {
  xOnlyPubKey: Bytes;
  leafHashes: Bytes[];
  /** Master key fingerprint as 8-char lowercase hex. */
  masterKeyFingerprint: string;
  path?: number[];
  pathStr?: string;
}

export interface PsbtUnknownInfo {
  key: Bytes;
  value: Bytes;
}

export interface PsbtXpubInfo {
  extendedKey: Bytes;
  /** Master key fingerprint as 8-char lowercase hex. */
  masterKeyFingerprint: string;
  path?: number[];
  pathStr?: string;
}

/** Witness UTXO: paired value+script, present-or-absent together. */
export interface WitnessUtxoInfo {
  value: number;
  script: Bytes;
}

/** Per-input PSBT data. Outpoint/sequence live on `unsignedTx.inputs[i]` —
 *  not duplicated here. */
export interface PsbtInputInfo {
  sighashType?: number;
  redeemScript?: Bytes;
  witnessScript?: Bytes;
  nonWitnessUtxo?: Bytes;
  witnessUtxo?: WitnessUtxoInfo;
  partialSigs?: PartialSigInfo[];
  finalScriptSig?: Bytes;
  finalScriptWitness?: Bytes;
  bip32Derivation?: Bip32DerivationInfo[];
  taprootKeySpendSig?: Bytes;
  taprootInternalKey?: Bytes;
  taprootMerkleRoot?: Bytes;
  taprootScriptSpendSigs?: TaprootScriptSpendSigInfo[];
  taprootLeafScripts?: TaprootLeafScriptInfo[];
  taprootBip32Derivation?: TaprootBip32DerivationInfo[];
  unknowns?: PsbtUnknownInfo[];
}

/** Per-output PSBT data. Value/scriptPubKey live on `unsignedTx.outputs[i]`. */
export interface PsbtOutputInfo {
  redeemScript?: Bytes;
  witnessScript?: Bytes;
  bip32Derivation?: Bip32DerivationInfo[];
  taprootInternalKey?: Bytes;
  taprootTapTree?: Bytes;
  taprootBip32Derivation?: TaprootBip32DerivationInfo[];
  unknowns?: PsbtUnknownInfo[];
}

/** Encode-input shape for `psbt.encode`. */
export interface PsbtData {
  unsignedTx: TxData;
  xpubs?: PsbtXpubInfo[];
  unknowns?: PsbtUnknownInfo[];
  inputs: PsbtInputInfo[];
  outputs: PsbtOutputInfo[];
}

/** Decode-output shape from `psbt.decode`. Adds derived `fee` / `isComplete`
 *  and the unsigned tx with computed txid/wtxid. */
export interface PsbtDecodeResult extends PsbtData {
  unsignedTx: TxDecodeResult;
  xpubs: PsbtXpubInfo[];
  unknowns: PsbtUnknownInfo[];
  inputs: PsbtInputInfo[];
  outputs: PsbtOutputInfo[];
  fee: number;
  isComplete: boolean;
}

/** A flattened unknown TLV entry from `psbt.allUnknowns`. */
export interface PsbtUnknownEntry {
  level: 'global' | 'input' | 'output';
  /** -1 for global, otherwise the input/output index. */
  index: number;
  key: Uint8Array;
  value: Uint8Array;
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
