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

export interface TimeConstraints {
    constrained: boolean;
    validAtTime: number;
    validAtAge: number;
}

export interface VerifyResult {
  valid: boolean;
  timeConstraints?: TimeConstraints;
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
  /** Base58-encoded xpub/xprv string (e.g. `"xpub6CUGRUo..."`).
   *  The PSBT wire format stores 78 raw bytes; the codec converts both
   *  ways so consumers can read and write the human-friendly form. */
  extendedKey: string;
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
  /** BIP-322 generic signed message (global key type 0x09). An empty string
   *  is a valid message, so absent (`undefined`) is distinct from `""`. */
  genericSignedMessage?: string;
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

// ---------------------------------------------------------------------------
// Output descriptor shapes (BIP380)
// ---------------------------------------------------------------------------

/** The classification of a descriptor's top-level output. */
export type DescType =
  | 'Bare'
  | 'Sh'
  | 'Pkh'
  | 'Wpkh'
  | 'Wsh'
  | 'ShWsh'
  | 'ShWpkh'
  | 'Tr';

/** The kind of a semantic-policy node produced by `Descriptor.lift()`. */
export type SemanticPolicyType =
  | 'unsatisfiable'
  | 'trivial'
  | 'key'
  | 'after'
  | 'older'
  | 'sha256'
  | 'hash256'
  | 'ripemd160'
  | 'hash160'
  | 'thresh';

/** An abstract policy corresponding to the semantics of a descriptor, as
 *  returned by `Descriptor.lift()`. A recursive tree; only the fields relevant
 *  to `type` are present. */
export interface SemanticPolicy {
  type: SemanticPolicyType;
  /** Present when `type` is `"key"`: the public key string. */
  key?: string;
  /** Present when `type` is `"after"` or `"older"`: the locktime value. */
  lockTime?: number;
  /** Present for the hash types: the hex-encoded hash value. */
  hash?: string;
  /** Present when `type` is `"thresh"`: the required threshold count. */
  threshold?: number;
  /** Present when `type` is `"thresh"`: the nested policies. */
  policies?: SemanticPolicy[];
}

/** The present/missing lookup table used to construct a spending plan via
 *  `Descriptor.planAt()`. Every lookup is optional; an absent one is treated as
 *  "the corresponding signature is not available". Lookups are invoked with the
 *  concrete (derived) key string(s) the descriptor requires at the planned
 *  index. */
export interface DescriptorAssets {
  /** Whether an ECDSA signature is available for the given public key. */
  lookupEcdsaSig?: (pubKey: string) => boolean;
  /** The size, in bytes, of an available taproot key-spend signature, or a
   *  falsy value if none is available. */
  lookupTapKeySpendSig?: (pubKey: string) => number | false | undefined;
  /** The size, in bytes, of an available taproot leaf-script signature, or a
   *  falsy value if none is available. */
  lookupTapLeafScriptSig?: (
    pubKey: string,
    leafHash: string,
  ) => number | false | undefined;
  /** The maximum relative locktime allowed. */
  relativeLocktime?: number;
  /** The maximum absolute locktime allowed. */
  absoluteLocktime?: number;
}

/** Provides the concrete signatures used to complete a plan via
 *  `Plan.satisfy()`. Each lookup returns the signature bytes (a hex string or
 *  Uint8Array), or a falsy value if it cannot provide the data. */
export interface DescriptorSatisfier {
  lookupEcdsaSig?: (pubKey: string) => Bytes | false | undefined;
  lookupTapKeySpendSig?: () => Bytes | false | undefined;
  lookupTapLeafScriptSig?: (
    pubKey: string,
    leafHash: string,
  ) => Bytes | false | undefined;
}

/** The completed witness and scriptSig produced by `Plan.satisfy()`. */
export interface SatisfyResult {
  witness: Uint8Array[];
  scriptSig: Uint8Array;
}
