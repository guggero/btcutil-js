/**
 * Internal codec for the JSON-shaped values that the WASM bridge uses for
 * PSBT and raw transaction round-tripping.
 *
 * The Go side serialises a struct mirror of `wire.MsgTx` and `psbt.Packet`
 * to JSON, where every byte-blob field is hex-encoded. The TS side converts
 * the hex strings back to `Uint8Array` for the public API surface, and on
 * encode accepts either form (`Bytes = string | Uint8Array`).
 */
import type {
  Bytes,
  TxData,
  TxDecodeResult,
  TxInput,
  TxInputDecoded,
  TxOutput,
  TxOutputDecoded,
  PsbtData,
  PsbtDecodeResult,
  PsbtInputInfo,
  PsbtOutputInfo,
  PsbtUnknownInfo,
  PsbtXpubInfo,
  PartialSigInfo,
  Bip32DerivationInfo,
  TaprootScriptSpendSigInfo,
  TaprootLeafScriptInfo,
  TaprootBip32DerivationInfo,
  WitnessUtxoInfo,
} from './types';

// ---------------------------------------------------------------------------
// Hex helpers
// ---------------------------------------------------------------------------

/** Decode a (possibly empty) hex string into a Uint8Array. */
export function hexToBytes(hex: string): Uint8Array {
  if (hex.length === 0) return new Uint8Array(0);
  if (hex.length % 2 !== 0) {
    throw new Error(`hexToBytes: odd-length hex string`);
  }
  const out = new Uint8Array(hex.length >> 1);
  for (let i = 0; i < out.length; i++) {
    const hi = parseInt(hex.charAt(i * 2), 16);
    const lo = parseInt(hex.charAt(i * 2 + 1), 16);
    if (Number.isNaN(hi) || Number.isNaN(lo)) {
      throw new Error(`hexToBytes: invalid hex character`);
    }
    out[i] = (hi << 4) | lo;
  }
  return out;
}

/** Encode a Uint8Array as a lowercase hex string. */
export function bytesToHex(b: Uint8Array): string {
  let s = '';
  for (let i = 0; i < b.length; i++) {
    s += b[i].toString(16).padStart(2, '0');
  }
  return s;
}

/** Accept either a Uint8Array or a hex string and return hex. */
function toHexAny(b: Bytes | undefined | null): string | undefined {
  if (b == null) return undefined;
  if (typeof b === 'string') return b === '' ? undefined : b;
  if (b.length === 0) return undefined;
  return bytesToHex(b);
}

/** Decode a hex string (possibly empty/undefined) to Uint8Array. */
function fromHexOrEmpty(s: string | undefined | null): Uint8Array {
  if (!s) return new Uint8Array(0);
  return hexToBytes(s);
}

// ---------------------------------------------------------------------------
// Tx
// ---------------------------------------------------------------------------

/** Convert a parsed-JSON tx object to a `TxDecodeResult`. */
export function txFromJson(j: any): TxDecodeResult {
  return {
    txid: j.txid ?? '',
    wtxid: j.wtxid ?? '',
    version: j.version,
    locktime: j.locktime,
    inputs: (j.inputs ?? []).map(txInputFromJson),
    outputs: (j.outputs ?? []).map(txOutputFromJson),
  };
}

/** Convert a `TxData` (or `TxDecodeResult`) to a JSON-ready encode-input. */
export function txToJson(t: TxData): any {
  return {
    version: t.version,
    locktime: t.locktime,
    inputs: t.inputs.map(txInputToJson),
    outputs: t.outputs.map(txOutputToJson),
  };
}

function txInputFromJson(j: any): TxInputDecoded {
  return {
    txid: j.txid ?? '',
    vout: j.vout ?? 0,
    scriptSig: fromHexOrEmpty(j.scriptSig),
    sequence: j.sequence ?? 0,
    witness: (j.witness ?? []).map((w: string) => fromHexOrEmpty(w)),
  };
}

function txInputToJson(i: TxInput): any {
  const out: any = {
    txid: i.txid,
    vout: i.vout,
    sequence: i.sequence,
  };
  const scriptSig = toHexAny(i.scriptSig);
  if (scriptSig != null) out.scriptSig = scriptSig;
  if (i.witness && i.witness.length > 0) {
    out.witness = i.witness.map((w) => toHexAny(w) ?? '');
  }
  return out;
}

function txOutputFromJson(j: any): TxOutputDecoded {
  return {
    value: j.value ?? 0,
    scriptPubKey: fromHexOrEmpty(j.scriptPubKey),
  };
}

function txOutputToJson(o: TxOutput): any {
  const out: any = { value: o.value };
  const script = toHexAny(o.scriptPubKey);
  if (script != null) out.scriptPubKey = script;
  return out;
}

// ---------------------------------------------------------------------------
// PSBT
// ---------------------------------------------------------------------------

/** Convert a parsed-JSON PSBT object to a `PsbtDecodeResult`. */
export function psbtFromJson(j: any): PsbtDecodeResult {
  return {
    unsignedTx: txFromJson(j.unsignedTx),
    xpubs: (j.xpubs ?? []).map(xpubFromJson),
    unknowns: (j.unknowns ?? []).map(unknownFromJson),
    inputs: (j.inputs ?? []).map(psbtInputFromJson),
    outputs: (j.outputs ?? []).map(psbtOutputFromJson),
    fee: j.fee ?? -1,
    isComplete: !!j.isComplete,
  };
}

/** Convert a `PsbtData` to a JSON-ready encode-input. */
export function psbtToJson(p: PsbtData): any {
  const out: any = {
    unsignedTx: txToJson(p.unsignedTx),
    inputs: p.inputs.map(psbtInputToJson),
    outputs: p.outputs.map(psbtOutputToJson),
  };
  if (p.xpubs && p.xpubs.length > 0) out.xpubs = p.xpubs.map(xpubToJson);
  if (p.unknowns && p.unknowns.length > 0) {
    out.unknowns = p.unknowns.map(unknownToJson);
  }
  return out;
}

function psbtInputFromJson(j: any): PsbtInputInfo {
  const out: PsbtInputInfo = {};
  if (typeof j.sighashType === 'number') out.sighashType = j.sighashType;
  if (j.redeemScript) out.redeemScript = hexToBytes(j.redeemScript);
  if (j.witnessScript) out.witnessScript = hexToBytes(j.witnessScript);
  if (j.nonWitnessUtxo) out.nonWitnessUtxo = hexToBytes(j.nonWitnessUtxo);
  if (j.witnessUtxo) {
    out.witnessUtxo = {
      value: j.witnessUtxo.value,
      script: fromHexOrEmpty(j.witnessUtxo.script),
    };
  }
  if (j.partialSigs && j.partialSigs.length > 0) {
    out.partialSigs = j.partialSigs.map(partialSigFromJson);
  }
  if (j.finalScriptSig) out.finalScriptSig = hexToBytes(j.finalScriptSig);
  if (j.finalScriptWitness) {
    out.finalScriptWitness = hexToBytes(j.finalScriptWitness);
  }
  if (j.bip32Derivation && j.bip32Derivation.length > 0) {
    out.bip32Derivation = j.bip32Derivation.map(bip32FromJson);
  }
  if (j.taprootKeySpendSig) {
    out.taprootKeySpendSig = hexToBytes(j.taprootKeySpendSig);
  }
  if (j.taprootInternalKey) {
    out.taprootInternalKey = hexToBytes(j.taprootInternalKey);
  }
  if (j.taprootMerkleRoot) {
    out.taprootMerkleRoot = hexToBytes(j.taprootMerkleRoot);
  }
  if (j.taprootScriptSpendSigs && j.taprootScriptSpendSigs.length > 0) {
    out.taprootScriptSpendSigs = j.taprootScriptSpendSigs.map(taprootSpendSigFromJson);
  }
  if (j.taprootLeafScripts && j.taprootLeafScripts.length > 0) {
    out.taprootLeafScripts = j.taprootLeafScripts.map(taprootLeafFromJson);
  }
  if (j.taprootBip32Derivation && j.taprootBip32Derivation.length > 0) {
    out.taprootBip32Derivation = j.taprootBip32Derivation.map(taprootBip32FromJson);
  }
  if (j.unknowns && j.unknowns.length > 0) {
    out.unknowns = j.unknowns.map(unknownFromJson);
  }
  return out;
}

function psbtInputToJson(i: PsbtInputInfo): any {
  const out: any = {};
  if (typeof i.sighashType === 'number' && i.sighashType !== 0) {
    out.sighashType = i.sighashType;
  }
  const rs = toHexAny(i.redeemScript);    if (rs) out.redeemScript = rs;
  const ws = toHexAny(i.witnessScript);   if (ws) out.witnessScript = ws;
  const nw = toHexAny(i.nonWitnessUtxo);  if (nw) out.nonWitnessUtxo = nw;
  if (i.witnessUtxo) {
    out.witnessUtxo = {
      value: i.witnessUtxo.value,
      script: toHexAny(i.witnessUtxo.script) ?? '',
    };
  }
  if (i.partialSigs && i.partialSigs.length > 0) {
    out.partialSigs = i.partialSigs.map(partialSigToJson);
  }
  const fs = toHexAny(i.finalScriptSig);     if (fs) out.finalScriptSig = fs;
  const fw = toHexAny(i.finalScriptWitness); if (fw) out.finalScriptWitness = fw;
  if (i.bip32Derivation && i.bip32Derivation.length > 0) {
    out.bip32Derivation = i.bip32Derivation.map(bip32ToJson);
  }
  const tks = toHexAny(i.taprootKeySpendSig); if (tks) out.taprootKeySpendSig = tks;
  const tik = toHexAny(i.taprootInternalKey); if (tik) out.taprootInternalKey = tik;
  const tmr = toHexAny(i.taprootMerkleRoot);  if (tmr) out.taprootMerkleRoot = tmr;
  if (i.taprootScriptSpendSigs && i.taprootScriptSpendSigs.length > 0) {
    out.taprootScriptSpendSigs = i.taprootScriptSpendSigs.map(taprootSpendSigToJson);
  }
  if (i.taprootLeafScripts && i.taprootLeafScripts.length > 0) {
    out.taprootLeafScripts = i.taprootLeafScripts.map(taprootLeafToJson);
  }
  if (i.taprootBip32Derivation && i.taprootBip32Derivation.length > 0) {
    out.taprootBip32Derivation = i.taprootBip32Derivation.map(taprootBip32ToJson);
  }
  if (i.unknowns && i.unknowns.length > 0) {
    out.unknowns = i.unknowns.map(unknownToJson);
  }
  return out;
}

function psbtOutputFromJson(j: any): PsbtOutputInfo {
  const out: PsbtOutputInfo = {};
  if (j.redeemScript) out.redeemScript = hexToBytes(j.redeemScript);
  if (j.witnessScript) out.witnessScript = hexToBytes(j.witnessScript);
  if (j.bip32Derivation && j.bip32Derivation.length > 0) {
    out.bip32Derivation = j.bip32Derivation.map(bip32FromJson);
  }
  if (j.taprootInternalKey) {
    out.taprootInternalKey = hexToBytes(j.taprootInternalKey);
  }
  if (j.taprootTapTree) out.taprootTapTree = hexToBytes(j.taprootTapTree);
  if (j.taprootBip32Derivation && j.taprootBip32Derivation.length > 0) {
    out.taprootBip32Derivation = j.taprootBip32Derivation.map(taprootBip32FromJson);
  }
  if (j.unknowns && j.unknowns.length > 0) {
    out.unknowns = j.unknowns.map(unknownFromJson);
  }
  return out;
}

function psbtOutputToJson(o: PsbtOutputInfo): any {
  const out: any = {};
  const rs = toHexAny(o.redeemScript);  if (rs) out.redeemScript = rs;
  const ws = toHexAny(o.witnessScript); if (ws) out.witnessScript = ws;
  if (o.bip32Derivation && o.bip32Derivation.length > 0) {
    out.bip32Derivation = o.bip32Derivation.map(bip32ToJson);
  }
  const tik = toHexAny(o.taprootInternalKey); if (tik) out.taprootInternalKey = tik;
  const ttt = toHexAny(o.taprootTapTree);     if (ttt) out.taprootTapTree = ttt;
  if (o.taprootBip32Derivation && o.taprootBip32Derivation.length > 0) {
    out.taprootBip32Derivation = o.taprootBip32Derivation.map(taprootBip32ToJson);
  }
  if (o.unknowns && o.unknowns.length > 0) {
    out.unknowns = o.unknowns.map(unknownToJson);
  }
  return out;
}

// ---- nested record converters ----

function partialSigFromJson(j: any): PartialSigInfo {
  return {
    pubKey: fromHexOrEmpty(j.pubKey),
    signature: fromHexOrEmpty(j.signature),
  };
}

function partialSigToJson(s: PartialSigInfo): any {
  return {
    pubKey: toHexAny(s.pubKey) ?? '',
    signature: toHexAny(s.signature) ?? '',
  };
}

function bip32FromJson(j: any): Bip32DerivationInfo {
  return {
    pubKey: fromHexOrEmpty(j.pubKey),
    masterKeyFingerprint: j.masterKeyFingerprint ?? '00000000',
    path: j.path ?? [],
    pathStr: j.pathStr ?? undefined,
  };
}

function bip32ToJson(b: Bip32DerivationInfo): any {
  const out: any = {
    pubKey: toHexAny(b.pubKey) ?? '',
    masterKeyFingerprint: b.masterKeyFingerprint,
  };
  if (b.path && b.path.length > 0) out.path = b.path;
  if (b.pathStr) out.pathStr = b.pathStr;
  return out;
}

function taprootSpendSigFromJson(j: any): TaprootScriptSpendSigInfo {
  return {
    xOnlyPubKey: fromHexOrEmpty(j.xOnlyPubKey),
    leafHash: fromHexOrEmpty(j.leafHash),
    signature: fromHexOrEmpty(j.signature),
    sigHash: j.sigHash ?? 0,
  };
}

function taprootSpendSigToJson(s: TaprootScriptSpendSigInfo): any {
  return {
    xOnlyPubKey: toHexAny(s.xOnlyPubKey) ?? '',
    leafHash: toHexAny(s.leafHash) ?? '',
    signature: toHexAny(s.signature) ?? '',
    sigHash: s.sigHash,
  };
}

function taprootLeafFromJson(j: any): TaprootLeafScriptInfo {
  return {
    controlBlock: fromHexOrEmpty(j.controlBlock),
    script: fromHexOrEmpty(j.script),
    leafVersion: j.leafVersion ?? 0,
  };
}

function taprootLeafToJson(l: TaprootLeafScriptInfo): any {
  return {
    controlBlock: toHexAny(l.controlBlock) ?? '',
    script: toHexAny(l.script) ?? '',
    leafVersion: l.leafVersion,
  };
}

function taprootBip32FromJson(j: any): TaprootBip32DerivationInfo {
  return {
    xOnlyPubKey: fromHexOrEmpty(j.xOnlyPubKey),
    leafHashes: (j.leafHashes ?? []).map((h: string) => fromHexOrEmpty(h)),
    masterKeyFingerprint: j.masterKeyFingerprint ?? '00000000',
    path: j.path ?? [],
    pathStr: j.pathStr ?? undefined,
  };
}

function taprootBip32ToJson(t: TaprootBip32DerivationInfo): any {
  const out: any = {
    xOnlyPubKey: toHexAny(t.xOnlyPubKey) ?? '',
    masterKeyFingerprint: t.masterKeyFingerprint,
  };
  if (t.leafHashes && t.leafHashes.length > 0) {
    out.leafHashes = t.leafHashes.map((h) => toHexAny(h) ?? '');
  }
  if (t.path && t.path.length > 0) out.path = t.path;
  if (t.pathStr) out.pathStr = t.pathStr;
  return out;
}

function unknownFromJson(j: any): PsbtUnknownInfo {
  return {
    key: fromHexOrEmpty(j.key),
    value: fromHexOrEmpty(j.value),
  };
}

function unknownToJson(u: PsbtUnknownInfo): any {
  return {
    key: toHexAny(u.key) ?? '',
    value: toHexAny(u.value) ?? '',
  };
}

function xpubFromJson(j: any): PsbtXpubInfo {
  return {
    extendedKey: fromHexOrEmpty(j.extendedKey),
    masterKeyFingerprint: j.masterKeyFingerprint ?? '00000000',
    path: j.path ?? [],
    pathStr: j.pathStr ?? undefined,
  };
}

function xpubToJson(x: PsbtXpubInfo): any {
  const out: any = {
    extendedKey: toHexAny(x.extendedKey) ?? '',
    masterKeyFingerprint: x.masterKeyFingerprint,
  };
  if (x.path && x.path.length > 0) out.path = x.path;
  if (x.pathStr) out.pathStr = x.pathStr;
  return out;
}
