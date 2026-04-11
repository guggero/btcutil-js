import { init, g, unwrap } from './init';
import type { Bytes, Network } from './types';

export interface WitnessProgramInfo {
  version: number;
  program: string;
}

export interface PkScriptAddrsResult {
  scriptClass: string;
  addresses: string[];
  reqSigs: number;
}

export interface MultiSigStats {
  numPubKeys: number;
  numSigs: number;
}

export interface PkScriptInfo {
  class: string;
  script: string;
  address?: string;
}

export interface ControlBlockInfo {
  internalKey: string;
  leafVersion: number;
  outputKeyYIsOdd: boolean;
  inclusionProof: string;
}

export interface TapLeafInput {
  script: Bytes;
  version?: number;
}

export interface TapLeafResult {
  leafHash: string;
  script: string;
  controlBlock: string;
}

export interface TapScriptTreeResult {
  outputKey: string;
  internalKey: string;
  merkleRoot: string;
  leaves: TapLeafResult[];
}

export interface PrevOut {
  script: Bytes;
  amount: number;
}

/** Bitcoin transaction script analysis, creation, taproot, and signing. */
export const txscript = {
  // -- script type checks --

  /** Calls Go: txscript.IsPayToPubKey() from btcd/txscript. */
  async isPayToPubKey(script: Bytes): Promise<boolean> {
    await init();
    return unwrap<boolean>(g().txscript.isPayToPubKey(script));
  },
  /** Calls Go: txscript.IsPayToPubKeyHash() from btcd/txscript. */
  async isPayToPubKeyHash(script: Bytes): Promise<boolean> {
    await init();
    return unwrap<boolean>(g().txscript.isPayToPubKeyHash(script));
  },
  /** Calls Go: txscript.IsPayToScriptHash() from btcd/txscript. */
  async isPayToScriptHash(script: Bytes): Promise<boolean> {
    await init();
    return unwrap<boolean>(g().txscript.isPayToScriptHash(script));
  },
  /** Calls Go: txscript.IsPayToWitnessPubKeyHash() from btcd/txscript. */
  async isPayToWitnessPubKeyHash(script: Bytes): Promise<boolean> {
    await init();
    return unwrap<boolean>(g().txscript.isPayToWitnessPubKeyHash(script));
  },
  /** Calls Go: txscript.IsPayToWitnessScriptHash() from btcd/txscript. */
  async isPayToWitnessScriptHash(script: Bytes): Promise<boolean> {
    await init();
    return unwrap<boolean>(g().txscript.isPayToWitnessScriptHash(script));
  },
  /** Calls Go: txscript.IsPayToTaproot() from btcd/txscript. */
  async isPayToTaproot(script: Bytes): Promise<boolean> {
    await init();
    return unwrap<boolean>(g().txscript.isPayToTaproot(script));
  },
  /** Calls Go: txscript.IsWitnessProgram() from btcd/txscript. */
  async isWitnessProgram(script: Bytes): Promise<boolean> {
    await init();
    return unwrap<boolean>(g().txscript.isWitnessProgram(script));
  },
  /** Calls Go: txscript.IsNullData() from btcd/txscript. */
  async isNullData(script: Bytes): Promise<boolean> {
    await init();
    return unwrap<boolean>(g().txscript.isNullData(script));
  },
  /** Calls Go: txscript.IsMultisigScript() from btcd/txscript. */
  async isMultisigScript(script: Bytes): Promise<boolean> {
    await init();
    return unwrap<boolean>(g().txscript.isMultisigScript(script));
  },
  /** Calls Go: txscript.IsUnspendable() from btcd/txscript. */
  async isUnspendable(script: Bytes): Promise<boolean> {
    await init();
    return unwrap<boolean>(g().txscript.isUnspendable(script));
  },
  /** Calls Go: txscript.IsPushOnlyScript() from btcd/txscript. */
  async isPushOnlyScript(script: Bytes): Promise<boolean> {
    await init();
    return unwrap<boolean>(g().txscript.isPushOnlyScript(script));
  },
  /** Calls Go: txscript.ScriptHasOpSuccess() from btcd/txscript. */
  async scriptHasOpSuccess(script: Bytes): Promise<boolean> {
    await init();
    return unwrap<boolean>(g().txscript.scriptHasOpSuccess(script));
  },

  // -- script analysis --

  /** Disassemble a script to human-readable opcodes.
   *  Calls Go: txscript.DisasmString() from btcd/txscript. */
  async disasmString(script: Bytes): Promise<string> {
    await init();
    return unwrap<string>(g().txscript.disasmString(script));
  },
  /** Get the standard script class name.
   *  Calls Go: txscript.GetScriptClass() from btcd/txscript. */
  async getScriptClass(script: Bytes): Promise<string> {
    await init();
    return unwrap<string>(g().txscript.getScriptClass(script));
  },
  /** Extract witness program version and data from a script.
   *  Calls Go: txscript.ExtractWitnessProgramInfo() from btcd/txscript. */
  async extractWitnessProgramInfo(script: Bytes): Promise<WitnessProgramInfo> {
    await init();
    return unwrap<WitnessProgramInfo>(g().txscript.extractWitnessProgramInfo(script));
  },
  /** Extract addresses and required signatures from a pkScript.
   *  Calls Go: txscript.ExtractPkScriptAddrs() from btcd/txscript. */
  async extractPkScriptAddrs(script: Bytes, network: Network = 'mainnet'): Promise<PkScriptAddrsResult> {
    await init();
    return unwrap<PkScriptAddrsResult>(g().txscript.extractPkScriptAddrs(script, network));
  },
  /** Extract all data pushes from a script.
   *  Calls Go: txscript.PushedData() from btcd/txscript. */
  async pushedData(script: Bytes): Promise<Uint8Array[]> {
    await init();
    return unwrap<Uint8Array[]>(g().txscript.pushedData(script));
  },
  /** Count signature operations in a script.
   *  Calls Go: txscript.GetSigOpCount() from btcd/txscript. */
  async getSigOpCount(script: Bytes): Promise<number> {
    await init();
    return unwrap<number>(g().txscript.getSigOpCount(script));
  },
  /** Get multisig script statistics (number of pubkeys and required sigs).
   *  Calls Go: txscript.CalcMultiSigStats() from btcd/txscript. */
  async calcMultiSigStats(script: Bytes): Promise<MultiSigStats> {
    await init();
    return unwrap<MultiSigStats>(g().txscript.calcMultiSigStats(script));
  },
  /** Parse a pkScript into class, script hex, and (optional) address.
   *  Calls Go: txscript.ParsePkScript() from btcd/txscript. */
  async parsePkScript(script: Bytes, network: Network = 'mainnet'): Promise<PkScriptInfo> {
    await init();
    return unwrap<PkScriptInfo>(g().txscript.parsePkScript(script, network));
  },
  /** Recover the pkScript from a spent input's sigScript and witness.
   *  Calls Go: txscript.ComputePkScript() from btcd/txscript. */
  async computePkScript(sigScript: Bytes, witness: Bytes[], network: Network = 'mainnet'): Promise<PkScriptInfo> {
    await init();
    return unwrap<PkScriptInfo>(g().txscript.computePkScript(sigScript, witness, network));
  },

  // -- script creation --

  /** Create a pkScript that pays to the given address.
   *  Calls Go: txscript.PayToAddrScript() from btcd/txscript. */
  async payToAddrScript(address: string, network: Network = 'mainnet'): Promise<Uint8Array> {
    await init();
    return unwrap<Uint8Array>(g().txscript.payToAddrScript(address, network));
  },
  /** Create an OP_RETURN null data script.
   *  Calls Go: txscript.NullDataScript() from btcd/txscript. */
  async nullDataScript(data: Bytes): Promise<Uint8Array> {
    await init();
    return unwrap<Uint8Array>(g().txscript.nullDataScript(data));
  },
  /** Create a P2TR script from a 32-byte x-only public key (hex).
   *  Calls Go: txscript.PayToTaprootScript() from btcd/txscript. */
  async payToTaprootScript(pubKey: Bytes): Promise<Uint8Array> {
    await init();
    return unwrap<Uint8Array>(g().txscript.payToTaprootScript(pubKey));
  },
  /** Create a multisig script from public keys (hex[]).
   *  Calls Go: txscript.MultiSigScript() from btcd/txscript. */
  async multiSigScript(pubKeys: Bytes[], nRequired: number, network: Network = 'mainnet'): Promise<Uint8Array> {
    await init();
    return unwrap<Uint8Array>(g().txscript.multiSigScript(pubKeys, nRequired, network));
  },

  // -- taproot --

  /** Compute the taproot output key from an internal key and optional script root.
   *  Calls Go: txscript.ComputeTaprootOutputKey() from btcd/txscript. */
  async computeTaprootOutputKey(internalKey: Bytes, scriptRoot?: Bytes): Promise<Uint8Array> {
    await init();
    return unwrap<Uint8Array>(g().txscript.computeTaprootOutputKey(internalKey, scriptRoot ?? ''));
  },
  /** Compute the taproot output key for a key-only spend (no script tree).
   *  Calls Go: txscript.ComputeTaprootKeyNoScript() from btcd/txscript. */
  async computeTaprootKeyNoScript(internalKey: Bytes): Promise<Uint8Array> {
    await init();
    return unwrap<Uint8Array>(g().txscript.computeTaprootKeyNoScript(internalKey));
  },
  /** Tweak a private key for taproot key-path spending.
   *  Calls Go: txscript.TweakTaprootPrivKey() from btcd/txscript. */
  async tweakTaprootPrivKey(privKey: Bytes, scriptRoot?: Bytes): Promise<Uint8Array> {
    await init();
    return unwrap<Uint8Array>(g().txscript.tweakTaprootPrivKey(privKey, scriptRoot ?? ''));
  },
  /** Parse a serialized control block.
   *  Calls Go: txscript.ParseControlBlock() from btcd/txscript. */
  async parseControlBlock(controlBlock: Bytes): Promise<ControlBlockInfo> {
    await init();
    return unwrap<ControlBlockInfo>(g().txscript.parseControlBlock(controlBlock));
  },
  /** Build a taproot script tree from leaves and compute the output key.
   *  Calls Go: txscript.AssembleTaprootScriptTree() + ComputeTaprootOutputKey() from btcd/txscript. */
  async assembleTaprootScriptTree(internalKey: Bytes, leaves: TapLeafInput[]): Promise<TapScriptTreeResult> {
    await init();
    return unwrap<TapScriptTreeResult>(g().txscript.assembleTaprootScriptTree(internalKey, leaves));
  },

  // -- sighash --

  /** Compute a legacy (pre-segwit) signature hash.
   *  Calls Go: txscript.CalcSignatureHash() from btcd/txscript. */
  async calcSignatureHash(script: Bytes, hashType: number, rawTx: Bytes, inputIndex: number): Promise<Uint8Array> {
    await init();
    return unwrap<Uint8Array>(g().txscript.calcSignatureHash(script, hashType, rawTx, inputIndex));
  },
  /** Compute a BIP-143 witness v0 signature hash.
   *  Calls Go: txscript.CalcWitnessSigHash() from btcd/txscript. */
  async calcWitnessSigHash(script: Bytes, hashType: number, rawTx: Bytes, inputIndex: number, amount: number): Promise<Uint8Array> {
    await init();
    return unwrap<Uint8Array>(g().txscript.calcWitnessSigHash(script, hashType, rawTx, inputIndex, amount));
  },
  /** Compute a BIP-341 taproot signature hash. Requires prevOuts for all inputs.
   *  Calls Go: txscript.CalcTaprootSignatureHash() from btcd/txscript. */
  async calcTaprootSignatureHash(hashType: number, rawTx: Bytes, inputIndex: number, prevOuts: PrevOut[]): Promise<Uint8Array> {
    await init();
    return unwrap<Uint8Array>(g().txscript.calcTaprootSignatureHash(hashType, rawTx, inputIndex, prevOuts));
  },

  // -- signing --

  /** Create a legacy input signature (DER-encoded + hashType byte).
   *  Calls Go: txscript.RawTxInSignature() from btcd/txscript. */
  async rawTxInSignature(rawTx: Bytes, inputIndex: number, subScript: Bytes, hashType: number, privKey: Bytes): Promise<Uint8Array> {
    await init();
    return unwrap<Uint8Array>(g().txscript.rawTxInSignature(rawTx, inputIndex, subScript, hashType, privKey));
  },
  /** Create a witness v0 input signature (DER-encoded + hashType byte).
   *  Calls Go: txscript.RawTxInWitnessSignature() from btcd/txscript. */
  async rawTxInWitnessSignature(rawTx: Bytes, inputIndex: number, amount: number, subScript: Bytes, hashType: number, privKey: Bytes): Promise<Uint8Array> {
    await init();
    return unwrap<Uint8Array>(g().txscript.rawTxInWitnessSignature(rawTx, inputIndex, amount, subScript, hashType, privKey));
  },
  /** Create a complete witness stack (signature + pubkey) for a P2WPKH spend.
   *  Calls Go: txscript.WitnessSignature() from btcd/txscript. */
  async witnessSignature(rawTx: Bytes, inputIndex: number, amount: number, subScript: Bytes, hashType: number, privKey: Bytes, compress: boolean): Promise<Uint8Array[]> {
    await init();
    return unwrap<Uint8Array[]>(g().txscript.witnessSignature(rawTx, inputIndex, amount, subScript, hashType, privKey, compress));
  },
  /** Create a taproot key-path signature. Requires prevOuts for all inputs.
   *  Calls Go: txscript.RawTxInTaprootSignature() from btcd/txscript. */
  async rawTxInTaprootSignature(rawTx: Bytes, inputIndex: number, merkleRoot: Bytes, hashType: number, privKey: Bytes, prevOuts: PrevOut[]): Promise<Uint8Array> {
    await init();
    return unwrap<Uint8Array>(g().txscript.rawTxInTaprootSignature(rawTx, inputIndex, merkleRoot, hashType, privKey, prevOuts));
  },
};
