import { init, g, unwrap } from './init';
import type { Network } from './types';

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
  script: string;
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
  script: string;
  amount: number;
}

/** Bitcoin transaction script analysis, creation, taproot, and signing. */
export const txscript = {
  // -- script type checks --

  /** Calls Go: txscript.IsPayToPubKey() from btcd/txscript. */
  async isPayToPubKey(hexScript: string): Promise<boolean> {
    await init();
    return unwrap<boolean>(g().txscript.isPayToPubKey(hexScript));
  },
  /** Calls Go: txscript.IsPayToPubKeyHash() from btcd/txscript. */
  async isPayToPubKeyHash(hexScript: string): Promise<boolean> {
    await init();
    return unwrap<boolean>(g().txscript.isPayToPubKeyHash(hexScript));
  },
  /** Calls Go: txscript.IsPayToScriptHash() from btcd/txscript. */
  async isPayToScriptHash(hexScript: string): Promise<boolean> {
    await init();
    return unwrap<boolean>(g().txscript.isPayToScriptHash(hexScript));
  },
  /** Calls Go: txscript.IsPayToWitnessPubKeyHash() from btcd/txscript. */
  async isPayToWitnessPubKeyHash(hexScript: string): Promise<boolean> {
    await init();
    return unwrap<boolean>(g().txscript.isPayToWitnessPubKeyHash(hexScript));
  },
  /** Calls Go: txscript.IsPayToWitnessScriptHash() from btcd/txscript. */
  async isPayToWitnessScriptHash(hexScript: string): Promise<boolean> {
    await init();
    return unwrap<boolean>(g().txscript.isPayToWitnessScriptHash(hexScript));
  },
  /** Calls Go: txscript.IsPayToTaproot() from btcd/txscript. */
  async isPayToTaproot(hexScript: string): Promise<boolean> {
    await init();
    return unwrap<boolean>(g().txscript.isPayToTaproot(hexScript));
  },
  /** Calls Go: txscript.IsWitnessProgram() from btcd/txscript. */
  async isWitnessProgram(hexScript: string): Promise<boolean> {
    await init();
    return unwrap<boolean>(g().txscript.isWitnessProgram(hexScript));
  },
  /** Calls Go: txscript.IsNullData() from btcd/txscript. */
  async isNullData(hexScript: string): Promise<boolean> {
    await init();
    return unwrap<boolean>(g().txscript.isNullData(hexScript));
  },
  /** Calls Go: txscript.IsMultisigScript() from btcd/txscript. */
  async isMultisigScript(hexScript: string): Promise<boolean> {
    await init();
    return unwrap<boolean>(g().txscript.isMultisigScript(hexScript));
  },
  /** Calls Go: txscript.IsUnspendable() from btcd/txscript. */
  async isUnspendable(hexScript: string): Promise<boolean> {
    await init();
    return unwrap<boolean>(g().txscript.isUnspendable(hexScript));
  },
  /** Calls Go: txscript.IsPushOnlyScript() from btcd/txscript. */
  async isPushOnlyScript(hexScript: string): Promise<boolean> {
    await init();
    return unwrap<boolean>(g().txscript.isPushOnlyScript(hexScript));
  },
  /** Calls Go: txscript.ScriptHasOpSuccess() from btcd/txscript. */
  async scriptHasOpSuccess(hexScript: string): Promise<boolean> {
    await init();
    return unwrap<boolean>(g().txscript.scriptHasOpSuccess(hexScript));
  },

  // -- script analysis --

  /** Disassemble a script to human-readable opcodes.
   *  Calls Go: txscript.DisasmString() from btcd/txscript. */
  async disasmString(hexScript: string): Promise<string> {
    await init();
    return unwrap<string>(g().txscript.disasmString(hexScript));
  },
  /** Get the standard script class name.
   *  Calls Go: txscript.GetScriptClass() from btcd/txscript. */
  async getScriptClass(hexScript: string): Promise<string> {
    await init();
    return unwrap<string>(g().txscript.getScriptClass(hexScript));
  },
  /** Extract witness program version and data from a script.
   *  Calls Go: txscript.ExtractWitnessProgramInfo() from btcd/txscript. */
  async extractWitnessProgramInfo(hexScript: string): Promise<WitnessProgramInfo> {
    await init();
    return unwrap<WitnessProgramInfo>(g().txscript.extractWitnessProgramInfo(hexScript));
  },
  /** Extract addresses and required signatures from a pkScript.
   *  Calls Go: txscript.ExtractPkScriptAddrs() from btcd/txscript. */
  async extractPkScriptAddrs(hexScript: string, network: Network = 'mainnet'): Promise<PkScriptAddrsResult> {
    await init();
    return unwrap<PkScriptAddrsResult>(g().txscript.extractPkScriptAddrs(hexScript, network));
  },
  /** Extract all data pushes from a script.
   *  Calls Go: txscript.PushedData() from btcd/txscript. */
  async pushedData(hexScript: string): Promise<string[]> {
    await init();
    return unwrap<string[]>(g().txscript.pushedData(hexScript));
  },
  /** Count signature operations in a script.
   *  Calls Go: txscript.GetSigOpCount() from btcd/txscript. */
  async getSigOpCount(hexScript: string): Promise<number> {
    await init();
    return unwrap<number>(g().txscript.getSigOpCount(hexScript));
  },
  /** Get multisig script statistics (number of pubkeys and required sigs).
   *  Calls Go: txscript.CalcMultiSigStats() from btcd/txscript. */
  async calcMultiSigStats(hexScript: string): Promise<MultiSigStats> {
    await init();
    return unwrap<MultiSigStats>(g().txscript.calcMultiSigStats(hexScript));
  },
  /** Parse a pkScript into class, script hex, and (optional) address.
   *  Calls Go: txscript.ParsePkScript() from btcd/txscript. */
  async parsePkScript(hexScript: string, network: Network = 'mainnet'): Promise<PkScriptInfo> {
    await init();
    return unwrap<PkScriptInfo>(g().txscript.parsePkScript(hexScript, network));
  },
  /** Recover the pkScript from a spent input's sigScript and witness.
   *  Calls Go: txscript.ComputePkScript() from btcd/txscript. */
  async computePkScript(hexSigScript: string, hexWitness: string[], network: Network = 'mainnet'): Promise<PkScriptInfo> {
    await init();
    return unwrap<PkScriptInfo>(g().txscript.computePkScript(hexSigScript, hexWitness, network));
  },

  // -- script creation --

  /** Create a pkScript that pays to the given address.
   *  Calls Go: txscript.PayToAddrScript() from btcd/txscript. */
  async payToAddrScript(address: string, network: Network = 'mainnet'): Promise<string> {
    await init();
    return unwrap<string>(g().txscript.payToAddrScript(address, network));
  },
  /** Create an OP_RETURN null data script.
   *  Calls Go: txscript.NullDataScript() from btcd/txscript. */
  async nullDataScript(hexData: string): Promise<string> {
    await init();
    return unwrap<string>(g().txscript.nullDataScript(hexData));
  },
  /** Create a P2TR script from a 32-byte x-only public key (hex).
   *  Calls Go: txscript.PayToTaprootScript() from btcd/txscript. */
  async payToTaprootScript(hexPubKey: string): Promise<string> {
    await init();
    return unwrap<string>(g().txscript.payToTaprootScript(hexPubKey));
  },
  /** Create a multisig script from public keys (hex[]).
   *  Calls Go: txscript.MultiSigScript() from btcd/txscript. */
  async multiSigScript(hexPubKeys: string[], nRequired: number, network: Network = 'mainnet'): Promise<string> {
    await init();
    return unwrap<string>(g().txscript.multiSigScript(hexPubKeys, nRequired, network));
  },

  // -- taproot --

  /** Compute the taproot output key from an internal key and optional script root.
   *  Calls Go: txscript.ComputeTaprootOutputKey() from btcd/txscript. */
  async computeTaprootOutputKey(hexInternalKey: string, hexScriptRoot?: string): Promise<string> {
    await init();
    return unwrap<string>(g().txscript.computeTaprootOutputKey(hexInternalKey, hexScriptRoot ?? ''));
  },
  /** Compute the taproot output key for a key-only spend (no script tree).
   *  Calls Go: txscript.ComputeTaprootKeyNoScript() from btcd/txscript. */
  async computeTaprootKeyNoScript(hexInternalKey: string): Promise<string> {
    await init();
    return unwrap<string>(g().txscript.computeTaprootKeyNoScript(hexInternalKey));
  },
  /** Tweak a private key for taproot key-path spending.
   *  Calls Go: txscript.TweakTaprootPrivKey() from btcd/txscript. */
  async tweakTaprootPrivKey(hexPrivKey: string, hexScriptRoot?: string): Promise<string> {
    await init();
    return unwrap<string>(g().txscript.tweakTaprootPrivKey(hexPrivKey, hexScriptRoot ?? ''));
  },
  /** Parse a serialized control block.
   *  Calls Go: txscript.ParseControlBlock() from btcd/txscript. */
  async parseControlBlock(hexControlBlock: string): Promise<ControlBlockInfo> {
    await init();
    return unwrap<ControlBlockInfo>(g().txscript.parseControlBlock(hexControlBlock));
  },
  /** Build a taproot script tree from leaves and compute the output key.
   *  Calls Go: txscript.AssembleTaprootScriptTree() + ComputeTaprootOutputKey() from btcd/txscript. */
  async assembleTaprootScriptTree(hexInternalKey: string, leaves: TapLeafInput[]): Promise<TapScriptTreeResult> {
    await init();
    return unwrap<TapScriptTreeResult>(g().txscript.assembleTaprootScriptTree(hexInternalKey, leaves));
  },

  // -- sighash --

  /** Compute a legacy (pre-segwit) signature hash.
   *  Calls Go: txscript.CalcSignatureHash() from btcd/txscript. */
  async calcSignatureHash(hexScript: string, hashType: number, hexRawTx: string, inputIndex: number): Promise<string> {
    await init();
    return unwrap<string>(g().txscript.calcSignatureHash(hexScript, hashType, hexRawTx, inputIndex));
  },
  /** Compute a BIP-143 witness v0 signature hash.
   *  Calls Go: txscript.CalcWitnessSigHash() from btcd/txscript. */
  async calcWitnessSigHash(hexScript: string, hashType: number, hexRawTx: string, inputIndex: number, amount: number): Promise<string> {
    await init();
    return unwrap<string>(g().txscript.calcWitnessSigHash(hexScript, hashType, hexRawTx, inputIndex, amount));
  },
  /** Compute a BIP-341 taproot signature hash. Requires prevOuts for all inputs.
   *  Calls Go: txscript.CalcTaprootSignatureHash() from btcd/txscript. */
  async calcTaprootSignatureHash(hashType: number, hexRawTx: string, inputIndex: number, prevOuts: PrevOut[]): Promise<string> {
    await init();
    return unwrap<string>(g().txscript.calcTaprootSignatureHash(hashType, hexRawTx, inputIndex, prevOuts));
  },

  // -- signing --

  /** Create a legacy input signature (DER-encoded + hashType byte).
   *  Calls Go: txscript.RawTxInSignature() from btcd/txscript. */
  async rawTxInSignature(hexRawTx: string, inputIndex: number, hexSubScript: string, hashType: number, hexPrivKey: string): Promise<string> {
    await init();
    return unwrap<string>(g().txscript.rawTxInSignature(hexRawTx, inputIndex, hexSubScript, hashType, hexPrivKey));
  },
  /** Create a witness v0 input signature (DER-encoded + hashType byte).
   *  Calls Go: txscript.RawTxInWitnessSignature() from btcd/txscript. */
  async rawTxInWitnessSignature(hexRawTx: string, inputIndex: number, amount: number, hexSubScript: string, hashType: number, hexPrivKey: string): Promise<string> {
    await init();
    return unwrap<string>(g().txscript.rawTxInWitnessSignature(hexRawTx, inputIndex, amount, hexSubScript, hashType, hexPrivKey));
  },
  /** Create a complete witness stack (signature + pubkey) for a P2WPKH spend.
   *  Calls Go: txscript.WitnessSignature() from btcd/txscript. */
  async witnessSignature(hexRawTx: string, inputIndex: number, amount: number, hexSubScript: string, hashType: number, hexPrivKey: string, compress: boolean): Promise<string[]> {
    await init();
    return unwrap<string[]>(g().txscript.witnessSignature(hexRawTx, inputIndex, amount, hexSubScript, hashType, hexPrivKey, compress));
  },
  /** Create a taproot key-path signature. Requires prevOuts for all inputs.
   *  Calls Go: txscript.RawTxInTaprootSignature() from btcd/txscript. */
  async rawTxInTaprootSignature(hexRawTx: string, inputIndex: number, hexMerkleRoot: string, hashType: number, hexPrivKey: string, prevOuts: PrevOut[]): Promise<string> {
    await init();
    return unwrap<string>(g().txscript.rawTxInTaprootSignature(hexRawTx, inputIndex, hexMerkleRoot, hashType, hexPrivKey, prevOuts));
  },
};
