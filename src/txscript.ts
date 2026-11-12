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

/** The outcome of `txscript.verifyScript`. */
export interface VerifyScriptResult {
  /** Whether the input is a valid spend of its previous output. */
  valid: boolean;
  /** Why the spend was rejected; absent when valid. */
  error?: string;
  /** The name of the script error code of the rejection, e.g.
   *  `ErrTaprootSigInvalid`. Absent when valid, and for the rare rejection
   *  that isn't a script error. */
  errorCode?: string;
}

/** The name of a script verification flag, as Bitcoin Core names its
 *  `SCRIPT_VERIFY_*` flags (without the prefix). `txscript.scriptFlagNames`
 *  returns the full list at runtime. */
export type ScriptFlag =
  | 'P2SH'
  | 'STRICTENC'
  | 'DERSIG'
  | 'LOW_S'
  | 'NULLDUMMY'
  | 'SIGPUSHONLY'
  | 'MINIMALDATA'
  | 'DISCOURAGE_UPGRADABLE_NOPS'
  | 'CLEANSTACK'
  | 'CHECKLOCKTIMEVERIFY'
  | 'CHECKSEQUENCEVERIFY'
  | 'WITNESS'
  | 'DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM'
  | 'MINIMALIF'
  | 'NULLFAIL'
  | 'WITNESS_PUBKEYTYPE'
  | 'CONST_SCRIPTCODE'
  | 'TAPROOT'
  | 'DISCOURAGE_UPGRADABLE_TAPROOT_VERSION'
  | 'DISCOURAGE_OP_SUCCESS'
  | 'DISCOURAGE_UPGRADABLE_PUBKEYTYPE'
  | 'RESTRICT_SIGHASH'
  | 'MINIMALIF_ALL'
  | 'TEMPLATEHASH'
  | 'DISCOURAGE_TEMPLATEHASH'
  | 'CHECKSIGFROMSTACK'
  | 'DISCOURAGE_CHECKSIGFROMSTACK'
  | 'INTERNALKEY'
  | 'DISCOURAGE_INTERNALKEY';

/** The state of the script engine before one op code runs. */
export interface ScriptStep {
  /** Index into `ScriptTrace.scripts` of the script being executed. */
  scriptIndex: number;
  /** Index of the op code that runs next within that script. In the last
   *  step of a successful run it points one past the final op code. */
  opcodeIndex: number;
  /** Disassembly of the op code that runs next; absent in the last step of
   *  a successful run. */
  opcode?: string;
  /** The stack, bottom first. */
  stack: Uint8Array[];
  /** The alt stack, bottom first. */
  altStack: Uint8Array[];
  /** What is left of the BIP 342 signature operation budget of a taproot
   *  input: 50 plus the size of the witness, minus 50 for every executed
   *  signature check with a non-empty signature. Absent for other inputs,
   *  and before the engine got to the witness program. */
  sigOpsBudget?: number;
}

/** The outcome of `txscript.traceScript`. */
export interface ScriptTrace extends VerifyScriptResult {
  /** Disassembly of every script the engine got to execute, one string per
   *  op code: the signature script, the public key script and, where there
   *  is one, the redeem, witness or tap script. A tapscript that is skipped
   *  because it contains an OP_SUCCESS op code isn't listed. */
  scripts: string[][];
  /** Whether the tapscript was skipped because it contains an OP_SUCCESS op
   *  code, which makes the spend valid without executing anything. Which op
   *  codes count depends on the flags: OP_TEMPLATEHASH, OP_CHECKSIGFROMSTACK
   *  and OP_INTERNALKEY are OP_SUCCESS op codes unless their flag is set. */
  opSuccess: boolean;
  /** The engine state before every op code. When the run fails, the last
   *  step is the state the failing op code ran on. */
  steps: ScriptStep[];
}

/** The BIP 446 template hash of an input and the fields of the message it is
 *  the tagged hash of, in message order. */
export interface TemplateHashPreimage {
  /** The template hash: `TaggedHash(tag, message)`. */
  hash: Uint8Array;
  /** The BIP 340 tag, `TemplateHash`. */
  tag: string;
  /** The hashed message: the concatenation of the fields below. */
  message: Uint8Array;
  /** Transaction version, 4 bytes little endian. */
  version: Uint8Array;
  /** Transaction lock time, 4 bytes little endian. */
  lockTime: Uint8Array;
  /** SHA256 of the sequences of all inputs (BIP 341 `sha_sequences`). */
  shaSequences: Uint8Array;
  /** SHA256 of all serialized outputs (BIP 341 `sha_outputs`). */
  shaOutputs: Uint8Array;
  /** One byte, 1 if the input has an annex and 0 otherwise. */
  annexPresent: Uint8Array;
  /** Index of the input, 4 bytes little endian. */
  inputIndex: Uint8Array;
  /** SHA256 of the length-prefixed annex (BIP 341 `sha_annex`); only
   *  present when the input has an annex. */
  shaAnnex?: Uint8Array;
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

  /** Compute the BIP-342 signature hash an OP_CHECKSIG in a tapscript leaf
   *  checks. Requires prevOuts for all inputs and the script of the leaf
   *  being spent. `annex` is the full annex of the input, including the 0x50
   *  tag.
   *  Calls Go: txscript.CalcTapscriptSignaturehash() from btcd/txscript. */
  async calcTapscriptSignatureHash(hashType: number, rawTx: Bytes, inputIndex: number, prevOuts: PrevOut[], leafScript: Bytes, annex?: Bytes): Promise<Uint8Array> {
    await init();
    return unwrap<Uint8Array>(g().txscript.calcTapscriptSignatureHash(hashType, rawTx, inputIndex, prevOuts, leafScript, annex));
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
  // -- script execution --

  /** Execute the script pair of one input, reporting whether it is a valid
   *  spend of its previous output. The transaction must already carry the
   *  input's signature script and witness; `prevOuts` supplies the previous
   *  output of every input, in input order (taproot sighashes commit to all
   *  of them).
   *
   *  `flags` selects the script verification flags by name. Without it the
   *  standard flags are used (see `standardScriptFlags`); an empty array
   *  means no flags at all.
   *
   *  An invalid spend is reported as `{valid: false, error, errorCode}`, not
   *  thrown: only malformed arguments throw.
   *  Calls Go: txscript.NewEngine() and Engine.Execute() from btcd/txscript. */
  async verifyScript(rawTx: Bytes, inputIndex: number, prevOuts: PrevOut[], flags?: ScriptFlag[]): Promise<VerifyScriptResult> {
    await init();
    return unwrap<VerifyScriptResult>(g().txscript.verifyScript(rawTx, inputIndex, prevOuts, flags));
  },
  /** Execute the script pair of one input like `verifyScript` does, and
   *  record the stack and alt stack before every op code, for stepping
   *  through a script.
   *  Calls Go: txscript.NewDebugEngine() and Engine.Execute() from btcd/txscript. */
  async traceScript(rawTx: Bytes, inputIndex: number, prevOuts: PrevOut[], flags?: ScriptFlag[]): Promise<ScriptTrace> {
    await init();
    return unwrap<ScriptTrace>(g().txscript.traceScript(rawTx, inputIndex, prevOuts, flags));
  },
  /** The names of all script verification flags `verifyScript` and
   *  `traceScript` accept. */
  async scriptFlagNames(): Promise<ScriptFlag[]> {
    await init();
    return unwrap<ScriptFlag[]>(g().txscript.scriptFlagNames());
  },
  /** The names of the standard script verification flags: what a node
   *  applies to transactions entering its mempool while none of the tapscript
   *  op code upgrades (BIP 446, 348, 349) is active. With these,
   *  OP_TEMPLATEHASH, OP_CHECKSIGFROMSTACK and OP_INTERNALKEY are rejected as
   *  discouraged. Remove a `DISCOURAGE_*` flag to execute its op code, and
   *  also the flag of the op code itself (plus `DISCOURAGE_OP_SUCCESS`) to
   *  see the OP_SUCCESS behavior it has before activation.
   *  Calls Go: txscript.StandardVerifyFlags from btcd/txscript. */
  async standardScriptFlags(): Promise<ScriptFlag[]> {
    await init();
    return unwrap<ScriptFlag[]>(g().txscript.standardScriptFlags());
  },

  // -- script assembly --

  /** Turn a human-readable script into its serialized form: the inverse of
   *  `disasmString`. Tokens are separated by whitespace and are either an op
   *  code name (`OP_DUP`, `OP_TEMPLATEHASH`, ...), one of the numbers `-1`
   *  and `0` to `16`, or hex data, which becomes the smallest push of those
   *  bytes. Prefix data with `0x` if it would otherwise be read as a number
   *  (`0x10` is the byte 0x10, `10` is OP_10).
   *  Calls Go: txscript.ScriptBuilder from btcd/txscript. */
  async assembleScript(asm: string): Promise<Uint8Array> {
    await init();
    return unwrap<Uint8Array>(g().txscript.assembleScript(asm));
  },

  // -- BIP 446 template hash --

  /** Compute the BIP 446 template hash of an input: what OP_TEMPLATEHASH
   *  pushes when that input is spent through a tapscript. It commits to the
   *  version, lock time, all sequences and all outputs of the transaction,
   *  the input index and the annex, but to none of the previous outputs.
   *  `annex` is the full annex of the input, including the 0x50 tag.
   *  Calls Go: txscript.CalcTemplateHash() from btcd/txscript. */
  async calcTemplateHash(rawTx: Bytes, inputIndex: number, annex?: Bytes): Promise<Uint8Array> {
    await init();
    return unwrap<Uint8Array>(g().txscript.calcTemplateHash(rawTx, inputIndex, annex));
  },
  /** Compute the BIP 446 template hash of an input together with the fields
   *  of the message that is hashed, for showing what the hash commits to.
   *  Calls Go: txscript.CalcTemplateHash() from btcd/txscript. */
  async templateHashPreimage(rawTx: Bytes, inputIndex: number, annex?: Bytes): Promise<TemplateHashPreimage> {
    await init();
    return unwrap<TemplateHashPreimage>(g().txscript.templateHashPreimage(rawTx, inputIndex, annex));
  },
};
