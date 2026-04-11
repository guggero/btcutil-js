import { init, g, unwrap } from './init';
import type { Bytes, PsbtDecodeResult } from './types';

export interface PsbtInput {
  txid: string;
  vout: number;
  sequence?: number;
}

export interface PsbtOutput {
  value: number;
  script: Bytes;
}

export interface PsbtSignResult {
  psbt: string;
  /** 0 = successful, 1 = already finalized, -1 = invalid. */
  outcome: number;
}

export interface PsbtMaybeFinalizeResult {
  psbt: string;
  finalized: boolean;
}

/** Partially Signed Bitcoin Transaction (BIP-174) utilities.
 *
 *  Mutating functions (addIn*, addOut*, sign, finalize*) take a base64 PSBT,
 *  apply the change, and return a new base64 PSBT. Chain calls to build up
 *  a transaction:
 *
 *  ```ts
 *  let p = await psbt.create(inputs, outputs);
 *  p = await psbt.addInWitnessUtxo(p, 0, 50000, pkScript);
 *  const { psbt: signed } = await psbt.sign(p, 0, sig, pubKey);
 *  const finalized = await psbt.maybeFinalizeAll(signed);
 *  const rawTx = await psbt.extract(finalized);
 *  ``` */
export const psbt = {
  // -- read-only --

  /** Decode a base64-encoded PSBT and return structured info including all
   *  per-input and per-output fields (partial sigs, BIP-32 derivation,
   *  taproot fields, etc.).
   *  Calls Go: psbt.NewFromRawBytes() from btcutil/psbt. */
  async decode(base64Psbt: string): Promise<PsbtDecodeResult> {
    await init();
    return unwrap<PsbtDecodeResult>(g().psbt.decode(base64Psbt));
  },

  /** Check if all inputs are finalized and ready to extract.
   *  Calls Go: psbt.Packet.IsComplete() from btcutil/psbt. */
  async isComplete(base64Psbt: string): Promise<boolean> {
    await init();
    return unwrap<boolean>(g().psbt.isComplete(base64Psbt));
  },

  /** Extract the final signed transaction from a completed PSBT.
   *  Calls Go: psbt.Extract() from btcutil/psbt. */
  async extract(base64Psbt: string): Promise<Uint8Array> {
    await init();
    return unwrap<Uint8Array>(g().psbt.extract(base64Psbt));
  },

  /** Get the transaction fee in satoshis (requires UTXO info on all inputs).
   *  Calls Go: psbt.Packet.GetTxFee() from btcutil/psbt. */
  async getFee(base64Psbt: string): Promise<number> {
    await init();
    return unwrap<number>(g().psbt.getFee(base64Psbt));
  },

  /** Convert a base64 PSBT to raw bytes.
   *  Calls Go: psbt.Packet.Serialize() from btcutil/psbt. */
  async fromBase64(base64Psbt: string): Promise<Uint8Array> {
    await init();
    return unwrap<Uint8Array>(g().psbt.fromBase64(base64Psbt));
  },

  /** Convert raw PSBT bytes to base64.
   *  Calls Go: psbt.Packet.B64Encode() from btcutil/psbt. */
  async toBase64(psbtData: Bytes): Promise<string> {
    await init();
    return unwrap<string>(g().psbt.toBase64(psbtData));
  },

  /** Sum all input UTXO values in satoshis.
   *  Calls Go: psbt.SumUtxoInputValues() from btcutil/psbt. */
  async sumUtxoInputValues(base64Psbt: string): Promise<number> {
    await init();
    return unwrap<number>(g().psbt.sumUtxoInputValues(base64Psbt));
  },

  /** Verify all inputs have UTXO information attached. Throws on error.
   *  Calls Go: psbt.InputsReadyToSign() from btcutil/psbt. */
  async inputsReadyToSign(base64Psbt: string): Promise<void> {
    await init();
    unwrap<boolean>(g().psbt.inputsReadyToSign(base64Psbt));
  },

  /** Validate PSBT format per BIP-174. Throws on error.
   *  Calls Go: psbt.Packet.SanityCheck() from btcutil/psbt. */
  async sanityCheck(base64Psbt: string): Promise<void> {
    await init();
    unwrap<boolean>(g().psbt.sanityCheck(base64Psbt));
  },

  // -- creation --

  /** Create a new PSBT from inputs and outputs.
   *  Calls Go: psbt.New() from btcutil/psbt.
   *  @param inputs  - Array of `{ txid, vout, sequence? }`.
   *  @param outputs - Array of `{ value, script }`.
   *  @returns Base64-encoded PSBT. */
  async create(
    inputs: PsbtInput[],
    outputs: PsbtOutput[],
    version?: number,
    lockTime?: number,
  ): Promise<string> {
    await init();
    return unwrap<string>(
      g().psbt.create(inputs, outputs, version, lockTime),
    );
  },

  /** Create a new PSBT from an unsigned raw transaction.
   *  Calls Go: psbt.NewFromUnsignedTx() from btcutil/psbt. */
  async fromUnsignedTx(rawTx: Bytes): Promise<string> {
    await init();
    return unwrap<string>(g().psbt.fromUnsignedTx(rawTx));
  },

  // -- updater: inputs --

  /** Add a full previous transaction for a non-segwit input.
   *  Calls Go: psbt.Updater.AddInNonWitnessUtxo() from btcutil/psbt. */
  async addInNonWitnessUtxo(
    base64Psbt: string, inIndex: number, rawTx: Bytes,
  ): Promise<string> {
    await init();
    return unwrap<string>(
      g().psbt.addInNonWitnessUtxo(base64Psbt, inIndex, rawTx),
    );
  },

  /** Add a witness UTXO (value + pkScript) for a segwit input.
   *  Calls Go: psbt.Updater.AddInWitnessUtxo() from btcutil/psbt. */
  async addInWitnessUtxo(
    base64Psbt: string, inIndex: number, value: number, pkScript: Bytes,
  ): Promise<string> {
    await init();
    return unwrap<string>(
      g().psbt.addInWitnessUtxo(base64Psbt, inIndex, value, pkScript),
    );
  },

  /** Set the sighash type for an input.
   *  Calls Go: psbt.Updater.AddInSighashType() from btcutil/psbt. */
  async addInSighashType(
    base64Psbt: string, inIndex: number, sighashType: number,
  ): Promise<string> {
    await init();
    return unwrap<string>(
      g().psbt.addInSighashType(base64Psbt, inIndex, sighashType),
    );
  },

  /** Add a P2SH redeem script to an input.
   *  Calls Go: psbt.Updater.AddInRedeemScript() from btcutil/psbt. */
  async addInRedeemScript(
    base64Psbt: string, inIndex: number, redeemScript: Bytes,
  ): Promise<string> {
    await init();
    return unwrap<string>(
      g().psbt.addInRedeemScript(base64Psbt, inIndex, redeemScript),
    );
  },

  /** Add a witness script to an input.
   *  Calls Go: psbt.Updater.AddInWitnessScript() from btcutil/psbt. */
  async addInWitnessScript(
    base64Psbt: string, inIndex: number, witnessScript: Bytes,
  ): Promise<string> {
    await init();
    return unwrap<string>(
      g().psbt.addInWitnessScript(base64Psbt, inIndex, witnessScript),
    );
  },

  /** Add BIP-32 derivation info to an input.
   *  Calls Go: psbt.Updater.AddInBip32Derivation() from btcutil/psbt. */
  async addInBip32Derivation(
    base64Psbt: string, inIndex: number,
    fingerprint: number, path: number[], pubKey: Bytes,
  ): Promise<string> {
    await init();
    return unwrap<string>(
      g().psbt.addInBip32Derivation(
        base64Psbt, inIndex, fingerprint, path, pubKey,
      ),
    );
  },

  // -- updater: outputs --

  /** Add BIP-32 derivation info to an output.
   *  Calls Go: psbt.Updater.AddOutBip32Derivation() from btcutil/psbt. */
  async addOutBip32Derivation(
    base64Psbt: string, outIndex: number,
    fingerprint: number, path: number[], pubKey: Bytes,
  ): Promise<string> {
    await init();
    return unwrap<string>(
      g().psbt.addOutBip32Derivation(
        base64Psbt, outIndex, fingerprint, path, pubKey,
      ),
    );
  },

  /** Add a P2SH redeem script to an output.
   *  Calls Go: psbt.Updater.AddOutRedeemScript() from btcutil/psbt. */
  async addOutRedeemScript(
    base64Psbt: string, outIndex: number, redeemScript: Bytes,
  ): Promise<string> {
    await init();
    return unwrap<string>(
      g().psbt.addOutRedeemScript(base64Psbt, outIndex, redeemScript),
    );
  },

  /** Add a witness script to an output.
   *  Calls Go: psbt.Updater.AddOutWitnessScript() from btcutil/psbt. */
  async addOutWitnessScript(
    base64Psbt: string, outIndex: number, witnessScript: Bytes,
  ): Promise<string> {
    await init();
    return unwrap<string>(
      g().psbt.addOutWitnessScript(base64Psbt, outIndex, witnessScript),
    );
  },

  // -- signing --

  /** Attach a signature to an input. Returns the updated PSBT and the
   *  sign outcome (0=success, 1=already finalized, -1=invalid).
   *  Calls Go: psbt.Updater.Sign() from btcutil/psbt. */
  async sign(
    base64Psbt: string, inIndex: number,
    sig: Bytes, pubKey: Bytes,
    redeemScript?: Bytes, witnessScript?: Bytes,
  ): Promise<PsbtSignResult> {
    await init();
    return unwrap<PsbtSignResult>(
      g().psbt.sign(
        base64Psbt, inIndex, sig, pubKey,
        redeemScript, witnessScript,
      ),
    );
  },

  // -- finalization --

  /** Finalize a specific input (create final scriptSig/witness).
   *  Calls Go: psbt.Finalize() from btcutil/psbt. */
  async finalize(base64Psbt: string, inIndex: number): Promise<string> {
    await init();
    return unwrap<string>(g().psbt.finalize(base64Psbt, inIndex));
  },

  /** Try to finalize a specific input. Returns whether it was finalized.
   *  Calls Go: psbt.MaybeFinalize() from btcutil/psbt. */
  async maybeFinalize(
    base64Psbt: string, inIndex: number,
  ): Promise<PsbtMaybeFinalizeResult> {
    await init();
    return unwrap<PsbtMaybeFinalizeResult>(
      g().psbt.maybeFinalize(base64Psbt, inIndex),
    );
  },

  /** Try to finalize all inputs at once.
   *  Calls Go: psbt.MaybeFinalizeAll() from btcutil/psbt. */
  async maybeFinalizeAll(base64Psbt: string): Promise<string> {
    await init();
    return unwrap<string>(g().psbt.maybeFinalizeAll(base64Psbt));
  },

  // -- sorting --

  /** Sort inputs and outputs in-place per BIP-69.
   *  Calls Go: psbt.InPlaceSort() from btcutil/psbt. */
  async inPlaceSort(base64Psbt: string): Promise<string> {
    await init();
    return unwrap<string>(g().psbt.inPlaceSort(base64Psbt));
  },
};
