import { init, g, unwrap } from './init';
import type { Bytes, PsbtDecodeResult } from './types';

/** Partially Signed Bitcoin Transaction (BIP-174) utilities. */
export const psbt = {
  /** Decode a base64-encoded PSBT and return structured info.
   *  Calls Go: psbt.NewFromRawBytes() from btcutil/psbt. */
  async decode(base64Psbt: string): Promise<PsbtDecodeResult> {
    await init();
    return unwrap<PsbtDecodeResult>(g().psbt.decode(base64Psbt));
  },

  /** Check if a base64-encoded PSBT is fully signed and ready to extract.
   *  Calls Go: psbt.Packet.IsComplete() from btcutil/psbt. */
  async isComplete(base64Psbt: string): Promise<boolean> {
    await init();
    return unwrap<boolean>(g().psbt.isComplete(base64Psbt));
  },

  /** Extract the final signed transaction (hex) from a completed PSBT.
   *  Calls Go: psbt.Extract() from btcutil/psbt. */
  async extract(base64Psbt: string): Promise<Uint8Array> {
    await init();
    return unwrap<Uint8Array>(g().psbt.extract(base64Psbt));
  },

  /** Get the transaction fee in satoshis from a PSBT (requires UTXO info).
   *  Calls Go: psbt.Packet.GetTxFee() from btcutil/psbt. */
  async getFee(base64Psbt: string): Promise<number> {
    await init();
    return unwrap<number>(g().psbt.getFee(base64Psbt));
  },

  /** Convert a base64-encoded PSBT to raw bytes (hex).
   *  Calls Go: psbt.NewFromRawBytes() + psbt.Packet.Serialize() from btcutil/psbt. */
  async fromBase64(base64Psbt: string): Promise<Uint8Array> {
    await init();
    return unwrap<Uint8Array>(g().psbt.fromBase64(base64Psbt));
  },

  /** Convert raw PSBT bytes (hex) to a base64-encoded string.
   *  Calls Go: psbt.NewFromRawBytes() + psbt.Packet.B64Encode() from btcutil/psbt. */
  async toBase64(psbtData: Bytes): Promise<string> {
    await init();
    return unwrap<string>(g().psbt.toBase64(psbtData));
  },
};
