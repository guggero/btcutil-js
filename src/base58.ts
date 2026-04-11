import { init, g, unwrap } from './init';
import type { Base58CheckDecodeResult } from './types';

/** Base58 encoding and decoding (with and without check). */
export const base58 = {
  /** Encode bytes (hex) to a base58 string.
   *  Calls Go: base58.Encode() from btcutil/base58. */
  async encode(hexData: string): Promise<string> {
    await init();
    return unwrap<string>(g().base58.encode(hexData));
  },

  /** Decode a base58 string to bytes (hex).
   *  Calls Go: base58.Decode() from btcutil/base58. */
  async decode(str: string): Promise<string> {
    await init();
    return unwrap<string>(g().base58.decode(str));
  },

  /** Encode bytes (hex) with a version byte and checksum.
   *  Calls Go: base58.CheckEncode() from btcutil/base58. */
  async checkEncode(hexData: string, version: number): Promise<string> {
    await init();
    return unwrap<string>(g().base58.checkEncode(hexData, version));
  },

  /** Decode a base58check string, verifying the checksum.
   *  Calls Go: base58.CheckDecode() from btcutil/base58. */
  async checkDecode(str: string): Promise<Base58CheckDecodeResult> {
    await init();
    return unwrap<Base58CheckDecodeResult>(g().base58.checkDecode(str));
  },
};
