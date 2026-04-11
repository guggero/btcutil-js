import { init, g, unwrap } from './init';
import type { Bech32DecodeResult, Bytes } from './types';

/** Bech32 and bech32m encoding/decoding. */
export const bech32 = {
  /** Bech32-encode 5-bit data (hex) with the given HRP.
   *  Calls Go: bech32.Encode() from btcutil/bech32. */
  async encode(hrp: string, data5bit: Bytes): Promise<string> {
    await init();
    return unwrap<string>(g().bech32.encode(hrp, data5bit));
  },

  /** Bech32m-encode 5-bit data (hex) with the given HRP.
   *  Calls Go: bech32.EncodeM() from btcutil/bech32. */
  async encodeM(hrp: string, data5bit: Bytes): Promise<string> {
    await init();
    return unwrap<string>(g().bech32.encodeM(hrp, data5bit));
  },

  /** Decode a bech32 string (90-char limit). Returns 5-bit data.
   *  Calls Go: bech32.Decode() from btcutil/bech32. */
  async decode(str: string): Promise<Bech32DecodeResult> {
    await init();
    return unwrap<Bech32DecodeResult>(g().bech32.decode(str));
  },

  /** Decode a bech32 string without length limit. Returns 5-bit data.
   *  Calls Go: bech32.DecodeNoLimit() from btcutil/bech32. */
  async decodeNoLimit(str: string): Promise<Bech32DecodeResult> {
    await init();
    return unwrap<Bech32DecodeResult>(g().bech32.decodeNoLimit(str));
  },

  /** Encode base-256 data (hex) as a bech32 string. Handles 8->5 bit conversion.
   *  Calls Go: bech32.EncodeFromBase256() from btcutil/bech32. */
  async encodeFromBase256(hrp: string, data: Bytes): Promise<string> {
    await init();
    return unwrap<string>(g().bech32.encodeFromBase256(hrp, data));
  },

  /** Decode a bech32 string to base-256 data (hex). Handles 5->8 bit conversion.
   *  Calls Go: bech32.DecodeToBase256() from btcutil/bech32. */
  async decodeToBase256(str: string): Promise<Bech32DecodeResult> {
    await init();
    return unwrap<Bech32DecodeResult>(g().bech32.decodeToBase256(str));
  },

  /** Convert between bit groups (e.g. 8->5 or 5->8).
   *  Calls Go: bech32.ConvertBits() from btcutil/bech32. */
  async convertBits(
    data: Bytes,
    fromBits: number,
    toBits: number,
    pad: boolean,
  ): Promise<Uint8Array> {
    await init();
    return unwrap<Uint8Array>(
      g().bech32.convertBits(data, fromBits, toBits, pad),
    );
  },
};
