import { init, g, unwrap } from './init';
import type { Bytes } from './types';

/** SHA-256 and tagged hash utilities from btcd/chaincfg/chainhash. */
export const chainhash = {
  /** Compute SHA-256 of data (hex). Returns hex.
   *  Calls Go: chainhash.HashB() from btcd/chaincfg/chainhash. */
  async hash(data: Bytes): Promise<Uint8Array> {
    await init();
    return unwrap<Uint8Array>(g().chainhash.hash(data));
  },
  /** Compute double-SHA-256 (SHA256d) of data (hex). Returns hex.
   *  Calls Go: chainhash.DoubleHashB() from btcd/chaincfg/chainhash. */
  async doubleHash(data: Bytes): Promise<Uint8Array> {
    await init();
    return unwrap<Uint8Array>(g().chainhash.doubleHash(data));
  },
  /** Compute a BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msgs...).
   *  Calls Go: chainhash.TaggedHash() from btcd/chaincfg/chainhash. */
  async taggedHash(tag: Bytes, msgs: Bytes[]): Promise<Uint8Array> {
    await init();
    return unwrap<Uint8Array>(g().chainhash.taggedHash(tag, msgs));
  },
  /** Parse a byte-reversed hex hash string (like a txid) into raw bytes (hex).
   *  Calls Go: chainhash.NewHashFromStr() from btcd/chaincfg/chainhash. */
  async newHashFromStr(hashStr: string): Promise<Uint8Array> {
    await init();
    return unwrap<Uint8Array>(g().chainhash.newHashFromStr(hashStr));
  },
  /** Convert raw hash bytes (hex) to the standard byte-reversed display string.
   *  Calls Go: chainhash.Hash.String() from btcd/chaincfg/chainhash. */
  async hashToString(hash: Bytes): Promise<string> {
    await init();
    return unwrap<string>(g().chainhash.hashToString(hash));
  },
};
