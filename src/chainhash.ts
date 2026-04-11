import { init, g, unwrap } from './init';

/** SHA-256 and tagged hash utilities from btcd/chaincfg/chainhash. */
export const chainhash = {
  /** Compute SHA-256 of data (hex). Returns hex.
   *  Calls Go: chainhash.HashB() from btcd/chaincfg/chainhash. */
  async hash(hexData: string): Promise<string> {
    await init();
    return unwrap<string>(g().chainhash.hash(hexData));
  },
  /** Compute double-SHA-256 (SHA256d) of data (hex). Returns hex.
   *  Calls Go: chainhash.DoubleHashB() from btcd/chaincfg/chainhash. */
  async doubleHash(hexData: string): Promise<string> {
    await init();
    return unwrap<string>(g().chainhash.doubleHash(hexData));
  },
  /** Compute a BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msgs...).
   *  Calls Go: chainhash.TaggedHash() from btcd/chaincfg/chainhash. */
  async taggedHash(hexTag: string, hexMsgs: string[]): Promise<string> {
    await init();
    return unwrap<string>(g().chainhash.taggedHash(hexTag, hexMsgs));
  },
  /** Parse a byte-reversed hex hash string (like a txid) into raw bytes (hex).
   *  Calls Go: chainhash.NewHashFromStr() from btcd/chaincfg/chainhash. */
  async newHashFromStr(hashStr: string): Promise<string> {
    await init();
    return unwrap<string>(g().chainhash.newHashFromStr(hashStr));
  },
  /** Convert raw hash bytes (hex) to the standard byte-reversed display string.
   *  Calls Go: chainhash.Hash.String() from btcd/chaincfg/chainhash. */
  async hashToString(hexHash: string): Promise<string> {
    await init();
    return unwrap<string>(g().chainhash.hashToString(hexHash));
  },
};
