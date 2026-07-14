import { init, g, unwrap } from './init';
import { blockFromJson } from './codec';
import type { Bytes, BlockDecodeResult } from './types';

/** Full-block utilities. */
export const block = {
  /** Decode a raw block into its header fields, derived sizes (including
   *  BIP-141 weight) and all transactions (each in the same shape
   *  `tx.decode` produces, with derived txid/wtxid).
   *  Calls Go: wire.MsgBlock.Deserialize() from btcd/wire. */
  async decode(rawBlock: Bytes): Promise<BlockDecodeResult> {
    await init();
    const json = unwrap<string>(g().block.decode(rawBlock));
    return blockFromJson(JSON.parse(json));
  },

  /** The merkle tree of a raw block, bottom-up: `levels[0]` holds the
   *  txids (display byte order), the last level is `[merkleRoot]`. Odd
   *  levels use the standard duplicate-last-entry hashing rule, but the
   *  duplicate is not included in the returned level. */
  async merkleTree(rawBlock: Bytes): Promise<string[][]> {
    await init();
    return unwrap<string[][]>(g().block.merkleTree(rawBlock));
  },
};
