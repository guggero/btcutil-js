import { init, g, unwrap } from './init';
import type { Bytes } from './types';

/** BIP-69 deterministic transaction sorting. */
export const txsort = {
  /** Sort transaction inputs and outputs per BIP-69. Returns sorted tx hex.
   *  Calls Go: txsort.Sort() from btcutil/txsort. */
  async sort(rawTx: Bytes): Promise<Uint8Array> {
    await init();
    return unwrap<Uint8Array>(g().txsort.sort(rawTx));
  },

  /** Check if a transaction's inputs and outputs are sorted per BIP-69.
   *  Calls Go: txsort.IsSorted() from btcutil/txsort. */
  async isSorted(rawTx: Bytes): Promise<boolean> {
    await init();
    return unwrap<boolean>(g().txsort.isSorted(rawTx));
  },
};
