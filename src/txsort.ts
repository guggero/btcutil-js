import { init, g, unwrap } from './init';

/** BIP-69 deterministic transaction sorting. */
export const txsort = {
  /** Sort transaction inputs and outputs per BIP-69. Returns sorted tx hex.
   *  Calls Go: txsort.Sort() from btcutil/txsort. */
  async sort(hexRawTx: string): Promise<string> {
    await init();
    return unwrap<string>(g().txsort.sort(hexRawTx));
  },

  /** Check if a transaction's inputs and outputs are sorted per BIP-69.
   *  Calls Go: txsort.IsSorted() from btcutil/txsort. */
  async isSorted(hexRawTx: string): Promise<boolean> {
    await init();
    return unwrap<boolean>(g().txsort.isSorted(hexRawTx));
  },
};
