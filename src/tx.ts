import { init, g, unwrap } from './init';
import type { TxDecodeResult } from './types';

/** Transaction utilities. */
export const tx = {
  /** Compute the txid (double-SHA256, reversed) of a raw transaction (hex).
   *  Calls Go: btcutil.Tx.Hash() from btcutil (via btcutil.NewTx()). */
  async hash(hexRawTx: string): Promise<string> {
    await init();
    return unwrap<string>(g().tx.hash(hexRawTx));
  },

  /** Compute the witness txid (wtxid) of a raw transaction (hex).
   *  Calls Go: btcutil.Tx.WitnessHash() from btcutil (via btcutil.NewTx()). */
  async witnessHash(hexRawTx: string): Promise<string> {
    await init();
    return unwrap<string>(g().tx.witnessHash(hexRawTx));
  },

  /** Check if a raw transaction (hex) contains witness data.
   *  Calls Go: btcutil.Tx.HasWitness() from btcutil (via btcutil.NewTx()). */
  async hasWitness(hexRawTx: string): Promise<boolean> {
    await init();
    return unwrap<boolean>(g().tx.hasWitness(hexRawTx));
  },

  /** Decode a raw transaction (hex) into a structured object.
   *  Calls Go: btcutil.NewTx() from btcutil + wire.MsgTx field extraction. */
  async decode(hexRawTx: string): Promise<TxDecodeResult> {
    await init();
    return unwrap<TxDecodeResult>(g().tx.decode(hexRawTx));
  },
};
