import { init, g, unwrap } from './init';
import type { Bytes, TxDecodeResult } from './types';

/** Transaction utilities. */
export const tx = {
  /** Compute the txid (double-SHA256, reversed) of a raw transaction (hex).
   *  Calls Go: btcutil.Tx.Hash() from btcutil (via btcutil.NewTx()). */
  async hash(rawTx: Bytes): Promise<string> {
    await init();
    return unwrap<string>(g().tx.hash(rawTx));
  },

  /** Compute the witness txid (wtxid) of a raw transaction (hex).
   *  Calls Go: btcutil.Tx.WitnessHash() from btcutil (via btcutil.NewTx()). */
  async witnessHash(rawTx: Bytes): Promise<string> {
    await init();
    return unwrap<string>(g().tx.witnessHash(rawTx));
  },

  /** Check if a raw transaction (hex) contains witness data.
   *  Calls Go: btcutil.Tx.HasWitness() from btcutil (via btcutil.NewTx()). */
  async hasWitness(rawTx: Bytes): Promise<boolean> {
    await init();
    return unwrap<boolean>(g().tx.hasWitness(rawTx));
  },

  /** Decode a raw transaction (hex) into a structured object.
   *  Calls Go: btcutil.NewTx() from btcutil + wire.MsgTx field extraction. */
  async decode(rawTx: Bytes): Promise<TxDecodeResult> {
    await init();
    return unwrap<TxDecodeResult>(g().tx.decode(rawTx));
  },
};
