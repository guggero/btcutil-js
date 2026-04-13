import { init, g, unwrap } from './init';
import { txFromJson, txToJson } from './codec';
import type { Bytes, TxData, TxDecodeResult } from './types';

/** Transaction utilities. */
export const tx = {
  /** Compute the txid (double-SHA256, reversed) of a raw transaction. */
  async hash(rawTx: Bytes): Promise<string> {
    await init();
    return unwrap<string>(g().tx.hash(rawTx));
  },

  /** Compute the witness txid (wtxid) of a raw transaction. */
  async witnessHash(rawTx: Bytes): Promise<string> {
    await init();
    return unwrap<string>(g().tx.witnessHash(rawTx));
  },

  /** Check if a raw transaction contains witness data. */
  async hasWitness(rawTx: Bytes): Promise<boolean> {
    await init();
    return unwrap<boolean>(g().tx.hasWitness(rawTx));
  },

  /** Decode a raw transaction into a structured object (with derived
   *  txid/wtxid). */
  async decode(rawTx: Bytes): Promise<TxDecodeResult> {
    await init();
    const json = unwrap<string>(g().tx.decode(rawTx));
    return txFromJson(JSON.parse(json));
  },

  /** Encode a tx (just `TxData` — no derived fields needed) back to raw
   *  bytes. */
  async encode(data: TxData): Promise<Uint8Array> {
    await init();
    const json = JSON.stringify(txToJson(data));
    return unwrap<Uint8Array>(g().tx.encode(json));
  },
};
