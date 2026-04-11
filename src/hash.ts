import { init, g, unwrap } from './init';

/** Cryptographic hash functions. */
export const hash = {
  /** Compute RIPEMD160(SHA256(data)). Input and output are hex.
   *  Calls Go: btcutil.Hash160() from btcutil. */
  async hash160(hexData: string): Promise<Uint8Array> {
    await init();
    return unwrap<Uint8Array>(g().hash.hash160(hexData));
  },
};
