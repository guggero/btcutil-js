import { init, g, unwrap } from './init';
import type { Bytes } from './types';

/** Bloom filter utilities. */
export const bloom = {
  /** Compute MurmurHash3 of data (hex) with the given seed.
   *  Calls Go: bloom.MurmurHash3() from btcutil/bloom. */
  async murmurHash3(seed: number, data: Bytes): Promise<number> {
    await init();
    return unwrap<number>(g().bloom.murmurHash3(seed, data));
  },
};
