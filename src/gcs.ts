import { init, g, unwrap } from './init';
import type { Bytes, GcsFilterResult } from './types';

/** Golomb-Coded Set (GCS) filter utilities (BIP-158 compact block filters). */
export const gcs = {
  /** Build a GCS filter from data items.
   *  Calls Go: gcs.BuildGCSFilter() from btcutil/gcs.
   *  @param p - Filter parameter P (false positive rate = 1/2^P).
   *  @param m - Filter parameter M.
   *  @param key - 16-byte SipHash key (hex, 32 chars).
   *  @param dataItems - Array of data items (hex strings). */
  async buildFilter(
    p: number,
    m: number,
    key: Bytes,
    dataItems: Bytes[],
  ): Promise<GcsFilterResult> {
    await init();
    return unwrap<GcsFilterResult>(
      g().gcs.buildFilter(p, m, key, dataItems),
    );
  },

  /** Test if a single element matches the filter.
   *  Calls Go: gcs.Filter.Match() from btcutil/gcs (via gcs.FromBytes()). */
  async match(
    filter: Bytes,
    n: number,
    p: number,
    m: number,
    key: Bytes,
    target: Bytes,
  ): Promise<boolean> {
    await init();
    return unwrap<boolean>(
      g().gcs.match(filter, n, p, m, key, target),
    );
  },

  /** Test if any of the target elements match the filter.
   *  Calls Go: gcs.Filter.MatchAny() from btcutil/gcs (via gcs.FromBytes()). */
  async matchAny(
    filter: Bytes,
    n: number,
    p: number,
    m: number,
    key: Bytes,
    targets: Bytes[],
  ): Promise<boolean> {
    await init();
    return unwrap<boolean>(
      g().gcs.matchAny(filter, n, p, m, key, targets),
    );
  },
};
