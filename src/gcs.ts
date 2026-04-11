import { init, g, unwrap } from './init';
import type { GcsFilterResult } from './types';

/** Golomb-Coded Set (GCS) filter utilities (BIP-158 compact block filters). */
export const gcs = {
  /** Build a GCS filter from data items.
   *  Calls Go: gcs.BuildGCSFilter() from btcutil/gcs.
   *  @param p - Filter parameter P (false positive rate = 1/2^P).
   *  @param m - Filter parameter M.
   *  @param hexKey - 16-byte SipHash key (hex, 32 chars).
   *  @param hexDataItems - Array of data items (hex strings). */
  async buildFilter(
    p: number,
    m: number,
    hexKey: string,
    hexDataItems: string[],
  ): Promise<GcsFilterResult> {
    await init();
    return unwrap<GcsFilterResult>(
      g().gcs.buildFilter(p, m, hexKey, hexDataItems),
    );
  },

  /** Test if a single element matches the filter.
   *  Calls Go: gcs.Filter.Match() from btcutil/gcs (via gcs.FromBytes()). */
  async match(
    hexFilter: string,
    n: number,
    p: number,
    m: number,
    hexKey: string,
    hexTarget: string,
  ): Promise<boolean> {
    await init();
    return unwrap<boolean>(
      g().gcs.match(hexFilter, n, p, m, hexKey, hexTarget),
    );
  },

  /** Test if any of the target elements match the filter.
   *  Calls Go: gcs.Filter.MatchAny() from btcutil/gcs (via gcs.FromBytes()). */
  async matchAny(
    hexFilter: string,
    n: number,
    p: number,
    m: number,
    hexKey: string,
    hexTargets: string[],
  ): Promise<boolean> {
    await init();
    return unwrap<boolean>(
      g().gcs.matchAny(hexFilter, n, p, m, hexKey, hexTargets),
    );
  },
};
