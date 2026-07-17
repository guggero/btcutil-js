/**
 * A typed client for a block-dn server (https://github.com/guggero/block-dn):
 * Bitcoin chain data — headers, BIP158 compact filters, blocks — served as
 * CDN-cacheable HTTP files. Endpoints are height-aligned immutable files
 * plus a mutable in-memory tail; see the block-dn docs for the formats.
 */

import type { FilterType } from './types';

// Path segment for a filter flavour: the basic filter lives at the original
// un-typed endpoints, custom filters under /type/{filterType}/.
function typeSegment(filterType: FilterType): string {
  return filterType === 'basic' ? '' : `type/${filterType}/`;
}

/** The /status response of a block-dn server. */
export interface BlockDnStatus {
  chain_genesis_hash: string;
  chain_name: string;
  best_block_height: number;
  best_block_hash: string;
  best_filter_height: number;
  best_filter_header: string;
  entries_per_header_file: number;
  entries_per_filter_file: number;
  entries_per_sptweak_file?: number;
  all_files_synced: boolean;
  /** Whether the server also maintains the output-type-restricted custom
   *  filters (p2wpkh/p2wsh/p2tr/segwit). Absent on older servers. */
  custom_filters_available?: boolean;
  /** Tip of the BIP-352 tweak-data index; 0/absent when disabled. */
  best_sptweak_height?: number;
  /** Tip of the custom-filter index; 0/absent when disabled. */
  best_custom_filter_height?: number;
}

/** Options for a single fetch. */
export interface BlockDnFetchOptions {
  /** Retry attempts for transient (5xx / network) errors. Default 4. */
  attempts?: number;
  /** Append a cache-busting query parameter, bypassing any CDN-cached copy
   *  of the URL — the recovery path when a cached response turns out to be
   *  truncated/corrupted (detected via the filter-header commitment
   *  check). */
  fresh?: boolean;
  /** Which filter flavour to fetch. Default `'basic'`. */
  filterType?: FilterType;
}

export class BlockDnClient {
  readonly baseUrl: string;

  /** Total binary bytes downloaded through this client. */
  bytesFetched = 0;

  /** @param baseUrl e.g. `"https://block-dn.org"` */
  constructor(baseUrl: string) {
    this.baseUrl = baseUrl.replace(/\/+$/, '');
  }

  private async fetchBinary(
    path: string,
    { attempts = 4, fresh = false }: BlockDnFetchOptions = {},
  ): Promise<Uint8Array> {
    const url = `${this.baseUrl}${path}` +
      (fresh ? `?fresh=${Date.now()}` : '');
    for (let attempt = 1; ; attempt++) {
      try {
        const resp = await fetch(url);

        // Server-side hiccups (origin overload, CDN 5xx) are transient;
        // client errors are not.
        if (resp.status >= 500) {
          throw new Error(`${path}: HTTP ${resp.status}`);
        }
        if (!resp.ok) {
          return Promise.reject(
            new Error(`${path}: HTTP ${resp.status}`),
          );
        }
        const buf = new Uint8Array(await resp.arrayBuffer());

        // The server (or CDN) announces the exact length for most
        // endpoints; detect truncated transfers early instead of
        // failing verification later.
        const want = resp.headers.get('content-length');
        if (want !== null && buf.length !== Number(want)) {
          throw new Error(`${path}: truncated response ` +
            `(${buf.length}/${want} bytes)`);
        }
        this.bytesFetched += buf.length;
        return buf;
      } catch (err) {
        if (attempt >= attempts) throw err;
        await new Promise((r) =>
          setTimeout(r, 500 * 2 ** (attempt - 1)));
      }
    }
  }

  /** The server's current tip and file-layout parameters. */
  async status(): Promise<BlockDnStatus> {
    const resp = await fetch(`${this.baseUrl}/status`);
    if (!resp.ok) {
      throw new Error(`/status: HTTP ${resp.status}`);
    }
    return resp.json();
  }

  /** Raw 80-byte headers from the file-aligned startHeight up to either
   *  the file boundary or the server tip. */
  headers(startHeight: number): Promise<Uint8Array> {
    return this.fetchBinary(`/headers/${startHeight}`);
  }

  /** Raw 32-byte filter headers, same range semantics as headers(). */
  filterHeaders(
    startHeight: number,
    filterType: FilterType = 'basic',
  ): Promise<Uint8Array> {
    return this.fetchBinary(
      `/filter-headers/${typeSegment(filterType)}${startHeight}`,
    );
  }

  /** One var-int prefixed filter file (or the in-memory tail). */
  filters(
    startHeight: number,
    opts?: BlockDnFetchOptions,
  ): Promise<Uint8Array> {
    return this.fetchBinary(
      `/filters/${typeSegment(opts?.filterType ?? 'basic')}${startHeight}`,
      opts,
    );
  }

  /** The raw filter of a single block (tip following). Basic filters
   *  only — block-dn does not define a single-filter endpoint for the
   *  custom flavours. */
  filterSingle(height: number): Promise<Uint8Array> {
    return this.fetchBinary(`/filters/single/${height}`);
  }

  /** A full raw block by display-order hex hash. */
  block(hashHex: string): Promise<Uint8Array> {
    return this.fetchBinary(`/block/${hashHex}`);
  }

  /** One binary BIP-352 tweak file: an 18-byte self-describing header
   *  (network magic, format version, file type, start height, dust
   *  limit), then per block of the range a compact-size count followed by
   *  that many 33-byte compressed tweak keys (input_hash * A_sum), in
   *  transaction order. The dust limit selects one of the server's
   *  materialized filter levels (0, 600, 1000 or 3750 sats): a
   *  transaction is included if its largest taproot output value is
   *  strictly greater than the limit. Requires --index-sp-tweak-data on
   *  the server. */
  spTweaks(
    dustLimit: number,
    startHeight: number,
    opts?: BlockDnFetchOptions,
  ): Promise<Uint8Array> {
    return this.fetchBinary(
      `/sp/tweaks/${dustLimit}/${startHeight}`, opts,
    );
  }

  /** Whether an outpoint is currently unspent, via the server's proxied
   *  UTXO lookup. Returns null when the server can't answer. */
  async isUnspent(txid: string, vout: number): Promise<boolean | null> {
    try {
      const resp = await fetch(
        `${this.baseUrl}/utxo/${txid}-${vout}?format=json`,
      );
      if (!resp.ok) return null;
      const result = await resp.json();

      // Core's REST getutxos bitmap: '1' = unspent, '0' = spent.
      if (typeof result?.bitmap === 'string') {
        return result.bitmap.startsWith('1');
      }
      return null;
    } catch {
      return null;
    }
  }
}
