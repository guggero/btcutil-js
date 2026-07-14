// Minimal block-dn (https://github.com/guggero/block-dn) HTTP client.
// Endpoints are height-aligned immutable files (long-cached behind a CDN)
// plus a mutable in-memory tail; see the block-dn docs for the formats.

/** @typedef {{
 *    chain_name: string,
 *    best_block_height: number,
 *    best_block_hash: string,
 *    best_filter_height: number,
 *    best_filter_header: string,
 *    entries_per_header_file: number,
 *    entries_per_filter_file: number,
 * }} BlockDnStatus */

export class BlockDnClient {
  /** @param {string} baseUrl e.g. "https://block-dn.org" */
  constructor(baseUrl) {
    this.baseUrl = baseUrl.replace(/\/+$/, '');

    /** Total binary bytes downloaded through this client. */
    this.bytesFetched = 0;
  }

  /** `fresh: true` appends a cache-busting query parameter, bypassing any
   *  CDN-cached copy of the URL — the recovery path when a cached response
   *  turns out to be truncated/corrupted (detected via the filter-header
   *  commitment check). */
  async #fetchBinary(path, { attempts = 4, fresh = false } = {}) {
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
        // failing verification.
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

  /** @returns {Promise<BlockDnStatus>} */
  async status() {
    const resp = await fetch(`${this.baseUrl}/status`);
    if (!resp.ok) {
      throw new Error(`/status: HTTP ${resp.status}`);
    }
    return resp.json();
  }

  /** Raw 80-byte headers from the file-aligned startHeight up to either the
   *  file boundary or the server tip. */
  headers(startHeight) {
    return this.#fetchBinary(`/headers/${startHeight}`);
  }

  /** Raw 32-byte filter headers, same range semantics as headers(). */
  filterHeaders(startHeight) {
    return this.#fetchBinary(`/filter-headers/${startHeight}`);
  }

  /** One var-int prefixed filter file (or the in-memory tail). */
  filters(startHeight, opts) {
    return this.#fetchBinary(`/filters/${startHeight}`, opts);
  }

  /** The raw filter of a single block (tip following). */
  filterSingle(height) {
    return this.#fetchBinary(`/filters/single/${height}`);
  }

  /** A full raw block by display-order hex hash. */
  block(hashHex) {
    return this.#fetchBinary(`/block/${hashHex}`);
  }
}
