// The watch-only wallet orchestrator: BIP157/158 scanning over block-dn,
// with all validation and matching done by btcutil-js WASM primitives
// (neutrino namespace). Runs in the browser (OpfsStorage) and under Node
// (NodeStorage) unchanged.

import { BlockDnClient } from './block-dn-client.mjs';
import { MatchWorkerPool } from './worker-pool.mjs';

const HEADER_SIZE = 80;
const FILTER_HEADER_SIZE = 32;

// Mainnet birthday heuristics per watch type: scanning before the script
// type existed is provably useless.
const SEGWIT_HEIGHT = 481_824;
const TAPROOT_HEIGHT = 709_632;
const P2SH_HEIGHT = 173_805;

/** Guess a sensible scan start height from what is being watched. */
export function birthdayHeuristic(network, value) {
  if (network !== 'mainnet') {
    return 0;
  }
  const v = value.trim();

  // Descriptors: judge by their outermost script function.
  if (/^tr\(/.test(v)) return TAPROOT_HEIGHT;
  if (/^(wpkh|wsh)\(/.test(v)) return SEGWIT_HEIGHT;
  if (/^sh\(/.test(v)) return P2SH_HEIGHT;
  if (/\(/.test(v)) return 0;

  // Addresses: judge by their encoding.
  if (/^bc1p/i.test(v)) return TAPROOT_HEIGHT;
  if (/^bc1/i.test(v)) return SEGWIT_HEIGHT;
  if (/^3/.test(v)) return P2SH_HEIGHT;
  return 0;
}

/** Display-order hex of a raw internal-order hash. */
function reverseHex(bytes) {
  let s = '';
  for (let i = bytes.length - 1; i >= 0; i--) {
    s += bytes[i].toString(16).padStart(2, '0');
  }
  return s;
}

function toHex(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) {
    s += bytes[i].toString(16).padStart(2, '0');
  }
  return s;
}

/** Human-readable byte size for the scan stats line. */
export function formatBytes(n) {
  if (n < 1024) return `${n} B`;
  const units = ['KiB', 'MiB', 'GiB'];
  let value = n;
  let unit = 'B';
  for (const u of units) {
    if (value < 1024) break;
    value /= 1024;
    unit = u;
  }
  return `${value.toFixed(1)} ${unit}`;
}

/** The "N blocks scanned with X batches in Y s" stats line. */
export function formatScanStats(stats) {
  return `${stats.blocksScanned.toLocaleString()} blocks scanned with ` +
    `${stats.batches} batch${stats.batches === 1 ? '' : 'es'} in ` +
    `${stats.seconds.toFixed(1)} s (${stats.matchedBlocks} blocks ` +
    `matched, ${formatBytes(stats.bytesDownloaded)} downloaded)`;
}

/** Map items through an async fn with at most `limit` in flight — parallel
 *  but polite: an unbounded Promise.all over hundreds of block fetches can
 *  overwhelm the origin server. Results keep the input order. */
async function mapPool(items, limit, fn) {
  const results = new Array(items.length);
  let next = 0;
  const workers = Array.from(
    { length: Math.min(limit, items.length) },
    async () => {
      for (;;) {
        const i = next++;
        if (i >= items.length) return;
        results[i] = await fn(items[i], i);
      }
    },
  );
  await Promise.all(workers);
  return results;
}

export class WatchOnlyWallet {
  /**
   * @param {object} opts
   * @param {any} opts.lib       the btcutil-js sync API (await init())
   * @param {string} opts.network
   * @param {string} opts.serverUrl block-dn base URL
   * @param {any} opts.storage   OpfsStorage or NodeStorage
   * @param {number} [opts.batchSize] how many filter files (2000 blocks
   *   each) are fetched and scanned in parallel per batch (1..16). Higher
   *   values speed up scans at the cost of memory: each in-flight mainnet
   *   filter file is up to ~50 MiB.
   */
  static async open({ lib, network, serverUrl, storage, batchSize }) {
    const wallet = new WatchOnlyWallet();
    wallet.lib = lib;
    wallet.network = network;
    wallet.client = new BlockDnClient(serverUrl);
    wallet.storage = storage;
    wallet.batchSize = Math.max(
      1, Math.min(16, Math.floor(batchSize ?? 4)),
    );

    wallet.data = (await storage.getWallet()) ?? {
      network,
      watches: [],
      utxos: {},
      spent: {},
      scannedTo: -1,
    };
    if (wallet.data.network !== network) {
      throw new Error(`storage holds ${wallet.data.network} data`);
    }

    // Resume the validated header chain from its compact exported state;
    // fall back to a fresh chain (and re-validation) if none is stored.
    const state = await storage.getChainState();
    wallet.chain = lib.neutrino.headerChain(network, state ?? undefined);

    // The chain state and the flat files must agree; if they don't
    // (e.g. an interrupted sync), revalidate from the stored headers.
    const stored = await storage.headerCount();
    const tip = wallet.chain.tip().tipHeight;
    if (tip + 1 !== stored) {
      wallet.chain.free();
      wallet.chain = lib.neutrino.headerChain(network);
      const batch = 50_000;
      for (let h = 0; h < stored; h += batch) {
        const chunk = await storage.readHeaders(
          h, Math.min(batch, stored - h),
        );
        wallet.chain.append(chunk);
      }
    }

    return wallet;
  }

  // -- watches ------------------------------------------------------------

  /** Watch a single address. */
  async addAddress(address, birthHeight) {
    const script = this.lib.txscript.payToAddrScript(
      address, this.network,
    );
    await this.#addWatch({
      kind: 'address',
      value: address,
      birthHeight: birthHeight ??
        birthdayHeuristic(this.network, address),
      scripts: [toHex(script)],
      addresses: [address],
    });
  }

  /** Watch an output descriptor, deriving `count` addresses per multipath.
   *  (Fixed-range derivation — a production wallet would extend the gap on
   *  finds and rescan.) */
  async addDescriptor(descriptor, birthHeight, count = 100) {
    const desc = this.lib.descriptors.create(descriptor);
    try {
      const scripts = [];
      const addresses = [];
      for (let mp = 0; mp < desc.multipathLen(); mp++) {
        for (let i = 0; i < count; i++) {
          const addr = desc.addressAt(this.network, mp, i);
          addresses.push(addr);
          scripts.push(toHex(this.lib.txscript.payToAddrScript(
            addr, this.network,
          )));
        }
      }
      await this.#addWatch({
        kind: 'descriptor',
        value: desc.toString(),
        birthHeight: birthHeight ??
          birthdayHeuristic(this.network, descriptor),
        scripts,
        addresses,
      });
    } finally {
      desc.free();
    }
  }

  async #addWatch(watch) {
    this.data.watches.push(watch);

    // New watches need their whole range scanned: pull the scan cursor
    // back to the new birthday if it is already past it.
    if (this.data.scannedTo >= watch.birthHeight) {
      this.data.scannedTo = watch.birthHeight - 1;
    }
    await this.storage.setWallet(this.data);
  }

  // -- header sync ----------------------------------------------------------

  /** Sync block headers and filter headers to the server tip, validating
   *  everything. onProgress(kind, height, target) is called per file. */
  async syncHeaders(onProgress = () => {}) {
    const status = await this.client.status();
    const perFile = status.entries_per_header_file;
    const target = status.best_block_height;

    // Block headers: fetch aligned files, validate, persist the raw bytes.
    for (;;) {
      const tip = this.chain.tip().tipHeight;
      if (tip >= target) break;

      const boundary = Math.floor(((tip + 1) / perFile)) * perFile;
      const file = await this.client.headers(boundary);
      const skip = (tip + 1 - boundary) * HEADER_SIZE;
      const fresh = file.subarray(skip);
      if (fresh.length === 0) break;

      this.chain.append(fresh);
      await this.storage.appendHeaders(fresh);
      onProgress('headers', this.chain.tip().tipHeight, target);
    }
    await this.storage.setChainState(this.chain.exportState());

    // Filter headers: same file alignment. There is no client-side
    // cryptographic link to the block headers; each downloaded *filter*
    // is verified against this chain at scan time, which makes CDN/server
    // corruption detectable.
    for (;;) {
      const have = await this.storage.filterHeaderCount();
      if (have > target) break;

      const boundary = Math.floor((have / perFile)) * perFile;
      const file = await this.client.filterHeaders(boundary);
      const fresh = file.subarray((have - boundary) * FILTER_HEADER_SIZE);
      if (fresh.length === 0) break;

      await this.storage.appendFilterHeaders(fresh);
      onProgress(
        'filter-headers',
        await this.storage.filterHeaderCount() - 1, target,
      );
    }
  }

  // -- scanning -------------------------------------------------------------

  /** The scan start height: the lowest unscanned birthday. */
  scanStart() {
    const births = this.data.watches.map((w) => w.birthHeight);
    if (births.length === 0) return null;
    return Math.max(Math.min(...births), this.data.scannedTo + 1);
  }

  /** Build the Go-side watch list from all watches plus known UTXOs (for
   *  spend detection). Caller must free() it. */
  #buildWatchList() {
    const scripts = this.data.watches.flatMap((w) => w.scripts);
    const watch = this.lib.neutrino.watchList(scripts);
    for (const key of Object.keys(this.data.utxos)) {
      const [txid, vout] = key.split(':');
      watch.addOutpoint(txid, Number(vout));
    }
    return watch;
  }

  /** Apply one scanned block's finds to the wallet state. */
  async #applyBlock(watch, height, blockHash, result) {
    for (const out of result.outputs) {
      const key = `${out.txid}:${out.vout}`;
      if (this.data.utxos[key] || this.data.spent[key]) continue;

      this.data.utxos[key] = {
        value: out.value,
        height,
        blockHash,
        pkScript: toHex(out.pkScript),
        address: this.#addressForScript(out.pkScript),
      };

      // Watch the new UTXO so a later block's spend is detected.
      watch.addOutpoint(out.txid, out.vout);
    }

    for (const spend of result.spends) {
      const key = `${spend.prevTxid}:${spend.prevVout}`;
      const utxo = this.data.utxos[key];
      if (!utxo) continue;

      delete this.data.utxos[key];
      this.data.spent[key] = {
        ...utxo, spentBy: spend.txid, spentAt: height,
      };
      watch.removeOutpoint(spend.prevTxid, spend.prevVout);
    }
  }

  #addressForScript(script) {
    for (const w of this.data.watches) {
      const hex = toHex(script);
      const idx = w.scripts.indexOf(hex);
      if (idx >= 0) return w.addresses[idx];
    }
    return '';
  }

  /** Fetch and match one file-aligned filter range: download the filter
   *  file (in parallel with reading the stored header slices), then match —
   *  on a worker when a pool is given, inline otherwise. A filter that
   *  fails its commitment check usually means a truncated/corrupted file
   *  (possibly cached by a CDN), so the file is refetched once with a
   *  cache-busting parameter before giving up. */
  async #matchRange(pool, watch, { start, count }, from) {
    const attempt = async (fresh) => {
      const [filterFile, headers, filterHeaders] = await Promise.all([
        this.client.filters(start, { fresh }),
        this.storage.readHeaders(start, count),
        this.storage.readFilterHeaders(start, count),
      ]);
      const prev = start === 0 ? '' : reverseHex(
        await this.storage.readFilterHeaders(start - 1, 1),
      );

      // One pass: verify every filter against the committed filter
      // header chain and match against the watch list.
      const matches = pool
        ? await pool.match({
          startHeight: start, filterFile, headers, filterHeaders, prev,
        })
        : this.lib.neutrino.matchFilters(
          watch, start, filterFile, headers, filterHeaders, prev,
        );

      // Blocks below a watch's birthday only appear because files are
      // range-aligned; drop them here.
      return matches.filter((m) => m.height >= from);
    };

    try {
      return await attempt(false);
    } catch (err) {
      if (!String(err?.message).includes('committed filter header')) {
        throw err;
      }
      return attempt(true);
    }
  }

  /** Scan filters from the lowest unscanned birthday to the header tip,
   *  fetching and fully scanning blocks whose filter matches.
   *
   *  Filter files are processed in batches of `batchSize`: each file of a
   *  batch is downloaded and matched concurrently (matching runs on a pool
   *  of worker threads, each with its own WASM instance), then the batch
   *  completes as one unit (barrier) before the wallet state is persisted
   *  and onProgress(height, target, foundCount) fires — once per batch.
   *
   *  Returns the wallet summary plus `stats` for the completed scan. */
  async scan(onProgress = () => {}) {
    const from = this.scanStart();
    const tip = this.chain.tip().tipHeight;
    const stats = {
      blocksScanned: 0,
      batches: 0,
      matchedBlocks: 0,
      seconds: 0,
      bytesDownloaded: 0,
    };
    if (from === null || from > tip) {
      this.lastScanStats = stats;
      return { ...this.summary(), stats };
    }

    const startedAt = Date.now();
    const bytesBefore = this.client.bytesFetched;
    const status = await this.client.status();
    const perFile = status.entries_per_filter_file;
    const batchSpan = perFile * this.batchSize;

    const watch = this.#buildWatchList();

    // Real matching parallelism needs one WASM instance per thread; fall
    // back to inline matching if workers are unavailable (pool is null).
    const pool = this.batchSize > 1
      ? await MatchWorkerPool.create(
        this.batchSize, this.data.watches.flatMap((w) => w.scripts),
      )
      : null;

    try {
      const firstFile = Math.floor(from / perFile) * perFile;
      for (let batch = firstFile; batch <= tip; batch += batchSpan) {
        // The file-aligned ranges of this batch (the last one may hold
        // fewer files, and its last file fewer entries).
        const ranges = [];
        for (let i = 0; i < this.batchSize; i++) {
          const start = batch + i * perFile;
          if (start > tip) break;
          ranges.push({
            start, count: Math.min(perFile, tip - start + 1),
          });
        }

        // Download + match every range of the batch concurrently; the
        // await is the batch barrier. Ranges (and thus matches) stay in
        // ascending height order.
        const matches = (await Promise.all(ranges.map(
          (range) => this.#matchRange(pool, watch, range, from),
        ))).flat();
        stats.matchedBlocks += matches.length;

        // Fetch all matched blocks in parallel (bounded — a hot watch
        // list can match hundreds of blocks per batch), but apply them
        // strictly in ascending height order: an output found at
        // height h must be outpoint-watched before a later block of
        // the same batch spends it.
        const blocks = await mapPool(
          matches, this.batchSize * 2,
          (m) => this.client.block(m.blockHash),
        );
        for (let i = 0; i < matches.length; i++) {
          const result = this.lib.neutrino.scanBlock(watch, blocks[i]);
          await this.#applyBlock(
            watch, matches[i].height, matches[i].blockHash, result,
          );
        }

        // Barrier: the whole batch is complete — persist and report
        // exactly once.
        const last = ranges[ranges.length - 1];
        this.data.scannedTo = last.start + last.count - 1;
        await this.storage.setWallet(this.data);
        stats.batches++;
        onProgress(
          this.data.scannedTo, tip,
          Object.keys(this.data.utxos).length,
        );
      }
    } finally {
      watch.free();
      pool?.free();
    }

    stats.blocksScanned = tip - from + 1;
    stats.seconds = (Date.now() - startedAt) / 1000;
    stats.bytesDownloaded = this.client.bytesFetched - bytesBefore;
    this.lastScanStats = stats;

    return { ...this.summary(), stats };
  }

  // -- tip following ----------------------------------------------------------

  /** One tip poll: append new headers (handling shallow reorgs), then scan
   *  any new blocks via single-filter fetches. Returns true if the tip
   *  moved. */
  async followTip() {
    const status = await this.client.status();
    let tip = this.chain.tip().tipHeight;
    if (status.best_block_height <= tip &&
      status.best_block_hash === this.chain.tip().tipHash) {

      return false;
    }

    // A shallow reorg shows up as a prev-hash mismatch when appending the
    // new tail: roll back a few blocks and retry once.
    try {
      await this.#appendTail(status);
    } catch (err) {
      const back = Math.max(0, tip - 6);
      this.chain.rollback(back);
      await this.storage.truncateHeaders(back + 1);
      await this.storage.truncateFilterHeaders(back + 1);
      this.data.scannedTo = Math.min(this.data.scannedTo, back);
      await this.#appendTail(status);
    }
    await this.storage.setChainState(this.chain.exportState());
    await this.scan();

    return true;
  }

  async #appendTail(status) {
    const perFile = status.entries_per_header_file;
    for (;;) {
      const tip = this.chain.tip().tipHeight;
      if (tip >= status.best_block_height) break;

      const boundary = Math.floor((tip + 1) / perFile) * perFile;
      const [headerFile, fheaderFile] = await Promise.all([
        this.client.headers(boundary),
        this.client.filterHeaders(boundary),
      ]);

      const fresh = headerFile.subarray((tip + 1 - boundary) * HEADER_SIZE);
      if (fresh.length === 0) break;
      this.chain.append(fresh);
      await this.storage.appendHeaders(fresh);

      const have = await this.storage.filterHeaderCount();
      await this.storage.appendFilterHeaders(
        fheaderFile.subarray((have - boundary) * FILTER_HEADER_SIZE),
      );
    }
  }

  // -- queries ---------------------------------------------------------------

  utxos() {
    return Object.entries(this.data.utxos).map(([key, u]) => ({
      outpoint: key, ...u,
    }));
  }

  /** Entry counts and byte sizes of the locally cached chain data. */
  cacheStats() {
    return this.storage.stats();
  }

  summary() {
    const utxos = this.utxos();
    return {
      tipHeight: this.chain.tip().tipHeight,
      scannedTo: this.data.scannedTo,
      numWatches: this.data.watches.length,
      numUtxos: utxos.length,
      balanceSats: utxos.reduce((s, u) => s + u.value, 0),
      utxos,
    };
  }

  close() {
    this.chain.free();
  }
}
