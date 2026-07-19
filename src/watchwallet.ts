/**
 * A watch-only wallet engine doing BIP157/158 compact-filter scanning over
 * a block-dn HTTP server: header sync with full local validation, batched
 * parallel filter scanning (worker-pool matching where available), tip
 * following with shallow-reorg handling, and UTXO lifecycle tracking.
 *
 * The engine is UI-agnostic: it drives a {@link WalletStorage} backend and
 * reports progress through callbacks. The cryptography-toolkit "BIP-157:
 * Compact Filters" page is the browser frontend; tools/neutrino-demo.mjs
 * is a headless CLI driver.
 */

import { init, type BtcutilSync } from './init';
import { BlockDnClient, type BlockDnStatus } from './blockdn';
import { MatchWorkerPool } from './matchpool';
import { FILTER_TYPES } from './walletstore';
import type { WalletStorage, StorageStats } from './walletstore';
import type { HeaderChain, WatchList, FilterMatch } from './neutrino';
import type { FilterType, Network } from './types';

const HEADER_SIZE = 80;
const FILTER_HEADER_SIZE = 32;

// Mainnet birthday heuristics per watch type: scanning before the script
// type existed is provably useless.
const SEGWIT_HEIGHT = 481_824;
const TAPROOT_HEIGHT = 709_632;
const P2SH_HEIGHT = 173_805;

/** Guess a sensible scan start height from what is being watched. */
export function birthdayHeuristic(network: Network, value: string): number {
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

/** The custom-filter flavour a single output script belongs to, or null
 *  for anything outside the fully-native segwit set (legacy, nested
 *  segwit, non-standard). */
export function scriptFilterType(
  scriptHex: string,
): 'p2wpkh' | 'p2wsh' | 'p2tr' | null {
  if (/^0014[0-9a-f]{40}$/i.test(scriptHex)) return 'p2wpkh';
  if (/^0020[0-9a-f]{64}$/i.test(scriptHex)) return 'p2wsh';
  if (/^5120[0-9a-f]{64}$/i.test(scriptHex)) return 'p2tr';
  return null;
}

/** The smallest filter flavour covering all given output scripts: the
 *  single native-segwit type when the scripts are homogeneous, `segwit`
 *  for a native-segwit mixture, and the full `basic` filter as soon as any
 *  non-native-segwit script is watched (or when the server offers no
 *  custom filters). Spends of found UTXOs stay detectable because a
 *  watched UTXO always pays a watched script, so its spend appears in the
 *  same flavour's filter. */
export function selectFilterType(
  scriptsHex: string[],
  customFiltersAvailable: boolean,
): FilterType {
  if (!customFiltersAvailable || scriptsHex.length === 0) {
    return 'basic';
  }
  const types = new Set<string>();
  for (const script of scriptsHex) {
    const t = scriptFilterType(script);
    if (t === null) {
      return 'basic';
    }
    types.add(t);
  }
  return types.size === 1
    ? (types.values().next().value as FilterType)
    : 'segwit';
}

/** Display-order hex of a raw internal-order hash. */
function reverseHex(bytes: Uint8Array): string {
  let s = '';
  for (let i = bytes.length - 1; i >= 0; i--) {
    s += bytes[i].toString(16).padStart(2, '0');
  }
  return s;
}

function toHex(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) {
    s += bytes[i].toString(16).padStart(2, '0');
  }
  return s;
}

/** Human-readable byte size for the scan stats line. */
export function formatBytes(n: number): string {
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

/** Statistics of one completed {@link WatchOnlyWallet.scan} run. */
export interface ScanStats {
  blocksScanned: number;
  /** Number of 2000-block ranges processed and checkpointed. */
  batches: number;
  matchedBlocks: number;
  seconds: number;
  bytesDownloaded: number;
  /** The filter flavour the scan used. */
  filterType: FilterType;
}

/** The "N blocks scanned in X ranges in Y s" stats line. */
export function formatScanStats(stats: ScanStats): string {
  return `${stats.blocksScanned.toLocaleString()} blocks scanned in ` +
    `${stats.batches} range${stats.batches === 1 ? '' : 's'} in ` +
    `${stats.seconds.toFixed(1)} s (${stats.matchedBlocks} blocks ` +
    `matched, ${formatBytes(stats.bytesDownloaded)} downloaded, ` +
    `${stats.filterType} filters)`;
}

/** Map items through an async fn with at most `limit` in flight — parallel
 *  but polite: an unbounded Promise.all over hundreds of block fetches can
 *  overwhelm the origin server. Results keep the input order. */
export async function mapPool<T, R>(
  items: T[],
  limit: number,
  fn: (item: T, i: number) => Promise<R>,
): Promise<R[]> {
  const results = new Array<R>(items.length);
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

/** One watched item (address or descriptor) with its derived scripts. */
export interface WalletWatch {
  kind: 'address' | 'descriptor';
  value: string;
  birthHeight: number;
  scripts: string[];
  addresses: string[];
}

/** A tracked unspent output. */
export interface WalletUtxo {
  value: number;
  height: number;
  blockHash: string;
  pkScript: string;
  address: string;
}

/** The wallet summary returned by {@link WatchOnlyWallet.summary}. */
export interface WalletSummary {
  tipHeight: number;
  scannedTo: number;
  numWatches: number;
  numUtxos: number;
  balanceSats: number;
  utxos: (WalletUtxo & { outpoint: string })[];
}

/** Options for {@link WatchOnlyWallet.open}. */
export interface WatchOnlyWalletOptions {
  network: Network;
  /** block-dn base URL, e.g. `"https://block-dn.org"`. */
  serverUrl: string;
  storage: WalletStorage;
  /** How many filter files (2000 blocks each) are fetched and scanned in
   *  parallel per batch (1..16). Higher values speed up scans at the cost
   *  of memory: each in-flight mainnet filter file is up to ~50 MiB.
   *  Default 4. */
  batchSize?: number;
  /** Optional WASM source forwarded to `init()` (URL string). Also passed
   *  to the match workers. */
  wasmSource?: string;
  /** Explicit URL of the match-worker script; see
   *  {@link MatchPoolOptions.workerUrl}. */
  workerUrl?: string | URL;
}

interface WalletData {
  network: string;
  watches: WalletWatch[];
  utxos: Record<string, WalletUtxo>;
  spent: Record<string, WalletUtxo & { spentBy: string; spentAt: number }>;
  scannedTo: number;
}

export class WatchOnlyWallet {
  lib!: BtcutilSync;
  network!: Network;
  client!: BlockDnClient;
  storage!: WalletStorage;
  batchSize!: number;
  chain!: HeaderChain;
  lastScanStats: ScanStats | null = null;
  /** The filter flavour selected for the current watch set; refreshed by
   *  syncHeaders()/scan(). */
  filterType: FilterType = 'basic';

  /** Called whenever a new UTXO paying a watched script is recorded —
   *  set once after open(); fires from full scans and tip following
   *  alike. */
  onFound?: (utxo: {
    txid: string; vout: number; value: number; address: string;
    height: number;
  }) => void;

  /** Called whenever a previously recorded UTXO is detected as spent.
   *  `txid`/`vout` identify the spent UTXO, `spentBy` the spending
   *  transaction and `height` the block it confirmed in. */
  onSpent?: (spend: {
    txid: string; vout: number; value: number; address: string;
    spentBy: string; height: number;
  }) => void;

  private data!: WalletData;
  private wasmSource?: string;
  private workerUrl?: string | URL;

  /** Open (or create) a wallet on the given storage backend. */
  static async open(opts: WatchOnlyWalletOptions): Promise<WatchOnlyWallet> {
    const wallet = new WatchOnlyWallet();
    wallet.lib = await init(opts.wasmSource);
    wallet.network = opts.network;
    wallet.client = new BlockDnClient(opts.serverUrl);
    wallet.storage = opts.storage;
    wallet.batchSize = Math.max(
      1, Math.min(16, Math.floor(opts.batchSize ?? 8)),
    );
    wallet.wasmSource = opts.wasmSource;
    wallet.workerUrl = opts.workerUrl;

    wallet.data = (await opts.storage.getWallet()) ?? {
      network: opts.network,
      watches: [],
      utxos: {},
      spent: {},
      scannedTo: -1,
    };
    if (wallet.data.network !== opts.network) {
      throw new Error(`storage holds ${wallet.data.network} data`);
    }

    // Resume the validated header chain from its compact exported state;
    // fall back to a fresh chain (and re-validation) if none is stored.
    const state = await opts.storage.getChainState();
    wallet.chain = wallet.lib.neutrino.headerChain(
      opts.network, state ?? undefined,
    );

    // The chain state and the flat files must agree; if they don't
    // (e.g. an interrupted sync), revalidate from the stored headers.
    const stored = await opts.storage.headerCount();
    const tip = wallet.chain.tip().tipHeight;
    if (tip + 1 !== stored) {
      wallet.chain.free();
      wallet.chain = wallet.lib.neutrino.headerChain(opts.network);
      const batch = 50_000;
      for (let h = 0; h < stored; h += batch) {
        const chunk = await opts.storage.readHeaders(
          h, Math.min(batch, stored - h),
        );
        wallet.chain.append(chunk);
      }
    }

    return wallet;
  }

  // -- watches --------------------------------------------------------------

  /** Watch a single address. */
  async addAddress(address: string, birthHeight?: number): Promise<void> {
    const script = this.lib.txscript.payToAddrScript(
      address, this.network,
    );
    await this.addWatch({
      kind: 'address',
      value: address,
      birthHeight: birthHeight ??
        birthdayHeuristic(this.network, address),
      scripts: [toHex(script)],
      addresses: [address],
    });
  }

  /** Watch an output descriptor, deriving `count` addresses per multipath.
   *  (Fixed-range derivation — extending the gap on finds and rescanning
   *  is the caller's concern for now.) */
  async addDescriptor(
    descriptor: string,
    birthHeight?: number,
    count = 100,
  ): Promise<void> {
    const desc = this.lib.descriptors.create(descriptor);
    try {
      const scripts: string[] = [];
      const addresses: string[] = [];
      for (let mp = 0; mp < desc.multipathLen(); mp++) {
        for (let i = 0; i < count; i++) {
          const addr = desc.addressAt(this.network, mp, i);
          addresses.push(addr);
          scripts.push(toHex(this.lib.txscript.payToAddrScript(
            addr, this.network,
          )));
        }
      }
      await this.addWatch({
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

  private async addWatch(watch: WalletWatch): Promise<void> {
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
  async syncHeaders(
    onProgress: (
      kind: 'headers' | 'filter-headers',
      height: number,
      target: number,
    ) => void = () => {},
  ): Promise<void> {
    const status = await this.client.status();
    const perFile = status.entries_per_header_file;
    const target = status.best_block_height;

    // Block headers: fetch aligned files, validate, persist the raw
    // bytes.
    for (;;) {
      const tip = this.chain.tip().tipHeight;
      if (tip >= target) break;

      const boundary = Math.floor((tip + 1) / perFile) * perFile;
      const file = await this.client.headers(boundary);
      const skip = (tip + 1 - boundary) * HEADER_SIZE;
      const fresh = file.subarray(skip);
      if (fresh.length === 0) break;

      this.chain.append(fresh);
      await this.storage.appendHeaders(fresh);
      onProgress('headers', this.chain.tip().tipHeight, target);
    }
    await this.storage.setChainState(this.chain.exportState());

    await this.syncFilterHeaders(status, onProgress);
  }

  /** The smallest filter flavour covering the current watch set (given
   *  what the server offers). */
  private selectType(status: BlockDnStatus): FilterType {
    this.filterType = selectFilterType(
      this.data.watches.flatMap((w) => w.scripts),
      status.custom_filters_available === true,
    );
    return this.filterType;
  }

  /** Sync the selected flavour's filter-header chain to the tip. Chains of
   *  other flavours already in the store are left untouched — they coexist
   *  and stay valid for later scans with a different watch set.
   *
   *  There is no client-side cryptographic link to the block headers; each
   *  downloaded *filter* is verified against this chain at scan time,
   *  which makes CDN/server corruption detectable. */
  private async syncFilterHeaders(
    status: BlockDnStatus,
    onProgress: (
      kind: 'headers' | 'filter-headers',
      height: number,
      target: number,
    ) => void = () => {},
  ): Promise<void> {
    const filterType = this.selectType(status);
    const perFile = status.entries_per_header_file;
    const target = status.best_block_height;

    for (;;) {
      const have = await this.storage.filterHeaderCount(filterType);
      if (have > target) break;

      const boundary = Math.floor(have / perFile) * perFile;
      const file = await this.client.filterHeaders(boundary, filterType);
      const fresh = file.subarray((have - boundary) * FILTER_HEADER_SIZE);
      if (fresh.length === 0) break;

      await this.storage.appendFilterHeaders(fresh, filterType);
      onProgress(
        'filter-headers',
        await this.storage.filterHeaderCount(filterType) - 1, target,
      );
    }
  }

  // -- scanning -------------------------------------------------------------

  /** The scan start height: the lowest unscanned birthday, or null when
   *  there is nothing to scan. */
  scanStart(): number | null {
    const births = this.data.watches.map((w) => w.birthHeight);
    if (births.length === 0) return null;
    return Math.max(Math.min(...births), this.data.scannedTo + 1);
  }

  /** Build the Go-side watch list from all watches plus known UTXOs (for
   *  spend detection). Caller must free() it. */
  private buildWatchList(): WatchList {
    const scripts = this.data.watches.flatMap((w) => w.scripts);
    const watch = this.lib.neutrino.watchList(scripts);
    for (const key of Object.keys(this.data.utxos)) {
      const [txid, vout] = key.split(':');
      watch.addOutpoint(txid, Number(vout));
    }
    return watch;
  }

  /** Apply one scanned block's finds to the wallet state. */
  private async applyBlock(
    watch: WatchList,
    height: number,
    blockHash: string,
    result: { outputs: any[]; spends: any[] },
  ): Promise<void> {
    for (const out of result.outputs) {
      const key = `${out.txid}:${out.vout}`;
      if (this.data.utxos[key] || this.data.spent[key]) continue;

      const address = this.addressForScript(out.pkScript);
      this.data.utxos[key] = {
        value: out.value,
        height,
        blockHash,
        pkScript: toHex(out.pkScript),
        address,
      };

      // Watch the new UTXO so a later block's spend is detected.
      watch.addOutpoint(out.txid, out.vout);

      this.onFound?.({
        txid: out.txid, vout: out.vout, value: out.value, address,
        height,
      });
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

      this.onSpent?.({
        txid: spend.prevTxid, vout: spend.prevVout, value: utxo.value,
        address: utxo.address, spentBy: spend.txid, height,
      });
    }
  }

  private addressForScript(script: Uint8Array): string {
    const hex = toHex(script);
    for (const w of this.data.watches) {
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
  private async matchRange(
    pool: MatchWorkerPool | null,
    watch: WatchList,
    { start, count }: { start: number; count: number },
    from: number,
    filterType: FilterType,
    onRange?: (start: number, stage: 'fetch' | 'scan' | 'done',
      blocksDone?: number) => void,
    onBlocks?: (blocks: number) => void,
  ): Promise<FilterMatch[]> {
    const attempt = async (fresh: boolean): Promise<FilterMatch[]> => {
      onRange?.(start, 'fetch');
      const [filterFile, headers, filterHeaders] = await Promise.all([
        this.client.filters(start, { fresh, filterType }),
        this.storage.readHeaders(start, count),
        this.storage.readFilterHeaders(start, count, filterType),
      ]);
      const prev = start === 0 ? '' : reverseHex(
        await this.storage.readFilterHeaders(start - 1, 1, filterType),
      );

      // One pass: verify every filter against the committed filter
      // header chain and match against the watch list.
      onRange?.(start, 'scan');
      const matches = pool
        ? await pool.match({
          startHeight: start, filterFile, headers, filterHeaders,
          prev,
        }, onBlocks)
        : this.lib.neutrino.matchFilters(
          watch, start, filterFile, headers, filterHeaders, prev,
          onBlocks,
        );

      // Blocks below a watch's birthday only appear because files are
      // range-aligned; drop them here.
      return matches.filter((m) => m.height >= from);
    };

    try {
      return await attempt(false);
    } catch (err: any) {
      if (!String(err?.message).includes('committed filter header')) {
        throw err;
      }
      return attempt(true);
    }
  }

  /** Scan filters from the lowest unscanned birthday to the header tip,
   *  fetching and fully scanning blocks whose filter matches.
   *
   *  Filter files are processed on a sliding window of `batchSize`
   *  parallel units (matching runs on a pool of worker threads where
   *  available, each with its own WASM instance): a unit picks up the
   *  next range as soon as it finishes its current one, so ranges
   *  complete out of order. Matched blocks are applied — and the wallet
   *  state persisted — strictly in ascending height order, since an
   *  output found at height h must be outpoint-watched before a later
   *  block spends it, and the scannedTo resume checkpoint must stay
   *  contiguous.
   *
   *  onProgress(blocksDone, totalBlocks, foundCount) reports work done
   *  (including in-scan partial credit), not a chain position. The
   *  optional callbacks mirror the silent payment scanner's: `onRanges`
   *  announces the scan plan, `onRange` streams per-range stage
   *  transitions for a piece-map display.
   *
   *  Returns the wallet summary plus `stats` for the completed scan. */
  async scan(
    onProgress: (
      blocksDone: number, totalBlocks: number, foundCount: number,
    ) => void = () => {},
    callbacks: {
      onRanges?: (plan: {
        starts: number[];
        blocksPerRange: number;
        fromHeight: number;
        toHeight: number;
        totalBlocks: number;
      }) => void;
      onRange?: (start: number, stage: 'fetch' | 'scan' | 'done',
        blocksDone?: number) => void;
    } = {},
  ): Promise<WalletSummary & { stats: ScanStats }> {
    const from = this.scanStart();
    const tip = this.chain.tip().tipHeight;
    const stats: ScanStats = {
      blocksScanned: 0,
      batches: 0,
      matchedBlocks: 0,
      seconds: 0,
      bytesDownloaded: 0,
      filterType: this.filterType,
    };
    if (from === null || from > tip) {
      this.lastScanStats = stats;
      return { ...this.summary(), stats };
    }

    const startedAt = Date.now();
    const bytesBefore = this.client.bytesFetched;
    const status = await this.client.status();
    const perFile = status.entries_per_filter_file;

    // batchSize is a public field, so it can be adjusted between scans
    // on the same engine; re-clamp at use.
    const units = Math.max(1, Math.min(16, Math.floor(this.batchSize)));

    // The watch set may have changed since the last header sync (a new
    // legacy watch can demote a segwit-only selection to basic): re-select
    // and make sure the flavour's header chain is complete. A no-op when
    // syncHeaders() already brought it to the tip.
    const filterType = this.selectType(status);
    stats.filterType = filterType;
    await this.syncFilterHeaders(status);

    const watch = this.buildWatchList();

    // Real matching parallelism needs one WASM instance per thread; fall
    // back to inline matching if workers are unavailable (pool is null).
    const pool = units > 1
      ? await MatchWorkerPool.create(
        units,
        this.data.watches.flatMap((w) => w.scripts),
        { workerUrl: this.workerUrl, wasmUrl: this.wasmSource },
      )
      : null;

    try {
      const firstFile = Math.floor(from / perFile) * perFile;
      const ranges: { start: number; count: number }[] = [];
      for (let start = firstFile; start <= tip; start += perFile) {
        ranges.push({
          start, count: Math.min(perFile, tip - start + 1),
        });
      }
      const totalBlocks = tip - from + 1;
      callbacks.onRanges?.({
        starts: ranges.map((r) => r.start),
        blocksPerRange: perFile,
        fromHeight: from,
        toHeight: tip,
        totalBlocks,
      });

      // Progress counts work done: fully applied ranges plus in-scan
      // partial credit of in-flight ones.
      let blocksDone = 0;
      const partials = new Map<number, number>();
      const report = () => {
        let inflight = 0;
        partials.forEach((blocks) => {
          inflight += blocks;
        });
        onProgress(
          Math.min(blocksDone + inflight, totalBlocks), totalBlocks,
          Object.keys(this.data.utxos).length,
        );
      };

      // Matching runs on a sliding window (ranges complete out of
      // order), but matched blocks are applied and checkpointed
      // strictly in ascending range order: completed ranges park their
      // matches here until all earlier ranges are done, and a
      // promise-chained applier drains the contiguous prefix.
      const parked = new Map<number, FilterMatch[]>();
      let nextApply = 0;
      let applyChain: Promise<void> = Promise.resolve();

      const applyReady = async () => {
        for (;;) {
          if (nextApply >= ranges.length) return;
          const range = ranges[nextApply];
          const matches = parked.get(range.start);
          if (!matches) return;
          parked.delete(range.start);

          // Fetch this range's matched blocks in parallel (bounded),
          // then apply them in ascending height order.
          const blocks = await mapPool(
            matches, 8, (m) => this.client.block(m.blockHash),
          );
          for (let i = 0; i < matches.length; i++) {
            const result = this.lib.neutrino.scanBlock(
              watch, blocks[i],
            );
            await this.applyBlock(
              watch, matches[i].height, matches[i].blockHash, result,
            );
          }

          // The contiguous prefix grew — persist the checkpoint.
          this.data.scannedTo = range.start + range.count - 1;
          await this.storage.setWallet(this.data);
          stats.batches++;
          nextApply++;

          callbacks.onRange?.(
            range.start, 'done',
            range.start + range.count - Math.max(from, range.start),
          );
          partials.delete(range.start);
          blocksDone += range.start + range.count -
            Math.max(from, range.start);
          report();
        }
      };

      await mapPool(ranges, units, async (range) => {
        const skipped = Math.max(from, range.start) - range.start;
        const relevant = range.count - skipped;

        const matches = await this.matchRange(
          pool, watch, range, from, filterType, callbacks.onRange,
          (blocks) => {
            partials.set(range.start, Math.min(
              Math.max(0, blocks - skipped), relevant,
            ));
            callbacks.onRange?.(
              range.start, 'scan', partials.get(range.start),
            );
            report();
          },
        );
        stats.matchedBlocks += matches.length;
        parked.set(range.start, matches);

        // Serialize application through a promise chain: only one
        // applier runs at a time, and each drain pass consumes as much
        // of the contiguous prefix as is ready.
        await (applyChain = applyChain.then(applyReady));
      });
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
   *  any new blocks. Returns true if the tip moved. */
  async followTip(): Promise<boolean> {
    const status = await this.client.status();
    const tip = this.chain.tip().tipHeight;
    if (status.best_block_height <= tip &&
      status.best_block_hash === this.chain.tip().tipHash) {

      return false;
    }

    // A shallow reorg shows up as a prev-hash mismatch when appending
    // the new tail: roll back a few blocks and retry once.
    try {
      await this.appendTail(status);
    } catch {
      const back = Math.max(0, tip - 6);
      this.chain.rollback(back);
      await this.storage.truncateHeaders(back + 1);
      // Every cached flavour chain commits to the reorged-away blocks.
      for (const t of FILTER_TYPES) {
        if (await this.storage.filterHeaderCount(t) > back + 1) {
          await this.storage.truncateFilterHeaders(back + 1, t);
        }
      }
      this.data.scannedTo = Math.min(this.data.scannedTo, back);
      await this.appendTail(status);
    }
    await this.storage.setChainState(this.chain.exportState());
    await this.scan();

    return true;
  }

  private async appendTail(status: BlockDnStatus): Promise<void> {
    const perFile = status.entries_per_header_file;
    const filterType = this.selectType(status);
    for (;;) {
      const tip = this.chain.tip().tipHeight;
      if (tip >= status.best_block_height) break;

      const boundary = Math.floor((tip + 1) / perFile) * perFile;
      const [headerFile, fheaderFile] = await Promise.all([
        this.client.headers(boundary),
        this.client.filterHeaders(boundary, filterType),
      ]);

      const fresh = headerFile.subarray(
        (tip + 1 - boundary) * HEADER_SIZE,
      );
      if (fresh.length === 0) break;
      this.chain.append(fresh);
      await this.storage.appendHeaders(fresh);

      const have = await this.storage.filterHeaderCount(filterType);
      await this.storage.appendFilterHeaders(
        fheaderFile.subarray((have - boundary) * FILTER_HEADER_SIZE),
        filterType,
      );
    }
  }

  // -- queries ---------------------------------------------------------------

  utxos(): (WalletUtxo & { outpoint: string })[] {
    return Object.entries(this.data.utxos).map(([key, u]) => ({
      outpoint: key, ...u,
    }));
  }

  summary(): WalletSummary {
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

  /** Entry counts and byte sizes of the locally cached chain data. */
  cacheStats(): Promise<StorageStats> {
    return this.storage.stats();
  }

  close(): void {
    this.chain.free();
  }
}
