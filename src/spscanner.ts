/**
 * The BIP-352 Silent Payments scan engine: header sync with full local
 * validation, p2tr custom-filter-header caching (shared with the
 * watch-only wallet's storage), and a batched, worker-parallelized scan
 * over block-dn's tweak-data index. Scanning is ephemeral by design — each
 * run starts fresh from the requested height; only chain data is cached.
 *
 * Privacy model: the server learns which block ranges are downloaded, but
 * never the scan/spend keys or which outputs matched — all ECDH and
 * matching happens locally in WASM.
 */

import { init, type BtcutilSync } from './init';
import { BlockDnClient, type BlockDnStatus } from './blockdn';
import { SpScanPool } from './matchpool';
import {
  createSpScanner,
  scanBatchSync,
  scanBlockSpSync,
  type SpBatchMatch,
  type SpFoundOutput,
} from './spscan';
import { formatBytes, mapPool } from './watchwallet';
import type { WalletStorage } from './walletstore';
import type { HeaderChain } from './neutrino';
import type { Bytes, Network } from './types';

const HEADER_SIZE = 80;
const FILTER_HEADER_SIZE = 32;

/** The block heights at which taproot activated — silent payments cannot
 *  exist before these, so scans start here by default. */
export const TAPROOT_ACTIVATION: Partial<Record<Network, number>> = {
  mainnet: 709_632,
  testnet: 2_011_968,
  testnet3: 2_011_968,
  testnet4: 1,
  signet: 1,
};

/** The dust filter levels (satoshis) block-dn materializes SP tweak data
 *  at. A transaction is included in a level if its largest taproot output
 *  value is strictly greater than the level — so 0 contains every tweak,
 *  while the higher levels skip transactions whose taproot outputs are all
 *  uneconomical dust (such as inscription postage), shrinking both the
 *  download and the ECDH work substantially in spam-heavy ranges. A wallet
 *  can scan quickly at a high level and re-scan lower if an expected
 *  payment doesn't show up. */
export const SP_TWEAK_DUST_LIMITS = [0, 600, 1000, 3750] as const;

/** Display-order hex of a raw internal-order hash. */
function reverseHex(bytes: Uint8Array): string {
  let s = '';
  for (let i = bytes.length - 1; i >= 0; i--) {
    s += bytes[i].toString(16).padStart(2, '0');
  }
  return s;
}

/** A found silent-payment output with its chain context. */
export interface SpScanResult extends SpFoundOutput {
  height: number;
  blockHash: string;
  /** Whether the outpoint is still unspent (null: server can't say). */
  unspent: boolean | null;
}

/** Cumulative per-phase timings of one scan, summed across all ranges.
 *  Ranges run concurrently (and WASM scans run on parallel workers), so
 *  these sums can exceed the scan's wall-clock time — they attribute
 *  where the work went, not how long the user waited. */
export interface SpScanBreakdown {
  /** Tweak-data download + JSON parse (network + main thread). */
  tweakFetchMs: number;
  /** p2tr filter file download. */
  filterFetchMs: number;
  /** Header/filter-header reads from the local cache. */
  cacheReadMs: number;
  /** Wall time of the WASM scan calls (includes worker queueing). */
  scanMs: number;
  /** ECDH candidate derivation inside WASM — the crypto hot spot. */
  deriveMs: number;
  /** Filter decode + commitment verification inside WASM. */
  verifyMs: number;
  /** GCS matching inside WASM. */
  matchMs: number;
  /** Tweak JSON decode inside WASM. */
  wasmParseMs: number;
  /** Matched-block download + output identification. */
  blockMs: number;
}

/** Statistics of one completed scan. */
export interface SpScanStats {
  blocksScanned: number;
  /** Eligible (tweaked) transactions processed — at the scanned dust
   *  level, so a higher dust limit scans fewer. */
  txsScanned: number;
  matchedBlocks: number;
  foundOutputs: number;
  /** Served tweak entries skipped as invalid curve points. */
  invalidTweaks: number;
  seconds: number;
  bytesDownloaded: number;
  /** Where the time went, summed across concurrent ranges. */
  breakdown: SpScanBreakdown;
}

/** The stats line for display. */
export function formatSpScanStats(stats: SpScanStats): string {
  const invalid = stats.invalidTweaks > 0
    ? `, ${stats.invalidTweaks} invalid tweak entries skipped`
    : '';
  return `${stats.blocksScanned.toLocaleString()} blocks / ` +
    `${stats.txsScanned.toLocaleString()} eligible txs scanned in ` +
    `${stats.seconds.toFixed(1)} s (${stats.matchedBlocks} blocks ` +
    `matched, ${stats.foundOutputs} outputs found, ` +
    `${formatBytes(stats.bytesDownloaded)} downloaded${invalid})`;
}

/** A human-readable duration: `38ms`, `1.24s`. */
function formatMs(ms: number): string {
  return ms >= 1000 ? `${(ms / 1000).toFixed(2)}s` : `${Math.round(ms)}ms`;
}

/** The per-phase timing summary for display, one line. Phase times are
 *  summed across concurrent ranges/workers, so they can exceed the scan's
 *  wall-clock time. */
export function formatSpScanBreakdown(stats: SpScanStats): string {
  const b = stats.breakdown;
  const perTweak = stats.txsScanned > 0
    ? ` = ${(b.deriveMs * 1000 / stats.txsScanned).toFixed(0)}µs/tweak`
    : '';
  return `time spent (summed across workers): download ` +
    `${formatMs(b.tweakFetchMs + b.filterFetchMs)} (tweak data ` +
    `${formatMs(b.tweakFetchMs)}, filters ${formatMs(b.filterFetchMs)}), ` +
    `cache reads ${formatMs(b.cacheReadMs)}, wasm scan ` +
    `${formatMs(b.scanMs)} (ecdh derive ${formatMs(b.deriveMs)}` +
    `${perTweak}, filter verify ${formatMs(b.verifyMs)}, gcs match ` +
    `${formatMs(b.matchMs)}, json parse ${formatMs(b.wasmParseMs)}), ` +
    `matched blocks ${formatMs(b.blockMs)}`;
}

/** Options for {@link SilentPaymentScanner.open}. */
export interface SilentPaymentScannerOptions {
  network: Network;
  /** block-dn base URL; must run with --index-sp-tweak-data and
   *  --index-custom-filters. */
  serverUrl: string;
  storage: WalletStorage;
  /** Parallel 2000-block units per batch (1..16, default 4). Each unit
   *  holds a tweak-data JSON file in memory — on mainnet those run
   *  40-100 MB each, so higher values trade memory for speed. */
  batchSize?: number;
  wasmSource?: string;
  workerUrl?: string | URL;
}

/** Callbacks and range of one {@link SilentPaymentScanner.scan} run. */
export interface SpScanRun {
  /** 32-byte scan private key (hex or bytes). Never leaves the page. */
  scanPrivKey: Bytes;
  /** 33-byte compressed spend public key. */
  spendPubKey: Bytes;
  /** First height to scan; default: the network's taproot activation. */
  fromHeight?: number;
  /** Last height to scan; default: the chain/index tip. */
  toHeight?: number;
  /** Dust filter level to scan at, one of {@link SP_TWEAK_DUST_LIMITS}
   *  (default 0 = every tweak). Payments whose taproot outputs are all
   *  ≤ the limit are invisible at that level. */
  dustLimit?: number;
  onProgress?: (height: number, target: number, found: number) => void;
  /** Streamed as outputs are found (before the run completes). */
  onFound?: (result: SpScanResult) => void;
  /** Per-range timing log lines, for diagnosing where scan time goes. */
  onLog?: (line: string) => void;
}

export class SilentPaymentScanner {
  lib!: BtcutilSync;
  network!: Network;
  client!: BlockDnClient;
  storage!: WalletStorage;
  batchSize!: number;
  chain!: HeaderChain;

  /** The bech32m address of the most recent scan run. */
  address = '';
  changeAddress = '';

  private wasmSource?: string;
  private workerUrl?: string | URL;

  /** Open a scanner on the given storage backend. The storage is shared
   *  with the watch-only wallet engine: block headers, the validated
   *  chain state and the p2tr filter-header cache are reused across both;
   *  wallet data is never touched. */
  static async open(
    opts: SilentPaymentScannerOptions,
  ): Promise<SilentPaymentScanner> {
    const scanner = new SilentPaymentScanner();
    scanner.lib = await init(opts.wasmSource);
    scanner.network = opts.network;
    scanner.client = new BlockDnClient(opts.serverUrl);
    scanner.storage = opts.storage;
    scanner.batchSize = Math.max(
      1, Math.min(16, Math.floor(opts.batchSize ?? 4)),
    );
    scanner.wasmSource = opts.wasmSource;
    scanner.workerUrl = opts.workerUrl;

    // Resume the validated header chain from its compact exported state;
    // fall back to re-validation from the stored headers.
    const state = await opts.storage.getChainState();
    scanner.chain = scanner.lib.neutrino.headerChain(
      opts.network, state ?? undefined,
    );
    const stored = await opts.storage.headerCount();
    const tip = scanner.chain.tip().tipHeight;
    if (tip + 1 !== stored) {
      scanner.chain.free();
      scanner.chain = scanner.lib.neutrino.headerChain(opts.network);
      const batch = 50_000;
      for (let h = 0; h < stored; h += batch) {
        scanner.chain.append(await opts.storage.readHeaders(
          h, Math.min(batch, stored - h),
        ));
      }
    }

    return scanner;
  }

  /** Sync block headers and the p2tr filter-header chain to the server
   *  tip, validating headers locally. Cached data (including anything a
   *  previous watch-only wallet session synced) is reused. */
  async syncHeaders(
    onProgress: (
      kind: 'headers' | 'filter-headers',
      height: number,
      target: number,
    ) => void = () => {},
  ): Promise<BlockDnStatus> {
    const status = await this.client.status();
    if (!status.custom_filters_available) {
      throw new Error('the block-dn server does not serve custom ' +
        'filters (--index-custom-filters)');
    }
    if (!status.best_sptweak_height) {
      throw new Error('the block-dn server does not serve silent ' +
        'payment tweak data (--index-sp-tweak-data)');
    }

    const perFile = status.entries_per_header_file;
    const target = status.best_block_height;

    for (;;) {
      const tip = this.chain.tip().tipHeight;
      if (tip >= target) break;

      const boundary = Math.floor((tip + 1) / perFile) * perFile;
      const file = await this.client.headers(boundary);
      const fresh = file.subarray((tip + 1 - boundary) * HEADER_SIZE);
      if (fresh.length === 0) break;

      this.chain.append(fresh);
      await this.storage.appendHeaders(fresh);
      onProgress('headers', this.chain.tip().tipHeight, target);
    }
    await this.storage.setChainState(this.chain.exportState());

    // The p2tr filter-header chain, cached per flavour in the shared
    // store. Each downloaded filter is verified against this chain at
    // scan time.
    for (;;) {
      const have = await this.storage.filterHeaderCount('p2tr');
      if (have > target) break;

      const boundary = Math.floor(have / perFile) * perFile;
      const file = await this.client.filterHeaders(boundary, 'p2tr');
      const fresh = file.subarray((have - boundary) * FILTER_HEADER_SIZE);
      if (fresh.length === 0) break;

      await this.storage.appendFilterHeaders(fresh, 'p2tr');
      onProgress(
        'filter-headers',
        await this.storage.filterHeaderCount('p2tr') - 1, target,
      );
    }

    return status;
  }

  /** Scan for silent payment outputs from the given (or taproot
   *  activation) height to the chain tip. Found outputs stream through
   *  `onFound`; the returned array holds all of them plus stats. */
  async scan(run: SpScanRun): Promise<{
    results: SpScanResult[]; stats: SpScanStats;
  }> {
    const startedAt = Date.now();
    const bytesBefore = this.client.bytesFetched;

    const dustLimit = run.dustLimit ?? 0;
    if (!(SP_TWEAK_DUST_LIMITS as readonly number[]).includes(dustLimit)) {
      throw new Error(`unsupported dust limit ${dustLimit}; the server ` +
        `serves ${SP_TWEAK_DUST_LIMITS.join(', ')}`);
    }

    const status = await this.syncHeaders();
    const perFile = status.entries_per_filter_file;
    if (status.entries_per_sptweak_file !== undefined &&
      status.entries_per_sptweak_file !== perFile) {
      throw new Error(`unsupported server layout: ` +
        `${status.entries_per_sptweak_file} blocks per tweak file vs ` +
        `${perFile} per filter file`);
    }

    const activation = TAPROOT_ACTIVATION[this.network] ?? 0;
    const from = Math.max(run.fromHeight ?? activation, 0);
    const tip = Math.min(
      this.chain.tip().tipHeight,
      status.best_sptweak_height ?? 0,
      status.best_custom_filter_height ?? status.best_block_height,
      run.toHeight ?? Infinity,
    );

    const scanner = createSpScanner(
      run.scanPrivKey, run.spendPubKey, this.network,
    );
    this.address = scanner.address;
    this.changeAddress = scanner.changeAddress;

    const pool = this.batchSize > 1
      ? await SpScanPool.create(
        this.batchSize, run.scanPrivKey, run.spendPubKey, this.network,
        { workerUrl: this.workerUrl, wasmUrl: this.wasmSource },
      )
      : null;

    const results: SpScanResult[] = [];
    const stats: SpScanStats = {
      blocksScanned: tip >= from ? tip - from + 1 : 0,
      txsScanned: 0,
      matchedBlocks: 0,
      foundOutputs: 0,
      invalidTweaks: 0,
      seconds: 0,
      bytesDownloaded: 0,
      breakdown: {
        tweakFetchMs: 0, filterFetchMs: 0, cacheReadMs: 0, scanMs: 0,
        deriveMs: 0, verifyMs: 0, matchMs: 0, wasmParseMs: 0, blockMs: 0,
      },
    };

    try {
      const firstFile = Math.floor(from / perFile) * perFile;
      const batchSpan = perFile * this.batchSize;

      for (let batch = firstFile; batch <= tip; batch += batchSpan) {
        const ranges: { start: number; count: number }[] = [];
        for (let i = 0; i < this.batchSize; i++) {
          const start = batch + i * perFile;
          if (start > tip) break;
          ranges.push({
            start, count: Math.min(perFile, tip - start + 1),
          });
        }

        // Each range: fetch + scan concurrently; the await is the
        // batch barrier.
        const rangeResults = await Promise.all(ranges.map(
          (range) => this.scanRange(
            pool, scanner, range, from, dustLimit, run.onLog,
          ),
        ));

        const b = stats.breakdown;
        for (const rr of rangeResults) {
          stats.txsScanned += rr.txsScanned;
          stats.matchedBlocks += rr.matches.length;
          stats.invalidTweaks += rr.skippedTweaks;
          b.tweakFetchMs += rr.timing.tweakFetchMs;
          b.filterFetchMs += rr.timing.filterFetchMs;
          b.cacheReadMs += rr.timing.cacheReadMs;
          b.scanMs += rr.timing.scanMs;
          b.deriveMs += rr.timing.deriveMs;
          b.verifyMs += rr.timing.verifyMs;
          b.matchMs += rr.timing.matchMs;
          b.wasmParseMs += rr.timing.wasmParseMs;
        }

        // Fetch matched blocks (bounded) and identify the outputs on
        // the main thread, in ascending height order.
        const blockStarted = Date.now();
        const matches = rangeResults.flatMap((rr) => rr.matches);
        const blocks = await mapPool(
          matches, this.batchSize * 2,
          (m) => this.client.block(m.blockHash),
        );
        for (let i = 0; i < matches.length; i++) {
          const m = matches[i];
          const found = scanBlockSpSync(scanner, blocks[i], m.tweaks);
          for (const out of found) {
            const result: SpScanResult = {
              ...out,
              height: m.height,
              blockHash: m.blockHash,
              unspent: await this.client.isUnspent(
                out.txid, out.vout,
              ),
            };
            results.push(result);
            stats.foundOutputs++;
            run.onFound?.(result);
          }
        }
        if (matches.length > 0) {
          const blockMs = Date.now() - blockStarted;
          stats.breakdown.blockMs += blockMs;
          run.onLog?.(`matched blocks: fetched + identified ` +
            `${matches.length} block(s) in ${formatMs(blockMs)}`);
        }

        const last = ranges[ranges.length - 1];
        run.onProgress?.(
          last.start + last.count - 1, tip, stats.foundOutputs,
        );
      }
    } finally {
      scanner.free();
      pool?.free();
    }

    stats.seconds = (Date.now() - startedAt) / 1000;
    stats.bytesDownloaded = this.client.bytesFetched - bytesBefore;

    return { results, stats };
  }

  /** Fetch and scan one 2000-block range: tweak data + p2tr filter file
   *  from the network, header + filter-header slices from the cache. A
   *  commitment-check failure triggers one cache-busting refetch of the
   *  filter file. */
  private async scanRange(
    pool: SpScanPool | null,
    scanner: ReturnType<typeof createSpScanner>,
    { start, count }: { start: number; count: number },
    from: number,
    dustLimit: number,
    onLog?: (line: string) => void,
  ): Promise<{
    matches: SpBatchMatch[];
    txsScanned: number;
    skippedTweaks: number;
    timing: {
      tweakFetchMs: number; filterFetchMs: number; cacheReadMs: number;
      scanMs: number; deriveMs: number; verifyMs: number; matchMs: number;
      wasmParseMs: number;
    };
  }> {
    const attempt = async (fresh: boolean) => {
      const timing = {
        tweakFetchMs: 0, filterFetchMs: 0, cacheReadMs: 0, scanMs: 0,
        deriveMs: 0, verifyMs: 0, matchMs: 0, wasmParseMs: 0,
      };
      const timed = async <T>(
        p: Promise<T>, key: 'tweakFetchMs' | 'filterFetchMs' |
          'cacheReadMs',
      ): Promise<T> => {
        const started = Date.now();
        try {
          return await p;
        } finally {
          timing[key] += Date.now() - started;
        }
      };

      const [tweakData, filterFile, headers, filterHeaders] =
        await Promise.all([
          timed(this.client.spTweaks(dustLimit, start, { fresh }),
            'tweakFetchMs'),
          timed(this.client.filters(start, { fresh, filterType: 'p2tr' }),
            'filterFetchMs'),
          timed(this.storage.readHeaders(start, count), 'cacheReadMs'),
          timed(this.storage.readFilterHeaders(start, count, 'p2tr'),
            'cacheReadMs'),
        ]);
      // Sizes must be captured up front: the pool path transfers (and
      // thereby detaches) the buffers to a worker.
      const tweakBytes = tweakData.length;
      const filterBytes = filterFile.length;
      const prev = start === 0 ? '' : reverseHex(
        await this.storage.readFilterHeaders(start - 1, 1, 'p2tr'),
      );

      const scanStarted = Date.now();
      const batchResult = pool
        ? await pool.scanBatch({
          startHeight: start, tweakData, filterFile,
          headers, filterHeaders, prev, dustLimit,
        })
        : scanBatchSync(
          scanner, start, tweakData, filterFile, headers,
          filterHeaders, prev, dustLimit,
        );
      timing.scanMs = Date.now() - scanStarted;

      const wasm = batchResult.timings;
      if (wasm) {
        timing.deriveMs = wasm.deriveMs;
        timing.verifyMs = wasm.verifyMs;
        timing.matchMs = wasm.matchMs;
        timing.wasmParseMs = wasm.parseMs;
      }
      onLog?.(
        `[${start}-${start + count - 1}] tweak data ` +
        `${formatMs(timing.tweakFetchMs)}/` +
        `${formatBytes(tweakBytes)}, filters ` +
        `${formatMs(timing.filterFetchMs)}/` +
        `${formatBytes(filterBytes)}, cache ` +
        `${formatMs(timing.cacheReadMs)}, wasm scan ` +
        `${formatMs(timing.scanMs)}` +
        (wasm
          ? ` (ecdh derive ${formatMs(wasm.deriveMs)}, filter verify ` +
            `${formatMs(wasm.verifyMs)}, gcs match ` +
            `${formatMs(wasm.matchMs)}, decode ` +
            `${formatMs(wasm.parseMs)}; ` +
            `${wasm.tweaks.toLocaleString()} tweaks)`
          : ''),
      );

      // Matches below the requested start are present only because files
      // are range-aligned; each match carries its block's tweak keys for
      // the block scan.
      return {
        txsScanned: wasm?.tweaks ?? 0,
        skippedTweaks: batchResult.skippedTweaks,
        timing,
        matches: batchResult.matches.filter(
          (m: SpBatchMatch) => m.height >= from,
        ),
      };
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

  close(): void {
    this.chain.free();
  }
}
