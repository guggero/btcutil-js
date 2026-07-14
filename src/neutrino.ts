import { init, g, unwrap } from './init';
import type { Bytes, Network } from './types';

/** The current tip state of a {@link HeaderChain}. */
export interface HeaderChainState {
  /** Height of the last validated header, -1 for an empty chain. */
  tipHeight: number;
  /** Display-order (reversed) hex hash of the tip header, '' when empty. */
  tipHash: string;
  /** Unix timestamp of the tip header, 0 when empty. */
  tipTime: number;
  /** Accumulated proof of work as a hex string. */
  chainWork: string;
}

/** One matched block from {@link matchFilters}. */
export interface FilterMatch {
  height: number;
  blockHash: string;
}

/** A block output paying a watched script, from {@link scanBlock}. */
export interface ScanOutput {
  txid: string;
  vout: number;
  value: number;
  pkScript: Uint8Array;
}

/** A block input spending a watched outpoint, from {@link scanBlock}. */
export interface ScanSpend {
  prevTxid: string;
  prevVout: number;
  txid: string;
}

/** The result of scanning one full block. */
export interface ScanBlockResult {
  outputs: ScanOutput[];
  spends: ScanSpend[];
}

interface HeaderChainNewResult extends HeaderChainState {
  handle: number;
}

// The Go bridge returns extra fields (handle, appended) alongside the tip
// state; keep the cached state to exactly the HeaderChainState shape.
function cleanState(v: HeaderChainState): HeaderChainState {
  return {
    tipHeight: v.tipHeight,
    tipHash: v.tipHash,
    tipTime: v.tipTime,
    chainWork: v.chainWork,
  };
}

// Long-lived Go-side handles are released on GC (or explicit free()), same
// pattern as descriptors.ts.
const headerChainFinalizers = new FinalizationRegistry<number>((handle) => {
  try {
    g()?.neutrino?.headerChainFree(handle);
  } catch {
    // Best-effort cleanup: ignore if the module is already gone.
  }
});

const watchListFinalizers = new FinalizationRegistry<number>((handle) => {
  try {
    g()?.neutrino?.watchListFree(handle);
  } catch {
    // Best-effort cleanup: ignore if the module is already gone.
  }
});

/** A validating accumulator over a chain of raw block headers.
 *
 *  Headers are appended in batches (e.g. straight from block-dn header
 *  files); each one is checked for previous-hash linkage, proof of work,
 *  difficulty-retarget correctness and median-time-past. The chain keeps a
 *  sliding window of recent headers so shallow tail reorgs can be rolled
 *  back, and its compact state (~80 KiB) can be exported so a client resumes
 *  instantly instead of re-validating from genesis. */
export class HeaderChain {
  /** @internal */
  readonly handle: number;

  private state: HeaderChainState;
  private freed = false;

  /** @internal Construct via {@link neutrino.headerChain}. */
  constructor(info: HeaderChainNewResult) {
    this.handle = info.handle;
    this.state = cleanState(info);
    headerChainFinalizers.register(this, info.handle, this);
  }

  /** Validate and append a batch of serialized 80-byte headers. Throws if
   *  any header is invalid; all headers before the offending one remain
   *  appended. Returns the new tip state. */
  append(rawHeaders: Bytes): HeaderChainState & { appended: number } {
    const result = unwrap<HeaderChainState & { appended: number }>(
      g().neutrino.headerChainAppend(this.handle, rawHeaders),
    );
    this.state = cleanState(result);
    return result;
  }

  /** The current tip state. Queried live from the chain: a failed append
   *  keeps all headers before the offending one, so a cached copy could be
   *  stale after an error. */
  tip(): HeaderChainState {
    this.state = cleanState(
      unwrap<HeaderChainState>(
        g().neutrino.headerChainState(this.handle),
      ),
    );
    return this.state;
  }

  /** Drop all headers above the given height (tail reorg handling). Only
   *  heights within the in-memory window (~2000 blocks) can be rolled back
   *  to. */
  rollback(height: number): HeaderChainState {
    const result = unwrap<HeaderChainState>(
      g().neutrino.headerChainRollback(this.handle, height),
    );
    this.state = cleanState(result);
    return this.state;
  }

  /** Export the compact resume state (persist it, then pass it to
   *  {@link neutrino.headerChain} to resume without re-validating). */
  exportState(): Uint8Array {
    return unwrap<Uint8Array>(g().neutrino.headerChainExport(this.handle));
  }

  /** Release the Go-side chain. Safe to call more than once. */
  free(): void {
    if (this.freed) {
      return;
    }
    this.freed = true;
    headerChainFinalizers.unregister(this);
    unwrap(g().neutrino.headerChainFree(this.handle));
  }
}

/** The set of watched output scripts (receive detection) and outpoints
 *  (spend detection) that scans match against. Parked Go-side so large
 *  watch lists aren't re-marshalled for every filter file. */
export class WatchList {
  /** @internal */
  readonly handle: number;

  private freed = false;

  /** @internal Construct via {@link neutrino.watchList}. */
  constructor(handle: number) {
    this.handle = handle;
    watchListFinalizers.register(this, handle, this);
  }

  /** Add raw output scripts to watch. Returns the deduplicated total. */
  addScripts(scripts: Bytes[]): number {
    return unwrap<number>(
      g().neutrino.watchListAddScripts(this.handle, scripts),
    );
  }

  /** Watch an outpoint so {@link scanBlock} reports its spend. */
  addOutpoint(txid: string, vout: number): number {
    return unwrap<number>(
      g().neutrino.watchListAddOutpoint(this.handle, txid, vout),
    );
  }

  /** Stop watching an outpoint (e.g. once its spend was found). */
  removeOutpoint(txid: string, vout: number): number {
    return unwrap<number>(
      g().neutrino.watchListRemoveOutpoint(this.handle, txid, vout),
    );
  }

  /** Release the Go-side watch list. Safe to call more than once. */
  free(): void {
    if (this.freed) {
      return;
    }
    this.freed = true;
    watchListFinalizers.unregister(this);
    unwrap(g().neutrino.watchListFree(this.handle));
  }
}

/** @internal Shared by the async namespace and the sync API. */
export function createHeaderChain(
  network: Network,
  state?: Bytes,
): HeaderChain {
  const info = unwrap<HeaderChainNewResult>(
    g().neutrino.headerChainNew(network, state),
  );
  return new HeaderChain(info);
}

/** @internal Shared by the async namespace and the sync API. */
export function createWatchList(scripts?: Bytes[]): WatchList {
  const info = unwrap<{ handle: number }>(
    g().neutrino.watchListNew(scripts),
  );
  return new WatchList(info.handle);
}

/** @internal Shared by the async namespace and the sync API. */
export function matchFiltersSync(
  watch: WatchList,
  startHeight: number,
  filterFile: Bytes,
  headers: Bytes,
  filterHeaders: Bytes,
  prevFilterHeader: string,
): FilterMatch[] {
  return unwrap<FilterMatch[]>(
    g().neutrino.matchFilters(
      watch.handle,
      startHeight,
      filterFile,
      headers,
      filterHeaders,
      prevFilterHeader,
    ),
  );
}

/** @internal Shared by the async namespace and the sync API. */
export function scanBlockSync(
  watch: WatchList,
  blockBytes: Bytes,
): ScanBlockResult {
  return unwrap<ScanBlockResult>(
    g().neutrino.scanBlock(watch.handle, blockBytes),
  );
}

/** BIP157/158 light-client primitives ("neutrino over HTTP").
 *
 *  These are the validation and matching building blocks of a browser-based
 *  watch-only wallet; the fetching/persistence orchestration is provided by
 *  the WatchOnlyWallet engine (watchwallet.ts) built on top of these:
 *
 *  ```ts
 *  const chain = await neutrino.headerChain('mainnet');
 *  chain.append(headerFileBytes);            // validates PoW, retargets, ...
 *
 *  const watch = await neutrino.watchList([script1, script2]);
 *  const matches = await neutrino.matchFilters(
 *    watch, 0, filterFile, headersSlice, filterHeadersSlice, '',
 *  );
 *  for (const m of matches) {
 *    const found = await neutrino.scanBlock(watch, blockBytes);
 *  }
 *  ``` */
export const neutrino = {
  /** Create a {@link HeaderChain} for a network, optionally resuming from a
   *  previously exported state. */
  async headerChain(network: Network, state?: Bytes): Promise<HeaderChain> {
    await init();
    return createHeaderChain(network, state);
  },

  /** Create a {@link WatchList}, optionally seeded with output scripts. */
  async watchList(scripts?: Bytes[]): Promise<WatchList> {
    await init();
    return createWatchList(scripts);
  },

  /** Verify one block-dn filter file against the committed BIP157
   *  filter-header chain and match it against the watch list, in one pass.
   *
   *  `filterFile` is the var-int prefixed filter file, `headers` the raw
   *  80-byte headers and `filterHeaders` the 32-byte filter headers of the
   *  same height range starting at `startHeight`; `prevFilterHeader` is the
   *  display-order hex filter header of `startHeight - 1` (empty string for
   *  genesis). Throws if any filter fails its commitment check. */
  async matchFilters(
    watch: WatchList,
    startHeight: number,
    filterFile: Bytes,
    headers: Bytes,
    filterHeaders: Bytes,
    prevFilterHeader: string,
  ): Promise<FilterMatch[]> {
    await init();
    return matchFiltersSync(
      watch, startHeight, filterFile, headers, filterHeaders,
      prevFilterHeader,
    );
  },

  /** Extract watched-script outputs and watched-outpoint spends from a full
   *  serialized block (fetched after its filter matched). */
  async scanBlock(
    watch: WatchList,
    blockBytes: Bytes,
  ): Promise<ScanBlockResult> {
    await init();
    return scanBlockSync(watch, blockBytes);
  },
};
