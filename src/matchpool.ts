/**
 * A small pool of match-worker threads, portable across the browser
 * (Worker) and Node (worker_threads). Each worker holds its own WASM
 * instance and Go-side watch list, so GCS matching runs truly in parallel —
 * the main thread's WASM instance stays free.
 *
 * Pool creation degrades gracefully: if workers are unavailable in the
 * environment, or the worker script can't be loaded (e.g. a bundler that
 * didn't ship `neutrino-worker.js`), {@link MatchWorkerPool.create} resolves
 * to `null` and callers fall back to inline matching.
 */

import type { FilterMatch } from './neutrino';
import type { SpBatchResult } from './spscan';
import type { Bytes, Network } from './types';

/** Options for {@link MatchWorkerPool.create}. */
export interface MatchPoolOptions {
  /** Explicit URL of the worker script. Defaults to `neutrino-worker.js`
   *  next to this module — override when assets are re-hosted (pass an
   *  absolute URL). */
  workerUrl?: string | URL;
  /** WASM source URL forwarded to each worker's `init()`. Defaults to
   *  `btcutil.wasm` next to the module the worker imports. */
  wasmUrl?: string;
  /** How long to wait for a worker to initialize before giving up and
   *  reporting the pool as unavailable. Default 30s (each worker compiles
   *  the full WASM module once). */
  initTimeoutMs?: number;
}

/** One matchFilters work item. */
export interface MatchTask {
  startHeight: number;
  filterFile: Uint8Array;
  headers: Uint8Array;
  filterHeaders: Uint8Array;
  prev: string;
}

// One worker plus a promise-based request/response envelope.
class MatchWorker {
  private worker: any;
  private post!: (msg: any, transfer: any[]) => void;
  kill!: () => void;

  private pending = new Map<
    number,
    {
      resolve: (v: any) => void;
      reject: (e: Error) => void;
      onProgress?: (msg: any) => void;
    }
  >();
  private nextId = 1;

  static async spawn(url: string | URL): Promise<MatchWorker> {
    const w = new MatchWorker();
    if (typeof Worker !== 'undefined') {
      w.worker = new Worker(url, { type: 'module' });
      w.worker.onmessage = (e: MessageEvent) => w.dispatch(e.data);
      // A script that fails to load or parse surfaces here; fail every
      // in-flight request so pool creation can fall back.
      w.worker.onerror = (e: any) =>
        w.failAll(new Error(e?.message ?? 'worker error'));
      w.post = (msg, transfer) => w.worker.postMessage(msg, transfer);
      w.kill = () => w.worker.terminate();
    } else {
      const { Worker: NodeWorker } = await nodeImport(
        'node:worker_threads',
      );
      w.worker = new NodeWorker(url);
      w.worker.on('message', (m: any) => w.dispatch(m));
      w.worker.on('error', (err: Error) => w.failAll(err));
      w.post = (msg, transfer) => w.worker.postMessage(msg, transfer);
      w.kill = () => w.worker.terminate();
    }
    return w;
  }

  private dispatch(msg: any): void {
    const entry = this.pending.get(msg.id);
    if (!entry) return;
    // Progress messages stream while the request is still running; only
    // the final message (ok/error) settles it.
    if (msg.progress) {
      entry.onProgress?.(msg);
      return;
    }
    this.pending.delete(msg.id);
    if (msg.ok) entry.resolve(msg);
    else entry.reject(new Error(msg.error));
  }

  private failAll(err: Error): void {
    for (const entry of this.pending.values()) entry.reject(err);
    this.pending.clear();
  }

  request(
    msg: any,
    transfer: any[] = [],
    onProgress?: (msg: any) => void,
  ): Promise<any> {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject, onProgress });
      this.post({ ...msg, id }, transfer);
    });
  }
}

const nodeImport = new Function('m', 'return import(m)') as (
  m: string,
) => Promise<any>;

export class MatchWorkerPool {
  private workers: MatchWorker[] = [];
  private idle: MatchWorker[] = [];
  private waiters: ((w: MatchWorker) => void)[] = [];

  /** Spawn `size` workers, each initialized with its own WASM instance and
   *  the given watch scripts (hex strings). Resolves to `null` if workers
   *  aren't available or fail to initialize — callers fall back to inline
   *  matching. */
  static create(
    size: number,
    scripts: string[],
    opts: MatchPoolOptions = {},
  ): Promise<MatchWorkerPool | null> {
    return MatchWorkerPool.createWithInit(size, opts, {
      type: 'init', scripts, wasmUrl: opts.wasmUrl,
    });
  }

  /** Spawn `size` workers and send each the given init message — the
   *  generic base for pools with different worker-side contexts (script
   *  watch lists, silent-payment scanners, ...). */
  static async createWithInit(
    size: number,
    opts: MatchPoolOptions,
    initMsg: any,
  ): Promise<MatchWorkerPool | null> {
    const url = opts.workerUrl ??
      new URL('./neutrino-worker.js', import.meta.url);
    const timeoutMs = opts.initTimeoutMs ?? 30_000;

    const pool = new MatchWorkerPool();
    try {
      pool.workers = await Promise.all(
        Array.from({ length: size }, () => MatchWorker.spawn(url)),
      );
      const timeout = new Promise<never>((_, reject) =>
        setTimeout(
          () => reject(new Error('worker init timeout')), timeoutMs,
        ));
      await Promise.race([
        Promise.all(pool.workers.map((w) => w.request(initMsg))),
        timeout,
      ]);
      pool.idle = [...pool.workers];
      return pool;
    } catch {
      pool.free();
      return null;
    }
  }

  /** Run one request on an idle worker, transferring the given named
   *  Uint8Array buffers zero-copy (non-exact views are copied first).
   *  Progress messages the worker streams for this request are forwarded
   *  to `onProgress`. */
  async requestOnIdle(
    msg: any,
    buffers: Record<string, Uint8Array> = {},
    onProgress?: (msg: any) => void,
  ): Promise<any> {
    const exact = (view: Uint8Array): ArrayBuffer =>
      view.byteOffset === 0 && view.byteLength === view.buffer.byteLength
        ? (view.buffer as ArrayBuffer)
        : (view.slice().buffer as ArrayBuffer);

    const transfer: ArrayBuffer[] = [];
    const payload: any = { ...msg };
    for (const [name, view] of Object.entries(buffers)) {
      const buf = exact(view);
      payload[name] = buf;
      transfer.push(buf);
    }

    const worker = await this.acquire();
    try {
      return await worker.request(payload, transfer, onProgress);
    } finally {
      this.release(worker);
    }
  }

  private acquire(): Promise<MatchWorker> {
    const worker = this.idle.pop();
    if (worker) return Promise.resolve(worker);
    return new Promise((resolve) => this.waiters.push(resolve));
  }

  private release(worker: MatchWorker): void {
    const waiter = this.waiters.shift();
    if (waiter) waiter(worker);
    else this.idle.push(worker);
  }

  /** Run one matchFilters call on an idle worker. The three data buffers
   *  are transferred (zero-copy where possible), so they must not be used
   *  afterwards. `onBlocks` streams the number of blocks processed so far
   *  while the match runs. */
  async match(
    task: MatchTask,
    onBlocks?: (blocks: number) => void,
  ): Promise<FilterMatch[]> {
    // Transferring sends the *whole* backing ArrayBuffer; a view that
    // doesn't cover its buffer exactly (e.g. a subarray) must be copied
    // first or the worker would see stray bytes.
    const exact = (view: Uint8Array): ArrayBuffer =>
      view.byteOffset === 0 && view.byteLength === view.buffer.byteLength
        ? (view.buffer as ArrayBuffer)
        : (view.slice().buffer as ArrayBuffer);

    const worker = await this.acquire();
    try {
      const filterBuf = exact(task.filterFile);
      const headerBuf = exact(task.headers);
      const fheaderBuf = exact(task.filterHeaders);
      const resp = await worker.request(
        {
          type: 'match',
          startHeight: task.startHeight,
          filterFile: filterBuf,
          headers: headerBuf,
          filterHeaders: fheaderBuf,
          prev: task.prev,
        },
        [filterBuf, headerBuf, fheaderBuf],
        (msg) => onBlocks?.(msg.blocks),
      );
      return resp.matches;
    } finally {
      this.release(worker);
    }
  }

  free(): void {
    for (const w of this.workers) w.kill();
    this.workers = [];
    this.idle = [];
  }
}


/** One spScanBatch work item. */
export interface SpScanTask {
  startHeight: number;
  tweakData: Uint8Array;
  filterFile: Uint8Array;
  headers: Uint8Array;
  filterHeaders: Uint8Array;
  prev: string;
  dustLimit: number;
}

/** A pool of workers running BIP-352 batch scans, each with its own WASM
 *  instance and scanner context (ECDH-heavy work parallelizes across
 *  threads). Same graceful-degradation contract as MatchWorkerPool. */
export class SpScanPool {
  private pool!: MatchWorkerPool;

  /** Spawn `size` workers initialized with the scanning keys. Resolves to
   *  `null` if workers are unavailable — callers fall back to inline
   *  scanning. The scan private key is sent to same-origin workers only
   *  (never over the network). */
  static async create(
    size: number,
    scanPrivKey: Bytes,
    spendPubKey: Bytes,
    network: Network,
    opts: MatchPoolOptions = {},
  ): Promise<SpScanPool | null> {
    const inner = await MatchWorkerPool.createWithInit(size, opts, {
      type: 'spInit',
      scanPrivKey,
      spendPubKey,
      network,
      wasmUrl: opts.wasmUrl,
    });
    if (!inner) return null;
    const pool = new SpScanPool();
    pool.pool = inner;
    return pool;
  }

  /** Run one spScanBatch call on an idle worker. The four data buffers
   *  are transferred (zero-copy where possible), so they must not be used
   *  afterwards. `onBlocks` streams the number of blocks processed so far
   *  while the scan runs. */
  async scanBatch(
    task: SpScanTask,
    onBlocks?: (blocks: number) => void,
  ): Promise<SpBatchResult> {
    const resp = await this.pool.requestOnIdle(
      {
        type: 'spScanBatch',
        startHeight: task.startHeight,
        prev: task.prev,
        dustLimit: task.dustLimit,
      },
      {
        tweakData: task.tweakData,
        filterFile: task.filterFile,
        headers: task.headers,
        filterHeaders: task.filterHeaders,
      },
      (msg) => onBlocks?.(msg.blocks),
    );
    return {
      matches: resp.matches,
      skippedTweaks: resp.skippedTweaks ?? 0,
      timings: resp.timings,
    };
  }

  free(): void {
    this.pool.free();
  }
}
