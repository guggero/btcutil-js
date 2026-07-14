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
    { resolve: (v: any) => void; reject: (e: Error) => void }
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
    this.pending.delete(msg.id);
    if (msg.ok) entry.resolve(msg);
    else entry.reject(new Error(msg.error));
  }

  private failAll(err: Error): void {
    for (const entry of this.pending.values()) entry.reject(err);
    this.pending.clear();
  }

  request(msg: any, transfer: any[] = []): Promise<any> {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
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
  static async create(
    size: number,
    scripts: string[],
    opts: MatchPoolOptions = {},
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
        Promise.all(pool.workers.map((w) => w.request({
          type: 'init', scripts, wasmUrl: opts.wasmUrl,
        }))),
        timeout,
      ]);
      pool.idle = [...pool.workers];
      return pool;
    } catch {
      pool.free();
      return null;
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
   *  afterwards. */
  async match(task: MatchTask): Promise<FilterMatch[]> {
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
