// A small pool of match-worker threads, portable across the browser
// (Worker) and Node (worker_threads). Each worker holds its own WASM
// instance and Go-side watch list, so GCS matching runs truly in parallel —
// the main thread's WASM instance stays free for scanBlock and header work.

const WORKER_URL = new URL('./match-worker.mjs', import.meta.url);

// One worker plus a promise-based request/response envelope.
class MatchWorker {
  static async spawn() {
    const w = new MatchWorker();
    if (typeof Worker !== 'undefined') {
      w.worker = new Worker(WORKER_URL, { type: 'module' });
      w.worker.onmessage = (e) => w.#dispatch(e.data);
      w.post = (msg, transfer) => w.worker.postMessage(msg, transfer);
      w.kill = () => w.worker.terminate();
    } else {
      const { Worker: NodeWorker } = await import('node:worker_threads');
      w.worker = new NodeWorker(WORKER_URL);
      w.worker.on('message', (m) => w.#dispatch(m));
      w.post = (msg, transfer) => w.worker.postMessage(msg, transfer);
      w.kill = () => w.worker.terminate();
    }
    return w;
  }

  pending = new Map();
  nextId = 1;

  #dispatch(msg) {
    const entry = this.pending.get(msg.id);
    if (!entry) return;
    this.pending.delete(msg.id);
    if (msg.ok) entry.resolve(msg);
    else entry.reject(new Error(msg.error));
  }

  request(msg, transfer = []) {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.post({ ...msg, id }, transfer);
    });
  }
}

export class MatchWorkerPool {
  /** Spawn `size` workers, each initialized with its own WASM instance and
   *  the given watch scripts (hex strings). Returns null if workers aren't
   *  available in this environment — callers fall back to inline matching. */
  static async create(size, scripts) {
    try {
      const pool = new MatchWorkerPool();
      pool.workers = await Promise.all(
        Array.from({ length: size }, () => MatchWorker.spawn()),
      );
      await Promise.all(
        pool.workers.map((w) => w.request({ type: 'init', scripts })),
      );
      pool.idle = [...pool.workers];
      pool.waiters = [];
      return pool;
    } catch {
      return null;
    }
  }

  async #acquire() {
    if (this.idle.length > 0) return this.idle.pop();
    return new Promise((resolve) => this.waiters.push(resolve));
  }

  #release(worker) {
    const waiter = this.waiters.shift();
    if (waiter) waiter(worker);
    else this.idle.push(worker);
  }

  /** Run one matchFilters call on an idle worker. The three data buffers
   *  are transferred (zero-copy where possible), so they must not be used
   *  afterwards. */
  async match({ startHeight, filterFile, headers, filterHeaders, prev }) {
    // Transferring sends the *whole* backing ArrayBuffer; a view that
    // doesn't cover its buffer exactly (e.g. a subarray) must be copied
    // first or the worker would see stray bytes.
    const exact = (view) =>
      view.byteOffset === 0 && view.byteLength === view.buffer.byteLength
        ? view.buffer
        : view.slice().buffer;

    const worker = await this.#acquire();
    try {
      const filterBuf = exact(filterFile);
      const headerBuf = exact(headers);
      const fheaderBuf = exact(filterHeaders);
      const resp = await worker.request(
        {
          type: 'match',
          startHeight,
          filterFile: filterBuf,
          headers: headerBuf,
          filterHeaders: fheaderBuf,
          prev,
        },
        [filterBuf, headerBuf, fheaderBuf],
      );
      return resp.matches;
    } finally {
      this.#release(worker);
    }
  }

  free() {
    for (const w of this.workers) w.kill();
    this.workers = [];
    this.idle = [];
  }
}
