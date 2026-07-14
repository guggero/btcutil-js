// Filter-match worker: runs neutrino.matchFilters in its own thread with its
// own WASM instance (Go WASM is single-threaded, so real matching
// parallelism needs one module instance per worker). Spawned by
// worker-pool.mjs in both the browser (Worker) and Node (worker_threads).

let lib = null;
let watch = null;

async function handle(msg, reply) {
  try {
    switch (msg.type) {
      case 'init': {
        const { loadBtcutil } = await import('./lib-loader.mjs');
        const { init } = await loadBtcutil();
        lib = await init();
        watch = lib.neutrino.watchList(msg.scripts);
        reply({ id: msg.id, ok: true });
        break;
      }

      case 'match': {
        const matches = lib.neutrino.matchFilters(
          watch,
          msg.startHeight,
          new Uint8Array(msg.filterFile),
          new Uint8Array(msg.headers),
          new Uint8Array(msg.filterHeaders),
          msg.prev,
        );
        reply({ id: msg.id, ok: true, matches });
        break;
      }

      default:
        throw new Error(`unknown message type ${msg.type}`);
    }
  } catch (err) {
    reply({ id: msg.id, ok: false, error: String(err?.message ?? err) });
  }
}

// Environment split: browser dedicated workers expose `self`, Node
// worker_threads communicates via parentPort.
if (typeof self !== 'undefined') {
  self.onmessage = (e) => handle(e.data, (r) => self.postMessage(r));
} else {
  const { parentPort } = await import('node:worker_threads');
  parentPort.on('message', (m) => {
    handle(m, (r) => parentPort.postMessage(r));
  });
}
