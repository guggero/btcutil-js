/**
 * Filter-match worker entry point (built as its own bundle,
 * `dist/neutrino-worker.js`): runs neutrino.matchFilters in its own thread
 * with its own WASM instance — Go WASM is single-threaded, so real matching
 * parallelism needs one module instance per worker. Spawned by matchpool.ts
 * in both the browser (Worker) and Node (worker_threads).
 */

import { init } from './init';
import { createWatchList, matchFiltersSync, WatchList } from './neutrino';
import { createSpScanner, scanBatchSync, SpScanner } from './spscan';

let watch: WatchList | null = null;
let spScanner: SpScanner | null = null;

async function handle(msg: any, reply: (r: any) => void): Promise<void> {
  try {
    switch (msg.type) {
      case 'init': {
        await init(msg.wasmUrl);
        watch = createWatchList(msg.scripts);
        reply({ id: msg.id, ok: true });
        break;
      }

      case 'match': {
        if (!watch) {
          throw new Error('worker not initialized');
        }
        const matches = matchFiltersSync(
          watch,
          msg.startHeight,
          new Uint8Array(msg.filterFile),
          new Uint8Array(msg.headers),
          new Uint8Array(msg.filterHeaders),
          msg.prev,
          // Stream per-block progress as non-final messages; the final
          // reply below carries the same id with ok set.
          (blocks: number) => reply({
            id: msg.id, progress: true, blocks,
          }),
        );
        reply({ id: msg.id, ok: true, matches });
        break;
      }

      case 'spInit': {
        await init(msg.wasmUrl);
        spScanner = createSpScanner(
          msg.scanPrivKey, msg.spendPubKey, msg.network,
        );
        reply({ id: msg.id, ok: true, address: spScanner.address });
        break;
      }

      case 'spScanBatch': {
        if (!spScanner) {
          throw new Error('worker not sp-initialized');
        }
        const spResult = scanBatchSync(
          spScanner,
          msg.startHeight,
          new Uint8Array(msg.tweakData),
          new Uint8Array(msg.filterFile),
          new Uint8Array(msg.headers),
          new Uint8Array(msg.filterHeaders),
          msg.prev,
          msg.dustLimit,
          // Stream per-block progress as non-final messages; the final
          // reply below carries the same id with ok set.
          (blocks: number) => reply({
            id: msg.id, progress: true, blocks,
          }),
        );
        reply({
          id: msg.id, ok: true, matches: spResult.matches,
          skippedTweaks: spResult.skippedTweaks,
          timings: spResult.timings,
        });
        break;
      }

      default:
        throw new Error(`unknown message type ${msg.type}`);
    }
  } catch (err: any) {
    reply({ id: msg.id, ok: false, error: String(err?.message ?? err) });
  }
}

const nodeImport = new Function('m', 'return import(m)') as (
  m: string,
) => Promise<any>;

// Environment split: browser dedicated workers expose `self`, Node
// worker_threads communicates via parentPort.
if (typeof self !== 'undefined') {
  (self as any).onmessage = (e: MessageEvent) =>
    handle(e.data, (r) => (self as any).postMessage(r));
} else {
  nodeImport('node:worker_threads').then(({ parentPort }) => {
    parentPort.on('message', (m: any) => {
      handle(m, (r) => parentPort.postMessage(r));
    });
  });
}
