import { wasmExecJs } from './wasm_exec_inline';

// Type-only imports — erased at runtime, no circular dependency issues.
import type { base58 as _base58 } from './base58';
import type { bech32 as _bech32 } from './bech32';
import type { address as _address } from './address';
import type { amount as _amount } from './amount';
import type { hash as _hash } from './hash';
import type { wif as _wif } from './wif';
import type { hdkeychain as _hdkeychain } from './hdkeychain';
import type { bip322 as _bip322 } from './bip322';
import type { txsort as _txsort } from './txsort';
import type { tx as _tx } from './tx';
import type { psbt as _psbt } from './psbt';
import type { gcs as _gcs } from './gcs';
import type { bloom as _bloom } from './bloom';
import type { txscript as _txscript } from './txscript';
import type { btcec as _btcec } from './btcec';
import type { chaincfg as _chaincfg } from './chaincfg';
import type { chainhash as _chainhash } from './chainhash';

// ---------------------------------------------------------------------------
// Sync API type — strips Promise<> from every method return type.
// ---------------------------------------------------------------------------

/** Converts all `(...) => Promise<R>` methods to `(...) => R`. */
type Sync<T> = {
  [K in keyof T]: T[K] extends (...args: infer A) => Promise<infer R>
    ? (...args: A) => R
    : T[K];
};

/**
 * Synchronous API object returned by `init()`. All methods are sync — the
 * WASM module is already loaded, so no `await` is needed.
 *
 * @example
 * ```typescript
 * import { init } from 'btcutil-js';
 *
 * const btcutil = await init();
 * const encoded = btcutil.base58.encode('deadbeef');        // sync!
 * const info    = btcutil.address.decode('bc1q...');         // sync!
 * const sig     = btcutil.btcec.schnorrSign(privKey, hash);  // sync!
 * ```
 */
export interface BtcutilSync {
  base58: Sync<typeof _base58>;
  bech32: Sync<typeof _bech32>;
  address: Sync<typeof _address>;
  amount: Sync<typeof _amount>;
  hash: Sync<typeof _hash>;
  wif: Sync<typeof _wif>;
  hdkeychain: Sync<typeof _hdkeychain>;
  bip322: Sync<typeof _bip322>;
  txsort: Sync<typeof _txsort>;
  tx: Sync<typeof _tx>;
  psbt: Sync<typeof _psbt>;
  gcs: Sync<typeof _gcs>;
  bloom: Sync<typeof _bloom>;
  txscript: Sync<typeof _txscript>;
  btcec: Sync<typeof _btcec>;
  chaincfg: Sync<typeof _chaincfg>;
  chainhash: Sync<typeof _chainhash>;
}

// ---------------------------------------------------------------------------
// WASM loading
// ---------------------------------------------------------------------------

let initPromise: Promise<void> | null = null;
let syncApi: BtcutilSync | null = null;

function ensureGoRuntime(): void {
  if ((globalThis as any).Go) return;
  new Function(wasmExecJs)();
}

async function loadWasm(
  wasmSource?: ArrayBuffer | Response | string,
): Promise<void> {
  ensureGoRuntime();

  const go = new (globalThis as any).Go();

  const readyPromise = new Promise<void>((resolve) => {
    (globalThis as any).onBtcutilReady = () => {
      delete (globalThis as any).onBtcutilReady;
      resolve();
    };
  });

  let result: WebAssembly.WebAssemblyInstantiatedSource;

  if (wasmSource instanceof ArrayBuffer) {
    result = await WebAssembly.instantiate(wasmSource, go.importObject);
  } else if (typeof wasmSource === 'string') {
    result = await WebAssembly.instantiateStreaming(
      fetch(wasmSource),
      go.importObject,
    );
  } else if (wasmSource instanceof Response) {
    result = await WebAssembly.instantiateStreaming(
      wasmSource,
      go.importObject,
    );
  } else {
    if (typeof process !== 'undefined' && process.versions?.node) {
      const nodeImport = new Function('m', 'return import(m)') as (
        m: string,
      ) => Promise<any>;
      const { readFile } = await nodeImport('node:fs/promises');
      const { fileURLToPath } = await nodeImport('node:url');
      const { dirname, join } = await nodeImport('node:path');
      const dir = dirname(fileURLToPath(import.meta.url));
      const buf = await readFile(join(dir, 'btcutil.wasm'));
      result = await WebAssembly.instantiate(buf, go.importObject);
    } else {
      const url = new URL('btcutil.wasm', import.meta.url);
      result = await WebAssembly.instantiateStreaming(
        fetch(url.href),
        go.importObject,
      );
    }
  }

  go.run(result.instance);
  await readyPromise;
}

// ---------------------------------------------------------------------------
// Sync API builder
// ---------------------------------------------------------------------------

/** Wrap every function in a Go bridge namespace with `unwrap()`. */
function wrapNamespace(ns: any): any {
  const out: any = {};
  for (const key of Object.keys(ns)) {
    if (typeof ns[key] === 'function') {
      out[key] = (...args: any[]) => unwrap(ns[key](...args));
    }
  }
  return out;
}

function buildSyncApi(): BtcutilSync {
  const raw = g();
  return {
    base58: wrapNamespace(raw.base58),
    bech32: wrapNamespace(raw.bech32),
    address: wrapNamespace(raw.address),
    amount: wrapNamespace(raw.amount),
    hash: wrapNamespace(raw.hash),
    wif: wrapNamespace(raw.wif),
    hdkeychain: wrapNamespace(raw.hdkeychain),
    bip322: wrapNamespace(raw.bip322),
    txsort: wrapNamespace(raw.txsort),
    tx: wrapNamespace(raw.tx),
    psbt: wrapNamespace(raw.psbt),
    gcs: wrapNamespace(raw.gcs),
    bloom: wrapNamespace(raw.bloom),
    txscript: wrapNamespace(raw.txscript),
    btcec: wrapNamespace(raw.btcec),
    chaincfg: wrapNamespace(raw.chaincfg),
    chainhash: wrapNamespace(raw.chainhash),
  } as BtcutilSync;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Initialize the WASM module and return the synchronous API.
 *
 * Called automatically on first async namespace call. You can call it
 * explicitly to pre-load the module, provide a custom WASM source, or to
 * obtain the sync API:
 *
 * ```typescript
 * const btcutil = await init();
 * btcutil.base58.encode('deadbeef'); // sync — no await needed
 * ```
 *
 * @param wasmSource - Optional: a URL string, ArrayBuffer, or fetch Response.
 *   If omitted, btcutil.wasm is loaded from alongside this file.
 * @returns The synchronous API object with all namespaces.
 */
export async function init(
  wasmSource?: ArrayBuffer | Response | string,
): Promise<BtcutilSync> {
  if (!initPromise) {
    initPromise = loadWasm(wasmSource).catch((err) => {
      initPromise = null;
      throw err;
    });
  }
  await initPromise;
  if (!syncApi) {
    syncApi = buildSyncApi();
  }
  return syncApi;
}

/** Access the globalThis.btcutil bridge object. */
export function g(): any {
  return (globalThis as any).btcutil;
}

/** Unwrap a Go result ({result: T} or {error: string}) into T or throw. */
export function unwrap<T>(result: any): T {
  if (result && typeof result === 'object') {
    if ('error' in result && !('result' in result)) {
      throw new Error(result.error);
    }
    if ('result' in result) {
      return result.result as T;
    }
  }
  return result as T;
}
