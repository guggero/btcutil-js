import { wasmExecJs } from './wasm_exec_inline';

let initPromise: Promise<void> | null = null;

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

/**
 * Initialize the WASM module. Called automatically on first API call.
 * You can call this explicitly to pre-load the module or provide a custom
 * WASM source.
 *
 * @param wasmSource - Optional: a URL string, ArrayBuffer, or fetch Response.
 *   If omitted, btcutil.wasm is loaded from alongside this file.
 */
export async function init(
  wasmSource?: ArrayBuffer | Response | string,
): Promise<void> {
  if (!initPromise) {
    initPromise = loadWasm(wasmSource).catch((err) => {
      initPromise = null;
      throw err;
    });
  }
  return initPromise;
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
