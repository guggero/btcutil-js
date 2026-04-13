// Reads wasm_exec.js (Go's WASM runtime, a top-level IIFE) and wraps it in
// a real ES module that exports `Go` directly — no eval, no `Function()`
// constructor, no permanent globalThis pollution.
//
// Strategy: let the upstream IIFE run (it installs the wasm runtime shims
// `globalThis.fs / process / crypto` that the Go binary calls into at run
// time, conditionally — only when missing), then snapshot `globalThis.Go`
// into a module-local binding and restore the previous global so re-imports
// or other libraries that load wasm_exec.js are unaffected.
//
// Result: callers can `import { Go } from 'btcutil-js/...'` and the page's
// CSP only needs `'wasm-unsafe-eval'` (for WebAssembly.instantiate*) — no
// `'unsafe-eval'` for the loader itself.

import { readFileSync, writeFileSync } from 'node:fs';

const upstream = readFileSync('wasm-wrapper/wasm_exec.js', 'utf-8');

const output = `// Auto-generated from wasm-wrapper/wasm_exec.js — do not edit.
// Regenerate with: npm run generate:wasm-exec
/* eslint-disable */
// @ts-nocheck

const _g: any = globalThis as any;
const _prevGo: any = _g.Go;

${upstream}

const _Go: any = _g.Go;
if (_prevGo === undefined) {
  delete _g.Go;
} else {
  _g.Go = _prevGo;
}

export const Go: new () => any = _Go;
`;

writeFileSync('src/wasm_exec.ts', output);
