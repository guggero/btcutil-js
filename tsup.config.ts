import { defineConfig } from 'tsup';

export default defineConfig({
  // The worker is its own self-contained entry: it runs in a separate
  // thread with its own WASM instance and is loaded by URL (matchpool.ts),
  // never imported. Code splitting is disabled so both bundles stay
  // self-contained single files (index.js is imported straight from CDNs).
  entry: ['src/index.ts', 'src/neutrino-worker.ts'],
  format: ['cjs', 'esm'],
  splitting: false,
  dts: { entry: ['src/index.ts'] },
  clean: true,
  sourcemap: true,
  shims: true,
});
