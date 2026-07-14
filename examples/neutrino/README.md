# Watch-only wallet example — compact filters over HTTP

A browser-only (no backend, no P2P sockets) watch-only Bitcoin wallet built
from three pieces:

- **[block-dn](https://github.com/guggero/block-dn)** serves headers, BIP158
  compact filters and blocks as CDN-cacheable HTTP files. The server is
  user-configurable and only ever learns *which block ranges* an IP
  downloads — never which addresses are being watched.
- **btcutil-js WASM primitives** (the `neutrino` namespace) do everything
  consensus- and CPU-critical locally: header chain validation (proof of
  work, difficulty retargets, median-time-past), filter verification against
  the BIP157 commitment chain, GCS watch-list matching, and block scanning.
- **This example** is the thin orchestration layer: fetching, persistence
  (OPFS in the browser, plain files under Node), birthday heuristics, scan
  scheduling and a small UI.

## Browser

Serve the repository root:

```bash
npm run build          # or build:js if the wasm is already built
python3 -m http.server # from the repo root
# open http://localhost:8000/examples/neutrino/
```

The library is resolved by `lib-loader.mjs` in this order: the local
`dist/` build if present; otherwise npm via the jsDelivr CDN, pinned to the
version in the repo's `package.json` (falling back to `@latest`). The
bundled module has no bare imports and loads `btcutil.wasm` relative to its
own URL, so the CDN path needs no build step at all — which is what makes
the statically-deployed (GitHub Pages) copy of this page work without a
checked-in `dist/`. A loaded version that predates the `neutrino` module
fails with a descriptive error.

Pick a network + block-dn server (defaults to the public signet instance),
add an address or an output descriptor, optionally override the scan-start
height, and hit *Add & scan*. Chain data persists in OPFS, so reloads resume
from where the last session stopped.

## Node (headless demo / testing)

The same wallet core runs under Node:

```bash
node examples/neutrino/node-demo.mjs \
  --network signet --server https://signet.block-dn.org \
  --watch tb1q... --birthday 313000 \
  --datadir /tmp/neutrino-demo
```

Add `--follow` to keep polling the tip. Descriptors work too (quote them):
`--watch 'wpkh(tb.../<0;1>/*)'`.

## What it does, concretely

1. **Header sync** — downloads all 80-byte block headers and 32-byte filter
   headers (aligned, immutable, CDN-cached files), validates every header
   locally and persists the raw files plus a ~80 KiB chain-state snapshot
   for instant resume. Full signet: ~2 s. Full mainnet: ~110 MB download,
   a few seconds of validation.
2. **Scan** — from the lowest *birthday* of any watch item: streams filter
   files, verifies each filter against its committed filter header
   (corruption/tampering fails loudly), matches against the watch list, and
   only fetches full blocks whose filter matched. Filter files are
   processed in parallel batches (`--batch-size`, default 4, max 16): each
   file of a batch is downloaded and matched concurrently — matching runs
   on a pool of worker threads, each with its own WASM instance (Go WASM is
   single-threaded per instance) — then the batch completes as one unit
   before state is persisted and progress reported. Matched blocks are
   applied strictly in height order so a spend of an output found earlier
   in the same batch is still detected. Filters are discarded after
   matching — long-term storage stays ~110 MB + wallet state.

   Measured on signet (13,129 blocks, watch item matching ~every block,
   ~900 MiB downloaded): batch 1 → 143.6 s, batch 4 → 37.0 s (3.9×),
   batch 8 → 22.1 s (6.5×). A stats line ("N blocks scanned with X batches
   in Y s (M blocks matched, Z downloaded)") prints after every scan.

   A filter failing its commitment check (e.g. a truncated file cached by
   a CDN) is refetched once with a cache-busting parameter before the scan
   gives up.
3. **Tip following** — polls `/status`, appends new headers (shallow reorgs
   are rolled back and resynced), fetches single filters for new blocks.

## Known prototype limitations

- Descriptor watches derive a fixed range (default 100 addresses per
  multipath); a production wallet would extend the gap on finds and rescan.
- Reorg handling assumes reorgs no deeper than 6 blocks (block-dn's own
  reorg-safe depth on mainnet).
- With `--batch-size 1` matching runs inline on the main thread; any larger
  batch size uses the worker pool (`worker-pool.mjs` / `match-worker.mjs`),
  which also keeps the browser main thread responsive during scans.
- The filter-header chain is trusted from the configured server on first
  download (verified thereafter via per-filter commitments). Cross-checking
  the filter-header tip against a second source would harden this.

## Test vectors

`test/test-vectors/neutrino/` contains slices of real mainnet data fetched
from `https://block-dn.org` (headers/filters/filter-headers files and block
170), including an exported chain state at height 30,239 so the tests cross
the first real difficulty retarget (height 32,256) without shipping all
preceding headers.
