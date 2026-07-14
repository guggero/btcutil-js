#!/usr/bin/env node
// Headless dev/test driver for the watch-only wallet engine
// (WatchOnlyWallet + NodeStorage + BlockDnClient), e.g.:
//
//   node tools/neutrino-demo.mjs \
//     --network signet --server https://signet.block-dn.org \
//     --watch 'tb1q...' --birthday 150000 --datadir /tmp/neutrino-demo
//
// This is not a second frontend — the user-facing wallet UI lives in
// cryptography-toolkit (the "BIP-157: Compact Filters" page). This script
// exists so the whole engine, including the Node storage backend and the
// worker-pool matching path, can be exercised end-to-end without a browser.

import { parseArgs } from 'node:util';
import {
  WatchOnlyWallet, NodeStorage, birthdayHeuristic, formatScanStats,
  formatBytes,
} from '../dist/index.js';

const { values: args } = parseArgs({
  options: {
    network: { type: 'string', default: 'signet' },
    server: { type: 'string', default: 'https://signet.block-dn.org' },
    watch: { type: 'string', multiple: true, default: [] },
    birthday: { type: 'string' },
    datadir: { type: 'string', default: '.neutrino-demo' },
    follow: { type: 'boolean', default: false },
    'batch-size': { type: 'string', default: '4' },
  },
});

const storage = await NodeStorage.open(args.datadir);
const wallet = await WatchOnlyWallet.open({
  network: args.network,
  serverUrl: args.server,
  storage,
  batchSize: Number(args['batch-size']),
});

for (const value of args.watch) {
  const birthday = args.birthday !== undefined
    ? Number(args.birthday)
    : birthdayHeuristic(args.network, value);
  if (value.includes('(')) {
    await wallet.addDescriptor(value, birthday);
  } else {
    await wallet.addAddress(value, birthday);
  }
  console.log(`watching ${value} from height ${birthday}`);
}

console.time('header sync');
await wallet.syncHeaders((kind, height, target) => {
  process.stdout.write(`\r${kind}: ${height}/${target}        `);
});
process.stdout.write('\n');
console.timeEnd('header sync');

const { stats } = await wallet.scan((height, target, found) => {
  process.stdout.write(`\rscan: ${height}/${target} (${found} utxos)    `);
});
process.stdout.write('\n');
console.log(formatScanStats(stats));

const cache = await wallet.cacheStats();
console.log(`cached: ${cache.headerCount.toLocaleString()} headers, ` +
  `${cache.filterHeaderCount.toLocaleString()} filter headers — ` +
  `${formatBytes(cache.totalBytes)} in ${args.datadir}`);

const summary = wallet.summary();
console.log(`\ntip: ${summary.tipHeight}, scanned to: ${summary.scannedTo}`);
console.log(`balance: ${summary.balanceSats} sats in ${summary.numUtxos} ` +
  'utxos');
for (const utxo of summary.utxos) {
  console.log(`  ${utxo.outpoint} ${utxo.value} sats @ ${utxo.height} ` +
    `(${utxo.address})`);
}

if (args.follow) {
  console.log('\nfollowing tip (ctrl-c to stop)...');
  for (;;) {
    await new Promise((r) => setTimeout(r, 30_000));
    if (await wallet.followTip()) {
      const s = wallet.summary();
      console.log(`new tip ${s.tipHeight}, balance ${s.balanceSats} sats`);
    }
  }
}

wallet.close();
