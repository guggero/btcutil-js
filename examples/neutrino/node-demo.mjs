#!/usr/bin/env node
// Headless demo of the watch-only wallet core, e.g.:
//
//   node examples/neutrino/node-demo.mjs \
//     --network signet --server https://signet.block-dn.org \
//     --watch 'tb1q...' --birthday 150000 --datadir /tmp/neutrino-demo
//
// The same wallet.mjs drives the browser page (index.html); this runner
// exists so the whole pipeline can be exercised and tested without one.

import { parseArgs } from 'node:util';
import { loadBtcutil } from './lib-loader.mjs';
import {
  WatchOnlyWallet, birthdayHeuristic, formatScanStats, formatBytes,
} from './wallet.mjs';
import { NodeStorage } from './storage.mjs';

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

const { init } = await loadBtcutil();
const lib = await init();
const storage = await NodeStorage.open(args.datadir);
const wallet = await WatchOnlyWallet.open({
  lib,
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
