#!/usr/bin/env node
// Headless dev/test driver for the BIP-352 Silent Payments scan engine:
//
//   node tools/sp-demo.mjs \
//     --network signet --server https://signet.block-dn.org \
//     --scan-priv <32B hex> --spend-pub <33B hex> [--from <height>] \
//     --datadir /tmp/sp-demo
//
// Without keys, a random pair is generated (the run then validates the
// pipeline but finds nothing). The user-facing UI lives in
// cryptography-toolkit ("BIP-352: Silent Payments" page).

import { parseArgs } from 'node:util';
import {
  SilentPaymentScanner, NodeStorage, formatSpScanStats,
  formatSpScanBreakdown, formatBytes, init,
} from '../dist/index.js';

const { values: args } = parseArgs({
  options: {
    network: { type: 'string', default: 'signet' },
    server: { type: 'string', default: 'https://signet.block-dn.org' },
    'scan-priv': { type: 'string' },
    'spend-pub': { type: 'string' },
    from: { type: 'string' },
    to: { type: 'string' },
    dust: { type: 'string', default: '0' },
    datadir: { type: 'string', default: '.sp-demo' },
    'batch-size': { type: 'string', default: '4' },
    quiet: { type: 'boolean', default: false },
  },
});

const lib = await init();

let scanPriv = args['scan-priv'];
let spendPub = args['spend-pub'];
if (!scanPriv || !spendPub) {
  console.log('no keys given — using a random pair (zero finds expected)');
  const scanKp = lib.btcec.newPrivateKey();
  const spendKp = lib.btcec.newPrivateKey();
  scanPriv = Buffer.from(scanKp.privateKey).toString('hex');
  spendPub = Buffer.from(
    lib.btcec.serializeCompressed(spendKp.publicKey),
  ).toString('hex');
}

const storage = await NodeStorage.open(args.datadir);
const engine = await SilentPaymentScanner.open({
  network: args.network,
  serverUrl: args.server,
  storage,
  batchSize: Number(args['batch-size']),
});

console.time('header sync');
await engine.syncHeaders((kind, height, target) => {
  process.stdout.write(`\r${kind}: ${height}/${target}        `);
});
process.stdout.write('\n');
console.timeEnd('header sync');

const { results, stats } = await engine.scan({
  scanPrivKey: scanPriv,
  spendPubKey: spendPub,
  fromHeight: args.from !== undefined ? Number(args.from) : undefined,
  toHeight: args.to !== undefined ? Number(args.to) : undefined,
  dustLimit: Number(args.dust),
  onProgress: (height, target, found) => process.stdout.write(
    `\rscan: ${height}/${target} (${found} found)     `,
  ),
  onLog: (line) => {
    if (args.quiet) return;
    process.stdout.write('\r\x1b[2K');
    console.log(line);
  },
  onFound: (r) => {
    process.stdout.write('\n');
    console.log(`FOUND ${r.txid}:${r.vout} ${r.value} sats @ ${r.height}` +
      ` label=${r.label} k=${r.k}` +
      ` unspent=${r.unspent === null ? '?' : r.unspent}`);
  },
});
process.stdout.write('\n');

console.log(`address: ${engine.address}`);
console.log(`change address: ${engine.changeAddress}`);
console.log(formatSpScanStats(stats));
console.log(formatSpScanBreakdown(stats));

const cache = await engine.storage.stats();
console.log(`cached chain data: ${formatBytes(cache.totalBytes)} in ` +
  args.datadir);

for (const r of results) {
  console.log(`  ${r.txid}:${r.vout} ${r.value} sats @ ${r.height} ` +
    `(${r.label}, k=${r.k}, unspent=${r.unspent})`);
}

engine.close();
