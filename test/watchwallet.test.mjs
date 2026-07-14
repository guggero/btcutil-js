import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { tmpdir } from 'node:os';
import { mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import {
  birthdayHeuristic,
  formatBytes,
  formatScanStats,
  NodeStorage,
  BlockDnClient,
} from '../dist/index.js';

// Offline tests of the watch-only wallet engine's library surface. The
// network-dependent end-to-end flow is exercised manually via
// tools/neutrino-demo.mjs against a public signet instance.

describe('watchwallet: birthday heuristics', () => {
  const cases = [
    // Mainnet: script-type era heuristics.
    ['mainnet', 'bc1py1e53...', 709_632],
    ['mainnet', 'bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh', 481_824],
    ['mainnet', '3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy', 173_805],
    ['mainnet', '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa', 0],
    ['mainnet', 'tr(xpub.../*)', 709_632],
    ['mainnet', 'wpkh(xpub.../*)', 481_824],
    ['mainnet', 'wsh(multi(2,a,b))', 481_824],
    ['mainnet', 'sh(wpkh(xpub...))', 173_805],
    ['mainnet', 'pkh(xpub...)', 0],
    // Other networks: chains are short, always scan from genesis.
    ['signet', 'tb1p...', 0],
    ['regtest', 'bcrt1q...', 0],
  ];

  for (const [network, value, expected] of cases) {
    it(`${network} ${value.slice(0, 16)} -> ${expected}`, () => {
      assert.equal(birthdayHeuristic(network, value), expected);
    });
  }
});

describe('watchwallet: formatting', () => {
  it('formatBytes picks sensible units', () => {
    assert.equal(formatBytes(512), '512 B');
    assert.equal(formatBytes(90_000), '87.9 KiB');
    assert.equal(formatBytes(941_359_104), '897.8 MiB');
    assert.equal(formatBytes(3 * 1024 ** 3), '3.0 GiB');
  });

  it('formatScanStats produces the stats line', () => {
    const line = formatScanStats({
      blocksScanned: 13_129,
      batches: 2,
      matchedBlocks: 42,
      seconds: 37.04,
      bytesDownloaded: 941_359_104,
    });
    assert.equal(
      line,
      '13,129 blocks scanned with 2 batches in 37.0 s ' +
        '(42 blocks matched, 897.8 MiB downloaded)',
    );
  });
});

describe('watchwallet: NodeStorage', () => {
  it('round-trips headers, state and wallet; stats and clear work',
    async () => {
      const dir = mkdtempSync(join(tmpdir(), 'btcutil-store-'));
      const storage = await NodeStorage.open(dir);

      // Flat-file records: appends land at height * recordSize.
      const headers = new Uint8Array(160).fill(0xaa);
      await storage.appendHeaders(headers);
      assert.equal(await storage.headerCount(), 2);
      const slice = await storage.readHeaders(1, 1);
      assert.equal(slice.length, 80);
      assert.equal(slice[0], 0xaa);

      const fh = new Uint8Array(64).fill(0xbb);
      await storage.appendFilterHeaders(fh);
      assert.equal(await storage.filterHeaderCount(), 2);

      await storage.setChainState(new Uint8Array([1, 2, 3]));
      assert.deepEqual(
        await storage.getChainState(), new Uint8Array([1, 2, 3]),
      );

      await storage.setWallet({ hello: 'world' });
      assert.deepEqual(await storage.getWallet(), { hello: 'world' });

      const stats = await storage.stats();
      assert.equal(stats.headerCount, 2);
      assert.equal(stats.filterHeaderCount, 2);
      assert.equal(stats.headersBytes, 160);
      assert.equal(
        stats.totalBytes,
        160 + 64 + 3 + JSON.stringify({ hello: 'world' }).length,
      );

      // Truncation drops trailing records.
      await storage.truncateHeaders(1);
      assert.equal(await storage.headerCount(), 1);

      // Clear is complete and idempotent.
      await storage.clear();
      await storage.clear();
      assert.equal((await storage.stats()).totalBytes, 0);
      assert.equal(await storage.getWallet(), null);
      assert.equal(await storage.getChainState(), null);
    });
});

describe('watchwallet: BlockDnClient', () => {
  it('normalizes the base URL', () => {
    const client = new BlockDnClient('https://example.org///');
    assert.equal(client.baseUrl, 'https://example.org');
    assert.equal(client.bytesFetched, 0);
  });
});
