import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { tmpdir } from 'node:os';
import { mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import {
  birthdayHeuristic,
  formatBytes,
  formatScanStats,
  scriptFilterType,
  selectFilterType,
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
      filterType: 'p2tr',
    });
    assert.equal(
      line,
      '13,129 blocks scanned with 2 batches in 37.0 s ' +
        '(42 blocks matched, 897.8 MiB downloaded, p2tr filters)',
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

describe('watchwallet: filter-type selection', () => {
  const P2WPKH = '0014' + '11'.repeat(20);
  const P2WSH = '0020' + '22'.repeat(32);
  const P2TR = '5120' + '33'.repeat(32);
  const P2PKH = '76a914' + '44'.repeat(20) + '88ac';
  const P2SH = 'a914' + '55'.repeat(20) + '87';

  it('classifies single scripts', () => {
    assert.equal(scriptFilterType(P2WPKH), 'p2wpkh');
    assert.equal(scriptFilterType(P2WSH), 'p2wsh');
    assert.equal(scriptFilterType(P2TR), 'p2tr');
    assert.equal(scriptFilterType(P2PKH), null);
    assert.equal(scriptFilterType(P2SH), null);
    // OP_1 <32> is p2tr, but OP_0 with a non-standard length is not a
    // witness v0 program we know.
    assert.equal(scriptFilterType('0015' + '66'.repeat(21)), null);
  });

  const cases = [
    // Homogeneous native segwit -> the narrowest flavour.
    [[P2TR], true, 'p2tr'],
    [[P2WPKH, P2WPKH], true, 'p2wpkh'],
    [[P2WSH], true, 'p2wsh'],
    // Mixed native segwit -> the combined segwit flavour.
    [[P2WPKH, P2TR], true, 'segwit'],
    [[P2WPKH, P2WSH, P2TR], true, 'segwit'],
    // Anything legacy/nested in the mix -> full basic filters.
    [[P2WPKH, P2PKH], true, 'basic'],
    [[P2SH], true, 'basic'],
    // No custom filters on the server -> always basic.
    [[P2TR], false, 'basic'],
    // Nothing watched -> basic (nothing narrower to pick).
    [[], true, 'basic'],
  ];
  for (const [scripts, available, expected] of cases) {
    it(`${scripts.length} scripts, custom=${available} -> ${expected}`,
      () => {
        assert.equal(selectFilterType(scripts, available), expected);
      });
  }
});

describe('watchwallet: multi-chain filter-header storage', () => {
  it('chains of different flavours coexist independently', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'btcutil-store-'));
    const storage = await NodeStorage.open(dir);

    // Basic (default) and two custom chains, all different lengths.
    await storage.appendFilterHeaders(new Uint8Array(32).fill(1));
    await storage.appendFilterHeaders(new Uint8Array(64).fill(2), 'p2tr');
    await storage.appendFilterHeaders(new Uint8Array(96).fill(3), 'segwit');

    assert.equal(await storage.filterHeaderCount(), 1);
    assert.equal(await storage.filterHeaderCount('basic'), 1);
    assert.equal(await storage.filterHeaderCount('p2tr'), 2);
    assert.equal(await storage.filterHeaderCount('segwit'), 3);
    assert.equal(await storage.filterHeaderCount('p2wpkh'), 0);

    // Reads and truncates stay within their flavour.
    const p2tr = await storage.readFilterHeaders(1, 1, 'p2tr');
    assert.equal(p2tr[0], 2);
    await storage.truncateFilterHeaders(1, 'segwit');
    assert.equal(await storage.filterHeaderCount('segwit'), 1);
    assert.equal(await storage.filterHeaderCount('p2tr'), 2);

    // Stats aggregate all chains; count reports the longest.
    const stats = await storage.stats();
    assert.equal(stats.filterHeadersBytes, 32 + 64 + 32);
    assert.equal(stats.filterHeaderCount, 2);

    // clear() removes every flavour.
    await storage.clear();
    assert.equal(await storage.filterHeaderCount('p2tr'), 0);
    assert.equal((await storage.stats()).totalBytes, 0);
  });
});

describe('watchwallet: typed filter endpoints', () => {
  it('builds the /type/ URLs for custom flavours only', async () => {
    const urls = [];
    const realFetch = globalThis.fetch;
    globalThis.fetch = async (url) => {
      urls.push(String(url));
      return {
        ok: true,
        status: 200,
        headers: { get: () => null },
        arrayBuffer: async () => new ArrayBuffer(0),
      };
    };
    try {
      const client = new BlockDnClient('https://example.org');
      await client.filterHeaders(2000);
      await client.filterHeaders(2000, 'basic');
      await client.filterHeaders(2000, 'p2tr');
      await client.filters(4000);
      await client.filters(4000, { filterType: 'segwit' });
      await client.filters(4000, { fresh: true, filterType: 'p2wpkh' });
    } finally {
      globalThis.fetch = realFetch;
    }
    assert.equal(urls[0], 'https://example.org/filter-headers/2000');
    assert.equal(urls[1], 'https://example.org/filter-headers/2000');
    assert.equal(urls[2], 'https://example.org/filter-headers/type/p2tr/2000');
    assert.equal(urls[3], 'https://example.org/filters/4000');
    assert.equal(urls[4], 'https://example.org/filters/type/segwit/4000');
    assert.match(
      urls[5],
      /^https:\/\/example\.org\/filters\/type\/p2wpkh\/4000\?fresh=/,
    );
  });
});
