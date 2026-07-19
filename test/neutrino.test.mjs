import './setup.mjs';
import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { init, neutrino, tx, HeaderChain, WatchList } from '../dist/index.js';

// Real mainnet vectors, sliced from block-dn.org files: headers/filters/
// filter-headers file ranges plus an exported chain state at height 30239
// (so tests cross the first real retarget at 32256 without shipping all
// preceding headers).
const vector = (name) => readFileSync(
  new URL(`test-vectors/neutrino/${name}`, import.meta.url),
);

// headers 0..4031: the first two difficulty periods (retargets at 2016 and
// 4032 are clamped to the pow limit, exercising the clamp path).
const headers0 = vector('headers-0-4031.bin');

// Exported chain state at height 30239 plus headers 30240..34271: crossing
// height 32256, the first real mainnet difficulty change
// (1d00ffff -> 1d00d86a).
const state30239 = vector('state-30239.bin');
const headers30240 = vector('headers-30240-34271.bin');

// Filters + filter headers for heights 0..1999 and the full block 170
// containing the first-ever bitcoin transaction.
const filters0 = vector('filters-0-1999.bin');
const filterHeaders0 = vector('filter-headers-0-1999.bin');
const block170 = vector('block-170.bin');

// Reference values (assertions pin the validation logic to the real chain).
const tipHash4031 =
  '00000000f037ad09d0b05ee66b8c1da83030abaf909d2b1bf519c3c7d2cd3fdf';
const tipHash30239 =
  '000000005107662c86452e7365f32f8ffdc70d8d87aa6f78630a79f7d77fbfe6';
const tipHash34271 =
  '000000005e36047e39452a7beaaa6721048ac408a3e75bb60a8b0008713653ce';
const genesisHash =
  '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f';

// The first bitcoin transaction (block 170): coinbase b1fea524..., and
// f4184fc5... spending the block 9 coinbase outpoint 0437cd7f...:0.
const block170Coinbase =
  'b1fea52486ce0c62bb442b530a3f0132b826c74e473d1f2c220bfa78111c5082';
const firstTxTxid =
  'f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16';
const block9CoinbaseTxid =
  '0437cd7f8525ceed2324359c2d0ba26006d92d856a9c20fa0241106ee5a597c9';

// The block 170 coinbase output script (watched in the filter/scan tests):
// tx 0 starts right after the 80-byte header and 1-byte tx count.
async function coinbaseScript() {
  const decoded = await tx.decode(block170.subarray(81));
  return decoded.outputs[0].scriptPubKey;
}

// ---------------------------------------------------------------------------
// Header chain
// ---------------------------------------------------------------------------

describe('neutrino: header chain', () => {
  it('validates the first 4032 mainnet headers', async () => {
    const chain = await neutrino.headerChain('mainnet');
    assert.equal(chain.tip().tipHeight, -1);

    const state = chain.append(headers0);
    assert.equal(state.appended, 4032);
    assert.equal(state.tipHeight, 4031);
    assert.equal(state.tipHash, tipHash4031);
    assert.ok(BigInt('0x' + state.chainWork) > 0n);
    chain.free();
  });

  it('rejects a non-genesis first header', async () => {
    const chain = await neutrino.headerChain('mainnet');
    assert.throws(
      () => chain.append(headers0.subarray(80, 160)),
      /genesis/,
    );
    chain.free();
  });

  it('rejects a broken previous-hash link', async () => {
    const chain = await neutrino.headerChain('mainnet');
    const corrupt = Buffer.from(headers0.subarray(0, 160));
    corrupt[85] ^= 0x01; // a PrevBlock byte of header 1
    assert.throws(() => chain.append(corrupt), /previous hash/);

    // The valid genesis header before the corrupt one must remain.
    assert.equal(chain.tip().tipHeight, 0);
    assert.equal(chain.tip().tipHash, genesisHash);
    chain.free();
  });

  it('rejects a header whose hash is above the target', async () => {
    const chain = await neutrino.headerChain('mainnet');
    chain.append(headers0.subarray(0, 80));

    // Corrupt the nonce of header 1: linkage and bits stay valid but the
    // proof of work breaks.
    const corrupt = Buffer.from(headers0.subarray(80, 160));
    corrupt[76] ^= 0x01;
    assert.throws(() => chain.append(corrupt), /above the target/);
    chain.free();
  });

  it('rejects wrong difficulty bits', async () => {
    const chain = await neutrino.headerChain('mainnet');
    chain.append(headers0.subarray(0, 80));

    const corrupt = Buffer.from(headers0.subarray(80, 160));
    corrupt[72] ^= 0x01; // bits byte
    assert.throws(() => chain.append(corrupt), /difficulty bits/);
    chain.free();
  });

  it('crosses the first real retarget from imported state', async () => {
    const chain = await neutrino.headerChain('mainnet', state30239);
    assert.equal(chain.tip().tipHeight, 30239);
    assert.equal(chain.tip().tipHash, tipHash30239);

    // Appending 30240..34271 crosses height 32256 where the difficulty
    // changed for the first time (1d00ffff -> 1d00d86a). Any error in
    // the retarget arithmetic would reject the real header.
    const state = chain.append(headers30240);
    assert.equal(state.tipHeight, 34271);
    assert.equal(state.tipHash, tipHash34271);
    chain.free();
  });

  it('rejects tampered bits at the retarget boundary', async () => {
    const chain = await neutrino.headerChain('mainnet', state30239);

    // Headers 30240..32255 are fine; give block 32256 the old bits
    // (1d00ffff instead of the retargeted 1d00d86a).
    const upTo = (32256 - 30240) * 80;
    chain.append(headers30240.subarray(0, upTo));

    const corrupt = Buffer.from(headers30240.subarray(upTo, upTo + 80));
    corrupt.writeUInt32LE(0x1d00ffff, 72);
    assert.throws(() => chain.append(corrupt), /difficulty bits/);
    chain.free();
  });

  it('rolls back within the window and re-appends', async () => {
    const chain = await neutrino.headerChain('mainnet');
    chain.append(headers0);

    const state = chain.rollback(4000);
    assert.equal(state.tipHeight, 4000);

    const again = chain.append(headers0.subarray(4001 * 80));
    assert.equal(again.tipHeight, 4031);
    assert.equal(again.tipHash, tipHash4031);
    chain.free();
  });

  it('rejects a rollback beyond the in-memory window', async () => {
    const chain = await neutrino.headerChain('mainnet');
    chain.append(headers0);
    assert.throws(() => chain.rollback(100), /window/);
    chain.free();
  });

  it('export/import state round trips exactly', async () => {
    const chain = await neutrino.headerChain('mainnet');
    const state = chain.append(headers0);

    const exported = chain.exportState();
    const resumed = await neutrino.headerChain('mainnet', exported);
    assert.deepEqual(resumed.tip(), {
      tipHeight: state.tipHeight,
      tipHash: state.tipHash,
      tipTime: state.tipTime,
      chainWork: state.chainWork,
    });
    resumed.free();
    chain.free();
  });

  it('rejects state from a different network', async () => {
    const chain = await neutrino.headerChain('mainnet');
    chain.append(headers0.subarray(0, 80));
    const exported = chain.exportState();
    chain.free();

    await assert.rejects(
      () => neutrino.headerChain('signet', exported),
      /different network/,
    );
  });

  it('free() is idempotent', async () => {
    const chain = await neutrino.headerChain('mainnet');
    chain.free();
    assert.doesNotThrow(() => chain.free());
  });
});

// ---------------------------------------------------------------------------
// Filter verification and matching
// ---------------------------------------------------------------------------

describe('neutrino: filter matching', () => {
  let watchedScript;

  before(async () => {
    watchedScript = await coinbaseScript();
  });

  it('verifies 2000 filters and finds the block 170 script', async () => {
    const watch = await neutrino.watchList([watchedScript]);
    const progress = [];
    const matches = await neutrino.matchFilters(
      watch, 0, filters0,
      headers0.subarray(0, 2000 * 80),
      filterHeaders0, '', (blocks) => progress.push(blocks),
    );

    assert.deepEqual(matches, [{
      height: 170,
      blockHash: '00000000d1145790a8694403d4063f323d499e655c8342683' +
        '4d4ce2f8dd4a2ee',
    }]);

    // The progress callback streams the processed block count sparsely
    // (every 128 blocks) and finishes with the total.
    assert.ok(progress.length > 2);
    assert.equal(progress[0], 128);
    assert.equal(progress[progress.length - 1], 2000);
    for (let i = 1; i < progress.length; i++) {
      assert.ok(progress[i] > progress[i - 1]);
    }
    watch.free();
  });

  it('an empty watch list still verifies the file', async () => {
    const watch = await neutrino.watchList();
    const matches = await neutrino.matchFilters(
      watch, 0, filters0,
      headers0.subarray(0, 2000 * 80),
      filterHeaders0, '',
    );
    assert.deepEqual(matches, []);
    watch.free();
  });

  it('rejects a corrupted filter file', async () => {
    const watch = await neutrino.watchList([watchedScript]);
    const corrupt = Buffer.from(filters0);
    corrupt[500] ^= 0x01;

    await assert.rejects(
      () => neutrino.matchFilters(
        watch, 0, corrupt,
        headers0.subarray(0, 2000 * 80),
        filterHeaders0, '',
      ),
      /committed filter header/,
    );
    watch.free();
  });

  it('rejects a wrong previous filter header', async () => {
    const watch = await neutrino.watchList();
    await assert.rejects(
      () => neutrino.matchFilters(
        watch, 0, filters0,
        headers0.subarray(0, 2000 * 80),
        filterHeaders0,
        '11'.repeat(32),
      ),
      /committed filter header/,
    );
    watch.free();
  });

  it('rejects mismatched header/filter-header lengths', async () => {
    const watch = await neutrino.watchList();
    await assert.rejects(
      () => neutrino.matchFilters(
        watch, 0, filters0,
        headers0.subarray(0, 2000 * 80),
        filterHeaders0.subarray(0, 1999 * 32), '',
      ),
      /expected 2000 filter headers/,
    );
    watch.free();
  });
});

// ---------------------------------------------------------------------------
// Block scanning
// ---------------------------------------------------------------------------

describe('neutrino: block scanning', () => {
  it('finds watched-script outputs in a block', async () => {
    const watch = await neutrino.watchList([await coinbaseScript()]);
    const result = await neutrino.scanBlock(watch, block170);

    assert.equal(result.outputs.length, 1);
    assert.equal(result.outputs[0].txid, block170Coinbase);
    assert.equal(result.outputs[0].vout, 0);
    assert.equal(result.outputs[0].value, 5_000_000_000);
    assert.deepEqual(result.spends, []);
    watch.free();
  });

  it('finds watched-outpoint spends in a block', async () => {
    const watch = await neutrino.watchList();
    watch.addOutpoint(block9CoinbaseTxid, 0);

    // Block 170 contains the first-ever bitcoin transaction, spending
    // the block 9 coinbase.
    const result = await neutrino.scanBlock(watch, block170);
    assert.deepEqual(result.spends, [{
      prevTxid: block9CoinbaseTxid,
      prevVout: 0,
      txid: firstTxTxid,
    }]);

    // After removing the outpoint the spend is no longer reported.
    watch.removeOutpoint(block9CoinbaseTxid, 0);
    const again = await neutrino.scanBlock(watch, block170);
    assert.deepEqual(again.spends, []);
    watch.free();
  });
});

// ---------------------------------------------------------------------------
// Sync API
// ---------------------------------------------------------------------------

describe('neutrino: sync API', () => {
  let lib;

  before(async () => {
    lib = await init();
  });

  it('header chain works synchronously', () => {
    const chain = lib.neutrino.headerChain('mainnet');
    assert.ok(chain instanceof HeaderChain);
    const state = chain.append(headers0);
    assert.equal(state.tipHash, tipHash4031);
    chain.free();
  });

  it('watch list, matching and scanning work synchronously', async () => {
    const watch = lib.neutrino.watchList([await coinbaseScript()]);
    assert.ok(watch instanceof WatchList);

    const matches = lib.neutrino.matchFilters(
      watch, 0, filters0,
      headers0.subarray(0, 2000 * 80),
      filterHeaders0, '',
    );
    assert.equal(matches.length, 1);
    assert.equal(matches[0].height, 170);

    const result = lib.neutrino.scanBlock(watch, block170);
    assert.equal(result.outputs.length, 1);
    watch.free();
  });

  it('errors throw synchronously', () => {
    const chain = lib.neutrino.headerChain('mainnet');
    assert.throws(() => chain.append(new Uint8Array(79)));
    chain.free();
  });
});
