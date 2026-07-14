import './setup.mjs';
import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { init, block, chainhash } from '../dist/index.js';

// Real mainnet blocks: 100000 (4 transactions, the classic merkle-root
// example) and 586 (3 transactions, exercising the duplicate-last-entry
// rule for odd merkle levels).
const block100k = readFileSync(
  new URL('test-vectors/neutrino/block-100000.bin', import.meta.url),
);
const block586 = readFileSync(
  new URL('test-vectors/neutrino/block-586.bin', import.meta.url),
);
const block170 = readFileSync(
  new URL('test-vectors/neutrino/block-170.bin', import.meta.url),
);

const block100kHash =
  '000000000003ba27aa200b1cecaad478d2b00432346c3f1f3986da1afd33e506';
const block100kMerkleRoot =
  'f3e94742aca4b5ef85488dc37c06c3282295ffec960994b2c0d5ac2a25a95766';
const block100kCoinbaseTxid =
  '8c14f0db3df150123e6f3dbbf30f8b955a8249b62ac1d1ff16284aefa3d06d87';

describe('block: decode', () => {
  it('decodes block 100000 with header fields and sizes', async () => {
    const decoded = await block.decode(block100k);
    assert.equal(decoded.hash, block100kHash);
    assert.equal(decoded.merkleRoot, block100kMerkleRoot);
    assert.equal(decoded.version, 1);
    assert.equal(decoded.timestamp, 1293623863);
    assert.equal(decoded.bits, 0x1b04864c);
    assert.equal(decoded.nonce, 274148111);
    assert.equal(decoded.size, block100k.length);

    // Pre-segwit block: stripped size equals full size, so weight = 4x.
    assert.equal(decoded.legacySize, block100k.length);
    assert.equal(decoded.weight, block100k.length * 4);
  });

  it('decodes all transactions in the tx.decode shape', async () => {
    const decoded = await block.decode(block100k);
    assert.equal(decoded.transactions.length, 4);
    assert.equal(decoded.transactions[0].txid, block100kCoinbaseTxid);

    // The coinbase input has the all-zero prevout txid.
    const coinbase = decoded.transactions[0];
    assert.equal(coinbase.inputs[0].txid, '00'.repeat(32));
    assert.ok(coinbase.outputs[0].value > 0);
  });

  it('rejects garbage', async () => {
    await assert.rejects(() => block.decode(new Uint8Array(50)));
  });
});

describe('block: merkleTree', () => {
  it('builds the tree of block 100000 (even count)', async () => {
    const tree = await block.merkleTree(block100k);
    assert.deepEqual(tree.map((level) => level.length), [4, 2, 1]);
    assert.equal(tree[0][0], block100kCoinbaseTxid);
    assert.equal(tree[2][0], block100kMerkleRoot);
  });

  it('applies duplicate-last semantics for odd counts (block 586)',
    async () => {
      const tree = await block.merkleTree(block586);
      assert.deepEqual(tree.map((level) => level.length), [3, 2, 1]);

      // The root of the returned tree must equal the header's merkle
      // root — only true if the odd level was hashed with the
      // duplicate-last rule.
      const decoded = await block.decode(block586);
      assert.equal(tree[2][0], decoded.merkleRoot);

      // Second node of level 1 = dsha(txid3 || txid3).
      const last = tree[0][2];
      const internal = Buffer.from(last, 'hex').reverse();
      const dup = await chainhash.doubleHash(
        Buffer.concat([internal, internal]),
      );
      assert.equal(
        Buffer.from(dup).reverse().toString('hex'), tree[1][1],
      );
    });

  it('a two-transaction block has a two-level tree', async () => {
    const tree = await block.merkleTree(block170);
    assert.deepEqual(tree.map((level) => level.length), [2, 1]);
    assert.notEqual(tree[1][0], tree[0][0]);
  });
});

describe('block: sync API', () => {
  let lib;

  before(async () => {
    lib = await init();
  });

  it('decode + merkleTree work synchronously', () => {
    const decoded = lib.block.decode(block100k);
    assert.equal(decoded.hash, block100kHash);
    const tree = lib.block.merkleTree(block100k);
    assert.equal(tree.at(-1)[0], block100kMerkleRoot);
  });
});
