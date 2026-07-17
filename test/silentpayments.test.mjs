import './setup.mjs';
import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { init, silentpayments, btcec, chainhash } from '../dist/index.js';
import { toHex } from './util.mjs';

// The official BIP-352 send-and-receive test vectors (copied from the btcd
// silentpayments package). The receiving cases provide the scan/spend key
// material, the served-tweak-format `tweak` (input_hash * A_sum) and the
// expected output keys + private key tweaks.
const vectors = JSON.parse(readFileSync(
  new URL(
    'test-vectors/bip-0352_send_and_receive_test_vectors.json',
    import.meta.url,
  ),
  'utf-8',
));

function receiving(comment, index = 0) {
  const vector = vectors.find((v) => v.comment === comment);
  assert.ok(vector, `vector not found: ${comment}`);
  return vector.receiving[index];
}

// Build a scanner for a receiving case: the spend PUBLIC key is derived
// from the vector's private key.
async function scannerFor(r, network = 'mainnet') {
  const spendPub = (await btcec.pointMultiply(
    r.given.key_material.spend_priv_key,
  )).compressed;
  return silentpayments.scanner(
    r.given.key_material.scan_priv_key, spendPub, network,
  );
}

describe('silentpayments: scanner creation', () => {
  it('encodes the vector silent payment address', async () => {
    const r = receiving('Simple send: two inputs');
    const scanner = await scannerFor(r);
    assert.equal(scanner.address, r.expected.addresses[0]);
    assert.ok(scanner.changeAddress.startsWith('sp1'));
    assert.notEqual(scanner.changeAddress, scanner.address);
    scanner.free();
  });

  it('uses the testnet HRP on test networks', async () => {
    const r = receiving('Simple send: two inputs');
    const scanner = await scannerFor(r, 'signet');
    assert.ok(scanner.address.startsWith('tsp1'));
    scanner.free();
  });

  it('rejects malformed keys', async () => {
    await assert.rejects(
      () => silentpayments.scanner('00'.repeat(32), '02'.repeat(33)),
      /zero|invalid/,
    );
    await assert.rejects(
      () => silentpayments.scanner('11'.repeat(31), '02' + '11'.repeat(32)),
      /32 bytes/,
    );
  });

  it('free() is idempotent', async () => {
    const r = receiving('Simple send: two inputs');
    const scanner = await scannerFor(r);
    scanner.free();
    assert.doesNotThrow(() => scanner.free());
  });
});

describe('silentpayments: output identification (official vectors)', () => {
  it('identifies a simple base payment with the exact tweak', async () => {
    const r = receiving('Simple send: two inputs');
    const scanner = await scannerFor(r);

    const found = await silentpayments.scanOutputs(
      scanner, r.expected.tweak, r.given.outputs,
    );
    assert.equal(found.length, 1);
    assert.equal(found[0].label, 'base');
    assert.equal(found[0].k, 0);
    assert.equal(
      toHex(found[0].xOnlyPubKey), r.expected.outputs[0].pub_key,
    );
    assert.equal(
      toHex(found[0].privKeyTweak),
      r.expected.outputs[0].priv_key_tweak,
    );
    scanner.free();
  });

  it('walks output index k for multiple outputs to one recipient',
    async () => {
      const r = receiving(
        'Multiple outputs: multiple outputs, same recipient',
      );
      const scanner = await scannerFor(r);

      const found = await silentpayments.scanOutputs(
        scanner, r.expected.tweak, r.given.outputs,
      );
      assert.equal(found.length, 2);
      assert.deepEqual(
        found.map((f) => f.k).sort(), [0, 1],
      );

      // Every expected output must be found with its exact tweak.
      for (const expected of r.expected.outputs) {
        const match = found.find(
          (f) => toHex(f.xOnlyPubKey) === expected.pub_key,
        );
        assert.ok(match, `missing output ${expected.pub_key}`);
        assert.equal(
          toHex(match.privKeyTweak), expected.priv_key_tweak,
        );
      }
      scanner.free();
    });

  it('detects change outputs via the m=0 label', async () => {
    // The change side of the "sender change" vector tracks label 0 —
    // exactly the change label every scanner tracks implicitly.
    const r = receiving(
      'Single recipient: use silent payments for sender change',
    );
    assert.deepEqual(r.given.labels, [0]);
    const scanner = await scannerFor(r);

    const found = await silentpayments.scanOutputs(
      scanner, r.expected.tweak, r.given.outputs,
    );
    assert.equal(found.length, 1);
    assert.equal(found[0].label, 'change');
    assert.equal(
      toHex(found[0].xOnlyPubKey), r.expected.outputs[0].pub_key,
    );
    assert.equal(
      toHex(found[0].privKeyTweak),
      r.expected.outputs[0].priv_key_tweak,
    );
    scanner.free();
  });

  it('the payment side of the same transaction sees only its output',
    async () => {
      const r = receiving(
        'Single recipient: use silent payments for sender change', 1,
      );
      assert.deepEqual(r.given.labels, []);
      const scanner = await scannerFor(r);

      const found = await silentpayments.scanOutputs(
        scanner, r.expected.tweak, r.given.outputs,
      );
      assert.equal(found.length, 1);
      assert.equal(found[0].label, 'base');
      assert.equal(
        toHex(found[0].xOnlyPubKey), r.expected.outputs[0].pub_key,
      );
      scanner.free();
    });

  it('does not identify outputs of labels it does not track', async () => {
    // This vector pays a labeled address (m=2); a base+change scanner
    // must not claim it.
    const r = receiving('Receiving with labels: label with even parity');
    const scanner = await scannerFor(r);

    const found = await silentpayments.scanOutputs(
      scanner, r.expected.tweak, r.given.outputs,
    );
    assert.equal(found.length, 0);
    scanner.free();
  });
});

const fromHex = (hex) => Uint8Array.from(
  hex.match(/../g) ?? [], (b) => parseInt(b, 16),
);

// Serialize block-dn's binary SP tweak format: the 18-byte self-describing
// header (network magic LE, version, file type 2, start height LE, dust
// limit LE), then per block a compact-size count plus the concatenated
// 33-byte tweak keys. `blocks` is an array of arrays of 33-byte
// Uint8Arrays; all test counts are < 253, so the compact size is one byte.
const MAINNET_MAGIC = 0xd9b4bef9;

function spTweakFile(startHeight, dustLimit, blocks, {
  magic = MAINNET_MAGIC, version = 0, fileType = 2,
} = {}) {
  const body = blocks.flatMap((tweaks) => [
    Uint8Array.of(tweaks.length), ...tweaks,
  ]);
  const size = 18 + body.reduce((n, part) => n + part.length, 0);
  const file = new Uint8Array(size);
  const view = new DataView(file.buffer);
  view.setUint32(0, magic, true);
  file[4] = version;
  file[5] = fileType;
  view.setUint32(6, startHeight, true);
  view.setBigUint64(10, BigInt(dustLimit), true);
  let offset = 18;
  for (const part of body) {
    file.set(part, offset);
    offset += part.length;
  }
  return file;
}

describe('silentpayments: batch scanning', () => {
  // Build a synthetic one-block batch around a vector: an 80-byte header
  // stands in for the block, a real GCS filter (BIP158 parameters, key
  // derived from the header hash) contains the expected output script, and
  // the filter header chain is computed exactly like block-dn does.
  async function syntheticBatch(r, extraScripts = []) {
    const lib = await init();
    const header = new Uint8Array(80).fill(0x42);
    const blockHash = lib.chainhash.doubleHash(header);

    const script = (xOnlyHex) => '5120' + xOnlyHex;
    const items = [
      ...r.expected.outputs.map((o) => script(o.pub_key)),
      ...extraScripts,
    ];
    const built = lib.gcs.buildFilter(
      19, 784931, blockHash.subarray(0, 16), items,
    );

    // NBytes framing: varint(N) || filter (N < 253 here), then the
    // var-bytes file framing around it.
    assert.ok(built.n < 253);
    const nBytes = new Uint8Array(1 + built.filter.length);
    nBytes[0] = built.n;
    nBytes.set(built.filter, 1);
    const filterFile = new Uint8Array(1 + nBytes.length);
    filterFile[0] = nBytes.length;
    filterFile.set(nBytes, 1);

    // filterHeader = dsha(dsha(nBytes) || prev), prev = zero hash.
    const filterHash = lib.chainhash.doubleHash(nBytes);
    const prev = new Uint8Array(32);
    const concat = new Uint8Array(64);
    concat.set(filterHash, 0);
    concat.set(prev, 32);
    const filterHeader = lib.chainhash.doubleHash(concat);

    const tweaks = spTweakFile(5000, 0, [[fromHex(r.expected.tweak)]]);

    return { header, filterFile, filterHeader, tweaks };
  }

  it('matches a block whose filter contains the payment', async () => {
    const r = receiving('Simple send: two inputs');
    const scanner = await scannerFor(r);
    const batch = await syntheticBatch(r);

    const result = await silentpayments.scanBatch(
      scanner, 5000, batch.tweaks, batch.filterFile, batch.header,
      batch.filterHeader, '', 0,
    );
    assert.equal(result.matches.length, 1);
    assert.equal(result.matches[0].height, 5000);
    assert.equal(result.skippedTweaks, 0);

    // The match carries the block's tweak keys for the block scan.
    assert.equal(toHex(result.matches[0].tweaks), r.expected.tweak);

    // The pass reports where its time went; the synthetic batch holds
    // exactly one tweak.
    assert.equal(result.timings.tweaks, 1);
    for (const phase of ['parseMs', 'deriveMs', 'verifyMs', 'matchMs']) {
      assert.equal(typeof result.timings[phase], 'number');
      assert.ok(result.timings[phase] >= 0, `${phase} negative`);
    }
    scanner.free();
  });

  it('does not match foreign filters', async () => {
    const r = receiving('Simple send: two inputs');
    const other = receiving(
      'Receiving with labels: label with even parity',
    );
    const scanner = await scannerFor(r);

    const batch = await syntheticBatch(other);
    const result = await silentpayments.scanBatch(
      scanner, 5000, batch.tweaks, batch.filterFile, batch.header,
      batch.filterHeader, '', 0,
    );
    assert.equal(result.matches.length, 0);
    assert.equal(result.skippedTweaks, 0);
    scanner.free();
  });

  it('skips invalid tweak entries instead of aborting', async () => {
    // A tweak key that is not a valid curve point can never be a real
    // payment (e.g. the all-zero point an older indexer emitted for an
    // input-pubkey sum at the point at infinity) — the scan must skip
    // and count such entries, not fail.
    const r = receiving('Simple send: two inputs');
    const scanner = await scannerFor(r);
    const batch = await syntheticBatch(r);

    batch.tweaks = spTweakFile(5000, 0, [[
      fromHex(r.expected.tweak),
      fromHex('02' + '00'.repeat(32)), // x = 0 is not on the curve
      fromHex('03' + '00'.repeat(32)),
    ]]);

    const result = await silentpayments.scanBatch(
      scanner, 5000, batch.tweaks, batch.filterFile,
      batch.header, batch.filterHeader, '', 0,
    );

    // The valid tweak still matches; the two bad ones are counted.
    assert.equal(result.matches.length, 1);
    assert.equal(result.skippedTweaks, 2);
    scanner.free();
  });

  it('rejects a corrupted filter file', async () => {
    const r = receiving('Simple send: two inputs');
    const scanner = await scannerFor(r);
    const batch = await syntheticBatch(r);
    batch.filterFile[2] ^= 0x01;

    await assert.rejects(
      () => silentpayments.scanBatch(
        scanner, 5000, batch.tweaks, batch.filterFile, batch.header,
        batch.filterHeader, '', 0,
      ),
      /committed filter header/,
    );
    scanner.free();
  });

  it('validates the self-describing tweak file header', async () => {
    const r = receiving('Simple send: two inputs');
    const scanner = await scannerFor(r);
    const batch = await syntheticBatch(r);
    const blocks = [[fromHex(r.expected.tweak)]];

    const cases = [
      // Start height mismatch (requesting 6000 for a 5000 file).
      [6000, 0, spTweakFile(5000, 0, blocks), /starts at 5000/],
      // Dust limit mismatch (requesting 0, file filtered at 600).
      [5000, 0, spTweakFile(5000, 600, blocks), /dust limit 600/],
      // Foreign network (signet magic on a mainnet scanner).
      [5000, 0, spTweakFile(5000, 0, blocks, { magic: 0x40cf030a }),
        /network magic/],
      // Unknown future format version.
      [5000, 0, spTweakFile(5000, 0, blocks, { version: 1 }),
        /format version 1/],
      // Wrong file type (1 is a filter file, not SP tweak data).
      [5000, 0, spTweakFile(5000, 0, blocks, { fileType: 1 }),
        /file type 1/],
      // Truncated header.
      [5000, 0, spTweakFile(5000, 0, blocks).subarray(0, 17),
        /too short/],
    ];
    for (const [height, dust, tweaks, want] of cases) {
      await assert.rejects(
        () => silentpayments.scanBatch(
          scanner, height, tweaks, batch.filterFile, batch.header,
          batch.filterHeader, '', dust,
        ),
        want,
      );
    }

    // A tweak count pointing past the end of the file must not crash.
    const truncated = spTweakFile(5000, 0, blocks);
    truncated[18] = 200; // claims 200 keys, only 1 present
    await assert.rejects(
      () => silentpayments.scanBatch(
        scanner, 5000, truncated, batch.filterFile, batch.header,
        batch.filterHeader, '', 0,
      ),
      /exceeds remaining data/,
    );
    scanner.free();
  });
});

describe('silentpayments: block scanning (pooled identification)', () => {
  // Hand-craft a minimal 2-transaction block: a coinbase with a
  // non-taproot output, and a payment transaction whose taproot outputs
  // are the vector's expected silent payment outputs. The binary tweak
  // format carries no transaction indexes, so identification must pair
  // the tweak with the right transaction by output key alone.
  function syntheticBlock(r) {
    const le32 = (n) => {
      const b = new Uint8Array(4);
      new DataView(b.buffer).setUint32(0, n, true);
      return b;
    };
    const le64 = (n) => {
      const b = new Uint8Array(8);
      new DataView(b.buffer).setBigUint64(0, BigInt(n), true);
      return b;
    };
    const concat = (...parts) => {
      const size = parts.reduce((n, p) => n + p.length, 0);
      const out = new Uint8Array(size);
      let offset = 0;
      for (const p of parts) {
        out.set(p, offset);
        offset += p.length;
      }
      return out;
    };

    const coinbase = concat(
      le32(1),                          // version
      Uint8Array.of(1),                 // one input
      new Uint8Array(32),               // null prevout hash
      fromHex('ffffffff'),              // null prevout index
      Uint8Array.of(1, 0x51),           // scriptSig: OP_TRUE
      fromHex('ffffffff'),              // sequence
      Uint8Array.of(1),                 // one output
      le64(5_000_000_000),              // 50 BTC
      Uint8Array.of(1, 0x51),           // non-taproot script
      le32(0),                          // locktime
    );

    const value = 12_345;
    const payment = concat(
      le32(2),                          // version
      Uint8Array.of(1),                 // one input
      new Uint8Array(32).fill(0x11),    // prevout hash
      le32(0),                          // prevout index
      Uint8Array.of(0),                 // empty scriptSig
      fromHex('ffffffff'),              // sequence
      Uint8Array.of(r.expected.outputs.length),
      ...r.expected.outputs.flatMap((o) => [
        le64(value),
        Uint8Array.of(0x22),            // 34-byte script
        fromHex('5120' + o.pub_key),    // P2TR
      ]),
      le32(0),                          // locktime
    );

    const block = concat(
      new Uint8Array(80).fill(0x42),    // header
      Uint8Array.of(2),                 // two transactions
      coinbase,
      payment,
    );
    return { block, payment, value };
  }

  it('identifies the vector payment in a full block', async () => {
    const r = receiving('Simple send: two inputs');
    const scanner = await scannerFor(r);
    const { block, payment, value } = syntheticBlock(r);

    const found = await silentpayments.scanBlock(
      scanner, block, fromHex(r.expected.tweak),
    );
    assert.equal(found.length, 1);
    assert.equal(found[0].vout, 0);
    assert.equal(found[0].value, value);
    assert.equal(found[0].label, 'base');
    assert.equal(found[0].k, 0);
    assert.equal(toHex(found[0].xOnlyPubKey), r.expected.outputs[0].pub_key);
    assert.equal(
      toHex(found[0].privKeyTweak), r.expected.outputs[0].priv_key_tweak,
    );

    // The txid must point at the payment transaction, not the coinbase.
    const txid = toHex(
      (await chainhash.doubleHash(payment)).slice().reverse(),
    );
    assert.equal(found[0].txid, txid);
    scanner.free();
  });

  it('walks k across multiple outputs in a block context', async () => {
    const r = receiving(
      'Multiple outputs: multiple outputs, same recipient',
    );
    const scanner = await scannerFor(r);
    const { block } = syntheticBlock(r);

    const found = await silentpayments.scanBlock(
      scanner, block, fromHex(r.expected.tweak),
    );
    assert.equal(found.length, r.expected.outputs.length);
    assert.deepEqual(found.map((f) => f.k).sort(), [0, 1]);
    scanner.free();
  });

  it('finds nothing for a foreign tweak and rejects bad input', async () => {
    const r = receiving('Simple send: two inputs');
    const scanner = await scannerFor(r);
    const { block } = syntheticBlock(r);

    // A valid but unrelated tweak point (the generator) matches nothing.
    const found = await silentpayments.scanBlock(
      scanner, block, fromHex('0279be667ef9dcbbac55a06295ce870b07029bfc' +
        'db2dce28d959f2815b16f81798'),
    );
    assert.equal(found.length, 0);

    // Tweak data must be whole 33-byte keys.
    await assert.rejects(
      () => silentpayments.scanBlock(scanner, block, new Uint8Array(34)),
      /multiple of 33/,
    );
    scanner.free();
  });
});


describe('silentpayments: sync API', () => {
  let lib;

  before(async () => {
    lib = await init();
  });

  it('scanner, scanOutputs and scanBatch work synchronously', () => {
    const r = receiving('Simple send: two inputs');
    const spendPub = lib.btcec.pointMultiply(
      r.given.key_material.spend_priv_key,
    ).compressed;
    const scanner = lib.silentpayments.scanner(
      r.given.key_material.scan_priv_key, spendPub, 'mainnet',
    );
    assert.equal(scanner.address, r.expected.addresses[0]);

    const found = lib.silentpayments.scanOutputs(
      scanner, r.expected.tweak, r.given.outputs,
    );
    assert.equal(found.length, 1);
    assert.equal(
      toHex(found[0].privKeyTweak),
      r.expected.outputs[0].priv_key_tweak,
    );
    scanner.free();
  });
});
