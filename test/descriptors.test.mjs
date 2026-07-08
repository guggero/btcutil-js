import './setup.mjs';
import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { init, descriptors, Descriptor, Plan } from '../dist/index.js';
import { toHex } from './util.mjs';

// Derivation vectors copied from btcd's descriptors package
// (descriptors/testdata/derivation.json).
const derivationVectors = JSON.parse(readFileSync(
  new URL('test-vectors/descriptors-derivation.json', import.meta.url),
  'utf-8',
));

// Method vectors copied from btcd descriptors/methods_test.go and
// descriptors/plan_test.go.
const testXpub1 =
  "[e81a5744/48'/0'/0'/2']xpub6Duv8Gj9gZeA3sUo5nUMPEv6FZ81GHn3feyaUej5" +
  'KqcjPKsYLww4xBX4MmYZUPX5NqzaVJWYdYZwGLECtgQruG4FkZMh566RkfUT2pbzsEg' +
  '/<0;1>/*';
const testXpub2 =
  "[3c157b79/48'/0'/0'/2']xpub6DdSN9RNZi3eDjhZWA8PJ5mSuWgfmPdBduXWzSP91" +
  'Y3GxKWNwkjyc5mF9FcpTFymUh9C4Bar45b6rWv6Y5kSbi9yJDjuJUDzQSWUh3ijzXP' +
  '/<0;1>/*';
const testTr =
  `tr(${testXpub1},and_v(v:pk(${testXpub2}),older(65535)))#lg9nqqhr`;

// A 64-byte dummy Schnorr signature (matches plan_test.go's testTapLeafSig,
// which is []byte("aaaa...") — 64 ASCII 'a' = 0x61).
const testTapLeafSig = new Uint8Array(64).fill(0x61);

// A valid DER-encoded ECDSA signature with its sighash byte (testEcdsaSigHex).
const testEcdsaSigHex =
  '3045022100e621a7686d51fb23e761adff4367881a6fb16bc5635ff34eea39afdaf' +
  '033e4d702207998512f52bd3dae100951a6df9e66bcb78c194dcaa3c7fd2451180b' +
  '5cc94d4e01';

// ---------------------------------------------------------------------------
// Derivation vectors (async API)
// ---------------------------------------------------------------------------

describe('descriptors: derivation vectors', () => {
  derivationVectors.forEach((v) => {
    it(v.name, async () => {
      // Vectors that must fail to parse (e.g. a bad checksum).
      if (v.expectErr) {
        await assert.rejects(
          () => descriptors.create(v.descriptor),
          (e) => e.message.includes(v.expectErr),
        );
        return;
      }

      const d = await descriptors.create(v.descriptor);
      try {
        assert.equal(d.multipathLen(), v.numMultipath);

        // String() always includes the checksum; the vector supplies it
        // separately when the input had none.
        const expected = v.hasChecksum
          ? v.descriptor
          : v.descriptor + v.checksum;
        assert.equal(d.toString(), expected);

        for (const a of v.addresses ?? []) {
          if (a.expectErr) {
            assert.throws(
              () => d.addressAt(
                a.network, a.multipathIndex, a.derivationIndex,
              ),
              (e) => e.message.includes(a.expectErr),
            );
            continue;
          }

          assert.equal(
            d.addressAt(a.network, a.multipathIndex, a.derivationIndex),
            a.address,
          );
        }
      } finally {
        d.free();
      }
    });
  });
});

// ---------------------------------------------------------------------------
// Individual methods (async API)
// ---------------------------------------------------------------------------

describe('descriptors: methods', () => {
  it('keys() returns the keys in order', async () => {
    const d = await descriptors.create(testTr);
    assert.deepEqual(d.keys(), [testXpub1, testXpub2]);
    d.free();
  });

  it('descType() classifies the output type', async () => {
    const tr = await descriptors.create(testTr);
    assert.equal(tr.descType(), 'Tr');
    tr.free();

    const wpkh = await descriptors.create(
      'wpkh(xpub6BzikmgQmvoYG3ShFhXU1LFKaUeU832dHoYL6ka9JpCqKXr7PTHQHa' +
        'oSMbGU36CZNcoryVPsFBjt9aYyCQHtYi6BQTo6VfRv9xVRuSNNteB)',
    );
    assert.equal(wpkh.descType(), 'Wpkh');
    wpkh.free();
  });

  it('maxWeightToSatisfy() returns the reference bound', async () => {
    const d = await descriptors.create(
      'wpkh(xpub6BzikmgQmvoYG3ShFhXU1LFKaUeU832dHoYL6ka9JpCqKXr7PTHQHa' +
        'oSMbGU36CZNcoryVPsFBjt9aYyCQHtYi6BQTo6VfRv9xVRuSNNteB/*)',
    );
    assert.equal(d.maxWeightToSatisfy(), 107);
    d.free();
  });

  it('maxWeightToSatisfy() throws for an unsatisfiable descriptor',
    async () => {
      const d = await descriptors.create('wsh(0)');
      assert.throws(() => d.maxWeightToSatisfy());
      d.free();
    });

  it('lift() produces the semantic policy tree', async () => {
    const d = await descriptors.create(testTr);
    assert.deepEqual(d.lift(), {
      type: 'thresh',
      threshold: 1,
      policies: [
        { type: 'key', key: testXpub1 },
        {
          type: 'thresh',
          threshold: 2,
          policies: [
            { type: 'key', key: testXpub2 },
            { type: 'older', lockTime: 65535 },
          ],
        },
      ],
    });
    d.free();
  });

  it('scriptCodeAt() returns the P2WSH sorted-multisig script', async () => {
    const d = await descriptors.create(
      `wsh(sortedmulti(2,${testXpub1},${testXpub2}))#jx2cv4q8`,
    );
    const expected =
      '5221020b44e43e2f276697d23c2248f80bb09e84f702ddae399d194f5132f47' +
      '2bf8713210326547ceb5352bd238ca7e1da004e9d6625baf3324feda4ead694' +
      '36042a53510452ae';
    assert.equal(toHex(d.scriptCodeAt(0, 0)), expected);
    d.free();
  });

  it('multipath index out of bounds throws for every index method',
    async () => {
      const d = await descriptors.create(testTr);
      const outOfBounds = 0xffffffff;
      assert.throws(() => d.addressAt('mainnet', outOfBounds, 0));
      assert.throws(() => d.scriptCodeAt(outOfBounds, 0));
      assert.throws(() => d.planAt(outOfBounds, 0, {}));
      d.free();
    });

  it('create() rejects an invalid descriptor', async () => {
    await assert.rejects(() => descriptors.create('not-a-descriptor!!!'));
  });
});

// ---------------------------------------------------------------------------
// Spending plans (async API)
// ---------------------------------------------------------------------------

describe('descriptors: spending plans', () => {
  it('P2WSH single-key plan and satisfaction', async () => {
    const d = await descriptors.create(`wsh(pk(${testXpub1}))`);
    const plan = d.planAt(0, 0, { lookupEcdsaSig: () => true });

    assert.ok(plan instanceof Plan);
    assert.equal(plan.satisfactionWeight, 78);
    assert.equal(plan.scriptSigSize, 1);
    assert.equal(plan.witnessSize, 74);

    const result = plan.satisfy({
      lookupEcdsaSig: () => testEcdsaSigHex,
    });
    assert.equal(result.witness.length, 1);
    assert.equal(toHex(result.witness[0]), testEcdsaSigHex);
    assert.equal(result.scriptSig.length, 0);

    plan.free();
    d.free();
  });

  it('taproot key-path plan and satisfaction', async () => {
    const d = await descriptors.create(testTr);
    const plan = d.planAt(0, 0, { lookupTapKeySpendSig: () => 64 });
    assert.equal(plan.satisfactionWeight, 70);

    const result = plan.satisfy({
      lookupTapKeySpendSig: () => testTapLeafSig,
    });
    assert.deepEqual(result.witness, [testTapLeafSig]);
    assert.equal(result.scriptSig.length, 0);

    plan.free();
    d.free();
  });

  it('taproot leaf-script plan and satisfaction', async () => {
    const d = await descriptors.create(testTr);
    const plan = d.planAt(0, 0, {
      lookupTapLeafScriptSig: () => 64,
      relativeLocktime: 65535,
    });
    assert.equal(plan.satisfactionWeight, 144);
    assert.equal(plan.scriptSigSize, 1);
    assert.equal(plan.witnessSize, 140);

    const result = plan.satisfy({
      lookupTapLeafScriptSig: () => testTapLeafSig,
    });
    const script =
      '200b44e43e2f276697d23c2248f80bb09e84f702ddae399d194f5132f472bf8' +
      '713ad03ffff00b2';
    const controlBlock =
      'c126547ceb5352bd238ca7e1da004e9d6625baf3324feda4ead69436042a535' +
      '104';
    assert.equal(result.witness.length, 3);
    assert.equal(toHex(result.witness[0]), toHex(testTapLeafSig));
    assert.equal(toHex(result.witness[1]), script);
    assert.equal(toHex(result.witness[2]), controlBlock);
    assert.equal(result.scriptSig.length, 0);

    plan.free();
    d.free();
  });

  it('planAt() throws when assets are insufficient', async () => {
    const d = await descriptors.create(testTr);
    // A taproot leaf-script spend needs a relative locktime of at least
    // 65535; without one, no non-malleable plan exists.
    assert.throws(() => d.planAt(0, 0, {
      lookupTapLeafScriptSig: () => 64,
    }));
    d.free();
  });
});

// ---------------------------------------------------------------------------
// Handle lifecycle
// ---------------------------------------------------------------------------

describe('descriptors: handle lifecycle', () => {
  it('free() is idempotent', async () => {
    const d = await descriptors.create(testTr);
    d.free();
    assert.doesNotThrow(() => d.free());
  });

  it('distinct descriptors get independent handles', async () => {
    const a = await descriptors.create(testTr);
    const b = await descriptors.create(testTr);
    // Freeing one must not disturb the other.
    a.free();
    assert.equal(b.descType(), 'Tr');
    assert.equal(b.addressAt('mainnet', 0, 0), b.addressAt('mainnet', 0, 0));
    b.free();
  });
});

// ---------------------------------------------------------------------------
// Sync API (via init())
// ---------------------------------------------------------------------------

describe('descriptors: sync API', () => {
  let lib;

  before(async () => {
    lib = await init();
  });

  it('create() returns a Descriptor synchronously', () => {
    const d = lib.descriptors.create(testTr);
    assert.ok(d instanceof Descriptor);
    d.free();
  });

  it('all read methods work synchronously', () => {
    const d = lib.descriptors.create(
      'wpkh(xpub6BzikmgQmvoYG3ShFhXU1LFKaUeU832dHoYL6ka9JpCqKXr7PTHQHa' +
        'oSMbGU36CZNcoryVPsFBjt9aYyCQHtYi6BQTo6VfRv9xVRuSNNteB/*)',
    );
    assert.equal(d.descType(), 'Wpkh');
    assert.equal(d.multipathLen(), 1);
    assert.equal(
      d.addressAt('mainnet', 0, 0),
      'bc1qaz3jjsgpe29v5yzrvd58hsjgx5a9msujsgmyte',
    );
    assert.equal(d.maxWeightToSatisfy(), 107);
    d.free();
  });

  it('lift() and scriptCodeAt() work synchronously', () => {
    const tr = lib.descriptors.create(testTr);
    assert.equal(tr.lift().type, 'thresh');
    tr.free();

    const wsh = lib.descriptors.create(
      `wsh(sortedmulti(2,${testXpub1},${testXpub2}))#jx2cv4q8`,
    );
    assert.equal(
      toHex(wsh.scriptCodeAt(0, 0)).slice(0, 4),
      '5221',
    );
    wsh.free();
  });

  it('planAt() and satisfy() work synchronously', () => {
    const d = lib.descriptors.create(testTr);
    const plan = d.planAt(0, 0, { lookupTapKeySpendSig: () => 64 });
    assert.equal(plan.satisfactionWeight, 70);
    const result = plan.satisfy({
      lookupTapKeySpendSig: () => testTapLeafSig,
    });
    assert.deepEqual(result.witness, [testTapLeafSig]);
    plan.free();
    d.free();
  });

  it('errors throw synchronously', () => {
    const d = lib.descriptors.create(testTr);
    assert.throws(() => d.addressAt('mainnet', 5, 0));
    d.free();
    assert.throws(() => lib.descriptors.create('not-a-descriptor!!!'));
  });
});
