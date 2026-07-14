import './setup.mjs';
import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import { init, musig2, btcec } from '../dist/index.js';

describe('musig2: two-round flow', () => {
  let signers;
  let pubs;
  let msg;

  before(async () => {
    const lib = await init();
    signers = [1, 2, 3].map(() => lib.btcec.newPrivateKey());
    pubs = signers.map((s) => lib.btcec.serializeCompressed(s.publicKey));
    msg = lib.chainhash.doubleHash(
      new TextEncoder().encode('musig2 test message'),
    );
  });

  it('key aggregation is order independent (sorted keys)', async () => {
    const agg1 = await musig2.aggregateKeys(pubs);
    const agg2 = await musig2.aggregateKeys([...pubs].reverse());
    assert.deepEqual(agg1.combinedKey, agg2.combinedKey);
    assert.equal(agg1.xOnlyKey.length, 32);
    assert.equal(agg1.combinedKey.length, 33);
    assert.equal(
      agg1.parityOdd, agg1.combinedKey[0] === 0x03,
    );
  });

  it('nonce generation is randomized and well-formed', async () => {
    const n1 = await musig2.genNonces(pubs[0], signers[0].privateKey);
    const n2 = await musig2.genNonces(pubs[0], signers[0].privateKey);
    assert.equal(n1.pubNonce.length, 66);
    assert.equal(n1.secNonce.length, 97);
    assert.notDeepEqual(n1.pubNonce, n2.pubNonce);
  });

  it('full sign flow produces a valid BIP-340 signature', async () => {
    const agg = await musig2.aggregateKeys(pubs);

    // Round 1: everyone generates and shares nonces.
    const nonces = [];
    for (let i = 0; i < signers.length; i++) {
      nonces.push(await musig2.genNonces(
        pubs[i], signers[i].privateKey,
      ));
    }
    const combinedNonce = await musig2.aggregateNonces(
      nonces.map((n) => n.pubNonce),
    );
    assert.equal(combinedNonce.length, 66);

    // Round 2: everyone partial-signs; the final nonce R must come out
    // identically for every signer.
    const partials = [];
    for (let i = 0; i < signers.length; i++) {
      partials.push(await musig2.partialSign(
        nonces[i].secNonce, signers[i].privateKey, combinedNonce,
        pubs, msg,
      ));
    }
    assert.equal(partials[0].s.length, 32);
    assert.equal(partials[0].r.length, 33);
    for (const p of partials.slice(1)) {
      assert.deepEqual(p.r, partials[0].r);
    }

    const finalSig = await musig2.combineSigs(
      partials[0].r, partials.map((p) => p.s),
    );
    assert.equal(finalSig.length, 64);
    assert.equal(
      await btcec.schnorrVerify(agg.xOnlyKey, msg, finalSig), true,
    );

    // Dropping one partial signature must break verification.
    const badSig = await musig2.combineSigs(
      partials[0].r, partials.slice(1).map((p) => p.s),
    );
    assert.equal(
      await btcec.schnorrVerify(agg.xOnlyKey, msg, badSig), false,
    );
  });

  it('rejects malformed inputs', async () => {
    await assert.rejects(() => musig2.aggregateKeys([]), /at least one/);
    await assert.rejects(
      () => musig2.aggregateNonces([new Uint8Array(65)]),
      /66 bytes/,
    );
    await assert.rejects(
      () => musig2.genNonces(new Uint8Array(32)),
      /invalid public key/,
    );
  });
});

describe('musig2: sync API', () => {
  let lib;

  before(async () => {
    lib = await init();
  });

  it('full flow works synchronously', () => {
    const s = [1, 2].map(() => lib.btcec.newPrivateKey());
    const pubs = s.map((k) => lib.btcec.serializeCompressed(k.publicKey));
    const msg = lib.chainhash.doubleHash(new Uint8Array([1, 2, 3]));

    const agg = lib.musig2.aggregateKeys(pubs);
    const nonces = s.map((k, i) =>
      lib.musig2.genNonces(pubs[i], k.privateKey));
    const combined = lib.musig2.aggregateNonces(
      nonces.map((n) => n.pubNonce),
    );
    const partials = s.map((k, i) => lib.musig2.partialSign(
      nonces[i].secNonce, k.privateKey, combined, pubs, msg,
    ));
    const sig = lib.musig2.combineSigs(
      partials[0].r, partials.map((p) => p.s),
    );
    assert.equal(lib.btcec.schnorrVerify(agg.xOnlyKey, msg, sig), true);
  });
});
