import './setup.mjs';
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { init, hdkeychain, hash, address, btcec, chainhash } from '../dist/index.js';

// These tests mirror the README examples exactly to ensure they stay correct.

describe('integration: async API (README example)', () => {
  it('seed -> master -> derive -> address', async () => {
    // Generate a BIP-84 native SegWit address from a random seed.
    const seed = await hdkeychain.generateSeed();
    const master = await hdkeychain.newMaster(seed);
    const child = await hdkeychain.derivePath(master, "m/84'/0'/0'/0/0");
    const pubKey = await hdkeychain.publicKey(child);
    const pkHash = await hash.hash160(pubKey);
    const addr = await address.fromWitnessPubKeyHash(pkHash);

    assert.ok(addr.startsWith('bc1q'));
    const info = await address.decode(addr);
    assert.equal(info.type, 'p2wpkh');
    assert.deepEqual(info.witnessProgram, pkHash);
  });
});

describe('integration: sync API (README example)', () => {
  it('seed -> address + schnorr sign/verify', async () => {
    const btcutil = await init();

    // Everything below is synchronous — no await needed.
    const seed = btcutil.hdkeychain.generateSeed();
    const master = btcutil.hdkeychain.newMaster(seed);
    const child = btcutil.hdkeychain.derivePath(master, "m/84'/0'/0'/0/0");
    const pubKey = btcutil.hdkeychain.publicKey(child);
    const pkHash = btcutil.hash.hash160(pubKey);
    const addr = btcutil.address.fromWitnessPubKeyHash(pkHash);

    assert.ok(addr.startsWith('bc1q'));

    // Signing is sync too.
    const kp = btcutil.btcec.newPrivateKey();
    const msgHash = btcutil.chainhash.doubleHash(
      new Uint8Array([0x68, 0x65, 0x6c, 0x6c, 0x6f]), // "hello"
    );
    const sig = btcutil.btcec.schnorrSign(kp.privateKey, msgHash);
    const valid = btcutil.btcec.schnorrVerify(
      btcutil.btcec.schnorrSerializePubKey(kp.publicKey), msgHash, sig,
    );

    assert.equal(valid, true);

    // Errors throw synchronously.
    assert.throws(() => btcutil.address.decode('not-an-address'));
  });
});
