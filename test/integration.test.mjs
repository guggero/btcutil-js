import './setup.mjs';
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { hdkeychain, hash, address } from '../dist/index.js';

describe('integration: HD wallet flow', () => {
  it('seed -> master -> derive -> address', async () => {
    const seed = await hdkeychain.generateSeed();
    const master = await hdkeychain.newMaster(seed);
    const child = await hdkeychain.derivePath(master, "m/84'/0'/0'/0/0");
    const pubKey = await hdkeychain.publicKey(child);
    const pkHash = await hash.hash160(pubKey);
    const addr = await address.fromWitnessPubKeyHash(pkHash);
    assert.ok(addr.startsWith('bc1q'));

    const info = await address.decode(addr);
    assert.equal(info.type, 'p2wpkh');
    assert.equal(info.witnessProgram, pkHash);
  });
});
