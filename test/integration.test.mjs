import './setup.mjs';
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { hdkeychain, hash, address } from '../dist/index.js';
import { toHex } from './util.mjs';


describe('integration: HD wallet flow', () => {
  it('seed -> master -> derive -> address', async () => {
    const seed = await hdkeychain.generateSeed();
    assert.ok(seed instanceof Uint8Array);
    const master = await hdkeychain.newMaster(toHex(seed));
    const child = await hdkeychain.derivePath(master, "m/84'/0'/0'/0/0");
    const pubKey = await hdkeychain.publicKey(child);
    assert.ok(pubKey instanceof Uint8Array);
    const pkHash = await hash.hash160(toHex(pubKey));
    assert.ok(pkHash instanceof Uint8Array);
    const addr = await address.fromWitnessPubKeyHash(toHex(pkHash));
    assert.ok(addr.startsWith('bc1q'));

    const info = await address.decode(addr);
    assert.equal(info.type, 'p2wpkh');
    assert.equal(toHex(info.witnessProgram), toHex(pkHash));
  });
});
