import './setup.mjs';
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { hdkeychain } from '../dist/index.js';
import { toHex } from './util.mjs';


describe('hdkeychain', () => {
  const testSeed = '000102030405060708090a0b0c0d0e0f';

  it('newMaster creates valid xprv', async () => {
    const xprv = await hdkeychain.newMaster(testSeed);
    assert.ok(xprv.startsWith('xprv'));
  });

  it('fromString returns correct info', async () => {
    const xprv = await hdkeychain.newMaster(testSeed);
    const info = await hdkeychain.fromString(xprv);
    assert.equal(info.isPrivate, true);
    assert.equal(info.depth, 0);
    assert.equal(info.childIndex, 0);
    assert.ok(info.publicKey instanceof Uint8Array);
    assert.ok(info.publicKey.length === 33);
  });

  it('derive produces child key', async () => {
    const xprv = await hdkeychain.newMaster(testSeed);
    const child = await hdkeychain.derive(xprv, 0);
    assert.ok(child.startsWith('xprv'));
    assert.notEqual(child, xprv);
  });

  it('deriveHardened produces hardened child', async () => {
    const xprv = await hdkeychain.newMaster(testSeed);
    const child = await hdkeychain.deriveHardened(xprv, 44);
    assert.ok(child.startsWith('xprv'));
  });

  it('derivePath with BIP-44 path', async () => {
    const xprv = await hdkeychain.newMaster(testSeed);
    const child = await hdkeychain.derivePath(xprv, "m/44'/0'/0'/0/0");
    assert.ok(child.startsWith('xprv'));

    let key = xprv;
    key = await hdkeychain.deriveHardened(key, 44);
    key = await hdkeychain.deriveHardened(key, 0);
    key = await hdkeychain.deriveHardened(key, 0);
    key = await hdkeychain.derive(key, 0);
    key = await hdkeychain.derive(key, 0);
    assert.equal(child, key);
  });

  it('neuter produces xpub', async () => {
    const xprv = await hdkeychain.newMaster(testSeed);
    const xpub = await hdkeychain.neuter(xprv);
    assert.ok(xpub.startsWith('xpub'));

    const info = await hdkeychain.fromString(xpub);
    assert.equal(info.isPrivate, false);
  });

  it('generateSeed produces random bytes', async () => {
    const seed1 = await hdkeychain.generateSeed();
    const seed2 = await hdkeychain.generateSeed();
    assert.ok(seed1 instanceof Uint8Array);
    assert.equal(seed1.length, 32);
    assert.notEqual(toHex(seed1), toHex(seed2));
  });

  it('publicKey returns compressed key', async () => {
    const xprv = await hdkeychain.newMaster(testSeed);
    const pubKey = await hdkeychain.publicKey(xprv);
    assert.ok(pubKey instanceof Uint8Array);
    assert.equal(pubKey.length, 33);
    assert.ok(pubKey[0] === 0x02 || pubKey[0] === 0x03);
  });

  it('address returns P2PKH address', async () => {
    const xprv = await hdkeychain.newMaster(testSeed);
    const addr = await hdkeychain.address(xprv);
    assert.ok(addr.startsWith('1'));
  });

  it('testnet master key starts with tprv', async () => {
    const tprv = await hdkeychain.newMaster(testSeed, 'testnet');
    assert.ok(tprv.startsWith('tprv'));
  });

  it('newMaster rejects too-short seed', async () => {
    // Minimum seed is 16 bytes (32 hex chars). 8 bytes should fail.
    await assert.rejects(() => hdkeychain.newMaster('0011223344556677'));
  });

  it('newMaster rejects invalid hex', async () => {
    await assert.rejects(() => hdkeychain.newMaster('xyz'));
  });

  it('fromString rejects garbage', async () => {
    await assert.rejects(() => hdkeychain.fromString('not-a-key'));
  });

  it('derive rejects hardened derivation from xpub', async () => {
    const xprv = await hdkeychain.newMaster(testSeed);
    const xpub = await hdkeychain.neuter(xprv);
    await assert.rejects(() => hdkeychain.deriveHardened(xpub, 0));
  });

  // Regression: security-review.md M-4
  it('deriveHardened rejects index >= HardenedKeyStart (no overflow)', async () => {
    const xprv = await hdkeychain.newMaster(testSeed);
    // 2^31 would wrap to non-hardened derivation, silently producing a
    // different key. Must error out instead.
    await assert.rejects(() => hdkeychain.deriveHardened(xprv, 0x80000000));
    await assert.rejects(() => hdkeychain.deriveHardened(xprv, 0xffffffff));
  });

  it('derive rejects hardened indices and negative input', async () => {
    const xprv = await hdkeychain.newMaster(testSeed);
    // Hardened — caller should use deriveHardened.
    await assert.rejects(() => hdkeychain.derive(xprv, 0x80000000));
    // Negative — JS uint32(-1) would silently land on 0xffffffff (hardened).
    await assert.rejects(() => hdkeychain.derive(xprv, -1));
  });

  it('derivePath rejects invalid path component', async () => {
    const xprv = await hdkeychain.newMaster(testSeed);
    await assert.rejects(() => hdkeychain.derivePath(xprv, 'm/abc/0'));
  });

  it('generateSeed rejects too-short length', async () => {
    // Minimum seed length is 16 bytes.
    await assert.rejects(() => hdkeychain.generateSeed(1));
  });

  it('neuter of xpub returns same xpub', async () => {
    const xprv = await hdkeychain.newMaster(testSeed);
    const xpub = await hdkeychain.neuter(xprv);
    const xpub2 = await hdkeychain.neuter(xpub);
    assert.equal(xpub, xpub2);
  });
});
