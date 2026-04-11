import './setup.mjs';
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { hdkeychain } from '../dist/index.js';

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
    assert.ok(info.publicKey.length === 66);
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
    assert.equal(seed1.length, 64);
    assert.notEqual(seed1, seed2);
  });

  it('publicKey returns compressed key', async () => {
    const xprv = await hdkeychain.newMaster(testSeed);
    const pubKey = await hdkeychain.publicKey(xprv);
    assert.equal(pubKey.length, 66);
    assert.ok(pubKey.startsWith('02') || pubKey.startsWith('03'));
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
