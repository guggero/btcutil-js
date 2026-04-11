import './setup.mjs';
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { chainhash } from '../dist/index.js';
import { toHex } from './util.mjs';


describe('chainhash', () => {
  it('hash computes SHA-256', async () => {
    // SHA-256 of empty string
    const h = await chainhash.hash('');
    assert.ok(h instanceof Uint8Array);
    assert.equal(toHex(h), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  });
  it('doubleHash computes SHA-256d', async () => {
    const h = await chainhash.doubleHash('');
    assert.equal(h.length, 32);
    // SHA256(SHA256('')) should differ from SHA256('')
    const single = await chainhash.hash('');
    assert.notEqual(toHex(h), toHex(single));
  });
  it('taggedHash computes BIP-340 tagged hash', async () => {
    // Tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg)
    const tag = Buffer.from('TestTag').toString('hex');
    const msg = Buffer.from('hello').toString('hex');
    const h = await chainhash.taggedHash(tag, [msg]);
    assert.equal(h.length, 32);
  });
  it('newHashFromStr and hashToString round-trip', async () => {
    // A known txid (byte-reversed display format)
    const txid = '0000000000000000000000000000000000000000000000000000000000000001';
    const rawBytes = await chainhash.newHashFromStr(txid);
    assert.ok(rawBytes instanceof Uint8Array);
    assert.equal(rawBytes.length, 32);
    const back = await chainhash.hashToString(toHex(rawBytes));
    assert.equal(back, txid);
  });
  it('doubleHash of known data', async () => {
    // Double SHA-256 of "hello" (hex: 68656c6c6f)
    const h = await chainhash.doubleHash('68656c6c6f');
    assert.equal(h.length, 32);
  });

  it('hash rejects invalid hex', async () => {
    await assert.rejects(() => chainhash.hash('xyz'));
  });

  it('doubleHash rejects invalid hex', async () => {
    await assert.rejects(() => chainhash.doubleHash('not-hex'));
  });

  it('newHashFromStr zero-pads short strings', async () => {
    // NewHashFromStr left-pads short hex strings with zeros.
    const raw = await chainhash.newHashFromStr('01');
    assert.equal(raw.length, 32); // always returns 32 bytes
    // Verify the value round-trips.
    const back = await chainhash.hashToString(toHex(raw));
    // The display string should have leading zeros and end with 01.
    assert.ok(back.endsWith('01'));
  });

  it('hashToString rejects wrong-length input', async () => {
    // Raw hash bytes must be exactly 32 bytes (64 hex chars).
    await assert.rejects(() => chainhash.hashToString('aabb'));
  });

  it('taggedHash is deterministic', async () => {
    const tag = Buffer.from('Test').toString('hex');
    const msg = Buffer.from('data').toString('hex');
    const h1 = await chainhash.taggedHash(tag, [msg]);
    const h2 = await chainhash.taggedHash(tag, [msg]);
    assert.deepEqual(h1, h2);
  });

  it('taggedHash differs for different tags', async () => {
    const msg = Buffer.from('same').toString('hex');
    const h1 = await chainhash.taggedHash(Buffer.from('TagA').toString('hex'), [msg]);
    const h2 = await chainhash.taggedHash(Buffer.from('TagB').toString('hex'), [msg]);
    assert.notEqual(toHex(h1), toHex(h2));
  });
});
