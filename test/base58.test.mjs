import './setup.mjs';
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { base58 } from '../dist/index.js';
import { toHex } from './util.mjs';


describe('base58', () => {
  it('encode / decode round-trip', async () => {
    const hex = '0488ade4';
    const encoded = await base58.encode(hex);
    assert.ok(encoded.length > 0);
    const decoded = await base58.decode(encoded);
    assert.ok(decoded instanceof Uint8Array);
    assert.equal(toHex(decoded), hex);
  });

  it('checkEncode / checkDecode round-trip', async () => {
    const hex = '0014751e76e8199196d454941c45d1b3a323f1433bd6';
    const version = 5;
    const encoded = await base58.checkEncode(hex, version);
    assert.ok(encoded.length > 0);
    const { data, version: v } = await base58.checkDecode(encoded);
    assert.ok(data instanceof Uint8Array);
    assert.equal(toHex(data), hex);
    assert.equal(v, version);
  });

  it('checkDecode rejects invalid checksum', async () => {
    await assert.rejects(() => base58.checkDecode('1badchecksum'));
  });

  it('encode rejects invalid hex', async () => {
    await assert.rejects(() => base58.encode('zzzz'));
  });

  it('encode of empty hex returns empty string', async () => {
    const encoded = await base58.encode('');
    assert.equal(encoded, '');
  });

  it('decode of empty string returns empty bytes', async () => {
    const decoded = await base58.decode('');
    assert.ok(decoded instanceof Uint8Array);
    assert.equal(decoded.length, 0);
  });

  it('checkDecode rejects too-short input', async () => {
    // Base58check needs at least 5 bytes (1 version + 4 checksum).
    await assert.rejects(() => base58.checkDecode('1'));
  });

  it('checkEncode rejects invalid hex', async () => {
    await assert.rejects(() => base58.checkEncode('not-hex', 0));
  });
});
