import './setup.mjs';
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { bech32 } from '../dist/index.js';

describe('bech32', () => {
  it('encodeFromBase256 / decodeToBase256 round-trip', async () => {
    const hrp = 'bc';
    const hex = 'aabb';
    const encoded = await bech32.encodeFromBase256(hrp, hex);
    assert.ok(encoded.startsWith('bc1'));
    const result = await bech32.decodeToBase256(encoded);
    assert.equal(result.hrp, hrp);
    assert.equal(result.data, hex);
  });

  it('convertBits 8→5→8', async () => {
    const original = 'deadbeef';
    const bits5 = await bech32.convertBits(original, 8, 5, true);
    const back = await bech32.convertBits(bits5, 5, 8, false);
    assert.equal(back, original);
  });

  it('decode rejects invalid bech32', async () => {
    await assert.rejects(() => bech32.decode('not-a-bech32-string'));
  });

  it('decode rejects mixed case', async () => {
    await assert.rejects(() => bech32.decode('BC1Qw508d6qejxtdg4y5r3zarvaryvg6kdaj'));
  });

  it('encode rejects invalid hex data', async () => {
    await assert.rejects(() => bech32.encode('bc', 'zzzz'));
  });

  it('encodeFromBase256 with empty HRP produces valid bech32', async () => {
    // Empty HRP is technically valid in bech32 (unusual but allowed).
    const encoded = await bech32.encodeFromBase256('', 'aabb');
    assert.ok(encoded.includes('1')); // separator still present
  });

  it('convertBits rejects invalid hex', async () => {
    await assert.rejects(() => bech32.convertBits('xyz', 8, 5, true));
  });

  it('decodeToBase256 rejects truncated string', async () => {
    await assert.rejects(() => bech32.decodeToBase256('bc1'));
  });

  it('decode enforces 90-char limit', async () => {
    // A valid-looking but too-long bech32 string should fail decode (not decodeNoLimit).
    const long = 'bc1' + 'q'.repeat(100);
    await assert.rejects(() => bech32.decode(long));
  });
});
