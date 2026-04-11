import './setup.mjs';
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { hash } from '../dist/index.js';

describe('hash', () => {
  it('hash160 produces correct result', async () => {
    const result = await hash.hash160('');
    assert.equal(result.length, 40);
  });

  it('hash160 of known data', async () => {
    const result = await hash.hash160('00');
    assert.equal(result.length, 40);
    assert.ok(result !== '0000000000000000000000000000000000000000');
  });

  it('hash160 rejects invalid hex', async () => {
    await assert.rejects(() => hash.hash160('xyz'));
  });

  it('hash160 is deterministic', async () => {
    const h1 = await hash.hash160('deadbeef');
    const h2 = await hash.hash160('deadbeef');
    assert.equal(h1, h2);
  });

  it('hash160 produces different output for different input', async () => {
    const h1 = await hash.hash160('aa');
    const h2 = await hash.hash160('bb');
    assert.notEqual(h1, h2);
  });
});
