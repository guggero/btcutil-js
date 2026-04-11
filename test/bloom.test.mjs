import './setup.mjs';
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { bloom } from '../dist/index.js';

describe('bloom', () => {
  it('murmurHash3 returns deterministic result', async () => {
    const h1 = await bloom.murmurHash3(0, 'deadbeef');
    const h2 = await bloom.murmurHash3(0, 'deadbeef');
    assert.equal(h1, h2);
    assert.equal(typeof h1, 'number');
  });

  it('different seeds produce different hashes', async () => {
    const h1 = await bloom.murmurHash3(0, 'deadbeef');
    const h2 = await bloom.murmurHash3(1, 'deadbeef');
    assert.notEqual(h1, h2);
  });

  it('rejects invalid hex data', async () => {
    await assert.rejects(() => bloom.murmurHash3(0, 'xyz'));
  });

  it('hashes empty data without error', async () => {
    const h = await bloom.murmurHash3(0, '');
    assert.equal(typeof h, 'number');
  });

  it('different data produces different hashes', async () => {
    const h1 = await bloom.murmurHash3(42, 'aa');
    const h2 = await bloom.murmurHash3(42, 'bb');
    assert.notEqual(h1, h2);
  });
});
