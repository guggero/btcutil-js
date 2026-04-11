import './setup.mjs';
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { gcs } from '../dist/index.js';
import { toHex } from './util.mjs';


describe('gcs', () => {
  const p = 20;
  const m = 1 << 20;
  const key = '00112233445566778899aabbccddeeff';

  it('buildFilter and match round-trip', async () => {
    const items = ['deadbeef', 'cafebabe', '01020304'];
    const result = await gcs.buildFilter(p, m, key, items);
    assert.ok(result.filter instanceof Uint8Array);
    assert.ok(result.filter.length > 0);
    assert.equal(result.n, 3);

    const matched = await gcs.match(
      toHex(result.filter), result.n, p, m, key, 'deadbeef',
    );
    assert.equal(matched, true);
  });

  it('match returns false for non-existent item', async () => {
    const items = ['deadbeef', 'cafebabe'];
    const result = await gcs.buildFilter(p, m, key, items);

    const matched = await gcs.match(
      toHex(result.filter), result.n, p, m, key, 'ffffffff',
    );
    assert.equal(matched, false);
  });

  it('matchAny finds existing items', async () => {
    const items = ['deadbeef', 'cafebabe', '01020304'];
    const result = await gcs.buildFilter(p, m, key, items);

    const matched = await gcs.matchAny(
      toHex(result.filter), result.n, p, m, key,
      ['ffffffff', 'cafebabe'],
    );
    assert.equal(matched, true);
  });

  it('matchAny returns false when no match', async () => {
    const items = ['deadbeef', 'cafebabe'];
    const result = await gcs.buildFilter(p, m, key, items);

    const matched = await gcs.matchAny(
      toHex(result.filter), result.n, p, m, key,
      ['ffffffff', 'eeeeeeee'],
    );
    assert.equal(matched, false);
  });

  it('buildFilter rejects wrong key length', async () => {
    // Key must be exactly 16 bytes (32 hex chars).
    await assert.rejects(() => gcs.buildFilter(p, m, 'aabb', ['deadbeef']));
  });

  it('buildFilter rejects invalid hex in data items', async () => {
    await assert.rejects(() => gcs.buildFilter(p, m, key, ['xyz']));
  });

  it('match rejects invalid filter hex', async () => {
    await assert.rejects(() => gcs.match('xyz', 1, p, m, key, 'deadbeef'));
  });

  it('match rejects wrong key length', async () => {
    const items = ['deadbeef'];
    const result = await gcs.buildFilter(p, m, key, items);
    await assert.rejects(() => gcs.match(toHex(result.filter), result.n, p, m, 'short', 'deadbeef'));
  });
});
