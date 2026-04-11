import './setup.mjs';
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { txsort, tx } from '../dist/index.js';
import { toHex } from './util.mjs';


const legacyTxHex =
  '02000000' +
  '01' +
  '0000000000000000000000000000000000000000000000000000000000000000' +
  '00000000' +
  '01' + '00' +
  'ffffffff' +
  '01' +
  'e803000000000000' +
  '00' +
  '00000000';

describe('txsort', () => {
  it('sort returns valid transaction', async () => {
    const sorted = await txsort.sort(legacyTxHex);
    assert.ok(sorted instanceof Uint8Array);
    assert.ok(sorted.length > 0);
    const decoded = await tx.decode(toHex(sorted));
    assert.equal(decoded.inputs.length, 1);
  });

  it('isSorted returns boolean', async () => {
    const result = await txsort.isSorted(legacyTxHex);
    assert.equal(typeof result, 'boolean');
  });

  it('single-input tx is always sorted', async () => {
    const result = await txsort.isSorted(legacyTxHex);
    assert.equal(result, true);
  });

  it('sort rejects invalid hex', async () => {
    await assert.rejects(() => txsort.sort('zzzz'));
  });

  it('isSorted rejects truncated tx', async () => {
    await assert.rejects(() => txsort.isSorted('02000000'));
  });

  it('sort is idempotent', async () => {
    const sorted1 = await txsort.sort(legacyTxHex);
    const sorted2 = await txsort.sort(toHex(sorted1));
    assert.equal(toHex(sorted1), toHex(sorted2));
  });
});
