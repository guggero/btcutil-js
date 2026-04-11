import './setup.mjs';
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { amount } from '../dist/index.js';

describe('amount', () => {
  it('fromBTC converts correctly', async () => {
    const sat = await amount.fromBTC(1.5);
    assert.equal(sat, 150000000);
  });

  it('toBTC converts correctly', async () => {
    const btc = await amount.toBTC(50000);
    assert.equal(btc, 0.0005);
  });

  it('fromBTC rejects NaN', async () => {
    await assert.rejects(() => amount.fromBTC(NaN));
  });

  it('format with default unit', async () => {
    const str = await amount.format(100000000);
    assert.ok(str.includes('1'));
    assert.ok(str.includes('BTC'));
  });

  it('format with satoshi unit', async () => {
    const str = await amount.format(12345, 'sat');
    assert.ok(str.includes('12345'));
  });

  it('fromBTC rejects Infinity', async () => {
    await assert.rejects(() => amount.fromBTC(Infinity));
  });

  it('fromBTC of max supply returns correct satoshis', async () => {
    const sat = await amount.fromBTC(21_000_000);
    assert.equal(sat, 2_100_000_000_000_000);
  });

  it('fromBTC handles negative amounts', async () => {
    // btcutil.NewAmount accepts negatives (e.g. for fee deltas).
    const sat = await amount.fromBTC(-0.5);
    assert.equal(sat, -50000000);
  });

  it('toBTC handles zero', async () => {
    const btc = await amount.toBTC(0);
    assert.equal(btc, 0);
  });

  it('format rejects unknown unit', async () => {
    await assert.rejects(() => amount.format(100, 'invalidunit'));
  });
});
