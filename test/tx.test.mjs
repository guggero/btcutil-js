import './setup.mjs';
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { tx } from '../dist/index.js';
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

const segwitTxHex =
  '02000000' +
  '0001' +
  '01' +
  '0000000000000000000000000000000000000000000000000000000000000000' +
  '00000000' +
  '00' +
  'ffffffff' +
  '01' +
  'e803000000000000' +
  '00' +
  '02' +
  '04' + 'deadbeef' +
  '04' + 'cafebabe' +
  '00000000';

describe('tx', () => {
  it('hash returns txid (legacy)', async () => {
    const txid = await tx.hash(legacyTxHex);
    assert.equal(txid.length, 64); // txid is still a display string
  });

  it('hash returns txid (segwit)', async () => {
    const txid = await tx.hash(segwitTxHex);
    assert.equal(txid.length, 64);
  });

  it('witnessHash returns wtxid', async () => {
    const wtxid = await tx.witnessHash(segwitTxHex);
    assert.equal(wtxid.length, 64);
    const txid = await tx.hash(segwitTxHex);
    assert.notEqual(txid, wtxid);
  });

  it('hasWitness detects witness data', async () => {
    assert.equal(await tx.hasWitness(segwitTxHex), true);
    assert.equal(await tx.hasWitness(legacyTxHex), false);
  });

  it('decode returns structured info', async () => {
    const decoded = await tx.decode(segwitTxHex);
    assert.equal(decoded.version, 2);
    assert.equal(decoded.inputs.length, 1);
    assert.equal(decoded.outputs.length, 1);
    assert.equal(decoded.txid.length, 64); // txid is still a string
    assert.equal(decoded.wtxid.length, 64); // wtxid is still a string
    assert.equal(decoded.inputs[0].txid.length, 64);
    assert.equal(typeof decoded.inputs[0].sequence, 'number');
    assert.equal(decoded.outputs[0].value, 1000);
    assert.equal(decoded.inputs[0].witness.length, 2);
    assert.ok(decoded.inputs[0].witness[0] instanceof Uint8Array);
    assert.equal(toHex(decoded.inputs[0].witness[0]), 'deadbeef');
    assert.equal(toHex(decoded.inputs[0].witness[1]), 'cafebabe');
  });

  it('hash rejects invalid hex', async () => {
    await assert.rejects(() => tx.hash('zzzz'));
  });

  it('decode rejects truncated transaction', async () => {
    // Just the version bytes — not enough data for a full tx.
    await assert.rejects(() => tx.decode('02000000'));
  });

  it('decode rejects empty input', async () => {
    await assert.rejects(() => tx.decode(''));
  });

  it('witnessHash rejects invalid hex', async () => {
    await assert.rejects(() => tx.witnessHash('notvalid'));
  });

  it('hasWitness rejects invalid tx', async () => {
    await assert.rejects(() => tx.hasWitness('01'));
  });

  it('txid and wtxid are equal for non-witness tx', async () => {
    const txid = await tx.hash(legacyTxHex);
    const wtxid = await tx.witnessHash(legacyTxHex);
    assert.equal(txid, wtxid);
  });
});
