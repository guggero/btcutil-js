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

describe('tx: encode round-trip', () => {
  it('decode → encode preserves legacy tx bytes', async () => {
    const decoded = await tx.decode(legacyTxHex);
    const encoded = await tx.encode(decoded);
    assert.equal(toHex(encoded), legacyTxHex);
  });

  it('decode → encode preserves segwit tx bytes', async () => {
    const decoded = await tx.decode(segwitTxHex);
    const encoded = await tx.encode(decoded);
    assert.equal(toHex(encoded), segwitTxHex);
  });

  it('encoded tx has the same txid as the original', async () => {
    const decoded = await tx.decode(segwitTxHex);
    const encoded = await tx.encode(decoded);
    const reTxid = await tx.hash(toHex(encoded));
    assert.equal(reTxid, decoded.txid);
  });

  it('decode → encode → decode is idempotent', async () => {
    const d1 = await tx.decode(segwitTxHex);
    const e1 = await tx.encode(d1);
    const d2 = await tx.decode(toHex(e1));
    assert.equal(d2.txid, d1.txid);
    assert.equal(d2.wtxid, d1.wtxid);
    assert.equal(d2.version, d1.version);
    assert.equal(d2.locktime, d1.locktime);
    assert.equal(d2.inputs.length, d1.inputs.length);
    assert.equal(d2.outputs.length, d1.outputs.length);
  });

  it('encode accepts modified fields', async () => {
    const decoded = await tx.decode(legacyTxHex);
    decoded.locktime = 12345;
    const encoded = await tx.encode(decoded);
    const redecoded = await tx.decode(toHex(encoded));
    assert.equal(redecoded.locktime, 12345);
  });

  it('encode accepts a newly constructed tx', async () => {
    const tx1 = {
      version: 2,
      locktime: 0,
      inputs: [{
        txid: '0000000000000000000000000000000000000000000000000000000000000001',
        vout: 0,
        scriptSig: new Uint8Array([0x00]),
        sequence: 0xffffffff,
        witness: [],
      }],
      outputs: [{
        value: 50000,
        scriptPubKey: new Uint8Array([0x00, 0x14,
          0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94,
          0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6,
        ]),
      }],
    };
    const encoded = await tx.encode(tx1);
    assert.ok(encoded instanceof Uint8Array);
    const redecoded = await tx.decode(toHex(encoded));
    assert.equal(redecoded.version, 2);
    assert.equal(redecoded.outputs[0].value, 50000);
  });
});
