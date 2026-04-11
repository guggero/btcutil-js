import './setup.mjs';
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { psbt } from '../dist/index.js';

// A minimal valid PSBT (base64) with 1 unsigned input and 1 output.
// Created by hand-encoding the BIP-174 format:
//   magic "psbt\xff"
//   global: unsigned tx (key 0x00)
//   separator 0x00
//   input section (empty, just separator 0x00)
//   output section (empty, just separator 0x00)
//
// The unsigned tx inside is a minimal 1-in, 1-out transaction:
//   version=2, 1 input (prev=zeros, idx=0, empty scriptsig, seq=ffffffff),
//   1 output (1000 sats, empty scriptPubKey), locktime=0.
//
// We build the raw PSBT bytes as hex, then encode to base64 for tests.

import { Buffer } from 'node:buffer';

// Unsigned tx (no witness): same minimal legacy tx from tx.test.mjs.
const unsignedTxHex =
  '02000000' +
  '01' +
  '0000000000000000000000000000000000000000000000000000000000000000' +
  '00000000' +
  '00' +         // empty scriptSig (length 0)
  'ffffffff' +
  '01' +
  'e803000000000000' +
  '00' +         // empty scriptPubKey
  '00000000';

function buildMinimalPsbt() {
  // PSBT magic: "psbt" + 0xff
  const magic = '70736274ff';

  // Global: key 0x00 = unsigned tx
  const txBytes = unsignedTxHex;
  const keyLen = '01';   // key is 1 byte
  const key = '00';      // PSBT_GLOBAL_UNSIGNED_TX
  const valLen = (txBytes.length / 2).toString(16).padStart(2, '0');
  const globalKv = keyLen + key + valLen + txBytes;
  const globalSep = '00';

  // Input section: empty (just separator)
  const inputSep = '00';

  // Output section: empty (just separator)
  const outputSep = '00';

  return magic + globalKv + globalSep + inputSep + outputSep;
}

const psbtHex = buildMinimalPsbt();
const psbtBase64 = Buffer.from(psbtHex, 'hex').toString('base64');

describe('psbt', () => {
  it('decode returns structured info', async () => {
    const info = await psbt.decode(psbtBase64);
    assert.equal(info.version, 2);
    assert.equal(info.inputCount, 1);
    assert.equal(info.outputCount, 1);
    assert.equal(info.isComplete, false);
    assert.equal(info.inputs.length, 1);
    assert.equal(info.outputs.length, 1);
    assert.equal(info.outputs[0].value, 1000);
    assert.equal(info.inputs[0].previousVout, 0);
    assert.equal(info.inputs[0].hasNonWitnessUtxo, false);
    assert.equal(info.inputs[0].hasFinalScriptSig, false);
    assert.equal(info.inputs[0].hasFinalScriptWitness, false);
  });

  it('isComplete returns false for unsigned PSBT', async () => {
    const complete = await psbt.isComplete(psbtBase64);
    assert.equal(complete, false);
  });

  it('extract fails on incomplete PSBT', async () => {
    await assert.rejects(
      () => psbt.extract(psbtBase64),
      (err) => {
        assert.ok(err.message.includes('extract'));
        return true;
      },
    );
  });

  it('fromBase64 returns hex bytes', async () => {
    const hex = await psbt.fromBase64(psbtBase64);
    assert.equal(typeof hex, 'string');
    assert.ok(hex.length > 0);
    // Should start with the PSBT magic in hex: 70736274ff
    assert.ok(hex.startsWith('70736274ff'));
  });

  it('toBase64 round-trips with fromBase64', async () => {
    const hex = await psbt.fromBase64(psbtBase64);
    const b64 = await psbt.toBase64(hex);
    assert.equal(b64, psbtBase64);
  });

  it('decode rejects invalid base64', async () => {
    await assert.rejects(() => psbt.decode('not-valid-base64!!!'));
  });

  it('decode rejects non-PSBT data', async () => {
    const notPsbt = Buffer.from('deadbeef', 'hex').toString('base64');
    await assert.rejects(() => psbt.decode(notPsbt));
  });

  it('decode rejects empty string', async () => {
    await assert.rejects(() => psbt.decode(''));
  });

  it('toBase64 rejects invalid hex', async () => {
    await assert.rejects(() => psbt.toBase64('xyz'));
  });

  it('toBase64 rejects non-PSBT hex', async () => {
    await assert.rejects(() => psbt.toBase64('deadbeef'));
  });

  it('isComplete rejects invalid input', async () => {
    await assert.rejects(() => psbt.isComplete('not-base64'));
  });

  it('getFee fails when no UTXO info present', async () => {
    // Our minimal PSBT has no witness/non-witness UTXO data on inputs.
    await assert.rejects(() => psbt.getFee(psbtBase64));
  });
});
