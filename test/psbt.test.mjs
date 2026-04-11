import './setup.mjs';
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { psbt, btcec, chainhash, txscript, address } from '../dist/index.js';
import { toHex } from './util.mjs';
import { Buffer } from 'node:buffer';

// ---------------------------------------------------------------------------
// Hand-built minimal PSBT for basic read-only tests
// ---------------------------------------------------------------------------

const unsignedTxHex =
  '02000000' +
  '01' +
  '0000000000000000000000000000000000000000000000000000000000000000' +
  '00000000' +
  '00' +
  'ffffffff' +
  '01' +
  'e803000000000000' +
  '00' +
  '00000000';

function buildMinimalPsbt() {
  const magic = '70736274ff';
  const txBytes = unsignedTxHex;
  const keyLen = '01';
  const key = '00';
  const valLen = (txBytes.length / 2).toString(16).padStart(2, '0');
  const globalKv = keyLen + key + valLen + txBytes;
  return magic + globalKv + '00' + '00' + '00';
}

const psbtHex = buildMinimalPsbt();
const psbtBase64 = Buffer.from(psbtHex, 'hex').toString('base64');

// ---------------------------------------------------------------------------
// read-only tests (existing)
// ---------------------------------------------------------------------------

describe('psbt: read-only', () => {
  it('decode returns structured info', async () => {
    const info = await psbt.decode(psbtBase64);
    assert.equal(info.version, 2);
    assert.equal(info.inputCount, 1);
    assert.equal(info.outputCount, 1);
    assert.equal(info.isComplete, false);
    assert.equal(info.outputs[0].value, 1000);
    assert.equal(info.inputs[0].previousVout, 0);
    assert.equal(info.inputs[0].hasNonWitnessUtxo, false);
  });

  it('decode returns enhanced per-input fields', async () => {
    const info = await psbt.decode(psbtBase64);
    const inp = info.inputs[0];
    assert.ok(Array.isArray(inp.partialSigs));
    assert.equal(inp.partialSigs.length, 0);
    assert.ok(Array.isArray(inp.bip32Derivation));
    assert.ok(Array.isArray(inp.taprootScriptSpendSigs));
    assert.ok(Array.isArray(inp.taprootLeafScripts));
    assert.ok(Array.isArray(inp.taprootBip32Derivation));
    assert.ok(inp.finalScriptSig instanceof Uint8Array);
    assert.ok(inp.redeemScript instanceof Uint8Array);
    assert.ok(inp.witnessScript instanceof Uint8Array);
    assert.ok(inp.taprootKeySpendSig instanceof Uint8Array);
    assert.ok(inp.taprootInternalKey instanceof Uint8Array);
    assert.ok(inp.taprootMerkleRoot instanceof Uint8Array);
  });

  it('decode returns enhanced per-output fields', async () => {
    const info = await psbt.decode(psbtBase64);
    const out = info.outputs[0];
    assert.ok(out.redeemScript instanceof Uint8Array);
    assert.ok(out.witnessScript instanceof Uint8Array);
    assert.ok(Array.isArray(out.bip32Derivation));
    assert.ok(out.taprootInternalKey instanceof Uint8Array);
    assert.ok(out.taprootTapTree instanceof Uint8Array);
    assert.ok(Array.isArray(out.taprootBip32Derivation));
  });

  it('isComplete returns false for unsigned PSBT', async () => {
    assert.equal(await psbt.isComplete(psbtBase64), false);
  });

  it('extract fails on incomplete PSBT', async () => {
    await assert.rejects(() => psbt.extract(psbtBase64));
  });

  it('fromBase64 / toBase64 round-trip', async () => {
    const raw = await psbt.fromBase64(psbtBase64);
    assert.ok(raw instanceof Uint8Array);
    assert.equal(raw[0], 0x70); // 'p'
    const b64 = await psbt.toBase64(raw);
    assert.equal(b64, psbtBase64);
  });

  it('sanityCheck passes on valid PSBT', async () => {
    await psbt.sanityCheck(psbtBase64); // should not throw
  });

  it('decode rejects invalid base64', async () => {
    await assert.rejects(() => psbt.decode('not-valid'));
  });

  it('decode rejects non-PSBT data', async () => {
    await assert.rejects(() => psbt.decode(
      Buffer.from('deadbeef', 'hex').toString('base64'),
    ));
  });

  it('getFee fails when no UTXO info', async () => {
    await assert.rejects(() => psbt.getFee(psbtBase64));
  });
});

// ---------------------------------------------------------------------------
// creation
// ---------------------------------------------------------------------------

describe('psbt: creation', () => {
  it('create from inputs and outputs', async () => {
    const txid = '0000000000000000000000000000000000000000000000000000000000000001';
    const p = await psbt.create(
      [{ txid, vout: 0 }],
      [{ value: 1000, script: '0014751e76e8199196d454941c45d1b3a323f1433bd6' }],
    );
    assert.equal(typeof p, 'string'); // base64
    const info = await psbt.decode(p);
    assert.equal(info.inputCount, 1);
    assert.equal(info.outputCount, 1);
    assert.equal(info.outputs[0].value, 1000);
  });

  it('create with custom version and locktime', async () => {
    const txid = '0000000000000000000000000000000000000000000000000000000000000001';
    const p = await psbt.create(
      [{ txid, vout: 0 }],
      [{ value: 500, script: '' }],
      1,   // version
      100, // locktime
    );
    const info = await psbt.decode(p);
    assert.equal(info.version, 1);
    assert.equal(info.locktime, 100);
  });

  it('create with custom sequence', async () => {
    const txid = '0000000000000000000000000000000000000000000000000000000000000001';
    const p = await psbt.create(
      [{ txid, vout: 0, sequence: 0xfffffffe }],
      [{ value: 500, script: '' }],
    );
    const info = await psbt.decode(p);
    assert.equal(info.inputs[0].sequence, 0xfffffffe);
  });

  it('fromUnsignedTx creates from raw tx', async () => {
    const p = await psbt.fromUnsignedTx(unsignedTxHex);
    const info = await psbt.decode(p);
    assert.equal(info.inputCount, 1);
    assert.equal(info.outputCount, 1);
  });
});

// ---------------------------------------------------------------------------
// updater
// ---------------------------------------------------------------------------

describe('psbt: updater', () => {
  let base;
  const txid = '0000000000000000000000000000000000000000000000000000000000000001';
  const pkScript = '0014751e76e8199196d454941c45d1b3a323f1433bd6';

  it('setup: create a PSBT', async () => {
    base = await psbt.create(
      [{ txid, vout: 0 }],
      [{ value: 49000, script: pkScript }],
    );
  });

  it('addInWitnessUtxo attaches UTXO data', async () => {
    const p = await psbt.addInWitnessUtxo(base, 0, 50000, pkScript);
    const info = await psbt.decode(p);
    assert.equal(info.inputs[0].witnessUtxoValue, 50000);
    assert.ok(info.inputs[0].witnessUtxoScript instanceof Uint8Array);
  });

  it('addInSighashType sets sighash', async () => {
    let p = await psbt.addInWitnessUtxo(base, 0, 50000, pkScript);
    p = await psbt.addInSighashType(p, 0, 1); // SIGHASH_ALL
    const info = await psbt.decode(p);
    assert.equal(info.inputs[0].sighashType, 1);
  });

  it('addInBip32Derivation attaches derivation info', async () => {
    let p = await psbt.addInWitnessUtxo(base, 0, 50000, pkScript);
    const { publicKey } = await btcec.newPrivateKey();
    p = await psbt.addInBip32Derivation(
      p, 0, 0x12345678, [44, 0, 0, 0, 0], publicKey,
    );
    const info = await psbt.decode(p);
    assert.equal(info.inputs[0].bip32Derivation.length, 1);
    assert.equal(info.inputs[0].bip32Derivation[0].masterKeyFingerprint, 0x12345678);
    assert.deepEqual(info.inputs[0].bip32Derivation[0].path, [44, 0, 0, 0, 0]);
  });

  it('addOutBip32Derivation attaches output derivation', async () => {
    const { publicKey } = await btcec.newPrivateKey();
    const p = await psbt.addOutBip32Derivation(
      base, 0, 0xaabbccdd, [84, 0, 0, 1, 0], publicKey,
    );
    const info = await psbt.decode(p);
    assert.equal(info.outputs[0].bip32Derivation.length, 1);
    assert.equal(info.outputs[0].bip32Derivation[0].masterKeyFingerprint, 0xaabbccdd);
  });

  it('inputsReadyToSign fails without UTXO', async () => {
    await assert.rejects(() => psbt.inputsReadyToSign(base));
  });

  it('inputsReadyToSign passes with UTXO', async () => {
    const p = await psbt.addInWitnessUtxo(base, 0, 50000, pkScript);
    await psbt.inputsReadyToSign(p); // should not throw
  });

  it('sumUtxoInputValues returns sum', async () => {
    const p = await psbt.addInWitnessUtxo(base, 0, 50000, pkScript);
    const sum = await psbt.sumUtxoInputValues(p);
    assert.equal(sum, 50000);
  });

  it('getFee works with UTXO attached', async () => {
    const p = await psbt.addInWitnessUtxo(base, 0, 50000, pkScript);
    const fee = await psbt.getFee(p);
    assert.equal(fee, 50000 - 49000); // 1000 sats fee
  });
});

// ---------------------------------------------------------------------------
// sorting
// ---------------------------------------------------------------------------

describe('psbt: sorting', () => {
  it('inPlaceSort returns valid PSBT', async () => {
    const txid = '0000000000000000000000000000000000000000000000000000000000000001';
    const p = await psbt.create(
      [{ txid, vout: 0 }],
      [{ value: 1000, script: '' }],
    );
    const sorted = await psbt.inPlaceSort(p);
    assert.equal(typeof sorted, 'string');
    const info = await psbt.decode(sorted);
    assert.equal(info.inputCount, 1);
  });
});

// ---------------------------------------------------------------------------
// signing + finalization (negative cases — full signing needs real keys)
// ---------------------------------------------------------------------------

describe('psbt: finalization', () => {
  it('finalize fails on input without signatures', async () => {
    const txid = '0000000000000000000000000000000000000000000000000000000000000001';
    let p = await psbt.create(
      [{ txid, vout: 0 }],
      [{ value: 1000, script: '' }],
    );
    p = await psbt.addInWitnessUtxo(p, 0, 2000, '0014751e76e8199196d454941c45d1b3a323f1433bd6');
    await assert.rejects(() => psbt.finalize(p, 0));
  });

  it('maybeFinalizeAll throws when inputs have no UTXO info', async () => {
    const txid = '0000000000000000000000000000000000000000000000000000000000000001';
    const p = await psbt.create(
      [{ txid, vout: 0 }],
      [{ value: 1000, script: '' }],
    );
    await assert.rejects(() => psbt.maybeFinalizeAll(p));
  });

  it('sign rejects invalid signature data', async () => {
    const txid = '0000000000000000000000000000000000000000000000000000000000000001';
    let p = await psbt.create(
      [{ txid, vout: 0 }],
      [{ value: 1000, script: '' }],
    );
    p = await psbt.addInWitnessUtxo(p, 0, 2000, '0014751e76e8199196d454941c45d1b3a323f1433bd6');
    // Empty sig should be rejected.
    await assert.rejects(() => psbt.sign(p, 0, '', '0200'));
  });
});

// ---------------------------------------------------------------------------
// full P2WPKH workflow: create → UTXO → sign → finalize → extract
// ---------------------------------------------------------------------------

describe('psbt: full P2WPKH workflow', () => {
  it('create, sign, finalize, extract', async () => {
    // Generate a key pair.
    const kp = await btcec.newPrivateKey();

    // Derive the P2WPKH address and pkScript.
    const pkHash = await chainhash.hash(toHex(kp.publicKey)); // placeholder
    // Actually use hash160 for the real pkScript.
    const { hash: realHash } = await import('../dist/index.js');
    const h160 = await realHash.hash160(kp.publicKey);
    const addr = await address.fromWitnessPubKeyHash(h160);
    const script = await txscript.payToAddrScript(addr);

    // Create a PSBT spending a fake input to a P2WPKH output.
    const fakeTxid = '0101010101010101010101010101010101010101010101010101010101010101';
    let p = await psbt.create(
      [{ txid: fakeTxid, vout: 0 }],
      [{ value: 49000, script }],
    );

    // Add witness UTXO.
    p = await psbt.addInWitnessUtxo(p, 0, 50000, script);

    // Compute the sighash and sign.
    const info = await psbt.decode(p);
    assert.equal(info.inputs[0].witnessUtxoValue, 50000);

    // Use txscript to compute witness signature (sig + pubkey).
    // We need the raw unsigned tx from the PSBT.
    const rawPsbt = await psbt.fromBase64(p);
    // Re-parse to get the unsigned tx bytes for signing.
    // For P2WPKH, the subscript is the pkScript.
    const witness = await txscript.witnessSignature(
      unsignedTxHex, 0, 50000, toHex(script), 1, // SIGHASH_ALL
      kp.privateKey, true,
    );
    assert.ok(Array.isArray(witness));
    assert.equal(witness.length, 2); // [sig, pubkey]

    // Attach the signature via psbt.sign.
    const sigResult = await psbt.sign(
      p, 0, witness[0], kp.publicKey,
    );
    assert.equal(sigResult.outcome, 0); // SignSuccessful
    p = sigResult.psbt;

    // Verify the partial sig is now in the decoded PSBT.
    const info2 = await psbt.decode(p);
    assert.equal(info2.inputs[0].partialSigs.length, 1);

    // Finalize.
    p = await psbt.maybeFinalizeAll(p);
    assert.equal(await psbt.isComplete(p), true);

    // Extract the final transaction.
    const rawTx = await psbt.extract(p);
    assert.ok(rawTx instanceof Uint8Array);
    assert.ok(rawTx.length > 0);
  });
});
