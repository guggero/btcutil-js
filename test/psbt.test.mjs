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
// read-only tests
// ---------------------------------------------------------------------------

describe('psbt: read-only', () => {
  it('decode returns structured info', async () => {
    const info = await psbt.decode(psbtBase64);
    assert.equal(info.unsignedTx.version, 2);
    assert.equal(info.inputs.length, 1);
    assert.equal(info.outputs.length, 1);
    assert.equal(info.isComplete, false);
    assert.equal(info.unsignedTx.outputs[0].value, 1000);
    assert.equal(info.unsignedTx.inputs[0].vout, 0);
    assert.equal(info.inputs[0].nonWitnessUtxo, undefined);
  });

  it('decode returns enhanced per-input fields', async () => {
    const info = await psbt.decode(psbtBase64);
    const inp = info.inputs[0];
    // Optional fields are absent (undefined) on a freshly-built minimal PSBT.
    assert.equal(inp.partialSigs, undefined);
    assert.equal(inp.bip32Derivation, undefined);
    assert.equal(inp.taprootScriptSpendSigs, undefined);
    assert.equal(inp.taprootLeafScripts, undefined);
    assert.equal(inp.taprootBip32Derivation, undefined);
    assert.equal(inp.finalScriptSig, undefined);
    assert.equal(inp.redeemScript, undefined);
    assert.equal(inp.witnessScript, undefined);
    assert.equal(inp.taprootKeySpendSig, undefined);
    assert.equal(inp.taprootInternalKey, undefined);
    assert.equal(inp.taprootMerkleRoot, undefined);
  });

  it('decode returns enhanced per-output fields', async () => {
    const info = await psbt.decode(psbtBase64);
    const out = info.outputs[0];
    assert.equal(out.redeemScript, undefined);
    assert.equal(out.witnessScript, undefined);
    assert.equal(out.bip32Derivation, undefined);
    assert.equal(out.taprootInternalKey, undefined);
    assert.equal(out.taprootTapTree, undefined);
    assert.equal(out.taprootBip32Derivation, undefined);
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
    assert.equal(info.inputs.length, 1);
    assert.equal(info.outputs.length, 1);
    assert.equal(info.unsignedTx.outputs[0].value, 1000);
  });

  it('create with custom version and locktime', async () => {
    const txid = '0000000000000000000000000000000000000000000000000000000000000001';
    const p = await psbt.create(
      [{ txid, vout: 0 }],
      [{ value: 500, script: '6a' }],
      1,   // version
      100, // locktime
    );
    const info = await psbt.decode(p);
    assert.equal(info.unsignedTx.version, 1);
    assert.equal(info.unsignedTx.locktime, 100);
  });

  it('create with custom sequence', async () => {
    const txid = '0000000000000000000000000000000000000000000000000000000000000001';
    const p = await psbt.create(
      [{ txid, vout: 0, sequence: 0xfffffffe }],
      [{ value: 500, script: '6a' }],
    );
    const info = await psbt.decode(p);
    assert.equal(info.unsignedTx.inputs[0].sequence, 0xfffffffe);
  });

  it('fromUnsignedTx creates from raw tx', async () => {
    const p = await psbt.fromUnsignedTx(unsignedTxHex);
    const info = await psbt.decode(p);
    assert.equal(info.inputs.length, 1);
    assert.equal(info.outputs.length, 1);
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
    assert.ok(info.inputs[0].witnessUtxo);
    assert.equal(info.inputs[0].witnessUtxo.value, 50000);
    assert.ok(info.inputs[0].witnessUtxo.script instanceof Uint8Array);
    assert.equal(toHex(info.inputs[0].witnessUtxo.script), pkScript);
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
    // Fingerprint is now an 8-char lowercase hex string.
    assert.equal(info.inputs[0].bip32Derivation[0].masterKeyFingerprint, '12345678');
    assert.deepEqual(info.inputs[0].bip32Derivation[0].path, [44, 0, 0, 0, 0]);
    assert.equal(info.inputs[0].bip32Derivation[0].pathStr, 'm/44/0/0/0/0');
  });

  it('addOutBip32Derivation attaches output derivation', async () => {
    const { publicKey } = await btcec.newPrivateKey();
    const p = await psbt.addOutBip32Derivation(
      base, 0, 0xaabbccdd, [84, 0, 0, 1, 0], publicKey,
    );
    const info = await psbt.decode(p);
    assert.equal(info.outputs[0].bip32Derivation.length, 1);
    assert.equal(info.outputs[0].bip32Derivation[0].masterKeyFingerprint, 'aabbccdd');
  });

  it('inputsReadyToSign fails without UTXO', async () => {
    await assert.rejects(() => psbt.inputsReadyToSign(base));
  });

  it('inputsReadyToSign passes with UTXO', async () => {
    const p = await psbt.addInWitnessUtxo(base, 0, 50000, pkScript);
    await psbt.inputsReadyToSign(p);
  });

  it('sumUtxoInputValues returns sum', async () => {
    const p = await psbt.addInWitnessUtxo(base, 0, 50000, pkScript);
    const sum = await psbt.sumUtxoInputValues(p);
    assert.equal(sum, 50000);
  });

  it('getFee works with UTXO attached', async () => {
    const p = await psbt.addInWitnessUtxo(base, 0, 50000, pkScript);
    const fee = await psbt.getFee(p);
    assert.equal(fee, 50000 - 49000);
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
      [{ value: 1000, script: '6a' }],
    );
    const sorted = await psbt.inPlaceSort(p);
    assert.equal(typeof sorted, 'string');
    const info = await psbt.decode(sorted);
    assert.equal(info.inputs.length, 1);
  });
});

// ---------------------------------------------------------------------------
// signing + finalization (negative cases)
// ---------------------------------------------------------------------------

describe('psbt: finalization', () => {
  it('finalize fails on input without signatures', async () => {
    const txid = '0000000000000000000000000000000000000000000000000000000000000001';
    let p = await psbt.create(
      [{ txid, vout: 0 }],
      [{ value: 1000, script: '6a' }],
    );
    p = await psbt.addInWitnessUtxo(p, 0, 2000, '0014751e76e8199196d454941c45d1b3a323f1433bd6');
    await assert.rejects(() => psbt.finalize(p, 0));
  });

  it('maybeFinalizeAll throws when inputs have no UTXO info', async () => {
    const txid = '0000000000000000000000000000000000000000000000000000000000000001';
    const p = await psbt.create(
      [{ txid, vout: 0 }],
      [{ value: 1000, script: '6a' }],
    );
    await assert.rejects(() => psbt.maybeFinalizeAll(p));
  });

  it('sign rejects invalid signature data', async () => {
    const txid = '0000000000000000000000000000000000000000000000000000000000000001';
    let p = await psbt.create(
      [{ txid, vout: 0 }],
      [{ value: 1000, script: '6a' }],
    );
    p = await psbt.addInWitnessUtxo(p, 0, 2000, '0014751e76e8199196d454941c45d1b3a323f1433bd6');
    await assert.rejects(() => psbt.sign(p, 0, '', '0200'));
  });
});

// ---------------------------------------------------------------------------
// full P2WPKH workflow
// ---------------------------------------------------------------------------

describe('psbt: full P2WPKH workflow', () => {
  it('create, sign, finalize, extract', async () => {
    const kp = await btcec.newPrivateKey();
    const { hash: realHash } = await import('../dist/index.js');
    const h160 = await realHash.hash160(kp.publicKey);
    const addr = await address.fromWitnessPubKeyHash(h160);
    const script = await txscript.payToAddrScript(addr);

    const fakeTxid = '0101010101010101010101010101010101010101010101010101010101010101';
    let p = await psbt.create(
      [{ txid: fakeTxid, vout: 0 }],
      [{ value: 49000, script }],
    );
    p = await psbt.addInWitnessUtxo(p, 0, 50000, script);

    const info = await psbt.decode(p);
    assert.equal(info.inputs[0].witnessUtxo.value, 50000);

    const witness = await txscript.witnessSignature(
      unsignedTxHex, 0, 50000, toHex(script), 1,
      kp.privateKey, true,
    );
    assert.equal(witness.length, 2);

    const sigResult = await psbt.sign(p, 0, witness[0], kp.publicKey);
    assert.equal(sigResult.outcome, 0);
    p = sigResult.psbt;

    const info2 = await psbt.decode(p);
    assert.equal(info2.inputs[0].partialSigs.length, 1);

    p = await psbt.maybeFinalizeAll(p);
    assert.equal(await psbt.isComplete(p), true);

    const rawTx = await psbt.extract(p);
    assert.ok(rawTx instanceof Uint8Array);
    assert.ok(rawTx.length > 0);
  });
});

// ---------------------------------------------------------------------------
// encode round-trip
// ---------------------------------------------------------------------------

describe('psbt: decode includes unsignedTx', () => {
  it('minimal PSBT decode includes unsignedTx field', async () => {
    const info = await psbt.decode(psbtBase64);
    assert.ok(info.unsignedTx);
    assert.equal(info.unsignedTx.version, 2);
    assert.equal(info.unsignedTx.inputs.length, 1);
    assert.equal(info.unsignedTx.outputs.length, 1);
    assert.equal(info.unsignedTx.outputs[0].value, 1000);
  });
});

describe('psbt: encode round-trip', () => {
  it('encode(decode(psbt)) preserves the PSBT', async () => {
    const decoded = await psbt.decode(psbtBase64);
    const encoded = await psbt.encode(decoded);
    assert.equal(encoded, psbtBase64);
  });

  it('encode preserves input/output counts', async () => {
    const txid = '0000000000000000000000000000000000000000000000000000000000000001';
    const pkt = await psbt.create(
      [{ txid, vout: 0 }],
      [{ value: 49000, script: '0014751e76e8199196d454941c45d1b3a323f1433bd6' }],
    );
    const decoded = await psbt.decode(pkt);
    const encoded = await psbt.encode(decoded);
    const redecoded = await psbt.decode(encoded);
    assert.equal(redecoded.inputs.length, decoded.inputs.length);
    assert.equal(redecoded.outputs.length, decoded.outputs.length);
    assert.equal(redecoded.unsignedTx.version, decoded.unsignedTx.version);
    assert.equal(redecoded.unsignedTx.locktime, decoded.unsignedTx.locktime);
  });

  it('encode preserves witness UTXO fields', async () => {
    const txid = '0000000000000000000000000000000000000000000000000000000000000001';
    const pkScript = '0014751e76e8199196d454941c45d1b3a323f1433bd6';
    let pkt = await psbt.create(
      [{ txid, vout: 0 }],
      [{ value: 49000, script: pkScript }],
    );
    pkt = await psbt.addInWitnessUtxo(pkt, 0, 50000, pkScript);

    const decoded = await psbt.decode(pkt);
    const encoded = await psbt.encode(decoded);
    const redecoded = await psbt.decode(encoded);

    assert.equal(redecoded.inputs[0].witnessUtxo.value, 50000);
    assert.equal(toHex(redecoded.inputs[0].witnessUtxo.script), pkScript);
  });

  it('encode preserves sighash type', async () => {
    const txid = '0000000000000000000000000000000000000000000000000000000000000001';
    const pkScript = '0014751e76e8199196d454941c45d1b3a323f1433bd6';
    let pkt = await psbt.create(
      [{ txid, vout: 0 }],
      [{ value: 49000, script: pkScript }],
    );
    pkt = await psbt.addInWitnessUtxo(pkt, 0, 50000, pkScript);
    pkt = await psbt.addInSighashType(pkt, 0, 1);

    const decoded = await psbt.decode(pkt);
    const encoded = await psbt.encode(decoded);
    const redecoded = await psbt.decode(encoded);

    assert.equal(redecoded.inputs[0].sighashType, 1);
  });

  it('encode preserves BIP-32 derivation', async () => {
    const txid = '0000000000000000000000000000000000000000000000000000000000000001';
    const pkScript = '0014751e76e8199196d454941c45d1b3a323f1433bd6';
    let pkt = await psbt.create(
      [{ txid, vout: 0 }],
      [{ value: 49000, script: pkScript }],
    );
    pkt = await psbt.addInWitnessUtxo(pkt, 0, 50000, pkScript);

    const { publicKey } = await btcec.newPrivateKey();
    pkt = await psbt.addInBip32Derivation(
      pkt, 0, 0xdeadbeef, [44, 0, 0, 0, 5], publicKey,
    );

    const decoded = await psbt.decode(pkt);
    const encoded = await psbt.encode(decoded);
    const redecoded = await psbt.decode(encoded);

    const deriv = redecoded.inputs[0].bip32Derivation;
    assert.equal(deriv.length, 1);
    assert.equal(deriv[0].masterKeyFingerprint, 'deadbeef');
    assert.deepEqual(deriv[0].path, [44, 0, 0, 0, 5]);
  });

  it('encode preserves modified locktime', async () => {
    const decoded = await psbt.decode(psbtBase64);
    decoded.unsignedTx.locktime = 500000;
    const encoded = await psbt.encode(decoded);
    const redecoded = await psbt.decode(encoded);
    assert.equal(redecoded.unsignedTx.locktime, 500000);
  });

  it('encode round-trips after partial signing', async () => {
    const kp = await btcec.newPrivateKey();
    const pkHash = await import('../dist/index.js').then(m => m.hash.hash160(kp.publicKey));
    const txid = '0101010101010101010101010101010101010101010101010101010101010101';
    const pkScript = new Uint8Array([0x00, 0x14, ...pkHash]);

    let pkt = await psbt.create(
      [{ txid, vout: 0 }],
      [{ value: 49000, script: pkScript }],
    );
    pkt = await psbt.addInWitnessUtxo(pkt, 0, 50000, pkScript);

    const decoded = await psbt.decode(pkt);
    const encoded = await psbt.encode(decoded);
    assert.equal(encoded, pkt);
  });
});

// ---------------------------------------------------------------------------
// Empty PSBT support (improvement #7)
// ---------------------------------------------------------------------------

describe('psbt: empty PSBT support', () => {
  it('encodes a PSBT with zero inputs and zero outputs', async () => {
    const empty = {
      unsignedTx: { version: 2, locktime: 0, inputs: [], outputs: [] },
      inputs: [],
      outputs: [],
    };
    const encoded = await psbt.encode(empty);
    assert.equal(typeof encoded, 'string');
    assert.ok(encoded.length > 0);
  });
});

// ---------------------------------------------------------------------------
// allUnknowns helper
// ---------------------------------------------------------------------------

describe('psbt: allUnknowns', () => {
  it('returns empty for a PSBT with no unknowns', async () => {
    const all = await psbt.allUnknowns(psbtBase64);
    assert.deepEqual(all, []);
  });
});

// ---------------------------------------------------------------------------
// extended-key helpers (PSBT_GLOBAL_XPUB encoding)
// ---------------------------------------------------------------------------

describe('psbt: extended-key helpers', () => {
  // BIP-32 test-vector master xpub.
  const xpubStr = 'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8';

  it('encodeExtendedKey → 78 bytes; decodeExtendedKey round-trips', async () => {
    const bytes = await psbt.encodeExtendedKey(xpubStr);
    assert.ok(bytes instanceof Uint8Array);
    assert.equal(bytes.length, 78);
    const back = await psbt.decodeExtendedKey(bytes);
    assert.equal(back, xpubStr);
  });

  it('XPubJSON.extendedKey round-trips as base58 xpub string', async () => {
    // Build a PSBT, attach an XPub, round-trip, and verify the xpub
    // comes back as a base58 string (not hex bytes). BIP-174 requires
    // path-length == xpub depth, so we use the depth-0 master with an
    // empty path.
    const txid = '0000000000000000000000000000000000000000000000000000000000000001';
    const pkt = await psbt.create(
      [{txid, vout: 0}],
      [{value: 1000, script: '6a'}],
    );
    const decoded = await psbt.decode(pkt);
    decoded.xpubs = [{
      extendedKey: xpubStr,
      masterKeyFingerprint: 'deadbeef',
      path: [],
    }];
    const reencoded = await psbt.encode(decoded);
    const redecoded = await psbt.decode(reencoded);
    assert.equal(redecoded.xpubs.length, 1);
    assert.equal(redecoded.xpubs[0].extendedKey, xpubStr);
    assert.equal(redecoded.xpubs[0].masterKeyFingerprint, 'deadbeef');
    assert.deepEqual(redecoded.xpubs[0].path, []);
  });
});
