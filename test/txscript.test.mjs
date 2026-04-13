import './setup.mjs';
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { txscript, address, btcec, hash } from '../dist/index.js';
import { toHex } from './util.mjs';


// A P2WPKH script: OP_0 <20-byte-hash>
const p2wpkhScript = '0014751e76e8199196d454941c45d1b3a323f1433bd6';
// A P2PKH script: OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG
const p2pkhScript = '76a914751e76e8199196d454941c45d1b3a323f1433bd688ac';
// A P2SH script: OP_HASH160 <20-byte-hash> OP_EQUAL
const p2shScript = 'a91489abcdefabbaabbaabbaabbaabbaabbaabbaabba87';
// OP_RETURN <data>
const nullDataScript = '6a0b68656c6c6f20776f726c64';

describe('txscript: script type checks', () => {
  it('isPayToWitnessPubKeyHash', async () => {
    assert.equal(await txscript.isPayToWitnessPubKeyHash(p2wpkhScript), true);
    assert.equal(await txscript.isPayToWitnessPubKeyHash(p2pkhScript), false);
  });
  it('isPayToPubKeyHash', async () => {
    assert.equal(await txscript.isPayToPubKeyHash(p2pkhScript), true);
    assert.equal(await txscript.isPayToPubKeyHash(p2wpkhScript), false);
  });
  it('isPayToScriptHash', async () => {
    assert.equal(await txscript.isPayToScriptHash(p2shScript), true);
    assert.equal(await txscript.isPayToScriptHash(p2pkhScript), false);
  });
  it('isWitnessProgram', async () => {
    assert.equal(await txscript.isWitnessProgram(p2wpkhScript), true);
    assert.equal(await txscript.isWitnessProgram(p2pkhScript), false);
  });
  it('isNullData', async () => {
    assert.equal(await txscript.isNullData(nullDataScript), true);
    assert.equal(await txscript.isNullData(p2pkhScript), false);
  });
  it('isUnspendable', async () => {
    assert.equal(await txscript.isUnspendable(nullDataScript), true);
    assert.equal(await txscript.isUnspendable(p2pkhScript), false);
  });
  it('isPushOnlyScript on witness program', async () => {
    assert.equal(await txscript.isPushOnlyScript(p2wpkhScript), true);
  });
});

describe('txscript: script analysis', () => {
  it('disasmString', async () => {
    const asm = await txscript.disasmString(p2pkhScript);
    assert.ok(asm.includes('OP_DUP'));
    assert.ok(asm.includes('OP_CHECKSIG'));
  });
  it('getScriptClass', async () => {
    assert.equal(await txscript.getScriptClass(p2wpkhScript), 'witness_v0_keyhash');
    assert.equal(await txscript.getScriptClass(p2pkhScript), 'pubkeyhash');
    assert.equal(await txscript.getScriptClass(p2shScript), 'scripthash');
  });
  it('extractWitnessProgramInfo', async () => {
    const info = await txscript.extractWitnessProgramInfo(p2wpkhScript);
    assert.equal(info.version, 0);
    assert.ok(info.program instanceof Uint8Array);
    assert.equal(toHex(info.program), '751e76e8199196d454941c45d1b3a323f1433bd6');
  });
  it('extractPkScriptAddrs', async () => {
    const result = await txscript.extractPkScriptAddrs(p2wpkhScript);
    assert.equal(result.scriptClass, 'witness_v0_keyhash');
    assert.equal(result.addresses.length, 1);
    assert.equal(result.reqSigs, 1);
    assert.ok(result.addresses[0].startsWith('bc1'));
  });
  it('pushedData', async () => {
    const data = await txscript.pushedData(p2wpkhScript);
    assert.ok(data.length > 0);
    // Each element should be a Uint8Array
    assert.ok(data[0] instanceof Uint8Array);
  });
  it('getSigOpCount', async () => {
    const count = await txscript.getSigOpCount(p2pkhScript);
    assert.equal(count, 1);
  });
  it('parsePkScript', async () => {
    const info = await txscript.parsePkScript(p2wpkhScript);
    assert.equal(info.class, 'witness_v0_keyhash');
    assert.ok(info.address.startsWith('bc1'));
  });
});

describe('txscript: script creation', () => {
  it('payToAddrScript creates correct P2WPKH script', async () => {
    const addr = 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4';
    const script = await txscript.payToAddrScript(addr);
    assert.ok(script instanceof Uint8Array);
    assert.equal(await txscript.isPayToWitnessPubKeyHash(toHex(script)), true);
  });
  it('nullDataScript', async () => {
    const script = await txscript.nullDataScript('deadbeef');
    assert.ok(script instanceof Uint8Array);
    assert.equal(await txscript.isNullData(toHex(script)), true);
  });
  it('payToTaprootScript', async () => {
    const { publicKey } = await btcec.newPrivateKey();
    const xOnly = await btcec.schnorrSerializePubKey(toHex(publicKey));
    const script = await txscript.payToTaprootScript(toHex(xOnly));
    assert.ok(script instanceof Uint8Array);
    assert.equal(await txscript.isPayToTaproot(toHex(script)), true);
  });
});

describe('txscript: taproot', () => {
  it('computeTaprootKeyNoScript', async () => {
    const { publicKey } = await btcec.newPrivateKey();
    const xOnly = await btcec.schnorrSerializePubKey(toHex(publicKey));
    const outputKey = await txscript.computeTaprootKeyNoScript(toHex(xOnly));
    assert.ok(outputKey instanceof Uint8Array);
    assert.equal(outputKey.length, 32); // 32 bytes x-only
  });
  it('computeTaprootOutputKey with script root', async () => {
    const { publicKey } = await btcec.newPrivateKey();
    const xOnly = await btcec.schnorrSerializePubKey(toHex(publicKey));
    const scriptRoot = '0000000000000000000000000000000000000000000000000000000000000000';
    const outputKey = await txscript.computeTaprootOutputKey(toHex(xOnly), scriptRoot);
    assert.ok(outputKey instanceof Uint8Array);
    assert.equal(outputKey.length, 32);
    // With a script root, the output key should differ from key-only
    const keyOnly = await txscript.computeTaprootKeyNoScript(toHex(xOnly));
    assert.notEqual(toHex(outputKey), toHex(keyOnly));
  });
  it('tweakTaprootPrivKey round-trip', async () => {
    const { privateKey, publicKey } = await btcec.newPrivateKey();
    const xOnly = await btcec.schnorrSerializePubKey(toHex(publicKey));
    const outputKey = await txscript.computeTaprootKeyNoScript(toHex(xOnly));
    const tweakedPriv = await txscript.tweakTaprootPrivKey(toHex(privateKey));
    assert.ok(tweakedPriv instanceof Uint8Array);
    // The tweaked privkey's pubkey should match the output key
    const { publicKey: tweakedPub } = await btcec.privKeyFromBytes(toHex(tweakedPriv));
    const tweakedXOnly = await btcec.schnorrSerializePubKey(toHex(tweakedPub));
    assert.equal(toHex(tweakedXOnly), toHex(outputKey));
  });

  // ---------------------------------------------------------------------------
  // Regression: security-review.md H-1 — taproot script-root must be
  // honoured whether passed as a hex string or a Uint8Array. Pre-fix the
  // Uint8Array form silently fell through to "no script root", which would
  // cause loss of funds in a script-path-spend wallet.
  // ---------------------------------------------------------------------------
  it('computeTaprootOutputKey accepts Uint8Array script root', async () => {
    const { publicKey } = await btcec.newPrivateKey();
    const xOnly = await btcec.schnorrSerializePubKey(publicKey);
    const scriptRootHex = 'aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899';
    const scriptRootBytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      scriptRootBytes[i] = parseInt(scriptRootHex.slice(i * 2, i * 2 + 2), 16);
    }
    const fromHex = await txscript.computeTaprootOutputKey(xOnly, scriptRootHex);
    const fromBytes = await txscript.computeTaprootOutputKey(xOnly, scriptRootBytes);
    assert.deepEqual(fromBytes, fromHex);
    // Sanity: with the script root, the output key MUST differ from the
    // key-only tweak (this is what regressed pre-fix).
    const keyOnly = await txscript.computeTaprootKeyNoScript(xOnly);
    assert.notDeepEqual(fromBytes, keyOnly);
  });

  it('tweakTaprootPrivKey accepts Uint8Array script root', async () => {
    const { privateKey } = await btcec.newPrivateKey();
    const scriptRootHex = 'aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899';
    const scriptRootBytes = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      scriptRootBytes[i] = parseInt(scriptRootHex.slice(i * 2, i * 2 + 2), 16);
    }
    const fromHex = await txscript.tweakTaprootPrivKey(privateKey, scriptRootHex);
    const fromBytes = await txscript.tweakTaprootPrivKey(privateKey, scriptRootBytes);
    assert.deepEqual(fromBytes, fromHex);
    const keyOnly = await txscript.tweakTaprootPrivKey(privateKey);
    assert.notDeepEqual(fromBytes, keyOnly);
  });

  it('rawTxInTaprootSignature accepts Uint8Array merkle root', async () => {
    const { privateKey, publicKey } = await btcec.newPrivateKey();
    const xOnly = await btcec.schnorrSerializePubKey(publicKey);
    // Build a real P2TR pkScript so the sighash engine accepts it.
    const outKeyKeyOnly = await txscript.computeTaprootKeyNoScript(xOnly);
    const pkScript = new Uint8Array(34);
    pkScript[0] = 0x51; pkScript[1] = 0x20;
    pkScript.set(outKeyKeyOnly, 2);
    const segwitTxHex =
      '02000000' + '0001' + '01' +
      '0000000000000000000000000000000000000000000000000000000000000000' +
      '00000000' + '00' + 'ffffffff' +
      '01' + 'e803000000000000' + '00' +
      '02' + '04' + 'deadbeef' + '04' + 'cafebabe' +
      '00000000';
    const merkleHex = '5555555555555555555555555555555555555555555555555555555555555555';
    const merkleBytes = new Uint8Array(32).fill(0x55);
    const prevOuts = [{script: pkScript, amount: 0}];
    const sigFromHex = await txscript.rawTxInTaprootSignature(
      segwitTxHex, 0, merkleHex, 0, privateKey, prevOuts,
    );
    const sigFromBytes = await txscript.rawTxInTaprootSignature(
      segwitTxHex, 0, merkleBytes, 0, privateKey, prevOuts,
    );
    assert.deepEqual(sigFromBytes, sigFromHex);
    // And both must differ from the no-merkle-root sig (key path).
    const sigKeyPath = await txscript.rawTxInTaprootSignature(
      segwitTxHex, 0, '', 0, privateKey, prevOuts,
    );
    assert.notDeepEqual(sigFromBytes, sigKeyPath);
  });
  it('assembleTaprootScriptTree', async () => {
    const { publicKey } = await btcec.newPrivateKey();
    const xOnly = await btcec.schnorrSerializePubKey(toHex(publicKey));
    // Two simple OP_TRUE leaves
    const leaves = [
      { script: '51' }, // OP_TRUE
      { script: '52' }, // OP_2
    ];
    const tree = await txscript.assembleTaprootScriptTree(toHex(xOnly), leaves);
    assert.ok(tree.outputKey instanceof Uint8Array);
    assert.equal(tree.outputKey.length, 32);
    assert.ok(tree.merkleRoot instanceof Uint8Array);
    assert.equal(tree.merkleRoot.length, 32);
    assert.equal(tree.leaves.length, 2);
    assert.ok(tree.leaves[0].controlBlock instanceof Uint8Array);
    assert.ok(tree.leaves[0].controlBlock.length > 0);
    assert.ok(tree.leaves[0].leafHash instanceof Uint8Array);
    assert.ok(tree.leaves[0].leafHash.length === 32);
    // Control block should be parseable
    const cb = await txscript.parseControlBlock(toHex(tree.leaves[0].controlBlock));
    assert.ok(cb.internalKey instanceof Uint8Array);
    assert.equal(toHex(cb.internalKey), toHex(xOnly));
  });
});

describe('txscript: negative cases', () => {
  it('disasmString rejects invalid hex', async () => {
    await assert.rejects(() => txscript.disasmString('zzzz'));
  });

  it('getScriptClass returns nonstandard for random bytes', async () => {
    const cls = await txscript.getScriptClass('ff');
    assert.equal(cls, 'nonstandard');
  });

  it('extractWitnessProgramInfo rejects non-witness script', async () => {
    // P2PKH is not a witness program.
    const p2pkh = '76a914751e76e8199196d454941c45d1b3a323f1433bd688ac';
    await assert.rejects(() => txscript.extractWitnessProgramInfo(p2pkh));
  });

  it('payToAddrScript rejects invalid address', async () => {
    await assert.rejects(() => txscript.payToAddrScript('not-an-address'));
  });

  it('payToTaprootScript rejects invalid key', async () => {
    await assert.rejects(() => txscript.payToTaprootScript('0000'));
  });

  it('multiSigScript rejects nRequired > nKeys', async () => {
    const { publicKey } = await btcec.newPrivateKey();
    // Only 1 key but require 2 signatures.
    await assert.rejects(() => txscript.multiSigScript([toHex(publicKey)], 2));
  });

  it('nullDataScript rejects too-large data', async () => {
    // OP_RETURN standard limit is 80 bytes. 81 bytes should fail.
    const tooLarge = 'aa'.repeat(81);
    await assert.rejects(() => txscript.nullDataScript(tooLarge));
  });

  it('parseControlBlock rejects too-short data', async () => {
    await assert.rejects(() => txscript.parseControlBlock('aabb'));
  });

  it('computeTaprootOutputKey rejects invalid key', async () => {
    await assert.rejects(() => txscript.computeTaprootOutputKey('0000'));
  });

  it('calcMultiSigStats rejects non-multisig script', async () => {
    const p2pkh = '76a914751e76e8199196d454941c45d1b3a323f1433bd688ac';
    await assert.rejects(() => txscript.calcMultiSigStats(p2pkh));
  });

  it('computePkScript rejects empty sigScript and witness', async () => {
    await assert.rejects(() => txscript.computePkScript('', []));
  });

  it('parsePkScript rejects empty script', async () => {
    await assert.rejects(() => txscript.parsePkScript(''));
  });
});
