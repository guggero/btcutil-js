import './setup.mjs';
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { init } from '../dist/index.js';
import { toHex } from './util.mjs';


describe('sync API', () => {
  let lib;

  it('init() returns the sync API object', async () => {
    lib = await init();
    assert.ok(lib);
    assert.equal(typeof lib.base58.encode, 'function');
    assert.equal(typeof lib.address.decode, 'function');
    assert.equal(typeof lib.btcec.newPrivateKey, 'function');
  });

  it('repeated init() returns the same cached object', async () => {
    const lib2 = await init();
    assert.equal(lib, lib2);
  });

  it('base58 encode / decode', () => {
    const encoded = lib.base58.encode('deadbeef');
    assert.ok(encoded.length > 0);
    const decoded = lib.base58.decode(encoded);
    assert.ok(decoded instanceof Uint8Array);
    assert.equal(toHex(decoded), 'deadbeef');
  });

  it('base58 checkEncode / checkDecode', () => {
    const encoded = lib.base58.checkEncode('aabb', 5);
    const { data, version } = lib.base58.checkDecode(encoded);
    assert.ok(data instanceof Uint8Array);
    assert.equal(toHex(data), 'aabb');
    assert.equal(version, 5);
  });

  it('bech32 encodeFromBase256 / decodeToBase256', () => {
    const encoded = lib.bech32.encodeFromBase256('bc', 'aabb');
    const result = lib.bech32.decodeToBase256(encoded);
    assert.equal(result.hrp, 'bc');
    assert.ok(result.data instanceof Uint8Array);
    assert.equal(toHex(result.data), 'aabb');
  });

  it('address decode / fromWitnessPubKeyHash', () => {
    const program = '751e76e8199196d454941c45d1b3a323f1433bd6';
    const addr = lib.address.fromWitnessPubKeyHash(program);
    assert.ok(addr.startsWith('bc1q'));
    const info = lib.address.decode(addr);
    assert.equal(info.type, 'p2wpkh');
    assert.ok(info.witnessProgram instanceof Uint8Array);
    assert.equal(toHex(info.witnessProgram), program);
  });

  it('amount fromBTC / toBTC', () => {
    assert.equal(lib.amount.fromBTC(1.5), 150000000);
    assert.equal(lib.amount.toBTC(50000), 0.0005);
  });

  it('hash hash160', () => {
    const h = lib.hash.hash160('deadbeef');
    assert.ok(h instanceof Uint8Array);
    assert.equal(h.length, 20);
  });

  it('wif encode / decode', () => {
    const privKey = '0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d';
    const encoded = lib.wif.encode(privKey, 'mainnet', true);
    const decoded = lib.wif.decode(encoded);
    assert.ok(decoded.privateKey instanceof Uint8Array);
    assert.equal(toHex(decoded.privateKey), privKey);
  });

  it('hdkeychain full derivation flow', () => {
    const seed = lib.hdkeychain.generateSeed();
    assert.ok(seed instanceof Uint8Array);
    const master = lib.hdkeychain.newMaster(toHex(seed));
    assert.ok(master.startsWith('xprv'));
    const child = lib.hdkeychain.derivePath(master, "m/84'/0'/0'/0/0");
    assert.ok(child.startsWith('xprv'));
    const xpub = lib.hdkeychain.neuter(child);
    assert.ok(xpub.startsWith('xpub'));
    const pubKey = lib.hdkeychain.publicKey(child);
    assert.ok(pubKey instanceof Uint8Array);
    assert.equal(pubKey.length, 33);
  });

  it('bip322 verifyMessage', () => {
    const result = lib.bip322.verifyMessage(
      'test', 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4', 'AA==',
    );
    assert.equal(result.valid, false);
    assert.equal(typeof result.error, 'string');
  });

  it('tx decode / hash', () => {
    const legacyTx =
      '02000000' + '01' +
      '0000000000000000000000000000000000000000000000000000000000000000' +
      '00000000' + '01' + '00' + 'ffffffff' +
      '01' + 'e803000000000000' + '00' + '00000000';
    const txid = lib.tx.hash(legacyTx);
    assert.equal(txid.length, 64); // txid is still a string
    const decoded = lib.tx.decode(legacyTx);
    assert.equal(decoded.version, 2);
    assert.equal(decoded.outputs[0].value, 1000);
  });

  it('txsort sort / isSorted', () => {
    const legacyTx =
      '02000000' + '01' +
      '0000000000000000000000000000000000000000000000000000000000000000' +
      '00000000' + '01' + '00' + 'ffffffff' +
      '01' + 'e803000000000000' + '00' + '00000000';
    assert.equal(lib.txsort.isSorted(legacyTx), true);
    const sorted = lib.txsort.sort(legacyTx);
    assert.ok(sorted instanceof Uint8Array);
    assert.ok(sorted.length > 0);
  });

  it('btcec key generation and ECDSA sign/verify', () => {
    const kp = lib.btcec.newPrivateKey();
    assert.ok(kp.privateKey instanceof Uint8Array);
    assert.ok(kp.publicKey instanceof Uint8Array);
    assert.equal(kp.privateKey.length, 32);
    assert.equal(kp.publicKey.length, 33);
    const msgHash = lib.chainhash.doubleHash('68656c6c6f');
    assert.ok(msgHash instanceof Uint8Array);
    const sig = lib.btcec.ecdsaSign(toHex(kp.privateKey), toHex(msgHash));
    assert.ok(sig instanceof Uint8Array);
    assert.ok(sig.length > 0);
    assert.equal(lib.btcec.ecdsaVerify(toHex(kp.publicKey), toHex(msgHash), toHex(sig)), true);
  });

  it('btcec Schnorr sign/verify', () => {
    const kp = lib.btcec.newPrivateKey();
    const msgHash = lib.chainhash.doubleHash('aa');
    const sig = lib.btcec.schnorrSign(toHex(kp.privateKey), toHex(msgHash));
    assert.ok(sig instanceof Uint8Array);
    assert.equal(sig.length, 64);
    const xOnly = lib.btcec.schnorrSerializePubKey(toHex(kp.publicKey));
    assert.ok(xOnly instanceof Uint8Array);
    assert.equal(lib.btcec.schnorrVerify(toHex(xOnly), toHex(msgHash), toHex(sig)), true);
  });

  it('txscript script analysis and creation', () => {
    const addr = lib.address.fromWitnessPubKeyHash(
      '751e76e8199196d454941c45d1b3a323f1433bd6',
    );
    const script = lib.txscript.payToAddrScript(addr);
    assert.ok(script instanceof Uint8Array);
    assert.equal(lib.txscript.isPayToWitnessPubKeyHash(toHex(script)), true);
    assert.equal(lib.txscript.getScriptClass(toHex(script)), 'witness_v0_keyhash');
  });

  it('txscript taproot key computation', () => {
    const kp = lib.btcec.newPrivateKey();
    const xOnly = lib.btcec.schnorrSerializePubKey(toHex(kp.publicKey));
    const outKey = lib.txscript.computeTaprootKeyNoScript(toHex(xOnly));
    assert.ok(outKey instanceof Uint8Array);
    assert.equal(outKey.length, 32);
  });

  it('chaincfg getParams', () => {
    const params = lib.chaincfg.getParams('mainnet');
    assert.equal(params.name, 'mainnet');
    assert.equal(params.bech32HRPSegwit, 'bc');
  });

  it('chainhash hash / doubleHash / taggedHash', () => {
    const h = lib.chainhash.hash('');
    assert.ok(h instanceof Uint8Array);
    assert.equal(toHex(h), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    const dh = lib.chainhash.doubleHash('');
    assert.notEqual(toHex(dh), toHex(h));
    const tag = Buffer.from('TestTag').toString('hex');
    const msg = Buffer.from('data').toString('hex');
    const th = lib.chainhash.taggedHash(tag, [msg]);
    assert.ok(th instanceof Uint8Array);
    assert.equal(th.length, 32);
  });

  it('gcs buildFilter / match', () => {
    const key = '00112233445566778899aabbccddeeff';
    const result = lib.gcs.buildFilter(20, 1 << 20, key, ['deadbeef', 'cafebabe']);
    assert.equal(result.n, 2);
    assert.ok(result.filter instanceof Uint8Array);
    assert.equal(lib.gcs.match(toHex(result.filter), result.n, 20, 1 << 20, key, 'deadbeef'), true);
    assert.equal(lib.gcs.match(toHex(result.filter), result.n, 20, 1 << 20, key, 'ffffffff'), false);
  });

  it('bloom murmurHash3', () => {
    const h = lib.bloom.murmurHash3(0, 'deadbeef');
    assert.equal(typeof h, 'number');
  });

  it('psbt decode', () => {
    // Minimal PSBT from psbt.test.mjs
    const unsignedTxHex =
      '02000000' + '01' +
      '0000000000000000000000000000000000000000000000000000000000000000' +
      '00000000' + '00' + 'ffffffff' +
      '01' + 'e803000000000000' + '00' + '00000000';
    const magic = '70736274ff';
    const keyLen = '01';
    const key = '00';
    const valLen = (unsignedTxHex.length / 2).toString(16).padStart(2, '0');
    const psbtHex = magic + keyLen + key + valLen + unsignedTxHex + '00' + '00' + '00';
    const psbtBase64 = Buffer.from(psbtHex, 'hex').toString('base64');
    const info = lib.psbt.decode(psbtBase64);
    assert.equal(info.inputCount, 1);
    assert.equal(info.isComplete, false);
  });

  it('sync errors throw synchronously', () => {
    assert.throws(() => lib.base58.encode('zzzz'));
    assert.throws(() => lib.address.decode('not-an-address'));
    assert.throws(() => lib.btcec.pubKeyFromBytes('0000'));
  });
});
