import './setup.mjs';
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { address } from '../dist/index.js';
import { toHex } from './util.mjs';


describe('address', () => {
  it('decode P2WPKH address', async () => {
    const addr = 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4';
    const info = await address.decode(addr);
    assert.equal(info.type, 'p2wpkh');
    assert.equal(info.address, addr);
    assert.equal(info.witnessVersion, 0);
    assert.ok(info.witnessProgram instanceof Uint8Array);
    assert.ok(info.witnessProgram.length > 0);
  });

  it('decode mainnet P2WPKH address as testnet', async () => {
    const addr = 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4';
    const info = await address.decode(addr, 'signet');
    assert.equal(info.type, 'p2wpkh');
    assert.equal(info.address, addr);
    assert.equal(info.witnessVersion, 0);
    assert.ok(info.witnessProgram.length > 0);
    assert.equal(info.isForNet, false);
  });

  it('decode P2TR address', async () => {
    const program =
      'a60869f0dbcf1dc659c9cecbee090449d6213c565729bbbea5cd88978f6e9392';
    const addr = await address.fromTaproot(program);
    const info = await address.decode(addr);
    assert.equal(info.type, 'p2tr');
    assert.equal(info.witnessVersion, 1);
  });

  it('decode P2PKH address', async () => {
    const addr = '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2';
    const info = await address.decode(addr);
    assert.equal(info.type, 'p2pkh');
    assert.ok(info.hash160 instanceof Uint8Array);
    assert.ok(info.hash160.length === 20);
  });

  it('fromWitnessPubKeyHash round-trip', async () => {
    const program = '751e76e8199196d454941c45d1b3a323f1433bd6';
    const addr = await address.fromWitnessPubKeyHash(program);
    const info = await address.decode(addr);
    assert.equal(info.type, 'p2wpkh');
    assert.equal(toHex(info.witnessProgram), program);
  });

  it('fromTaproot round-trip', async () => {
    const program =
      'a60869f0dbcf1dc659c9cecbee090449d6213c565729bbbea5cd88978f6e9392';
    const addr = await address.fromTaproot(program);
    const info = await address.decode(addr);
    assert.equal(info.type, 'p2tr');
    assert.equal(toHex(info.witnessProgram), program);
  });

  it('fromPubKeyHash creates valid P2PKH', async () => {
    const pkHash = '751e76e8199196d454941c45d1b3a323f1433bd6';
    const addr = await address.fromPubKeyHash(pkHash);
    const info = await address.decode(addr);
    assert.equal(info.type, 'p2pkh');
  });

  it('fromScriptHash creates valid P2SH', async () => {
    const scriptHash = '89abcdefabbaabbaabbaabbaabbaabbaabbaabba';
    const addr = await address.fromScriptHash(scriptHash);
    const info = await address.decode(addr);
    assert.equal(info.type, 'p2sh');
  });

  it('decode rejects invalid address', async () => {
    await assert.rejects(() => address.decode('notanaddress'));
  });

  it('works with testnet network', async () => {
    const program = '751e76e8199196d454941c45d1b3a323f1433bd6';
    const addr = await address.fromWitnessPubKeyHash(program, 'testnet');
    assert.ok(addr.startsWith('tb1'));
  });

  it('decode rejects unknown network', async () => {
    await assert.rejects(() => address.decode('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4', 'fakenet'));
  });

  it('fromPubKeyHash rejects wrong hash length', async () => {
    // P2PKH hash must be exactly 20 bytes. 19 bytes should fail.
    await assert.rejects(() => address.fromPubKeyHash('751e76e8199196d454941c45d1b3a323f1433b'));
  });

  it('fromWitnessPubKeyHash rejects wrong program length', async () => {
    // P2WPKH witness program must be 20 bytes. 16 bytes should fail.
    await assert.rejects(() => address.fromWitnessPubKeyHash('751e76e8199196d454941c45d1b3a323'));
  });

  it('fromTaproot rejects wrong program length', async () => {
    // P2TR witness program must be 32 bytes. 20 bytes should fail.
    await assert.rejects(() => address.fromTaproot('751e76e8199196d454941c45d1b3a323f1433bd6'));
  });

  it('fromWitnessScriptHash rejects wrong program length', async () => {
    // P2WSH witness program must be 32 bytes.
    await assert.rejects(() => address.fromWitnessScriptHash('aabbccdd'));
  });

  it('fromPubKey rejects invalid public key', async () => {
    await assert.rejects(() => address.fromPubKey('0000'));
  });

  it('fromScript rejects invalid hex', async () => {
    await assert.rejects(() => address.fromScript('xyz'));
  });
});
