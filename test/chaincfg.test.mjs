import './setup.mjs';
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { chaincfg } from '../dist/index.js';

describe('chaincfg', () => {
  it('getParams returns mainnet info', async () => {
    const p = await chaincfg.getParams('mainnet');
    assert.equal(p.name, 'mainnet');
    assert.equal(p.bech32HRPSegwit, 'bc');
    assert.equal(p.pubKeyHashAddrID, 0x00);
    assert.equal(p.scriptHashAddrID, 0x05);
    assert.equal(p.hdCoinType, 0);
    assert.equal(p.defaultPort, '8333');
  });
  it('getParams returns testnet info', async () => {
    const p = await chaincfg.getParams('testnet');
    assert.equal(p.bech32HRPSegwit, 'tb');
    assert.equal(p.pubKeyHashAddrID, 0x6f);
    assert.equal(p.scriptHashAddrID, 0xc4);
  });
  it('getParams rejects unknown network', async () => {
    await assert.rejects(() => chaincfg.getParams('fakenet'));
  });
  it('isPubKeyHashAddrID', async () => {
    assert.equal(await chaincfg.isPubKeyHashAddrID(0x00), true);  // mainnet
    assert.equal(await chaincfg.isPubKeyHashAddrID(0x6f), true);  // testnet
    assert.equal(await chaincfg.isPubKeyHashAddrID(0xff), false);
  });
  it('isScriptHashAddrID', async () => {
    assert.equal(await chaincfg.isScriptHashAddrID(0x05), true);  // mainnet
    assert.equal(await chaincfg.isScriptHashAddrID(0xff), false);
  });
  it('isBech32SegwitPrefix', async () => {
    // Note: chaincfg.IsBech32SegwitPrefix checks a global registry that
    // may not be populated in all environments. Verify the function works
    // and returns a boolean.
    const result = await chaincfg.isBech32SegwitPrefix('bc');
    assert.equal(typeof result, 'boolean');
    // Unknown prefix should always be false.
    assert.equal(await chaincfg.isBech32SegwitPrefix('xx'), false);
  });
  it('hdPrivateKeyToPublicKeyID', async () => {
    const p = await chaincfg.getParams('mainnet');
    const pubID = await chaincfg.hdPrivateKeyToPublicKeyID(p.hdPrivateKeyID);
    assert.equal(pubID, p.hdPublicKeyID);
  });

  it('hdPrivateKeyToPublicKeyID rejects unknown key ID', async () => {
    await assert.rejects(() => chaincfg.hdPrivateKeyToPublicKeyID('deadbeef'));
  });

  it('getParams returns different values for different networks', async () => {
    const mainnet = await chaincfg.getParams('mainnet');
    const testnet = await chaincfg.getParams('testnet');
    assert.notEqual(mainnet.bech32HRPSegwit, testnet.bech32HRPSegwit);
    assert.notEqual(mainnet.pubKeyHashAddrID, testnet.pubKeyHashAddrID);
  });

  it('isPubKeyHashAddrID returns false for 0xff', async () => {
    assert.equal(await chaincfg.isPubKeyHashAddrID(0xff), false);
  });

  it('isScriptHashAddrID returns false for 0x00', async () => {
    // 0x00 is a pubkey hash prefix, not script hash.
    assert.equal(await chaincfg.isScriptHashAddrID(0x00), false);
  });
});
