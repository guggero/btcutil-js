import './setup.mjs';
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { wif } from '../dist/index.js';

describe('wif', () => {
  it('encode / decode round-trip', async () => {
    const privKey =
      '0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d';
    const encoded = await wif.encode(privKey, 'mainnet', true);
    assert.ok(encoded.startsWith('K') || encoded.startsWith('L'));

    const decoded = await wif.decode(encoded);
    assert.equal(decoded.privateKey, privKey);
    assert.equal(decoded.compressPubKey, true);
    assert.equal(decoded.network, 'mainnet');
    assert.ok(decoded.publicKey.length > 0);
  });

  it('uncompressed WIF starts with 5', async () => {
    const privKey =
      '0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d';
    const encoded = await wif.encode(privKey, 'mainnet', false);
    assert.ok(encoded.startsWith('5'));
  });

  it('decode rejects invalid WIF', async () => {
    await assert.rejects(() => wif.decode('notawif'));
  });

  it('decode rejects empty string', async () => {
    await assert.rejects(() => wif.decode(''));
  });

  it('encode rejects invalid hex private key', async () => {
    await assert.rejects(() => wif.encode('xyz', 'mainnet', true));
  });

  it('encode rejects unknown network', async () => {
    const privKey = '0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d';
    await assert.rejects(() => wif.encode(privKey, 'fakenet', true));
  });

  it('decode detects tampered checksum', async () => {
    const privKey = '0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d';
    const encoded = await wif.encode(privKey, 'mainnet', true);
    // Flip last character to corrupt checksum.
    const tampered = encoded.slice(0, -1) + (encoded.endsWith('A') ? 'B' : 'A');
    await assert.rejects(() => wif.decode(tampered));
  });
});
