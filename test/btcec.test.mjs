import './setup.mjs';
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { btcec, chainhash } from '../dist/index.js';

describe('btcec: key management', () => {
  it('newPrivateKey generates random key', async () => {
    const k1 = await btcec.newPrivateKey();
    const k2 = await btcec.newPrivateKey();
    assert.equal(k1.privateKey.length, 64); // 32 bytes
    assert.equal(k1.publicKey.length, 66); // 33 bytes compressed
    assert.notEqual(k1.privateKey, k2.privateKey);
  });
  it('privKeyFromBytes round-trip', async () => {
    const { privateKey } = await btcec.newPrivateKey();
    const result = await btcec.privKeyFromBytes(privateKey);
    assert.equal(result.privateKey, privateKey);
    assert.ok(result.publicKey.startsWith('02') || result.publicKey.startsWith('03'));
  });
  it('pubKeyFromBytes normalizes key', async () => {
    const { publicKey } = await btcec.newPrivateKey();
    const normalized = await btcec.pubKeyFromBytes(publicKey);
    assert.equal(normalized, publicKey);
  });
  it('isCompressedPubKey', async () => {
    const { publicKey } = await btcec.newPrivateKey();
    assert.equal(await btcec.isCompressedPubKey(publicKey), true);
    const uncompressed = await btcec.serializeUncompressed(publicKey);
    assert.equal(await btcec.isCompressedPubKey(uncompressed), false);
  });
  it('serializeUncompressed produces 65 bytes', async () => {
    const { publicKey } = await btcec.newPrivateKey();
    const unc = await btcec.serializeUncompressed(publicKey);
    assert.equal(unc.length, 130); // 65 bytes = 130 hex chars
    assert.ok(unc.startsWith('04'));
  });
});

describe('btcec: ECDH', () => {
  it('generateSharedSecret produces same secret for both parties', async () => {
    const alice = await btcec.newPrivateKey();
    const bob = await btcec.newPrivateKey();
    const secret1 = await btcec.generateSharedSecret(alice.privateKey, bob.publicKey);
    const secret2 = await btcec.generateSharedSecret(bob.privateKey, alice.publicKey);
    assert.equal(secret1, secret2);
    assert.equal(secret1.length, 64); // 32 bytes
  });
});

describe('btcec: ECDSA', () => {
  it('sign and verify', async () => {
    const { privateKey, publicKey } = await btcec.newPrivateKey();
    const msgHash = await chainhash.doubleHash('68656c6c6f'); // "hello"
    const sig = await btcec.ecdsaSign(privateKey, msgHash);
    assert.ok(sig.length > 0);
    const valid = await btcec.ecdsaVerify(publicKey, msgHash, sig);
    assert.equal(valid, true);
  });
  it('verify rejects wrong key', async () => {
    const k1 = await btcec.newPrivateKey();
    const k2 = await btcec.newPrivateKey();
    const msgHash = await chainhash.doubleHash('68656c6c6f');
    const sig = await btcec.ecdsaSign(k1.privateKey, msgHash);
    const valid = await btcec.ecdsaVerify(k2.publicKey, msgHash, sig);
    assert.equal(valid, false);
  });
  it('signCompact and recoverCompact round-trip', async () => {
    const { privateKey, publicKey } = await btcec.newPrivateKey();
    const msgHash = await chainhash.doubleHash('74657374'); // "test"
    const compact = await btcec.ecdsaSignCompact(privateKey, msgHash, true);
    assert.equal(compact.length, 130); // 65 bytes
    const recovered = await btcec.ecdsaRecoverCompact(compact, msgHash);
    assert.equal(recovered.publicKey, publicKey);
    assert.equal(recovered.compressed, true);
  });
  it('parseSignature normalizes', async () => {
    const { privateKey } = await btcec.newPrivateKey();
    const msgHash = await chainhash.doubleHash('aa');
    const sig = await btcec.ecdsaSign(privateKey, msgHash);
    const parsed = await btcec.ecdsaParseSignature(sig);
    assert.equal(parsed, sig); // already normalized
  });
});

describe('btcec: Schnorr', () => {
  it('sign and verify', async () => {
    const { privateKey, publicKey } = await btcec.newPrivateKey();
    const msgHash = await chainhash.doubleHash('736368');
    const sig = await btcec.schnorrSign(privateKey, msgHash);
    assert.equal(sig.length, 128); // 64 bytes
    // Verify with x-only key
    const xOnly = await btcec.schnorrSerializePubKey(publicKey);
    const valid = await btcec.schnorrVerify(xOnly, msgHash, sig);
    assert.equal(valid, true);
  });
  it('verify rejects wrong message', async () => {
    const { privateKey, publicKey } = await btcec.newPrivateKey();
    const msg1 = await chainhash.doubleHash('aa');
    const msg2 = await chainhash.doubleHash('bb');
    const sig = await btcec.schnorrSign(privateKey, msg1);
    const xOnly = await btcec.schnorrSerializePubKey(publicKey);
    assert.equal(await btcec.schnorrVerify(xOnly, msg2, sig), false);
  });
  it('schnorrParsePubKey and schnorrSerializePubKey round-trip', async () => {
    const { publicKey } = await btcec.newPrivateKey();
    const xOnly = await btcec.schnorrSerializePubKey(publicKey);
    assert.equal(xOnly.length, 64); // 32 bytes
    const compressed = await btcec.schnorrParsePubKey(xOnly);
    assert.equal(compressed.length, 66); // 33 bytes
  });
});

describe('btcec: negative cases', () => {
  it('pubKeyFromBytes rejects invalid key', async () => {
    await assert.rejects(() => btcec.pubKeyFromBytes('0000'));
  });

  it('pubKeyFromBytes rejects all-zero 33-byte key', async () => {
    await assert.rejects(() => btcec.pubKeyFromBytes('02' + '00'.repeat(32)));
  });

  it('serializeUncompressed rejects garbage', async () => {
    await assert.rejects(() => btcec.serializeUncompressed('ffff'));
  });

  it('ecdsaVerify rejects truncated signature', async () => {
    const { publicKey } = await btcec.newPrivateKey();
    const msgHash = await chainhash.doubleHash('aa');
    await assert.rejects(() => btcec.ecdsaVerify(publicKey, msgHash, 'aabb'));
  });

  it('ecdsaRecoverCompact rejects wrong-length signature', async () => {
    const msgHash = await chainhash.doubleHash('aa');
    await assert.rejects(() => btcec.ecdsaRecoverCompact('aabb', msgHash));
  });

  it('ecdsaParseDERSignature rejects non-DER data', async () => {
    await assert.rejects(() => btcec.ecdsaParseDERSignature('deadbeef'));
  });

  it('schnorrParsePubKey rejects wrong-length key', async () => {
    // Schnorr x-only keys must be exactly 32 bytes.
    await assert.rejects(() => btcec.schnorrParsePubKey('aabb'));
  });

  it('schnorrParseSignature rejects wrong-length sig', async () => {
    // Schnorr signatures must be exactly 64 bytes.
    await assert.rejects(() => btcec.schnorrParseSignature('aabb'));
  });

  it('schnorrVerify rejects wrong key for valid sig', async () => {
    const k1 = await btcec.newPrivateKey();
    const k2 = await btcec.newPrivateKey();
    const msgHash = await chainhash.doubleHash('cc');
    const sig = await btcec.schnorrSign(k1.privateKey, msgHash);
    const wrongXOnly = await btcec.schnorrSerializePubKey(k2.publicKey);
    assert.equal(await btcec.schnorrVerify(wrongXOnly, msgHash, sig), false);
  });

  it('generateSharedSecret rejects invalid pubkey', async () => {
    const { privateKey } = await btcec.newPrivateKey();
    await assert.rejects(() => btcec.generateSharedSecret(privateKey, '0000'));
  });

  it('privKeyFromBytes rejects invalid hex', async () => {
    await assert.rejects(() => btcec.privKeyFromBytes('xyz'));
  });
});
