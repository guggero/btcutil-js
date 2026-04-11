import './setup.mjs';
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { btcec, chainhash } from '../dist/index.js';
import { toHex } from './util.mjs';


describe('btcec: key management', () => {
  it('newPrivateKey generates random key', async () => {
    const k1 = await btcec.newPrivateKey();
    const k2 = await btcec.newPrivateKey();
    assert.ok(k1.privateKey instanceof Uint8Array);
    assert.ok(k1.publicKey instanceof Uint8Array);
    assert.equal(k1.privateKey.length, 32); // 32 bytes
    assert.equal(k1.publicKey.length, 33); // 33 bytes compressed
    assert.notEqual(toHex(k1.privateKey), toHex(k2.privateKey));
  });
  it('privKeyFromBytes round-trip', async () => {
    const { privateKey } = await btcec.newPrivateKey();
    const result = await btcec.privKeyFromBytes(toHex(privateKey));
    assert.ok(result.privateKey instanceof Uint8Array);
    assert.equal(toHex(result.privateKey), toHex(privateKey));
    assert.ok(result.publicKey[0] === 0x02 || result.publicKey[0] === 0x03);
  });
  it('pubKeyFromBytes normalizes key', async () => {
    const { publicKey } = await btcec.newPrivateKey();
    const normalized = await btcec.pubKeyFromBytes(toHex(publicKey));
    assert.ok(normalized instanceof Uint8Array);
    assert.equal(toHex(normalized), toHex(publicKey));
  });
  it('isCompressedPubKey', async () => {
    const { publicKey } = await btcec.newPrivateKey();
    assert.equal(await btcec.isCompressedPubKey(toHex(publicKey)), true);
    const uncompressed = await btcec.serializeUncompressed(toHex(publicKey));
    assert.equal(await btcec.isCompressedPubKey(toHex(uncompressed)), false);
  });
  it('serializeUncompressed produces 65 bytes', async () => {
    const { publicKey } = await btcec.newPrivateKey();
    const unc = await btcec.serializeUncompressed(toHex(publicKey));
    assert.ok(unc instanceof Uint8Array);
    assert.equal(unc.length, 65); // 65 bytes
    assert.ok(unc[0] === 0x04);
  });
});

describe('btcec: ECDH', () => {
  it('generateSharedSecret produces same secret for both parties', async () => {
    const alice = await btcec.newPrivateKey();
    const bob = await btcec.newPrivateKey();
    const secret1 = await btcec.generateSharedSecret(toHex(alice.privateKey), toHex(bob.publicKey));
    const secret2 = await btcec.generateSharedSecret(toHex(bob.privateKey), toHex(alice.publicKey));
    assert.ok(secret1 instanceof Uint8Array);
    assert.equal(toHex(secret1), toHex(secret2));
    assert.equal(secret1.length, 32); // 32 bytes
  });
});

describe('btcec: ECDSA', () => {
  it('sign and verify', async () => {
    const { privateKey, publicKey } = await btcec.newPrivateKey();
    const msgHash = await chainhash.doubleHash('68656c6c6f'); // "hello"
    const sig = await btcec.ecdsaSign(toHex(privateKey), toHex(msgHash));
    assert.ok(sig instanceof Uint8Array);
    assert.ok(sig.length > 0);
    const valid = await btcec.ecdsaVerify(toHex(publicKey), toHex(msgHash), toHex(sig));
    assert.equal(valid, true);
  });
  it('verify rejects wrong key', async () => {
    const k1 = await btcec.newPrivateKey();
    const k2 = await btcec.newPrivateKey();
    const msgHash = await chainhash.doubleHash('68656c6c6f');
    const sig = await btcec.ecdsaSign(toHex(k1.privateKey), toHex(msgHash));
    const valid = await btcec.ecdsaVerify(toHex(k2.publicKey), toHex(msgHash), toHex(sig));
    assert.equal(valid, false);
  });
  it('signCompact and recoverCompact round-trip', async () => {
    const { privateKey, publicKey } = await btcec.newPrivateKey();
    const msgHash = await chainhash.doubleHash('74657374'); // "test"
    const compact = await btcec.ecdsaSignCompact(toHex(privateKey), toHex(msgHash), true);
    assert.ok(compact instanceof Uint8Array);
    assert.equal(compact.length, 65); // 65 bytes
    const recovered = await btcec.ecdsaRecoverCompact(toHex(compact), toHex(msgHash));
    assert.ok(recovered.publicKey instanceof Uint8Array);
    assert.equal(toHex(recovered.publicKey), toHex(publicKey));
    assert.equal(recovered.compressed, true);
  });
  it('parseSignature normalizes', async () => {
    const { privateKey } = await btcec.newPrivateKey();
    const msgHash = await chainhash.doubleHash('aa');
    const sig = await btcec.ecdsaSign(toHex(privateKey), toHex(msgHash));
    const parsed = await btcec.ecdsaParseSignature(toHex(sig));
    assert.ok(parsed instanceof Uint8Array);
    assert.equal(toHex(parsed), toHex(sig)); // already normalized
  });
});

describe('btcec: Schnorr', () => {
  it('sign and verify', async () => {
    const { privateKey, publicKey } = await btcec.newPrivateKey();
    const msgHash = await chainhash.doubleHash('736368');
    const sig = await btcec.schnorrSign(toHex(privateKey), toHex(msgHash));
    assert.ok(sig instanceof Uint8Array);
    assert.equal(sig.length, 64); // 64 bytes
    // Verify with x-only key
    const xOnly = await btcec.schnorrSerializePubKey(toHex(publicKey));
    assert.ok(xOnly instanceof Uint8Array);
    const valid = await btcec.schnorrVerify(toHex(xOnly), toHex(msgHash), toHex(sig));
    assert.equal(valid, true);
  });
  it('verify rejects wrong message', async () => {
    const { privateKey, publicKey } = await btcec.newPrivateKey();
    const msg1 = await chainhash.doubleHash('aa');
    const msg2 = await chainhash.doubleHash('bb');
    const sig = await btcec.schnorrSign(toHex(privateKey), toHex(msg1));
    const xOnly = await btcec.schnorrSerializePubKey(toHex(publicKey));
    assert.equal(await btcec.schnorrVerify(toHex(xOnly), toHex(msg2), toHex(sig)), false);
  });
  it('schnorrParsePubKey and schnorrSerializePubKey round-trip', async () => {
    const { publicKey } = await btcec.newPrivateKey();
    const xOnly = await btcec.schnorrSerializePubKey(toHex(publicKey));
    assert.equal(xOnly.length, 32); // 32 bytes
    const compressed = await btcec.schnorrParsePubKey(toHex(xOnly));
    assert.ok(compressed instanceof Uint8Array);
    assert.equal(compressed.length, 33); // 33 bytes
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
    await assert.rejects(() => btcec.ecdsaVerify(toHex(publicKey), toHex(msgHash), 'aabb'));
  });

  it('ecdsaRecoverCompact rejects wrong-length signature', async () => {
    const msgHash = await chainhash.doubleHash('aa');
    await assert.rejects(() => btcec.ecdsaRecoverCompact('aabb', toHex(msgHash)));
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
    const sig = await btcec.schnorrSign(toHex(k1.privateKey), toHex(msgHash));
    const wrongXOnly = await btcec.schnorrSerializePubKey(toHex(k2.publicKey));
    assert.equal(await btcec.schnorrVerify(toHex(wrongXOnly), toHex(msgHash), toHex(sig)), false);
  });

  it('generateSharedSecret rejects invalid pubkey', async () => {
    const { privateKey } = await btcec.newPrivateKey();
    await assert.rejects(() => btcec.generateSharedSecret(toHex(privateKey), '0000'));
  });

  it('privKeyFromBytes rejects invalid hex', async () => {
    await assert.rejects(() => btcec.privKeyFromBytes('xyz'));
  });
});
