import { init, g, unwrap } from './init';

export interface KeyPairResult {
  privateKey: string;
  publicKey: string;
}

export interface RecoverCompactResult {
  publicKey: string;
  compressed: boolean;
}

/** secp256k1 elliptic curve cryptography: key management, ECDSA, Schnorr, ECDH. */
export const btcec = {
  // -- key management --

  /** Generate a new random private key.
   *  Calls Go: btcec.NewPrivateKey() from btcd/btcec/v2. */
  async newPrivateKey(): Promise<KeyPairResult> {
    await init();
    return unwrap<KeyPairResult>(g().btcec.newPrivateKey());
  },
  /** Derive the private/public key pair from raw private key bytes (hex).
   *  Calls Go: btcec.PrivKeyFromBytes() from btcd/btcec/v2. */
  async privKeyFromBytes(hexPrivKey: string): Promise<KeyPairResult> {
    await init();
    return unwrap<KeyPairResult>(g().btcec.privKeyFromBytes(hexPrivKey));
  },
  /** Parse a public key (compressed 33-byte or uncompressed 65-byte hex) and return normalized compressed form.
   *  Calls Go: btcec.ParsePubKey() from btcd/btcec/v2. */
  async pubKeyFromBytes(hexPubKey: string): Promise<Uint8Array> {
    await init();
    return unwrap<Uint8Array>(g().btcec.pubKeyFromBytes(hexPubKey));
  },
  /** Check if a public key is in compressed format.
   *  Calls Go: btcec.IsCompressedPubKey() from btcd/btcec/v2. */
  async isCompressedPubKey(hexPubKey: string): Promise<boolean> {
    await init();
    return unwrap<boolean>(g().btcec.isCompressedPubKey(hexPubKey));
  },
  /** Serialize a public key to uncompressed 65-byte form.
   *  Calls Go: btcec.PublicKey.SerializeUncompressed() from btcd/btcec/v2. */
  async serializeUncompressed(hexPubKey: string): Promise<Uint8Array> {
    await init();
    return unwrap<Uint8Array>(g().btcec.serializeUncompressed(hexPubKey));
  },
  /** Serialize a public key to compressed 33-byte form.
   *  Calls Go: btcec.PublicKey.SerializeCompressed() from btcd/btcec/v2. */
  async serializeCompressed(hexPubKey: string): Promise<Uint8Array> {
    await init();
    return unwrap<Uint8Array>(g().btcec.serializeCompressed(hexPubKey));
  },

  // -- ECDH --

  /** Compute an ECDH shared secret.
   *  Calls Go: btcec.GenerateSharedSecret() from btcd/btcec/v2. */
  async generateSharedSecret(hexPrivKey: string, hexPubKey: string): Promise<Uint8Array> {
    await init();
    return unwrap<Uint8Array>(g().btcec.generateSharedSecret(hexPrivKey, hexPubKey));
  },

  // -- ECDSA --

  /** Sign a 32-byte hash with ECDSA (RFC 6979 deterministic). Returns DER-encoded signature.
   *  Calls Go: ecdsa.Sign() from btcd/btcec/v2/ecdsa. */
  async ecdsaSign(hexPrivKey: string, hexHash: string): Promise<Uint8Array> {
    await init();
    return unwrap<Uint8Array>(g().btcec.ecdsaSign(hexPrivKey, hexHash));
  },
  /** Verify an ECDSA DER-encoded signature.
   *  Calls Go: ecdsa.Signature.Verify() from btcd/btcec/v2/ecdsa. */
  async ecdsaVerify(hexPubKey: string, hexHash: string, hexSignature: string): Promise<boolean> {
    await init();
    return unwrap<boolean>(g().btcec.ecdsaVerify(hexPubKey, hexHash, hexSignature));
  },
  /** Sign a hash and return a 65-byte compact (recoverable) signature.
   *  Calls Go: ecdsa.SignCompact() from btcd/btcec/v2/ecdsa. */
  async ecdsaSignCompact(hexPrivKey: string, hexHash: string, isCompressedKey: boolean): Promise<Uint8Array> {
    await init();
    return unwrap<Uint8Array>(g().btcec.ecdsaSignCompact(hexPrivKey, hexHash, isCompressedKey));
  },
  /** Recover the public key from a compact signature and hash.
   *  Calls Go: ecdsa.RecoverCompact() from btcd/btcec/v2/ecdsa. */
  async ecdsaRecoverCompact(hexSignature: string, hexHash: string): Promise<RecoverCompactResult> {
    await init();
    return unwrap<RecoverCompactResult>(g().btcec.ecdsaRecoverCompact(hexSignature, hexHash));
  },
  /** Parse and normalize a BER-encoded ECDSA signature.
   *  Calls Go: ecdsa.ParseSignature() from btcd/btcec/v2/ecdsa. */
  async ecdsaParseSignature(hexSignature: string): Promise<Uint8Array> {
    await init();
    return unwrap<Uint8Array>(g().btcec.ecdsaParseSignature(hexSignature));
  },
  /** Parse a strict DER-encoded ECDSA signature.
   *  Calls Go: ecdsa.ParseDERSignature() from btcd/btcec/v2/ecdsa. */
  async ecdsaParseDERSignature(hexSignature: string): Promise<Uint8Array> {
    await init();
    return unwrap<Uint8Array>(g().btcec.ecdsaParseDERSignature(hexSignature));
  },

  // -- Schnorr (BIP-340) --

  /** Sign a 32-byte hash with Schnorr (BIP-340). Returns 64-byte signature.
   *  Calls Go: schnorr.Sign() from btcd/btcec/v2/schnorr. */
  async schnorrSign(hexPrivKey: string, hexHash: string): Promise<Uint8Array> {
    await init();
    return unwrap<Uint8Array>(g().btcec.schnorrSign(hexPrivKey, hexHash));
  },
  /** Verify a BIP-340 Schnorr signature. Accepts 32-byte x-only or 33-byte compressed pubkey.
   *  Calls Go: schnorr.Signature.Verify() from btcd/btcec/v2/schnorr. */
  async schnorrVerify(hexPubKey: string, hexHash: string, hexSignature: string): Promise<boolean> {
    await init();
    return unwrap<boolean>(g().btcec.schnorrVerify(hexPubKey, hexHash, hexSignature));
  },
  /** Parse a 32-byte x-only public key (BIP-340). Returns 33-byte compressed key.
   *  Calls Go: schnorr.ParsePubKey() from btcd/btcec/v2/schnorr. */
  async schnorrParsePubKey(hexXOnlyPubKey: string): Promise<Uint8Array> {
    await init();
    return unwrap<Uint8Array>(g().btcec.schnorrParsePubKey(hexXOnlyPubKey));
  },
  /** Serialize a public key as 32-byte x-only (BIP-340).
   *  Calls Go: schnorr.SerializePubKey() from btcd/btcec/v2/schnorr. */
  async schnorrSerializePubKey(hexPubKey: string): Promise<Uint8Array> {
    await init();
    return unwrap<Uint8Array>(g().btcec.schnorrSerializePubKey(hexPubKey));
  },
  /** Parse a 64-byte Schnorr signature.
   *  Calls Go: schnorr.ParseSignature() from btcd/btcec/v2/schnorr. */
  async schnorrParseSignature(hexSignature: string): Promise<Uint8Array> {
    await init();
    return unwrap<Uint8Array>(g().btcec.schnorrParseSignature(hexSignature));
  },
};
