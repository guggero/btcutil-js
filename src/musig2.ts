import { init, g, unwrap } from './init';
import type { Bytes } from './types';

/** The aggregated MuSig2 key from `musig2.aggregateKeys`. */
export interface Musig2AggregateKeysResult {
  /** 33-byte compressed aggregated key. */
  combinedKey: Uint8Array;
  /** 32-byte x-only aggregated key (for BIP-340 verification). */
  xOnlyKey: Uint8Array;
  /** Whether the aggregated key has an odd Y coordinate. */
  parityOdd: boolean;
}

/** One signer's nonce pair from `musig2.genNonces`. */
export interface Musig2Nonces {
  /** 66-byte public nonce (two compressed points), shared with cosigners. */
  pubNonce: Uint8Array;
  /** 97-byte secret nonce — single use, never shared. */
  secNonce: Uint8Array;
}

/** One signer's partial signature from `musig2.partialSign`. */
export interface Musig2PartialSignResult {
  /** 32-byte partial signature scalar. */
  s: Uint8Array;
  /** 33-byte final nonce R — identical for every signer; needed by
   *  `combineSigs`. */
  r: Uint8Array;
}

/** BIP-327 MuSig2 multi-signature utilities (two-round flow).
 *
 *  These wrap the low-level step-by-step functions rather than a session
 *  object, so every intermediate value is inspectable:
 *
 *  ```ts
 *  const agg = await musig2.aggregateKeys([pub1, pub2]);
 *  const n1 = await musig2.genNonces(pub1);           // each signer
 *  const n2 = await musig2.genNonces(pub2);
 *  const combined = await musig2.aggregateNonces([n1.pubNonce, n2.pubNonce]);
 *  const p1 = await musig2.partialSign(
 *    n1.secNonce, priv1, combined, [pub1, pub2], msgHash);
 *  const p2 = await musig2.partialSign(
 *    n2.secNonce, priv2, combined, [pub1, pub2], msgHash);
 *  const sig = await musig2.combineSigs(p1.r, [p1.s, p2.s]);
 *  // btcec.schnorrVerify(agg.xOnlyKey, msgHash, sig) === true
 *  ```
 *
 *  All functions use BIP-327's sorted-keys convention, so the public key
 *  list may be passed in any order — as long as it is the same list
 *  everywhere. */
export const musig2 = {
  /** Aggregate the signers' public keys into the single MuSig2 key.
   *  Calls Go: musig2.AggregateKeys() from btcd/btcec/schnorr/musig2. */
  async aggregateKeys(pubKeys: Bytes[]): Promise<Musig2AggregateKeysResult> {
    await init();
    return unwrap<Musig2AggregateKeysResult>(
      g().musig2.aggregateKeys(pubKeys),
    );
  },

  /** Generate one signer's secret/public nonce pair. The signer's public
   *  key is required; the optional private key, combined key and 32-byte
   *  message mix additional commitment entropy into the nonce derivation
   *  per BIP-327.
   *  Calls Go: musig2.GenNonces() from btcd/btcec/schnorr/musig2. */
  async genNonces(
    pubKey: Bytes,
    privKey?: Bytes,
    combinedKey?: Bytes,
    msg?: Bytes,
  ): Promise<Musig2Nonces> {
    await init();
    return unwrap<Musig2Nonces>(
      g().musig2.genNonces(pubKey, privKey, combinedKey, msg),
    );
  },

  /** Combine all signers' 66-byte public nonces into the combined nonce.
   *  Calls Go: musig2.AggregateNonces() from btcd/btcec/schnorr/musig2. */
  async aggregateNonces(pubNonces: Bytes[]): Promise<Uint8Array> {
    await init();
    return unwrap<Uint8Array>(g().musig2.aggregateNonces(pubNonces));
  },

  /** Create one signer's partial signature over the 32-byte message.
   *  Returns the partial signature `s` and the final nonce `r` (identical
   *  for all signers), which `combineSigs` needs.
   *  Calls Go: musig2.Sign() from btcd/btcec/schnorr/musig2. */
  async partialSign(
    secNonce: Bytes,
    privKey: Bytes,
    combinedNonce: Bytes,
    pubKeys: Bytes[],
    msg: Bytes,
  ): Promise<Musig2PartialSignResult> {
    await init();
    return unwrap<Musig2PartialSignResult>(
      g().musig2.partialSign(
        secNonce, privKey, combinedNonce, pubKeys, msg,
      ),
    );
  },

  /** Combine the partial signatures (32-byte `s` values) with the final
   *  nonce `r` into the final 64-byte BIP-340 Schnorr signature, valid
   *  under the aggregated x-only key.
   *  Calls Go: musig2.CombineSigs() from btcd/btcec/schnorr/musig2. */
  async combineSigs(
    finalNonce: Bytes,
    partialSigs: Bytes[],
  ): Promise<Uint8Array> {
    await init();
    return unwrap<Uint8Array>(
      g().musig2.combineSigs(finalNonce, partialSigs),
    );
  },
};
