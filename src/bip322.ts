import { init, g, unwrap } from './init';
import type { Bytes, VerifyResult, Network } from './types';

/** BIP-322 generic signed message verification and signing helpers. */
export const bip322 = {
  /** Verify a BIP-322 signed message.
   *  Calls Go: bip322.VerifyMessage() from btcutil/bip322
   *  (after btcutil.DecodeAddress() to parse the address).
   *
   *  @param message   - The message that was signed.
   *  @param address   - The Bitcoin address to verify against.
   *  @param signature - The base64-encoded BIP-322 signature.
   *  @param network   - Bitcoin network (default: "mainnet").
   *  @returns An object with `valid` (boolean) and optionally `error` (string). */
  async verifyMessage(
    message: string,
    address: string,
    signature: string,
    network: Network = 'mainnet',
  ): Promise<VerifyResult> {
    await init();
    return unwrap<VerifyResult>(
      g().bip322.verifyMessage(
        message,
        address,
        signature,
        network,
      )
    );
  },

  /** Build the BIP-322 "to_sign" PSBT for the simple format.
   *  Calls Go: bip322.BuildToSignPacketSimple() from btcutil/bip322.
   *
   *  @param message  - The message to sign.
   *  @param pkScript - The pkScript of the signing address.
   *  @returns Base64-encoded PSBT ready for signing. */
  async buildToSignPacketSimple(
    message: string,
    pkScript: Bytes,
  ): Promise<string> {
    await init();
    return unwrap<string>(
      g().bip322.buildToSignPacketSimple(message, pkScript),
    );
  },

  /** Build the BIP-322 "to_sign" PSBT for the full format.
   *  Calls Go: bip322.BuildToSignPacketFull() from btcutil/bip322.
   *
   *  @param message      - The message to sign.
   *  @param pkScript     - The pkScript of the signing address.
   *  @param txVersion    - Transaction version (typically 2).
   *  @param lockTime     - Lock time (typically 0).
   *  @param sequence     - Input sequence (typically 0).
   *  @returns Base64-encoded PSBT ready for signing. */
  async buildToSignPacketFull(
    message: string,
    pkScript: Bytes,
    txVersion: number,
    lockTime: number,
    sequence: number,
  ): Promise<string> {
    await init();
    return unwrap<string>(
      g().bip322.buildToSignPacketFull(
        message, pkScript, txVersion, lockTime, sequence,
      ),
    );
  },

  /** Serialize a witness stack into the BIP-322 wire format.
   *  Calls Go: bip322.SerializeTxWitness() from btcutil/bip322.
   *
   *  @param witness - Array of witness items (hex strings or Uint8Arrays).
   *  @returns Serialized witness bytes (Uint8Array). */
  async serializeTxWitness(witness: Bytes[]): Promise<Uint8Array> {
    await init();
    return unwrap<Uint8Array>(
      g().bip322.serializeTxWitness(witness),
    );
  },

  /** Parse serialized witness bytes back into a witness stack.
   *  Calls Go: bip322.ParseTxWitness() from btcutil/bip322.
   *
   *  @param rawWitness - Serialized witness data (hex string or Uint8Array).
   *  @returns Array of witness stack items (Uint8Array[]). */
  async parseTxWitness(rawWitness: Bytes): Promise<Uint8Array[]> {
    await init();
    return unwrap<Uint8Array[]>(
      g().bip322.parseTxWitness(rawWitness),
    );
  },
};
