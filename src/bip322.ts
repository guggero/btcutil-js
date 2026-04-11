import { init } from './init';
import type { VerifyResult, Network } from './types';

/** BIP-322 generic signed message verification. */
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
    return (globalThis as any).btcutil.bip322.verifyMessage(
      message,
      address,
      signature,
      network,
    );
  },
};
