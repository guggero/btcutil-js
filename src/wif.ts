import { init, g, unwrap } from './init';
import type { Bytes, WifDecodeResult, Network } from './types';

/** Wallet Import Format encoding and decoding. */
export const wif = {
  /** Decode a WIF-encoded private key string.
   *  Calls Go: btcutil.DecodeWIF() from btcutil. */
  async decode(wifStr: string): Promise<WifDecodeResult> {
    await init();
    return unwrap<WifDecodeResult>(g().wif.decode(wifStr));
  },

  /** Encode a private key (hex) as a WIF string.
   *  Calls Go: btcutil.NewWIF() from btcutil (via btcec.PrivKeyFromBytes()).
   *  @param compress - Whether to use compressed public key (default: true). */
  async encode(
    privateKey: Bytes,
    network: Network = 'mainnet',
    compress: boolean = true,
  ): Promise<string> {
    await init();
    return unwrap<string>(
      g().wif.encode(privateKey, network, compress),
    );
  },
};
