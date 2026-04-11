import { init, g, unwrap } from './init';
import type { Network } from './types';

export interface ChainParams {
  name: string;
  defaultPort: string;
  bech32HRPSegwit: string;
  pubKeyHashAddrID: number;
  scriptHashAddrID: number;
  privateKeyID: number;
  hdPrivateKeyID: string;
  hdPublicKeyID: string;
  hdCoinType: number;
  coinbaseMaturity: number;
  subsidyReductionInterval: number;
}

/** Bitcoin network configuration parameters. */
export const chaincfg = {
  /** Get the full parameter set for a named network.
   *  Calls Go: chaincfg.MainNetParams / TestNet3Params / etc. from btcd/chaincfg. */
  async getParams(network: Network): Promise<ChainParams> {
    await init();
    return unwrap<ChainParams>(g().chaincfg.getParams(network));
  },
  /** Check if a byte is a known P2PKH address prefix.
   *  Calls Go: chaincfg.IsPubKeyHashAddrID() from btcd/chaincfg. */
  async isPubKeyHashAddrID(id: number): Promise<boolean> {
    await init();
    return unwrap<boolean>(g().chaincfg.isPubKeyHashAddrID(id));
  },
  /** Check if a byte is a known P2SH address prefix.
   *  Calls Go: chaincfg.IsScriptHashAddrID() from btcd/chaincfg. */
  async isScriptHashAddrID(id: number): Promise<boolean> {
    await init();
    return unwrap<boolean>(g().chaincfg.isScriptHashAddrID(id));
  },
  /** Check if a string is a known bech32 segwit HRP prefix.
   *  Calls Go: chaincfg.IsBech32SegwitPrefix() from btcd/chaincfg. */
  async isBech32SegwitPrefix(prefix: string): Promise<boolean> {
    await init();
    return unwrap<boolean>(g().chaincfg.isBech32SegwitPrefix(prefix));
  },
  /** Convert an HD private key version to its public counterpart.
   *  Calls Go: chaincfg.HDPrivateKeyToPublicKeyID() from btcd/chaincfg. */
  async hdPrivateKeyToPublicKeyID(hexPrivateKeyID: string): Promise<Uint8Array> {
    await init();
    return unwrap<Uint8Array>(g().chaincfg.hdPrivateKeyToPublicKeyID(hexPrivateKeyID));
  },
};
