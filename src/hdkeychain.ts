import { init, g, unwrap } from './init';
import type { ExtendedKeyInfo, Network } from './types';

/** BIP-32 hierarchical deterministic key derivation. */
export const hdkeychain = {
  /** Create a master extended key from a seed (hex).
   *  Calls Go: hdkeychain.NewMaster() from btcutil/hdkeychain. */
  async newMaster(hexSeed: string, network: Network = 'mainnet'): Promise<string> {
    await init();
    return unwrap<string>(g().hdkeychain.newMaster(hexSeed, network));
  },

  /** Parse an extended key string (xprv/xpub/tprv/tpub) and return info.
   *  Calls Go: hdkeychain.NewKeyFromString() from btcutil/hdkeychain. */
  async fromString(key: string): Promise<ExtendedKeyInfo> {
    await init();
    return unwrap<ExtendedKeyInfo>(g().hdkeychain.fromString(key));
  },

  /** Derive a child key at the given index. Use index >= 0x80000000 for hardened.
   *  Calls Go: hdkeychain.ExtendedKey.Derive() from btcutil/hdkeychain. */
  async derive(key: string, index: number): Promise<string> {
    await init();
    return unwrap<string>(g().hdkeychain.derive(key, index));
  },

  /** Derive a hardened child key (adds 0x80000000 to the index automatically).
   *  Calls Go: hdkeychain.ExtendedKey.Derive() with HardenedKeyStart from btcutil/hdkeychain. */
  async deriveHardened(key: string, index: number): Promise<string> {
    await init();
    return unwrap<string>(g().hdkeychain.deriveHardened(key, index));
  },

  /** Derive along a BIP-32 path like "m/44'/0'/0'/0/0".
   *  Supports both ' and h as hardened suffixes.
   *  Calls Go: hdkeychain.ExtendedKey.Derive() iteratively from btcutil/hdkeychain. */
  async derivePath(key: string, path: string): Promise<string> {
    await init();
    return unwrap<string>(g().hdkeychain.derivePath(key, path));
  },

  /** Convert a private extended key to its public counterpart.
   *  Calls Go: hdkeychain.ExtendedKey.Neuter() from btcutil/hdkeychain. */
  async neuter(key: string): Promise<string> {
    await init();
    return unwrap<string>(g().hdkeychain.neuter(key));
  },

  /** Generate a random seed of the given length in bytes (default: 32).
   *  Calls Go: hdkeychain.GenerateSeed() from btcutil/hdkeychain. */
  async generateSeed(length?: number): Promise<Uint8Array> {
    await init();
    return unwrap<Uint8Array>(g().hdkeychain.generateSeed(length));
  },

  /** Get the compressed public key (hex) for an extended key.
   *  Calls Go: hdkeychain.ExtendedKey.ECPubKey() from btcutil/hdkeychain. */
  async publicKey(key: string): Promise<Uint8Array> {
    await init();
    return unwrap<Uint8Array>(g().hdkeychain.publicKey(key));
  },

  /** Get the P2PKH address for an extended key.
   *  Calls Go: hdkeychain.ExtendedKey.Address() from btcutil/hdkeychain. */
  async address(key: string, network: Network = 'mainnet'): Promise<string> {
    await init();
    return unwrap<string>(g().hdkeychain.address(key, network));
  },
};
