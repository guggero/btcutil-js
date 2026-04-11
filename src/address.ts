import { init, g, unwrap } from './init';
import type { AddressInfo, Bytes, Network } from './types';

/** Bitcoin address encoding, decoding, and creation. */
export const address = {
  /** Decode a Bitcoin address string and return detailed info.
   *  Calls Go: btcutil.DecodeAddress() from btcutil. */
  async decode(addr: string, network: Network = 'mainnet'): Promise<AddressInfo> {
    await init();
    return unwrap<AddressInfo>(g().address.decode(addr, network));
  },

  /** Create a P2PKH address from a 20-byte pubkey hash (hex).
   *  Calls Go: btcutil.NewAddressPubKeyHash() from btcutil. */
  async fromPubKeyHash(hash: Bytes, network: Network = 'mainnet'): Promise<string> {
    await init();
    return unwrap<string>(g().address.fromPubKeyHash(hash, network));
  },

  /** Create a P2SH address from a 20-byte script hash (hex).
   *  Calls Go: btcutil.NewAddressScriptHashFromHash() from btcutil. */
  async fromScriptHash(hash: Bytes, network: Network = 'mainnet'): Promise<string> {
    await init();
    return unwrap<string>(g().address.fromScriptHash(hash, network));
  },

  /** Create a P2SH address by hashing a serialized script (hex).
   *  Calls Go: btcutil.NewAddressScriptHash() from btcutil. */
  async fromScript(script: Bytes, network: Network = 'mainnet'): Promise<string> {
    await init();
    return unwrap<string>(g().address.fromScript(script, network));
  },

  /** Create a P2WPKH address from a 20-byte witness program (hex).
   *  Calls Go: btcutil.NewAddressWitnessPubKeyHash() from btcutil. */
  async fromWitnessPubKeyHash(
    program: Bytes,
    network: Network = 'mainnet',
  ): Promise<string> {
    await init();
    return unwrap<string>(
      g().address.fromWitnessPubKeyHash(program, network),
    );
  },

  /** Create a P2WSH address from a 32-byte witness program (hex).
   *  Calls Go: btcutil.NewAddressWitnessScriptHash() from btcutil. */
  async fromWitnessScriptHash(
    program: Bytes,
    network: Network = 'mainnet',
  ): Promise<string> {
    await init();
    return unwrap<string>(
      g().address.fromWitnessScriptHash(program, network),
    );
  },

  /** Create a P2TR (Taproot) address from a 32-byte witness program (hex).
   *  Calls Go: btcutil.NewAddressTaproot() from btcutil. */
  async fromTaproot(program: Bytes, network: Network = 'mainnet'): Promise<string> {
    await init();
    return unwrap<string>(g().address.fromTaproot(program, network));
  },

  /** Create a P2PK address from a serialized public key (hex).
   *  Calls Go: btcutil.NewAddressPubKey() from btcutil. */
  async fromPubKey(pubKey: Bytes, network: Network = 'mainnet'): Promise<string> {
    await init();
    return unwrap<string>(g().address.fromPubKey(pubKey, network));
  },
};
