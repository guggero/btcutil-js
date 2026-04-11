# btcutil-js

A comprehensive Bitcoin utility library for JavaScript/TypeScript, powered by
Go's [btcd/btcutil](https://github.com/btcsuite/btcd/tree/master/btcutil)
compiled to WebAssembly. Works in both Node.js and browsers.

Provides **base58**, **bech32**, **address** encoding/decoding, **amount**
conversions, **Hash160**, **WIF**, **BIP-32 HD key** derivation, **BIP-69
transaction sorting**, **BIP-174 PSBT** inspection, **BIP-322 message
verification**, **BIP-158 GCS filters**, **Bloom filter** hashing, and raw
**transaction** utilities.

## Prerequisites

- **Go >= 1.25.0** — Install from <https://go.dev/dl/>
- **Node.js >= 18** — Install from <https://nodejs.org/>

## Building

Install npm dependencies, then build the WASM module and JS wrapper:

```bash
npm install
npm run build
```

This runs two steps under the hood:

1. **`npm run build:wasm`** — Compiles the Go source to `btcutil.wasm` using
   `GOOS=js GOARCH=wasm`.
2. **`npm run build:js`** — Inlines the Go WASM runtime, bundles the TypeScript
   source with [tsup](https://github.com/egoist/tsup), and copies
   `btcutil.wasm` into `dist/`.

## Usage

### Node.js / TypeScript

```bash
npm install btcutil-js
```

```typescript
import { hdkeychain, hash, address } from 'btcutil-js';

// Generate a BIP-84 native SegWit address from a random seed.
const seed = await hdkeychain.generateSeed();
const master = await hdkeychain.newMaster(seed);
const child = await hdkeychain.derivePath(master, "m/84'/0'/0'/0/0");
const pubKey = await hdkeychain.publicKey(child);
const pkHash = await hash.hash160(pubKey);
const addr = await address.fromWitnessPubKeyHash(pkHash);
console.log(addr); // bc1q…
```

### Synchronous API

Every namespace method is `async` by default because it lazily initializes
the WASM module on first call. If you prefer synchronous calls, call `init()`
once and use the returned object — all methods on it are sync:

```typescript
import { init } from 'btcutil-js';

const btcutil = await init();

// Everything below is synchronous — no await needed.
const seed = btcutil.hdkeychain.generateSeed();
const master = btcutil.hdkeychain.newMaster(seed);
const child = btcutil.hdkeychain.derivePath(master, "m/84'/0'/0'/0/0");
const pubKey = btcutil.hdkeychain.publicKey(child);
const pkHash = btcutil.hash.hash160(pubKey);
const addr = btcutil.address.fromWitnessPubKeyHash(pkHash);
console.log(addr); // bc1q…

// Signing is sync too.
const kp = btcutil.btcec.newPrivateKey();
const msgHash = btcutil.chainhash.doubleHash('68656c6c6f');
const sig = btcutil.btcec.schnorrSign(kp.privateKey, msgHash);
const valid = btcutil.btcec.schnorrVerify(
  btcutil.btcec.schnorrSerializePubKey(kp.publicKey), msgHash, sig,
);
console.log(valid); // true

// Errors throw synchronously.
try {
  btcutil.address.decode('not-an-address');
} catch (e) {
  console.error(e.message);
}
```

The sync API has the same namespaces and method signatures as the async one,
just without `Promise<>` wrappers. TypeScript provides full autocompletion and
type checking via the `BtcutilSync` type.

### Custom WASM loading

You can pre-initialize the WASM module with a custom source by calling `init`
before any other function:

```typescript
import { init } from 'btcutil-js';

// From a URL
await init('/assets/btcutil.wasm');

// From an ArrayBuffer
const buf = await fetch('/assets/btcutil.wasm').then(r => r.arrayBuffer());
await init(buf);

// From a fetch Response (uses streaming compilation)
await init(fetch('/assets/btcutil.wasm'));
```

## API

[See full API docs here, generated with `typedoc`](https://guggero.github.io/btcutil-js/).

The corresponding Go library this project wraps with WASM is documented here:
- [btcd/btcec](https://pkg.go.dev/github.com/btcsuite/btcd/btcec/v2)
- [btcd/btcutil](https://pkg.go.dev/github.com/btcsuite/btcd/btcutil)
- [btcd/btcutil/psbt](https://pkg.go.dev/github.com/btcsuite/btcd/btcutil/psbt)
- [btcd/chaincfg](https://pkg.go.dev/github.com/btcsuite/btcd@v0.25.0/chaincfg)
- [btcd/chaincfg/chainash](https://pkg.go.dev/github.com/btcsuite/btcd/chaincfg/chainhash)
- [btcd/txscript](https://pkg.go.dev/github.com/btcsuite/btcd@v0.25.0/txscript)

All functions are **async** (they ensure the WASM module is loaded on first
call). Byte data is represented as **hex strings** throughout. Network
parameters accept `"mainnet"` (default), `"testnet"` / `"testnet3"`,
`"testnet4"`, `"signet"`, `"regtest"`, or `"simnet"`.

---

### `init(wasmSource?)`

Explicitly initialize the WASM module. Called automatically on the first API
call. Accepts an optional `ArrayBuffer`, `Response`, or URL string.

---

### `base58`

Base58 encoding and decoding (with and without check).

| Method | Go function | Description |
|--------|-------------|-------------|
| `encode(hexData)` | `base58.Encode()` | Encode bytes to a base58 string. |
| `decode(str)` | `base58.Decode()` | Decode a base58 string to bytes (hex). |
| `checkEncode(hexData, version)` | `base58.CheckEncode()` | Encode with a version byte and checksum. |
| `checkDecode(str)` | `base58.CheckDecode()` | Decode and verify checksum. Returns `{ data, version }`. |

---

### `bech32`

Bech32 and bech32m encoding/decoding.

| Method | Go function | Description |
|--------|-------------|-------------|
| `encode(hrp, hexData5bit)` | `bech32.Encode()` | Bech32-encode 5-bit data with the given HRP. |
| `encodeM(hrp, hexData5bit)` | `bech32.EncodeM()` | Bech32m-encode 5-bit data with the given HRP. |
| `decode(str)` | `bech32.Decode()` | Decode a bech32 string (90-char limit). Returns `{ hrp, data }`. |
| `decodeNoLimit(str)` | `bech32.DecodeNoLimit()` | Decode without length limit. Returns `{ hrp, data }`. |
| `encodeFromBase256(hrp, hexData)` | `bech32.EncodeFromBase256()` | Encode base-256 data (handles 8→5 bit conversion). |
| `decodeToBase256(str)` | `bech32.DecodeToBase256()` | Decode to base-256 data (handles 5→8 bit conversion). Returns `{ hrp, data }`. |
| `convertBits(hexData, fromBits, toBits, pad)` | `bech32.ConvertBits()` | Convert between bit groups (e.g. 8→5 or 5→8). |

---

### `address`

Bitcoin address encoding, decoding, and creation.

| Method | Go function | Description |
|--------|-------------|-------------|
| `decode(addr, network?)` | `btcutil.DecodeAddress()` | Decode an address string. Returns `AddressInfo` with `type`, `scriptAddress`, `witnessVersion`, etc. |
| `fromPubKeyHash(hexHash, network?)` | `btcutil.NewAddressPubKeyHash()` | Create a P2PKH address from a 20-byte pubkey hash. |
| `fromScriptHash(hexHash, network?)` | `btcutil.NewAddressScriptHashFromHash()` | Create a P2SH address from a 20-byte script hash. |
| `fromScript(hexScript, network?)` | `btcutil.NewAddressScriptHash()` | Create a P2SH address by hashing a serialized script. |
| `fromWitnessPubKeyHash(hexProgram, network?)` | `btcutil.NewAddressWitnessPubKeyHash()` | Create a P2WPKH address from a 20-byte witness program. |
| `fromWitnessScriptHash(hexProgram, network?)` | `btcutil.NewAddressWitnessScriptHash()` | Create a P2WSH address from a 32-byte witness program. |
| `fromTaproot(hexProgram, network?)` | `btcutil.NewAddressTaproot()` | Create a P2TR (Taproot) address from a 32-byte witness program. |
| `fromPubKey(hexPubKey, network?)` | `btcutil.NewAddressPubKey()` | Create a P2PK address from a serialized public key. |

---

### `amount`

Bitcoin amount conversions between BTC and satoshis.

| Method | Go function | Description |
|--------|-------------|-------------|
| `fromBTC(btc)` | `btcutil.NewAmount()` | Convert a BTC float to satoshis. |
| `toBTC(satoshis)` | `Amount.ToBTC()` | Convert satoshis to BTC. |
| `format(satoshis, unit?)` | `Amount.Format()` | Format with a unit label. Units: `"BTC"`, `"mBTC"`, `"uBTC"`, `"satoshi"` / `"sat"`. |

---

### `hash`

Cryptographic hash functions.

| Method | Go function | Description |
|--------|-------------|-------------|
| `hash160(hexData)` | `btcutil.Hash160()` | Compute RIPEMD160(SHA256(data)). |

---

### `wif`

Wallet Import Format encoding and decoding.

| Method | Go function | Description |
|--------|-------------|-------------|
| `decode(wifStr)` | `btcutil.DecodeWIF()` | Decode a WIF string. Returns `{ privateKey, compressPubKey, publicKey, network }`. |
| `encode(hexPrivateKey, network?, compress?)` | `btcutil.NewWIF()` | Encode a private key as a WIF string. `compress` defaults to `true`. |

---

### `hdkeychain`

BIP-32 hierarchical deterministic key derivation.

| Method | Go function | Description |
|--------|-------------|-------------|
| `newMaster(hexSeed, network?)` | `hdkeychain.NewMaster()` | Create a master extended key from a seed. |
| `fromString(key)` | `hdkeychain.NewKeyFromString()` | Parse an xprv/xpub/tprv/tpub string. Returns `ExtendedKeyInfo`. |
| `derive(key, index)` | `ExtendedKey.Derive()` | Derive a child key at the given index. |
| `deriveHardened(key, index)` | `ExtendedKey.Derive()` | Derive a hardened child (adds `0x80000000` automatically). |
| `derivePath(key, path)` | `ExtendedKey.Derive()` | Derive along a BIP-32 path like `"m/44'/0'/0'/0/0"`. |
| `neuter(key)` | `ExtendedKey.Neuter()` | Convert a private key to its public counterpart. |
| `generateSeed(length?)` | `hdkeychain.GenerateSeed()` | Generate a random seed (default 32 bytes). |
| `publicKey(key)` | `ExtendedKey.ECPubKey()` | Get the compressed public key (hex). |
| `address(key, network?)` | `ExtendedKey.Address()` | Get the P2PKH address. |

---

### `bip322`

BIP-322 generic signed message verification.

| Method | Go function | Description |
|--------|-------------|-------------|
| `verifyMessage(message, address, signature, network?)` | `bip322.VerifyMessage()` | Verify a BIP-322 signed message. Returns `{ valid, error? }`. |

Supports **P2WPKH**, **P2SH-P2WPKH**, **P2TR** (Taproot), and **multisig**
address types.

---

### `txsort`

BIP-69 deterministic transaction sorting.

| Method | Go function | Description |
|--------|-------------|-------------|
| `sort(hexRawTx)` | `txsort.Sort()` | Sort inputs and outputs per BIP-69. Returns sorted tx hex. |
| `isSorted(hexRawTx)` | `txsort.IsSorted()` | Check if a transaction is BIP-69 sorted. |

---

### `tx`

Transaction utilities.

| Method | Go function | Description |
|--------|-------------|-------------|
| `hash(hexRawTx)` | `Tx.Hash()` | Compute the txid (double-SHA256, reversed). |
| `witnessHash(hexRawTx)` | `Tx.WitnessHash()` | Compute the witness txid (wtxid). |
| `hasWitness(hexRawTx)` | `Tx.HasWitness()` | Check if the transaction contains witness data. |
| `decode(hexRawTx)` | `btcutil.NewTx()` | Decode into a structured object with `txid`, `wtxid`, `version`, `locktime`, `inputs[]`, `outputs[]`. |

---

### `psbt`

Partially Signed Bitcoin Transaction (BIP-174) utilities.

| Method | Go function | Description |
|--------|-------------|-------------|
| `decode(base64Psbt)` | `psbt.NewFromRawBytes()` | Decode a base64 PSBT. Returns `PsbtDecodeResult` with inputs, outputs, fee, etc. |
| `isComplete(base64Psbt)` | `Packet.IsComplete()` | Check if the PSBT is fully signed. |
| `extract(base64Psbt)` | `psbt.Extract()` | Extract the final signed transaction (hex). |
| `getFee(base64Psbt)` | `Packet.GetTxFee()` | Get the fee in satoshis (requires UTXO info on inputs). |
| `fromBase64(base64Psbt)` | `Packet.Serialize()` | Convert a base64 PSBT to raw bytes (hex). |
| `toBase64(hexPsbt)` | `Packet.B64Encode()` | Convert raw PSBT bytes (hex) to base64. |

---

### `gcs`

Golomb-Coded Set filter utilities (BIP-158 compact block filters).

| Method | Go function | Description |
|--------|-------------|-------------|
| `buildFilter(p, m, hexKey, hexDataItems[])` | `gcs.BuildGCSFilter()` | Build a GCS filter. Returns `{ filter, n }`. |
| `match(hexFilter, n, p, m, hexKey, hexTarget)` | `Filter.Match()` | Test if a single element matches. |
| `matchAny(hexFilter, n, p, m, hexKey, hexTargets[])` | `Filter.MatchAny()` | Test if any element matches. |

Parameters: `p` = false-positive rate (1/2^P), `m` = filter parameter M,
`hexKey` = 16-byte SipHash key.

---

### `bloom`

Bloom filter utilities.

| Method | Go function | Description |
|--------|-------------|-------------|
| `murmurHash3(seed, hexData)` | `bloom.MurmurHash3()` | Compute MurmurHash3 of data with the given seed. |

---

### `txscript`

Bitcoin transaction script analysis, creation, taproot, and signing.

**Script type checks:**

| Method | Go function | Description |
|--------|-------------|-------------|
| `isPayToPubKey(hexScript)` | `txscript.IsPayToPubKey()` | Check if script is P2PK. |
| `isPayToPubKeyHash(hexScript)` | `txscript.IsPayToPubKeyHash()` | Check if script is P2PKH. |
| `isPayToScriptHash(hexScript)` | `txscript.IsPayToScriptHash()` | Check if script is P2SH. |
| `isPayToWitnessPubKeyHash(hexScript)` | `txscript.IsPayToWitnessPubKeyHash()` | Check if script is P2WPKH. |
| `isPayToWitnessScriptHash(hexScript)` | `txscript.IsPayToWitnessScriptHash()` | Check if script is P2WSH. |
| `isPayToTaproot(hexScript)` | `txscript.IsPayToTaproot()` | Check if script is P2TR. |
| `isWitnessProgram(hexScript)` | `txscript.IsWitnessProgram()` | Check if script is any witness program. |
| `isNullData(hexScript)` | `txscript.IsNullData()` | Check if script is OP_RETURN null data. |
| `isMultisigScript(hexScript)` | `txscript.IsMultisigScript()` | Check if script is multisig. |
| `isUnspendable(hexScript)` | `txscript.IsUnspendable()` | Check if script is provably unspendable. |
| `isPushOnlyScript(hexScript)` | `txscript.IsPushOnlyScript()` | Check if script contains only push ops. |
| `scriptHasOpSuccess(hexScript)` | `txscript.ScriptHasOpSuccess()` | Check if script contains OP_SUCCESS. |

**Script analysis:**

| Method | Go function | Description |
|--------|-------------|-------------|
| `disasmString(hexScript)` | `txscript.DisasmString()` | Disassemble script to human-readable opcodes. |
| `getScriptClass(hexScript)` | `txscript.GetScriptClass()` | Get the standard script class name. |
| `extractWitnessProgramInfo(hexScript)` | `txscript.ExtractWitnessProgramInfo()` | Extract witness version and program. Returns `{ version, program }`. |
| `extractPkScriptAddrs(hexScript, network?)` | `txscript.ExtractPkScriptAddrs()` | Extract addresses and required sigs. Returns `{ scriptClass, addresses[], reqSigs }`. |
| `pushedData(hexScript)` | `txscript.PushedData()` | Extract all data pushes from a script. |
| `getSigOpCount(hexScript)` | `txscript.GetSigOpCount()` | Count signature operations in a script. |
| `calcMultiSigStats(hexScript)` | `txscript.CalcMultiSigStats()` | Get multisig stats. Returns `{ numPubKeys, numSigs }`. |
| `parsePkScript(hexScript, network?)` | `txscript.ParsePkScript()` | Parse into `{ class, script, address? }`. |
| `computePkScript(hexSigScript, hexWitness[], network?)` | `txscript.ComputePkScript()` | Recover pkScript from spent input's sigScript/witness. |

**Script creation:**

| Method | Go function | Description |
|--------|-------------|-------------|
| `payToAddrScript(address, network?)` | `txscript.PayToAddrScript()` | Create a pkScript paying to an address. |
| `nullDataScript(hexData)` | `txscript.NullDataScript()` | Create an OP_RETURN null data script. |
| `payToTaprootScript(hexPubKey)` | `txscript.PayToTaprootScript()` | Create a P2TR script from a 32-byte x-only key. |
| `multiSigScript(hexPubKeys[], nRequired, network?)` | `txscript.MultiSigScript()` | Create a multisig script. |

**Taproot:**

| Method | Go function | Description |
|--------|-------------|-------------|
| `computeTaprootOutputKey(hexInternalKey, hexScriptRoot?)` | `txscript.ComputeTaprootOutputKey()` | Compute tweaked output key. |
| `computeTaprootKeyNoScript(hexInternalKey)` | `txscript.ComputeTaprootKeyNoScript()` | Compute output key for key-only spend (BIP-86). |
| `tweakTaprootPrivKey(hexPrivKey, hexScriptRoot?)` | `txscript.TweakTaprootPrivKey()` | Tweak a private key for taproot key-path spending. |
| `parseControlBlock(hexControlBlock)` | `txscript.ParseControlBlock()` | Parse a serialized control block. |
| `assembleTaprootScriptTree(hexInternalKey, leaves[])` | `txscript.AssembleTaprootScriptTree()` | Build a script tree with control blocks. Returns `{ outputKey, merkleRoot, leaves[] }`. |

**Signature hashing:**

| Method | Go function | Description |
|--------|-------------|-------------|
| `calcSignatureHash(hexScript, hashType, hexRawTx, idx)` | `txscript.CalcSignatureHash()` | Legacy (pre-segwit) sighash. |
| `calcWitnessSigHash(hexScript, hashType, hexRawTx, idx, amount)` | `txscript.CalcWitnessSigHash()` | BIP-143 witness v0 sighash. |
| `calcTaprootSignatureHash(hashType, hexRawTx, idx, prevOuts[])` | `txscript.CalcTaprootSignatureHash()` | BIP-341 taproot sighash. |

**Signing:**

| Method | Go function | Description |
|--------|-------------|-------------|
| `rawTxInSignature(hexRawTx, idx, hexSubScript, hashType, hexPrivKey)` | `txscript.RawTxInSignature()` | Legacy input signature (DER + hashType). |
| `rawTxInWitnessSignature(hexRawTx, idx, amount, hexSubScript, hashType, hexPrivKey)` | `txscript.RawTxInWitnessSignature()` | Witness v0 input signature. |
| `witnessSignature(hexRawTx, idx, amount, hexSubScript, hashType, hexPrivKey, compress)` | `txscript.WitnessSignature()` | Complete P2WPKH witness stack (sig + pubkey). |
| `rawTxInTaprootSignature(hexRawTx, idx, hexMerkleRoot, hashType, hexPrivKey, prevOuts[])` | `txscript.RawTxInTaprootSignature()` | Taproot key-path signature. |

Hash type constants: `SigHashAll = 1`, `SigHashNone = 2`, `SigHashSingle = 3`, `SigHashAnyOneCanPay = 0x80`, `SigHashDefault = 0` (taproot).

---

### `btcec`

secp256k1 elliptic curve cryptography: key management, ECDSA, Schnorr, ECDH.

**Key management:**

| Method | Go function | Description |
|--------|-------------|-------------|
| `newPrivateKey()` | `btcec.NewPrivateKey()` | Generate a random private key. Returns `{ privateKey, publicKey }`. |
| `privKeyFromBytes(hexPrivKey)` | `btcec.PrivKeyFromBytes()` | Derive key pair from private key bytes. Returns `{ privateKey, publicKey }`. |
| `pubKeyFromBytes(hexPubKey)` | `btcec.ParsePubKey()` | Parse and normalize a public key to compressed form. |
| `isCompressedPubKey(hexPubKey)` | `btcec.IsCompressedPubKey()` | Check if public key bytes are compressed (33 bytes). |
| `serializeUncompressed(hexPubKey)` | `PublicKey.SerializeUncompressed()` | Serialize to uncompressed 65-byte form. |
| `serializeCompressed(hexPubKey)` | `PublicKey.SerializeCompressed()` | Serialize to compressed 33-byte form. |

**ECDH:**

| Method | Go function | Description |
|--------|-------------|-------------|
| `generateSharedSecret(hexPrivKey, hexPubKey)` | `btcec.GenerateSharedSecret()` | Compute ECDH shared secret (32 bytes). |

**ECDSA:**

| Method | Go function | Description |
|--------|-------------|-------------|
| `ecdsaSign(hexPrivKey, hexHash)` | `ecdsa.Sign()` | Sign a 32-byte hash (RFC 6979). Returns DER-encoded signature. |
| `ecdsaVerify(hexPubKey, hexHash, hexSig)` | `Signature.Verify()` | Verify a DER-encoded ECDSA signature. |
| `ecdsaSignCompact(hexPrivKey, hexHash, isCompressed)` | `ecdsa.SignCompact()` | Sign and return a 65-byte recoverable compact signature. |
| `ecdsaRecoverCompact(hexSig, hexHash)` | `ecdsa.RecoverCompact()` | Recover public key from compact signature. Returns `{ publicKey, compressed }`. |
| `ecdsaParseSignature(hexSig)` | `ecdsa.ParseSignature()` | Parse and normalize a BER-encoded signature. |
| `ecdsaParseDERSignature(hexSig)` | `ecdsa.ParseDERSignature()` | Parse a strict DER-encoded signature. |

**Schnorr (BIP-340):**

| Method | Go function | Description |
|--------|-------------|-------------|
| `schnorrSign(hexPrivKey, hexHash)` | `schnorr.Sign()` | Sign a 32-byte hash. Returns 64-byte signature. |
| `schnorrVerify(hexPubKey, hexHash, hexSig)` | `Signature.Verify()` | Verify a Schnorr signature. |
| `schnorrParsePubKey(hexXOnlyPubKey)` | `schnorr.ParsePubKey()` | Parse a 32-byte x-only key. Returns 33-byte compressed. |
| `schnorrSerializePubKey(hexPubKey)` | `schnorr.SerializePubKey()` | Serialize to 32-byte x-only format. |
| `schnorrParseSignature(hexSig)` | `schnorr.ParseSignature()` | Parse a 64-byte Schnorr signature. |

---

### `chaincfg`

Bitcoin network configuration parameters.

| Method | Go function | Description |
|--------|-------------|-------------|
| `getParams(network)` | `chaincfg.*NetParams` | Get network parameters. Returns `{ name, bech32HRPSegwit, pubKeyHashAddrID, ... }`. |
| `isPubKeyHashAddrID(id)` | `chaincfg.IsPubKeyHashAddrID()` | Check if byte is a known P2PKH prefix. |
| `isScriptHashAddrID(id)` | `chaincfg.IsScriptHashAddrID()` | Check if byte is a known P2SH prefix. |
| `isBech32SegwitPrefix(prefix)` | `chaincfg.IsBech32SegwitPrefix()` | Check if string is a known bech32 HRP. |
| `hdPrivateKeyToPublicKeyID(hexID)` | `chaincfg.HDPrivateKeyToPublicKeyID()` | Convert HD private key version to public. |

---

### `chainhash`

SHA-256 and tagged hash utilities.

| Method | Go function | Description |
|--------|-------------|-------------|
| `hash(hexData)` | `chainhash.HashB()` | Compute SHA-256. |
| `doubleHash(hexData)` | `chainhash.DoubleHashB()` | Compute SHA-256d (double SHA-256). |
| `taggedHash(hexTag, hexMsgs[])` | `chainhash.TaggedHash()` | Compute BIP-340 tagged hash. |
| `newHashFromStr(hashStr)` | `chainhash.NewHashFromStr()` | Parse a byte-reversed hash string (like a txid) to raw bytes. |
| `hashToString(hexHash)` | `Hash.String()` | Convert raw bytes to byte-reversed display string. |

---

## Testing

```bash
npm run build
npm test
```

Tests cover all namespaces including BIP-322 test vectors, ECDSA/Schnorr
signing round-trips, taproot script tree assembly, and sighash computation.

## License

MIT
