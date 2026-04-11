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
call) — see [Synchronous API](#synchronous-api) above for a sync alternative.
Byte parameters accept either **hex strings** or **`Uint8Array`**, and byte
returns are always **`Uint8Array`** (type alias: `Bytes = string | Uint8Array`).
Network parameters accept `"mainnet"` (default), `"testnet"` / `"testnet3"`,
`"testnet4"`, `"signet"`, `"regtest"`, or `"simnet"`.

---

### `init(wasmSource?)`

Explicitly initialize the WASM module. Called automatically on the first API
call. Accepts an optional `ArrayBuffer`, `Response`, or URL string.

---

### `base58`

Base58 encoding and decoding (with and without check).

| Method | Go function | Description                                              |
|--------|-------------|----------------------------------------------------------|
| `encode(data)` | `base58.Encode()` | Encode bytes to a base58 string.                         |
| `decode(str)` | `base58.Decode()` | Decode a base58 string to bytes (Uint8Array).            |
| `checkEncode(data, version)` | `base58.CheckEncode()` | Encode with a version byte and checksum.                 |
| `checkDecode(str)` | `base58.CheckDecode()` | Decode and verify checksum. Returns `{ data, version }`. |

---

### `bech32`

Bech32 and bech32m encoding/decoding.

| Method | Go function | Description |
|--------|-------------|-------------|
| `encode(hrp, data5bit)` | `bech32.Encode()` | Bech32-encode 5-bit data with the given HRP. |
| `encodeM(hrp, data5bit)` | `bech32.EncodeM()` | Bech32m-encode 5-bit data with the given HRP. |
| `decode(str)` | `bech32.Decode()` | Decode a bech32 string (90-char limit). Returns `{ hrp, data }`. |
| `decodeNoLimit(str)` | `bech32.DecodeNoLimit()` | Decode without length limit. Returns `{ hrp, data }`. |
| `encodeFromBase256(hrp, data)` | `bech32.EncodeFromBase256()` | Encode base-256 data (handles 8→5 bit conversion). |
| `decodeToBase256(str)` | `bech32.DecodeToBase256()` | Decode to base-256 data (handles 5→8 bit conversion). Returns `{ hrp, data }`. |
| `convertBits(data, fromBits, toBits, pad)` | `bech32.ConvertBits()` | Convert between bit groups (e.g. 8→5 or 5→8). |

---

### `address`

Bitcoin address encoding, decoding, and creation.

| Method | Go function | Description |
|--------|-------------|-------------|
| `decode(addr, network?)` | `btcutil.DecodeAddress()` | Decode an address string. Returns `AddressInfo` with `type`, `scriptAddress`, `witnessVersion`, etc. |
| `fromPubKeyHash(hash, network?)` | `btcutil.NewAddressPubKeyHash()` | Create a P2PKH address from a 20-byte pubkey hash. |
| `fromScriptHash(hash, network?)` | `btcutil.NewAddressScriptHashFromHash()` | Create a P2SH address from a 20-byte script hash. |
| `fromScript(script, network?)` | `btcutil.NewAddressScriptHash()` | Create a P2SH address by hashing a serialized script. |
| `fromWitnessPubKeyHash(program, network?)` | `btcutil.NewAddressWitnessPubKeyHash()` | Create a P2WPKH address from a 20-byte witness program. |
| `fromWitnessScriptHash(program, network?)` | `btcutil.NewAddressWitnessScriptHash()` | Create a P2WSH address from a 32-byte witness program. |
| `fromTaproot(program, network?)` | `btcutil.NewAddressTaproot()` | Create a P2TR (Taproot) address from a 32-byte witness program. |
| `fromPubKey(pubKey, network?)` | `btcutil.NewAddressPubKey()` | Create a P2PK address from a serialized public key. |

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
| `hash160(data)` | `btcutil.Hash160()` | Compute RIPEMD160(SHA256(data)). |

---

### `wif`

Wallet Import Format encoding and decoding.

| Method | Go function | Description |
|--------|-------------|-------------|
| `decode(wifStr)` | `btcutil.DecodeWIF()` | Decode a WIF string. Returns `{ privateKey, compressPubKey, publicKey, network }`. |
| `encode(privateKey, network?, compress?)` | `btcutil.NewWIF()` | Encode a private key as a WIF string. `compress` defaults to `true`. |

---

### `hdkeychain`

BIP-32 hierarchical deterministic key derivation.

| Method | Go function | Description |
|--------|-------------|-------------|
| `newMaster(seed, network?)` | `hdkeychain.NewMaster()` | Create a master extended key from a seed. |
| `fromString(key)` | `hdkeychain.NewKeyFromString()` | Parse an xprv/xpub/tprv/tpub string. Returns `ExtendedKeyInfo`. |
| `derive(key, index)` | `ExtendedKey.Derive()` | Derive a child key at the given index. |
| `deriveHardened(key, index)` | `ExtendedKey.Derive()` | Derive a hardened child (adds `0x80000000` automatically). |
| `derivePath(key, path)` | `ExtendedKey.Derive()` | Derive along a BIP-32 path like `"m/44'/0'/0'/0/0"`. |
| `neuter(key)` | `ExtendedKey.Neuter()` | Convert a private key to its public counterpart. |
| `generateSeed(length?)` | `hdkeychain.GenerateSeed()` | Generate a random seed (default 32 bytes). |
| `publicKey(key)` | `ExtendedKey.ECPubKey()` | Get the compressed public key (Uint8Array). |
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
| `sort(rawTx)` | `txsort.Sort()` | Sort inputs and outputs per BIP-69. Returns sorted tx Uint8Array. |
| `isSorted(rawTx)` | `txsort.IsSorted()` | Check if a transaction is BIP-69 sorted. |

---

### `tx`

Transaction utilities.

| Method | Go function | Description |
|--------|-------------|-------------|
| `hash(rawTx)` | `Tx.Hash()` | Compute the txid (double-SHA256, reversed). |
| `witnessHash(rawTx)` | `Tx.WitnessHash()` | Compute the witness txid (wtxid). |
| `hasWitness(rawTx)` | `Tx.HasWitness()` | Check if the transaction contains witness data. |
| `decode(rawTx)` | `btcutil.NewTx()` | Decode into a structured object with `txid`, `wtxid`, `version`, `locktime`, `inputs[]`, `outputs[]`. |

---

### `psbt`

Partially Signed Bitcoin Transaction (BIP-174) utilities. Mutating functions
take a base64 PSBT, apply the change, and return a new base64 PSBT:

```typescript
let p = await psbt.create(inputs, outputs);
p = await psbt.addInWitnessUtxo(p, 0, 50000, pkScript);
const { psbt: signed } = await psbt.sign(p, 0, sig, pubKey);
const finalized = await psbt.maybeFinalizeAll(signed);
const rawTx = await psbt.extract(finalized);
```

**Read-only:**

| Method | Go function | Description |
|--------|-------------|-------------|
| `decode(base64Psbt)` | `psbt.NewFromRawBytes()` | Decode a PSBT with all per-input/output fields (partial sigs, BIP-32 derivation, taproot fields, etc.). |
| `isComplete(base64Psbt)` | `Packet.IsComplete()` | Check if all inputs are finalized. |
| `extract(base64Psbt)` | `psbt.Extract()` | Extract the final signed transaction. |
| `getFee(base64Psbt)` | `Packet.GetTxFee()` | Get the fee in satoshis (requires UTXO info). |
| `fromBase64(base64Psbt)` | `Packet.Serialize()` | Convert base64 PSBT to raw bytes. |
| `toBase64(psbtData)` | `Packet.B64Encode()` | Convert raw PSBT bytes to base64. |
| `sumUtxoInputValues(base64Psbt)` | `psbt.SumUtxoInputValues()` | Sum all input UTXO values in satoshis. |
| `inputsReadyToSign(base64Psbt)` | `psbt.InputsReadyToSign()` | Verify all inputs have UTXO info. Throws on error. |
| `sanityCheck(base64Psbt)` | `Packet.SanityCheck()` | Validate PSBT format per BIP-174. Throws on error. |

**Creation:**

| Method | Go function | Description |
|--------|-------------|-------------|
| `create(inputs[], outputs[], version?, lockTime?)` | `psbt.New()` | Create a new PSBT. Inputs: `{txid, vout, sequence?}`. Outputs: `{value, script}`. |
| `fromUnsignedTx(rawTx)` | `psbt.NewFromUnsignedTx()` | Create a PSBT from an unsigned raw transaction. |

**Updater — inputs:**

| Method | Go function | Description |
|--------|-------------|-------------|
| `addInNonWitnessUtxo(psbt, inIndex, rawTx)` | `Updater.AddInNonWitnessUtxo()` | Add full previous transaction for non-segwit. |
| `addInWitnessUtxo(psbt, inIndex, value, pkScript)` | `Updater.AddInWitnessUtxo()` | Add witness UTXO for segwit. |
| `addInSighashType(psbt, inIndex, sighashType)` | `Updater.AddInSighashType()` | Set sighash type for an input. |
| `addInRedeemScript(psbt, inIndex, script)` | `Updater.AddInRedeemScript()` | Add P2SH redeem script. |
| `addInWitnessScript(psbt, inIndex, script)` | `Updater.AddInWitnessScript()` | Add witness script. |
| `addInBip32Derivation(psbt, inIndex, fp, path, pubKey)` | `Updater.AddInBip32Derivation()` | Add BIP-32 derivation info. |

**Updater — outputs:**

| Method | Go function | Description |
|--------|-------------|-------------|
| `addOutBip32Derivation(psbt, outIndex, fp, path, pubKey)` | `Updater.AddOutBip32Derivation()` | Add BIP-32 derivation info. |
| `addOutRedeemScript(psbt, outIndex, script)` | `Updater.AddOutRedeemScript()` | Add P2SH redeem script. |
| `addOutWitnessScript(psbt, outIndex, script)` | `Updater.AddOutWitnessScript()` | Add witness script. |

**Signing:**

| Method | Go function | Description |
|--------|-------------|-------------|
| `sign(psbt, inIndex, sig, pubKey, redeemScript?, witnessScript?)` | `Updater.Sign()` | Attach a signature. Returns `{psbt, outcome}` (0=success, 1=finalized, -1=invalid). |

**Finalization:**

| Method | Go function | Description |
|--------|-------------|-------------|
| `finalize(psbt, inIndex)` | `psbt.Finalize()` | Finalize a specific input. |
| `maybeFinalize(psbt, inIndex)` | `psbt.MaybeFinalize()` | Try to finalize. Returns `{psbt, finalized}`. |
| `maybeFinalizeAll(psbt)` | `psbt.MaybeFinalizeAll()` | Try to finalize all inputs. |

**Sorting:**

| Method | Go function | Description |
|--------|-------------|-------------|
| `inPlaceSort(psbt)` | `psbt.InPlaceSort()` | Sort inputs/outputs per BIP-69. |

---

### `gcs`

Golomb-Coded Set filter utilities (BIP-158 compact block filters).

| Method | Go function | Description |
|--------|-------------|-------------|
| `buildFilter(p, m, key, dataItems[])` | `gcs.BuildGCSFilter()` | Build a GCS filter. Returns `{ filter, n }`. |
| `match(filter, n, p, m, key, target)` | `Filter.Match()` | Test if a single element matches. |
| `matchAny(filter, n, p, m, key, targets[])` | `Filter.MatchAny()` | Test if any element matches. |

Parameters: `p` = false-positive rate (1/2^P), `m` = filter parameter M,
`key` = 16-byte SipHash key.

---

### `bloom`

Bloom filter utilities.

| Method | Go function | Description |
|--------|-------------|-------------|
| `murmurHash3(seed, data)` | `bloom.MurmurHash3()` | Compute MurmurHash3 of data with the given seed. |

---

### `txscript`

Bitcoin transaction script analysis, creation, taproot, and signing.

**Script type checks:**

| Method | Go function | Description |
|--------|-------------|-------------|
| `isPayToPubKey(script)` | `txscript.IsPayToPubKey()` | Check if script is P2PK. |
| `isPayToPubKeyHash(script)` | `txscript.IsPayToPubKeyHash()` | Check if script is P2PKH. |
| `isPayToScriptHash(script)` | `txscript.IsPayToScriptHash()` | Check if script is P2SH. |
| `isPayToWitnessPubKeyHash(script)` | `txscript.IsPayToWitnessPubKeyHash()` | Check if script is P2WPKH. |
| `isPayToWitnessScriptHash(script)` | `txscript.IsPayToWitnessScriptHash()` | Check if script is P2WSH. |
| `isPayToTaproot(script)` | `txscript.IsPayToTaproot()` | Check if script is P2TR. |
| `isWitnessProgram(script)` | `txscript.IsWitnessProgram()` | Check if script is any witness program. |
| `isNullData(script)` | `txscript.IsNullData()` | Check if script is OP_RETURN null data. |
| `isMultisigScript(script)` | `txscript.IsMultisigScript()` | Check if script is multisig. |
| `isUnspendable(script)` | `txscript.IsUnspendable()` | Check if script is provably unspendable. |
| `isPushOnlyScript(script)` | `txscript.IsPushOnlyScript()` | Check if script contains only push ops. |
| `scriptHasOpSuccess(script)` | `txscript.ScriptHasOpSuccess()` | Check if script contains OP_SUCCESS. |

**Script analysis:**

| Method | Go function | Description |
|--------|-------------|-------------|
| `disasmString(script)` | `txscript.DisasmString()` | Disassemble script to human-readable opcodes. |
| `getScriptClass(script)` | `txscript.GetScriptClass()` | Get the standard script class name. |
| `extractWitnessProgramInfo(script)` | `txscript.ExtractWitnessProgramInfo()` | Extract witness version and program. Returns `{ version, program }`. |
| `extractPkScriptAddrs(script, network?)` | `txscript.ExtractPkScriptAddrs()` | Extract addresses and required sigs. Returns `{ scriptClass, addresses[], reqSigs }`. |
| `pushedData(script)` | `txscript.PushedData()` | Extract all data pushes from a script. |
| `getSigOpCount(script)` | `txscript.GetSigOpCount()` | Count signature operations in a script. |
| `calcMultiSigStats(script)` | `txscript.CalcMultiSigStats()` | Get multisig stats. Returns `{ numPubKeys, numSigs }`. |
| `parsePkScript(script, network?)` | `txscript.ParsePkScript()` | Parse into `{ class, script, address? }`. |
| `computePkScript(sigScript, witness[], network?)` | `txscript.ComputePkScript()` | Recover pkScript from spent input's sigScript/witness. |

**Script creation:**

| Method | Go function | Description |
|--------|-------------|-------------|
| `payToAddrScript(address, network?)` | `txscript.PayToAddrScript()` | Create a pkScript paying to an address. |
| `nullDataScript(data)` | `txscript.NullDataScript()` | Create an OP_RETURN null data script. |
| `payToTaprootScript(pubKey)` | `txscript.PayToTaprootScript()` | Create a P2TR script from a 32-byte x-only key. |
| `multiSigScript(pubKeys[], nRequired, network?)` | `txscript.MultiSigScript()` | Create a multisig script. |

**Taproot:**

| Method | Go function | Description |
|--------|-------------|-------------|
| `computeTaprootOutputKey(internalKey, scriptRoot?)` | `txscript.ComputeTaprootOutputKey()` | Compute tweaked output key. |
| `computeTaprootKeyNoScript(internalKey)` | `txscript.ComputeTaprootKeyNoScript()` | Compute output key for key-only spend (BIP-86). |
| `tweakTaprootPrivKey(privKey, scriptRoot?)` | `txscript.TweakTaprootPrivKey()` | Tweak a private key for taproot key-path spending. |
| `parseControlBlock(controlBlock)` | `txscript.ParseControlBlock()` | Parse a serialized control block. |
| `assembleTaprootScriptTree(internalKey, leaves[])` | `txscript.AssembleTaprootScriptTree()` | Build a script tree with control blocks. Returns `{ outputKey, merkleRoot, leaves[] }`. |

**Signature hashing:**

| Method | Go function | Description |
|--------|-------------|-------------|
| `calcSignatureHash(script, hashType, rawTx, idx)` | `txscript.CalcSignatureHash()` | Legacy (pre-segwit) sighash. |
| `calcWitnessSigHash(script, hashType, rawTx, idx, amount)` | `txscript.CalcWitnessSigHash()` | BIP-143 witness v0 sighash. |
| `calcTaprootSignatureHash(hashType, rawTx, idx, prevOuts[])` | `txscript.CalcTaprootSignatureHash()` | BIP-341 taproot sighash. |

**Signing:**

| Method | Go function | Description |
|--------|-------------|-------------|
| `rawTxInSignature(rawTx, idx, subScript, hashType, privKey)` | `txscript.RawTxInSignature()` | Legacy input signature (DER + hashType). |
| `rawTxInWitnessSignature(rawTx, idx, amount, subScript, hashType, privKey)` | `txscript.RawTxInWitnessSignature()` | Witness v0 input signature. |
| `witnessSignature(rawTx, idx, amount, subScript, hashType, privKey, compress)` | `txscript.WitnessSignature()` | Complete P2WPKH witness stack (sig + pubkey). |
| `rawTxInTaprootSignature(rawTx, idx, merkleRoot, hashType, privKey, prevOuts[])` | `txscript.RawTxInTaprootSignature()` | Taproot key-path signature. |

Hash type constants: `SigHashAll = 1`, `SigHashNone = 2`, `SigHashSingle = 3`, `SigHashAnyOneCanPay = 0x80`, `SigHashDefault = 0` (taproot).

---

### `btcec`

secp256k1 elliptic curve cryptography: key management, ECDSA, Schnorr, ECDH.

**Key management:**

| Method | Go function | Description |
|--------|-------------|-------------|
| `newPrivateKey()` | `btcec.NewPrivateKey()` | Generate a random private key. Returns `{ privateKey, publicKey }`. |
| `privKeyFromBytes(privKey)` | `btcec.PrivKeyFromBytes()` | Derive key pair from private key bytes. Returns `{ privateKey, publicKey }`. |
| `pubKeyFromBytes(pubKey)` | `btcec.ParsePubKey()` | Parse and normalize a public key to compressed form. |
| `isCompressedPubKey(pubKey)` | `btcec.IsCompressedPubKey()` | Check if public key bytes are compressed (33 bytes). |
| `serializeUncompressed(pubKey)` | `PublicKey.SerializeUncompressed()` | Serialize to uncompressed 65-byte form. |
| `serializeCompressed(pubKey)` | `PublicKey.SerializeCompressed()` | Serialize to compressed 33-byte form. |

**ECDH:**

| Method | Go function | Description |
|--------|-------------|-------------|
| `generateSharedSecret(privKey, pubKey)` | `btcec.GenerateSharedSecret()` | Compute ECDH shared secret (32 bytes). |

**ECDSA:**

| Method | Go function | Description |
|--------|-------------|-------------|
| `ecdsaSign(privKey, hash)` | `ecdsa.Sign()` | Sign a 32-byte hash (RFC 6979). Returns DER-encoded signature. |
| `ecdsaVerify(pubKey, hash, sig)` | `Signature.Verify()` | Verify a DER-encoded ECDSA signature. |
| `ecdsaSignCompact(privKey, hash, isCompressed)` | `ecdsa.SignCompact()` | Sign and return a 65-byte recoverable compact signature. |
| `ecdsaRecoverCompact(sig, hash)` | `ecdsa.RecoverCompact()` | Recover public key from compact signature. Returns `{ publicKey, compressed }`. |
| `ecdsaParseSignature(sig)` | `ecdsa.ParseSignature()` | Parse and normalize a BER-encoded signature. |
| `ecdsaParseDERSignature(sig)` | `ecdsa.ParseDERSignature()` | Parse a strict DER-encoded signature. |

**Schnorr (BIP-340):**

| Method | Go function | Description |
|--------|-------------|-------------|
| `schnorrSign(privKey, hash)` | `schnorr.Sign()` | Sign a 32-byte hash. Returns 64-byte signature. |
| `schnorrVerify(pubKey, hash, sig)` | `Signature.Verify()` | Verify a Schnorr signature. |
| `schnorrParsePubKey(xOnlyPubKey)` | `schnorr.ParsePubKey()` | Parse a 32-byte x-only key. Returns 33-byte compressed. |
| `schnorrSerializePubKey(pubKey)` | `schnorr.SerializePubKey()` | Serialize to 32-byte x-only format. |
| `schnorrParseSignature(sig)` | `schnorr.ParseSignature()` | Parse a 64-byte Schnorr signature. |

---

### `chaincfg`

Bitcoin network configuration parameters.

| Method | Go function | Description |
|--------|-------------|-------------|
| `getParams(network)` | `chaincfg.*NetParams` | Get network parameters. Returns `{ name, bech32HRPSegwit, pubKeyHashAddrID, ... }`. |
| `isPubKeyHashAddrID(id)` | `chaincfg.IsPubKeyHashAddrID()` | Check if byte is a known P2PKH prefix. |
| `isScriptHashAddrID(id)` | `chaincfg.IsScriptHashAddrID()` | Check if byte is a known P2SH prefix. |
| `isBech32SegwitPrefix(prefix)` | `chaincfg.IsBech32SegwitPrefix()` | Check if string is a known bech32 HRP. |
| `hdPrivateKeyToPublicKeyID(privateKeyID)` | `chaincfg.HDPrivateKeyToPublicKeyID()` | Convert HD private key version to public. |

---

### `chainhash`

SHA-256 and tagged hash utilities.

| Method | Go function | Description |
|--------|-------------|-------------|
| `hash(data)` | `chainhash.HashB()` | Compute SHA-256. |
| `doubleHash(data)` | `chainhash.DoubleHashB()` | Compute SHA-256d (double SHA-256). |
| `taggedHash(tag, msgs[])` | `chainhash.TaggedHash()` | Compute BIP-340 tagged hash. |
| `newHashFromStr(hashStr)` | `chainhash.NewHashFromStr()` | Parse a byte-reversed hash string (like a txid) to raw bytes. |
| `hashToString(hash)` | `Hash.String()` | Convert raw bytes to byte-reversed display string. |

---

## Testing

```bash
npm run build
npm test
```

Tests cover all namespaces including BIP-322 test vectors, ECDSA/Schnorr
signing round-trips, taproot script tree assembly, and sighash computation.

## Verifying the build

Each published release includes `dist/SHA256SUMS` (with the Go version and
SHA-256 hashes of `btcutil.wasm` and `wasm_exec.js`) and a detached PGP
signature `dist/SHA256SUMS.asc`.

Import the signing key and verify:

```bash
curl https://keybase.io/guggero/pgp_keys.asc | gpg --import
gpg --verify node_modules/btcutil-js/dist/SHA256SUMS.asc \
             node_modules/btcutil-js/dist/SHA256SUMS
```

Confirm the key fingerprint:

```bash
gpg --list-keys --with-subkey-fingerprints F4FC70F07310028424EFC20A8E4256593F177720
```

To verify the WASM blob is reproducible, rebuild from source with the same Go
version listed in `SHA256SUMS` and compare the hash:

```bash
npm run build:wasm
sha256sum dist/btcutil.wasm
```
