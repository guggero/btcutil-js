module github.com/guggero/btcutil-js/wasm-wrapper

go 1.26.1

require (
	github.com/btcsuite/btcd/address/v2 v2.0.0
	github.com/btcsuite/btcd/bip322 v1.0.0
	github.com/btcsuite/btcd/btcec/v2 v2.5.0
	github.com/btcsuite/btcd/btcutil/v2 v2.0.0
	github.com/btcsuite/btcd/chaincfg/v2 v2.0.0
	github.com/btcsuite/btcd/chainhash/v2 v2.0.0
	github.com/btcsuite/btcd/descriptors v1.0.0
	github.com/btcsuite/btcd/psbt/v2 v2.0.0
	github.com/btcsuite/btcd/silentpayments v1.0.0
	github.com/btcsuite/btcd/txscript/v2 v2.0.0
	github.com/btcsuite/btcd/wire/v2 v2.0.0
)

require (
	github.com/aead/siphash v1.0.1 // indirect
	github.com/btcsuite/btclog v1.0.0 // indirect
	github.com/decred/dcrd/crypto/blake256 v1.1.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0 // indirect
	github.com/kcalvinalvin/anet v0.0.0-20251112173137-d8ddc1f6dbee // indirect
	github.com/kkdai/bstream v1.0.0 // indirect
	golang.org/x/crypto v0.51.0 // indirect
	golang.org/x/sys v0.44.0 // indirect
)

// This single commit is the head of a branch that contains the following
// unmerged btcd PRs in order:
//  - https://github.com/btcsuite/btcd/pull/2521
//  - https://github.com/btcsuite/btcd/pull/2568
//  - https://github.com/btcsuite/btcd/pull/2466
replace (
	github.com/btcsuite/btcd/bip322 => github.com/guggero/btcd/bip322 v0.0.0-20260717100126-52c0c464fad6
	github.com/btcsuite/btcd/descriptors => github.com/guggero/btcd/descriptors v0.0.0-20260717100126-52c0c464fad6
	github.com/btcsuite/btcd/psbt/v2 => github.com/guggero/btcd/psbt/v2 v2.0.0-20260717100126-52c0c464fad6
	github.com/btcsuite/btcd/silentpayments => github.com/guggero/btcd/silentpayments v0.0.0-20260719104849-6acff1fa788a
	github.com/btcsuite/btcd/txscript/v2 => github.com/guggero/btcd/txscript/v2 v2.0.0-20260717100126-52c0c464fad6
)
