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

// The BIP-322 package is not yet merged. The PR also updates the psbt package.
replace (
	github.com/btcsuite/btcd/bip322 => github.com/guggero/btcd/bip322 v0.0.0-20260703084944-26b19cc04355
	github.com/btcsuite/btcd/psbt/v2 => github.com/guggero/btcd/psbt/v2 v2.0.0-20260703084944-26b19cc04355
	github.com/btcsuite/btcd/txscript/v2 => github.com/guggero/btcd/txscript/v2 v2.0.0-20260703084944-26b19cc04355
)

// The descriptors package also isn't merged yet.
replace github.com/btcsuite/btcd/descriptors => github.com/guggero/btcd/descriptors v0.0.0-20260707160445-fd5e24753cfc
