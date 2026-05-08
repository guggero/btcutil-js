module github.com/guggero/btcutil-js/wasm-wrapper

go 1.26.1

require (
	github.com/btcsuite/btcd v0.25.0
	github.com/btcsuite/btcd/btcec/v2 v2.3.5
	github.com/btcsuite/btcd/btcutil v1.1.6
	github.com/btcsuite/btcd/btcutil/bip322 v1.0.0
	github.com/btcsuite/btcd/btcutil/psbt v1.1.10
	github.com/btcsuite/btcd/chaincfg/chainhash v1.1.0
)

require (
	github.com/aead/siphash v1.0.1 // indirect
	github.com/btcsuite/btclog v1.0.0 // indirect
	github.com/decred/dcrd/crypto/blake256 v1.0.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.1 // indirect
	github.com/kkdai/bstream v0.0.0-20161212061736-f391b8402d23 // indirect
	golang.org/x/crypto v0.45.0 // indirect
	golang.org/x/sys v0.38.0 // indirect
)

// The BIP-322 package is not yet merged. The PR also updates the psbt package.
replace (
	github.com/btcsuite/btcd/btcutil/bip322 => github.com/guggero/btcd/btcutil/bip322 v0.0.0-20260429110905-6e4a7dee1f0a
	github.com/btcsuite/btcd/btcutil/psbt => github.com/guggero/btcd/btcutil/psbt v0.0.0-20260429110905-6e4a7dee1f0a
)
