module github.com/guggero/btcutil-js/wasm-wrapper

go 1.26.10

require (
	github.com/btcsuite/btcd/address/v2 v2.0.0
	github.com/btcsuite/btcd/bip322 v1.0.0
	github.com/btcsuite/btcd/btcec/v2 v2.5.0
	github.com/btcsuite/btcd/btcutil/v2 v2.0.1
	github.com/btcsuite/btcd/chaincfg/v2 v2.0.0
	github.com/btcsuite/btcd/chainhash/v2 v2.0.0
	github.com/btcsuite/btcd/descriptors v1.0.0
	github.com/btcsuite/btcd/psbt/v2 v2.0.0
	github.com/btcsuite/btcd/silentpayments v1.0.0
	github.com/btcsuite/btcd/txscript/v2 v2.0.0
	github.com/btcsuite/btcd/wire/v2 v2.0.1
)

require (
	github.com/aead/siphash v1.0.1 // indirect
	github.com/btcsuite/btclog v1.0.0 // indirect
	github.com/decred/dcrd/crypto/blake256 v1.1.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1 // indirect
	github.com/kkdai/bstream v1.0.0 // indirect
	golang.org/x/crypto v0.58.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
)

// This single commit is the head of a branch that contains the following
// unmerged btcd PRs in order:
//  - https://github.com/btcsuite/btcd/pull/2521
//  - https://github.com/btcsuite/btcd/pull/2568
//  - https://github.com/btcsuite/btcd/pull/2466
//  - https://github.com/btcsuite/btcd/pull/2198
//  - the op-templatehash branch (BIP 446, 348 and 349, no PR yet)
replace (
	github.com/btcsuite/btcd/bip322 => github.com/guggero/btcd/bip322 v0.0.0-20261112093439-b24ef08df461
	github.com/btcsuite/btcd/btcec/v2 => github.com/guggero/btcd/btcec/v2 v2.0.0-20261112093439-b24ef08df461
	github.com/btcsuite/btcd/btcutil/v2 => github.com/guggero/btcd/btcutil/v2 v2.0.0-20261112093439-b24ef08df461
	github.com/btcsuite/btcd/chaincfg/v2 => github.com/guggero/btcd/chaincfg/v2 v2.0.0-20261112093439-b24ef08df461
	github.com/btcsuite/btcd/descriptors => github.com/guggero/btcd/descriptors v0.0.0-20261112093439-b24ef08df461
	github.com/btcsuite/btcd/psbt/v2 => github.com/guggero/btcd/psbt/v2 v2.0.0-20261112093439-b24ef08df461
	github.com/btcsuite/btcd/silentpayments => github.com/guggero/btcd/silentpayments v0.0.0-20261112093439-b24ef08df461
	github.com/btcsuite/btcd/txscript/v2 => github.com/guggero/btcd/txscript/v2 v2.0.0-20261112093439-b24ef08df461
	github.com/btcsuite/btcd/wire/v2 => github.com/guggero/btcd/wire/v2 v2.0.0-20261112093439-b24ef08df461
)
