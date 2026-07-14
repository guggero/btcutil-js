//go:build js && wasm

package main

// The musig2 namespace wraps the low-level BIP-327 MuSig2 functions of
// btcec/v2/schnorr/musig2 — deliberately the step-by-step primitives rather
// than the Session/Context API, so an educational UI can display every
// intermediate value of the two-round flow: aggregate keys, generate and
// aggregate nonces, partial-sign, combine.
//
// All functions use the BIP-327 convention of lexicographically sorted
// public keys, so callers can pass the key list in any order as long as
// they pass the same list everywhere.

import (
	"syscall/js"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
)

// pubKeysFromArg parses a JS array of 33-byte compressed public keys.
func pubKeysFromArg(arg js.Value) ([]*btcec.PublicKey, map[string]any) {
	n := arg.Length()
	if n == 0 {
		return nil, errResult("at least one public key is required")
	}
	keys := make([]*btcec.PublicKey, n)
	for i := 0; i < n; i++ {
		raw, e := bytesFromArg(arg.Index(i))
		if e != nil {
			return nil, e
		}
		key, err := btcec.ParsePubKey(raw)
		if err != nil {
			return nil, errfResult("invalid public key %d: %s", i,
				err)
		}
		keys[i] = key
	}
	return keys, nil
}

// musig2AggregateKeys combines the signers' public keys into the single
// aggregated MuSig2 key.
// Calls Go: musig2.AggregateKeys() from btcec/schnorr/musig2.
func musig2AggregateKeys(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "pubKeys"); e != nil {
		return e
	}
	keys, e := pubKeysFromArg(args[0])
	if e != nil {
		return e
	}

	agg, _, _, err := musig2.AggregateKeys(keys, true)
	if err != nil {
		return errfResult("aggregate keys: %s", err)
	}

	compressed := agg.FinalKey.SerializeCompressed()
	return okResult(map[string]any{
		"combinedKey": bytesToJS(compressed),
		"xOnlyKey":    bytesToJS(schnorr.SerializePubKey(agg.FinalKey)),
		"parityOdd":   compressed[0] == 0x03,
	})
}

// musig2GenNonces generates the signer's secret/public nonce pair for one
// signing session. The public key is required (it is committed into the
// nonce derivation); the optional private key, combined key and message add
// further commitment entropy per BIP-327.
// Calls Go: musig2.GenNonces() from btcec/schnorr/musig2.
func musig2GenNonces(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "pubKey[, privKey, combinedKey, "+
		"msg]"); e != nil {

		return e
	}
	pubRaw, e := bytesFromArg(args[0])
	if e != nil {
		return e
	}
	pubKey, err := btcec.ParsePubKey(pubRaw)
	if err != nil {
		return errfResult("invalid public key: %s", err)
	}

	opts := []musig2.NonceGenOption{musig2.WithPublicKey(pubKey)}

	privRaw, e := optBytesFromArg(args, 1)
	if e != nil {
		return e
	}
	if privRaw != nil {
		priv, _ := btcec.PrivKeyFromBytes(privRaw)
		opts = append(opts, musig2.WithNonceSecretKeyAux(priv))
	}

	combinedRaw, e := optBytesFromArg(args, 2)
	if e != nil {
		return e
	}
	if combinedRaw != nil {
		combined, err := btcec.ParsePubKey(combinedRaw)
		if err != nil {
			return errfResult("invalid combined key: %s", err)
		}
		opts = append(opts, musig2.WithNonceCombinedKeyAux(combined))
	}

	msgRaw, e := optBytesFromArg(args, 3)
	if e != nil {
		return e
	}
	if msgRaw != nil {
		if len(msgRaw) != 32 {
			return errResult("msg must be 32 bytes")
		}
		var msg [32]byte
		copy(msg[:], msgRaw)
		opts = append(opts, musig2.WithNonceMessageAux(msg))
	}

	nonces, err := musig2.GenNonces(opts...)
	if err != nil {
		return errfResult("generate nonces: %s", err)
	}

	return okResult(map[string]any{
		"pubNonce": bytesToJS(nonces.PubNonce[:]),
		"secNonce": bytesToJS(nonces.SecNonce[:]),
	})
}

// musig2AggregateNonces combines all signers' public nonces into the single
// 66-byte combined nonce.
// Calls Go: musig2.AggregateNonces() from btcec/schnorr/musig2.
func musig2AggregateNonces(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "pubNonces"); e != nil {
		return e
	}

	n := args[0].Length()
	nonces := make([][musig2.PubNonceSize]byte, n)
	for i := 0; i < n; i++ {
		raw, e := bytesFromArg(args[0].Index(i))
		if e != nil {
			return e
		}
		if len(raw) != musig2.PubNonceSize {
			return errfResult("public nonce %d must be %d bytes",
				i, musig2.PubNonceSize)
		}
		copy(nonces[i][:], raw)
	}

	combined, err := musig2.AggregateNonces(nonces)
	if err != nil {
		return errfResult("aggregate nonces: %s", err)
	}
	return okResult(bytesToJS(combined[:]))
}

// musig2PartialSign creates one signer's partial signature. It returns the
// 32-byte partial signature s and the 33-byte final nonce R, which every
// signer computes identically and combineSigs needs.
// Calls Go: musig2.Sign() from btcec/schnorr/musig2.
func musig2PartialSign(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 5, "secNonce, privKey, combinedNonce, "+
		"pubKeys, msg"); e != nil {

		return e
	}

	secRaw, e := bytesFromArg(args[0])
	if e != nil {
		return e
	}
	if len(secRaw) != musig2.SecNonceSize {
		return errfResult("secNonce must be %d bytes",
			musig2.SecNonceSize)
	}
	var secNonce [musig2.SecNonceSize]byte
	copy(secNonce[:], secRaw)

	privRaw, e := bytesFromArg(args[1])
	if e != nil {
		return e
	}
	privKey, _ := btcec.PrivKeyFromBytes(privRaw)

	combinedRaw, e := bytesFromArg(args[2])
	if e != nil {
		return e
	}
	if len(combinedRaw) != musig2.PubNonceSize {
		return errfResult("combinedNonce must be %d bytes",
			musig2.PubNonceSize)
	}
	var combinedNonce [musig2.PubNonceSize]byte
	copy(combinedNonce[:], combinedRaw)

	keys, e := pubKeysFromArg(args[3])
	if e != nil {
		return e
	}

	msgRaw, e := bytesFromArg(args[4])
	if e != nil {
		return e
	}
	if len(msgRaw) != 32 {
		return errResult("msg must be 32 bytes")
	}
	var msg [32]byte
	copy(msg[:], msgRaw)

	partial, err := musig2.Sign(
		secNonce, privKey, combinedNonce, keys, msg,
		musig2.WithSortedKeys(),
	)
	if err != nil {
		return errfResult("partial sign: %s", err)
	}

	s := partial.S.Bytes()
	return okResult(map[string]any{
		"s": bytesToJS(s[:]),
		"r": bytesToJS(partial.R.SerializeCompressed()),
	})
}

// musig2CombineSigs combines all partial signatures (the 32-byte s values)
// with the final nonce R (returned by partialSign) into the final 64-byte
// BIP-340 Schnorr signature.
// Calls Go: musig2.CombineSigs() from btcec/schnorr/musig2.
func musig2CombineSigs(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 2, "finalNonce, partialSigs"); e != nil {
		return e
	}

	nonceRaw, e := bytesFromArg(args[0])
	if e != nil {
		return e
	}
	finalNonce, err := btcec.ParsePubKey(nonceRaw)
	if err != nil {
		return errfResult("invalid final nonce: %s", err)
	}

	n := args[1].Length()
	if n == 0 {
		return errResult("at least one partial signature is required")
	}
	partials := make([]*musig2.PartialSignature, n)
	for i := 0; i < n; i++ {
		raw, e := bytesFromArg(args[1].Index(i))
		if e != nil {
			return e
		}
		if len(raw) != 32 {
			return errfResult("partial signature %d must be 32 "+
				"bytes", i)
		}
		var s btcec.ModNScalar
		if overflow := s.SetByteSlice(raw); overflow {
			return errfResult("partial signature %d overflows "+
				"the curve order", i)
		}
		partials[i] = &musig2.PartialSignature{S: &s}
	}

	sig := musig2.CombineSigs(finalNonce, partials)
	return okResult(bytesToJS(sig.Serialize()))
}
