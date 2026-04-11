//go:build js && wasm

package main

import (
	"syscall/js"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	btcschnorr "github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// ---------------------------------------------------------------------------
// key management
// ---------------------------------------------------------------------------

func btcecNewPrivateKey(_ js.Value, args []js.Value) any {
	privKey, err := btcec.NewPrivateKey()
	if err != nil {
		return errfResult("newPrivateKey: %s", err)
	}
	return okResult(map[string]any{
		"privateKey": bytesToJS(privKey.Serialize()),
		"publicKey":  bytesToJS(privKey.PubKey().SerializeCompressed()),
	})
}

func btcecPrivKeyFromBytes(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "hexPrivKey"); e != nil {
		return e
	}
	b, e := hexDecode(args[0].String())
	if e != nil {
		return e
	}
	privKey, pubKey := btcec.PrivKeyFromBytes(b)
	return okResult(map[string]any{
		"privateKey": bytesToJS(privKey.Serialize()),
		"publicKey":  bytesToJS(pubKey.SerializeCompressed()),
	})
}

func btcecPubKeyFromBytes(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "hexPubKey"); e != nil {
		return e
	}
	b, e := hexDecode(args[0].String())
	if e != nil {
		return e
	}
	key, err := btcec.ParsePubKey(b)
	if err != nil {
		return errfResult("parsePubKey: %s", err)
	}
	return okResult(bytesToJS(key.SerializeCompressed()))
}

func btcecIsCompressedPubKey(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "hexPubKey"); e != nil {
		return e
	}
	b, e := hexDecode(args[0].String())
	if e != nil {
		return e
	}
	return okResult(btcec.IsCompressedPubKey(b))
}

func btcecSerializeUncompressed(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "hexPubKey"); e != nil {
		return e
	}
	b, e := hexDecode(args[0].String())
	if e != nil {
		return e
	}
	key, err := btcec.ParsePubKey(b)
	if err != nil {
		return errfResult("parsePubKey: %s", err)
	}
	return okResult(bytesToJS(key.SerializeUncompressed()))
}

func btcecSerializeCompressed(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "hexPubKey"); e != nil {
		return e
	}
	b, e := hexDecode(args[0].String())
	if e != nil {
		return e
	}
	key, err := btcec.ParsePubKey(b)
	if err != nil {
		return errfResult("parsePubKey: %s", err)
	}
	return okResult(bytesToJS(key.SerializeCompressed()))
}

// ---------------------------------------------------------------------------
// ECDH
// ---------------------------------------------------------------------------

func btcecGenerateSharedSecret(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 2, "hexPrivKey, hexPubKey"); e != nil {
		return e
	}
	privBytes, e := hexDecode(args[0].String())
	if e != nil {
		return e
	}
	pubBytes, e := hexDecode(args[1].String())
	if e != nil {
		return e
	}
	privKey, _ := btcec.PrivKeyFromBytes(privBytes)
	pubKey, err := btcec.ParsePubKey(pubBytes)
	if err != nil {
		return errfResult("parsePubKey: %s", err)
	}
	secret := btcec.GenerateSharedSecret(privKey, pubKey)
	return okResult(bytesToJS(secret))
}

// ---------------------------------------------------------------------------
// ECDSA
// ---------------------------------------------------------------------------

func btcecEcdsaSign(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 2, "hexPrivKey, hexHash"); e != nil {
		return e
	}
	privBytes, e := hexDecode(args[0].String())
	if e != nil {
		return e
	}
	hashBytes, e := hexDecode(args[1].String())
	if e != nil {
		return e
	}
	privKey, _ := btcec.PrivKeyFromBytes(privBytes)
	sig := ecdsa.Sign(privKey, hashBytes)
	return okResult(bytesToJS(sig.Serialize()))
}

func btcecEcdsaVerify(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 3, "hexPubKey, hexHash, hexSignature"); e != nil {
		return e
	}
	pubBytes, e := hexDecode(args[0].String())
	if e != nil {
		return e
	}
	hashBytes, e := hexDecode(args[1].String())
	if e != nil {
		return e
	}
	sigBytes, e := hexDecode(args[2].String())
	if e != nil {
		return e
	}
	pubKey, err := btcec.ParsePubKey(pubBytes)
	if err != nil {
		return errfResult("parsePubKey: %s", err)
	}
	sig, err := ecdsa.ParseSignature(sigBytes)
	if err != nil {
		return errfResult("parseSignature: %s", err)
	}
	return okResult(sig.Verify(hashBytes, pubKey))
}

func btcecEcdsaSignCompact(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 3,
		"hexPrivKey, hexHash, isCompressedKey"); e != nil {
		return e
	}
	privBytes, e := hexDecode(args[0].String())
	if e != nil {
		return e
	}
	hashBytes, e := hexDecode(args[1].String())
	if e != nil {
		return e
	}
	privKey, _ := btcec.PrivKeyFromBytes(privBytes)
	compact := ecdsa.SignCompact(privKey, hashBytes, args[2].Bool())
	return okResult(bytesToJS(compact))
}

func btcecEcdsaRecoverCompact(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 2, "hexSignature, hexHash"); e != nil {
		return e
	}
	sigBytes, e := hexDecode(args[0].String())
	if e != nil {
		return e
	}
	hashBytes, e := hexDecode(args[1].String())
	if e != nil {
		return e
	}
	pubKey, compressed, err := ecdsa.RecoverCompact(sigBytes, hashBytes)
	if err != nil {
		return errfResult("recoverCompact: %s", err)
	}
	return okResult(map[string]any{
		"publicKey":  bytesToJS(pubKey.SerializeCompressed()),
		"compressed": compressed,
	})
}

func btcecEcdsaParseSignature(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "hexSignature"); e != nil {
		return e
	}
	b, e := hexDecode(args[0].String())
	if e != nil {
		return e
	}
	sig, err := ecdsa.ParseSignature(b)
	if err != nil {
		return errfResult("parseSignature: %s", err)
	}
	return okResult(bytesToJS(sig.Serialize()))
}

func btcecEcdsaParseDERSignature(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "hexSignature"); e != nil {
		return e
	}
	b, e := hexDecode(args[0].String())
	if e != nil {
		return e
	}
	sig, err := ecdsa.ParseDERSignature(b)
	if err != nil {
		return errfResult("parseDERSignature: %s", err)
	}
	return okResult(bytesToJS(sig.Serialize()))
}

// ---------------------------------------------------------------------------
// Schnorr
// ---------------------------------------------------------------------------

func btcecSchnorrSign(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 2, "hexPrivKey, hexHash"); e != nil {
		return e
	}
	privBytes, e := hexDecode(args[0].String())
	if e != nil {
		return e
	}
	hashBytes, e := hexDecode(args[1].String())
	if e != nil {
		return e
	}
	privKey, _ := btcec.PrivKeyFromBytes(privBytes)
	sig, err := btcschnorr.Sign(privKey, hashBytes)
	if err != nil {
		return errfResult("schnorrSign: %s", err)
	}
	return okResult(bytesToJS(sig.Serialize()))
}

func btcecSchnorrVerify(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 3, "hexPubKey, hexHash, hexSignature"); e != nil {
		return e
	}
	pubBytes, e := hexDecode(args[0].String())
	if e != nil {
		return e
	}
	hashBytes, e := hexDecode(args[1].String())
	if e != nil {
		return e
	}
	sigBytes, e := hexDecode(args[2].String())
	if e != nil {
		return e
	}
	_ = hashBytes
	pubKey, err := btcschnorr.ParsePubKey(pubBytes)
	if err != nil {
		pubKey, err = btcec.ParsePubKey(pubBytes)
		if err != nil {
			return errfResult("parsePubKey: %s", err)
		}
	}
	sig, err := btcschnorr.ParseSignature(sigBytes)
	if err != nil {
		return errfResult("parseSignature: %s", err)
	}
	return okResult(sig.Verify(hashBytes, pubKey))
}

func btcecSchnorrParsePubKey(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "hexXOnlyPubKey"); e != nil {
		return e
	}
	b, e := hexDecode(args[0].String())
	if e != nil {
		return e
	}
	key, err := btcschnorr.ParsePubKey(b)
	if err != nil {
		return errfResult("schnorrParsePubKey: %s", err)
	}
	return okResult(bytesToJS(key.SerializeCompressed()))
}

func btcecSchnorrSerializePubKey(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "hexPubKey"); e != nil {
		return e
	}
	b, e := hexDecode(args[0].String())
	if e != nil {
		return e
	}
	key, err := btcec.ParsePubKey(b)
	if err != nil {
		return errfResult("parsePubKey: %s", err)
	}
	return okResult(bytesToJS(btcschnorr.SerializePubKey(key)))
}

func btcecSchnorrParseSignature(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "hexSignature"); e != nil {
		return e
	}
	b, e := hexDecode(args[0].String())
	if e != nil {
		return e
	}
	sig, err := btcschnorr.ParseSignature(b)
	if err != nil {
		return errfResult("schnorrParseSignature: %s", err)
	}
	return okResult(bytesToJS(sig.Serialize()))
}
