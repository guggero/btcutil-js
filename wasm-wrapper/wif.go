//go:build js && wasm

package main

import (
	"encoding/hex"
	"syscall/js"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
)

func wifDecode(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "wifStr"); e != nil {
		return e
	}
	w, err := btcutil.DecodeWIF(args[0].String())
	if err != nil {
		return errfResult("invalid WIF: %s", err)
	}

	network := "unknown"
	for name, params := range networkParams {
		if w.IsForNet(params) {
			network = name
			break
		}
	}

	return okResult(map[string]any{
		"privateKey":     hex.EncodeToString(w.PrivKey.Serialize()),
		"compressPubKey": w.CompressPubKey,
		"publicKey":      hex.EncodeToString(w.SerializePubKey()),
		"network":        network,
	})
}

func wifEncode(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "hexPrivateKey"); e != nil {
		return e
	}
	privBytes, e := hexDecode(args[0].String())
	if e != nil {
		return e
	}
	params, e := getNetwork(optString(args, 1, "mainnet"))
	if e != nil {
		return e
	}
	compress := optBool(args, 2, true)

	privKey, _ := btcec.PrivKeyFromBytes(privBytes)
	w, err := btcutil.NewWIF(privKey, params, compress)
	if err != nil {
		return errfResult("newWIF: %s", err)
	}
	return okResult(w.String())
}
