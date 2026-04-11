//go:build js && wasm

package main

import (
	"encoding/hex"
	"syscall/js"

	"github.com/btcsuite/btcd/btcutil/base58"
)

func base58Encode(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "hexData"); e != nil {
		return e
	}
	b, e := hexDecode(args[0].String())
	if e != nil {
		return e
	}
	return okResult(base58.Encode(b))
}

func base58Decode(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "str"); e != nil {
		return e
	}
	return okResult(hex.EncodeToString(base58.Decode(args[0].String())))
}

func base58CheckEncode(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 2, "hexData, version"); e != nil {
		return e
	}
	b, e := hexDecode(args[0].String())
	if e != nil {
		return e
	}
	version := byte(args[1].Int())
	return okResult(base58.CheckEncode(b, version))
}

func base58CheckDecode(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "str"); e != nil {
		return e
	}
	data, version, err := base58.CheckDecode(args[0].String())
	if err != nil {
		return errfResult("checkDecode failed: %s", err)
	}
	return okResult(map[string]any{
		"data":    hex.EncodeToString(data),
		"version": int(version),
	})
}
