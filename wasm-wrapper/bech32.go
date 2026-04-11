//go:build js && wasm

package main

import (
	"encoding/hex"
	"syscall/js"

	bech32pkg "github.com/btcsuite/btcd/btcutil/bech32"
)

func bech32Encode(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 2, "hrp, hexData5bit"); e != nil {
		return e
	}
	data, e := hexDecode(args[1].String())
	if e != nil {
		return e
	}
	s, err := bech32pkg.Encode(args[0].String(), data)
	if err != nil {
		return errfResult("bech32 encode: %s", err)
	}
	return okResult(s)
}

func bech32EncodeM(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 2, "hrp, hexData5bit"); e != nil {
		return e
	}
	data, e := hexDecode(args[1].String())
	if e != nil {
		return e
	}
	s, err := bech32pkg.EncodeM(args[0].String(), data)
	if err != nil {
		return errfResult("bech32m encode: %s", err)
	}
	return okResult(s)
}

func bech32Decode(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "bechStr"); e != nil {
		return e
	}
	hrp, data, err := bech32pkg.Decode(args[0].String())
	if err != nil {
		return errfResult("bech32 decode: %s", err)
	}
	return okResult(map[string]any{
		"hrp":  hrp,
		"data": hex.EncodeToString(data),
	})
}

func bech32DecodeNoLimit(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "bechStr"); e != nil {
		return e
	}
	hrp, data, err := bech32pkg.DecodeNoLimit(args[0].String())
	if err != nil {
		return errfResult("bech32 decodeNoLimit: %s", err)
	}
	return okResult(map[string]any{
		"hrp":  hrp,
		"data": hex.EncodeToString(data),
	})
}

func bech32EncodeFromBase256(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 2, "hrp, hexData"); e != nil {
		return e
	}
	data, e := hexDecode(args[1].String())
	if e != nil {
		return e
	}
	s, err := bech32pkg.EncodeFromBase256(args[0].String(), data)
	if err != nil {
		return errfResult("bech32 encodeFromBase256: %s", err)
	}
	return okResult(s)
}

func bech32DecodeToBase256(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "bechStr"); e != nil {
		return e
	}
	hrp, data, err := bech32pkg.DecodeToBase256(args[0].String())
	if err != nil {
		return errfResult("bech32 decodeToBase256: %s", err)
	}
	return okResult(map[string]any{
		"hrp":  hrp,
		"data": hex.EncodeToString(data),
	})
}

func bech32ConvertBits(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 4, "hexData, fromBits, toBits, pad"); e != nil {
		return e
	}
	data, e := hexDecode(args[0].String())
	if e != nil {
		return e
	}
	result, err := bech32pkg.ConvertBits(
		data,
		uint8(args[1].Int()),
		uint8(args[2].Int()),
		args[3].Bool(),
	)
	if err != nil {
		return errfResult("convertBits: %s", err)
	}
	return okResult(hex.EncodeToString(result))
}
