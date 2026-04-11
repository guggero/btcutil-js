//go:build js && wasm

package main

import (
	"encoding/hex"
	"syscall/js"

	"github.com/btcsuite/btcd/chaincfg"
)

func chaincfgGetParams(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "network"); e != nil {
		return e
	}
	params, e := getNetwork(args[0].String())
	if e != nil {
		return e
	}
	return okResult(map[string]any{
		"name":                     params.Name,
		"defaultPort":              params.DefaultPort,
		"bech32HRPSegwit":          params.Bech32HRPSegwit,
		"pubKeyHashAddrID":         int(params.PubKeyHashAddrID),
		"scriptHashAddrID":         int(params.ScriptHashAddrID),
		"privateKeyID":             int(params.PrivateKeyID),
		"hdPrivateKeyID":           hex.EncodeToString(params.HDPrivateKeyID[:]),
		"hdPublicKeyID":            hex.EncodeToString(params.HDPublicKeyID[:]),
		"hdCoinType":               int(params.HDCoinType),
		"coinbaseMaturity":         int(params.CoinbaseMaturity),
		"subsidyReductionInterval": int(params.SubsidyReductionInterval),
	})
}

func chaincfgIsPubKeyHashAddrID(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "id"); e != nil {
		return e
	}
	return okResult(chaincfg.IsPubKeyHashAddrID(byte(args[0].Int())))
}

func chaincfgIsScriptHashAddrID(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "id"); e != nil {
		return e
	}
	return okResult(chaincfg.IsScriptHashAddrID(byte(args[0].Int())))
}

func chaincfgIsBech32SegwitPrefix(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "prefix"); e != nil {
		return e
	}
	return okResult(chaincfg.IsBech32SegwitPrefix(args[0].String()))
}

func chaincfgHDPrivateKeyToPublicKeyID(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "hexPrivateKeyID"); e != nil {
		return e
	}
	b, e := hexDecode(args[0].String())
	if e != nil {
		return e
	}
	pubID, err := chaincfg.HDPrivateKeyToPublicKeyID(b)
	if err != nil {
		return errfResult("hdPrivateKeyToPublicKeyID: %s", err)
	}
	return okResult(hex.EncodeToString(pubID))
}
