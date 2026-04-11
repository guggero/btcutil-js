//go:build js && wasm

package main

import (
	"encoding/hex"
	"strconv"
	"strings"
	"syscall/js"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
)

func hdNewMaster(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "hexSeed"); e != nil {
		return e
	}
	seed, e := hexDecode(args[0].String())
	if e != nil {
		return e
	}
	params, e := getNetwork(optString(args, 1, "mainnet"))
	if e != nil {
		return e
	}
	key, err := hdkeychain.NewMaster(seed, params)
	if err != nil {
		return errfResult("newMaster: %s", err)
	}
	return okResult(key.String())
}

func hdFromString(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "key"); e != nil {
		return e
	}
	key, err := hdkeychain.NewKeyFromString(args[0].String())
	if err != nil {
		return errfResult("invalid extended key: %s", err)
	}

	pubKeyHex := ""
	if pk, err := key.ECPubKey(); err == nil {
		pubKeyHex = hex.EncodeToString(pk.SerializeCompressed())
	}

	return okResult(map[string]any{
		"key":               key.String(),
		"isPrivate":         key.IsPrivate(),
		"depth":             int(key.Depth()),
		"childIndex":        int(key.ChildIndex()),
		"parentFingerprint": int(key.ParentFingerprint()),
		"chainCode":         hex.EncodeToString(key.ChainCode()),
		"version":           hex.EncodeToString(key.Version()),
		"publicKey":         pubKeyHex,
	})
}

func hdDerive(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 2, "key, index"); e != nil {
		return e
	}
	key, err := hdkeychain.NewKeyFromString(args[0].String())
	if err != nil {
		return errfResult("invalid extended key: %s", err)
	}
	child, err := key.Derive(uint32(args[1].Int()))
	if err != nil {
		return errfResult("derive: %s", err)
	}
	return okResult(child.String())
}

func hdDeriveHardened(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 2, "key, index"); e != nil {
		return e
	}
	key, err := hdkeychain.NewKeyFromString(args[0].String())
	if err != nil {
		return errfResult("invalid extended key: %s", err)
	}
	child, err := key.Derive(
		hdkeychain.HardenedKeyStart + uint32(args[1].Int()),
	)
	if err != nil {
		return errfResult("deriveHardened: %s", err)
	}
	return okResult(child.String())
}

func hdDerivePath(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 2, "key, path"); e != nil {
		return e
	}
	key, err := hdkeychain.NewKeyFromString(args[0].String())
	if err != nil {
		return errfResult("invalid extended key: %s", err)
	}

	path := strings.TrimPrefix(args[1].String(), "m/")
	if path == "" || path == "m" {
		return okResult(key.String())
	}

	parts := strings.Split(path, "/")
	for _, part := range parts {
		hardened := false
		if strings.HasSuffix(part, "'") || strings.HasSuffix(part, "h") {
			hardened = true
			part = part[:len(part)-1]
		}
		idx, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return errfResult("invalid path component %q: %s",
				part, err)
		}
		if hardened {
			idx += hdkeychain.HardenedKeyStart
		}
		key, err = key.Derive(uint32(idx))
		if err != nil {
			return errfResult("derivePath: %s", err)
		}
	}
	return okResult(key.String())
}

func hdNeuter(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "key"); e != nil {
		return e
	}
	key, err := hdkeychain.NewKeyFromString(args[0].String())
	if err != nil {
		return errfResult("invalid extended key: %s", err)
	}
	pub, err := key.Neuter()
	if err != nil {
		return errfResult("neuter: %s", err)
	}
	return okResult(pub.String())
}

func hdGenerateSeed(_ js.Value, args []js.Value) any {
	length := uint8(hdkeychain.RecommendedSeedLen)
	if len(args) > 0 && args[0].Type() == js.TypeNumber {
		length = uint8(args[0].Int())
	}
	seed, err := hdkeychain.GenerateSeed(length)
	if err != nil {
		return errfResult("generateSeed: %s", err)
	}
	return okResult(hex.EncodeToString(seed))
}

func hdPublicKey(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "key"); e != nil {
		return e
	}
	key, err := hdkeychain.NewKeyFromString(args[0].String())
	if err != nil {
		return errfResult("invalid extended key: %s", err)
	}
	pub, err := key.ECPubKey()
	if err != nil {
		return errfResult("ecPubKey: %s", err)
	}
	return okResult(hex.EncodeToString(pub.SerializeCompressed()))
}

func hdAddress(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "key"); e != nil {
		return e
	}
	key, err := hdkeychain.NewKeyFromString(args[0].String())
	if err != nil {
		return errfResult("invalid extended key: %s", err)
	}
	params, e := getNetwork(optString(args, 1, "mainnet"))
	if e != nil {
		return e
	}
	addr, err := key.Address(params)
	if err != nil {
		return errfResult("address: %s", err)
	}
	return okResult(addr.EncodeAddress())
}
