//go:build js && wasm

package main

import (
	"syscall/js"

	"github.com/btcsuite/btcd/address/v2"
)

func addressDecode(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "address"); e != nil {
		return e
	}
	network := optString(args, 1, "mainnet")
	params, e := getNetwork(network)
	if e != nil {
		return e
	}

	addr, err := address.DecodeAddress(args[0].String(), params)
	if err != nil {
		return errfResult("decode address: %s", err)
	}

	info := map[string]any{
		"address":       addr.EncodeAddress(),
		"scriptAddress": bytesToJS(addr.ScriptAddress()),
		"isForNet":      addr.IsForNet(params),
	}

	switch a := addr.(type) {
	case *address.AddressPubKeyHash:
		info["type"] = "p2pkh"
		info["hash160"] = bytesToJS(a.Hash160()[:])
	case *address.AddressScriptHash:
		info["type"] = "p2sh"
		info["hash160"] = bytesToJS(a.Hash160()[:])
	case *address.AddressTaproot:
		info["type"] = "p2tr"
		info["witnessVersion"] = int(a.WitnessVersion())
		info["witnessProgram"] = bytesToJS(a.WitnessProgram())
	case *address.AddressWitnessPubKeyHash:
		info["type"] = "p2wpkh"
		info["witnessVersion"] = int(a.WitnessVersion())
		info["witnessProgram"] = bytesToJS(a.WitnessProgram())
	case *address.AddressWitnessScriptHash:
		info["type"] = "p2wsh"
		info["witnessVersion"] = int(a.WitnessVersion())
		info["witnessProgram"] = bytesToJS(a.WitnessProgram())
	case *address.AddressPubKey:
		info["type"] = "p2pk"
		info["pubKeyFormat"] = int(a.Format())
	default:
		info["type"] = "unknown"
	}

	return okResult(info)
}

func addressFromPubKeyHash(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "hexHash"); e != nil {
		return e
	}
	hash, e := bytesFromArg(args[0])
	if e != nil {
		return e
	}
	params, e := getNetwork(optString(args, 1, "mainnet"))
	if e != nil {
		return e
	}
	addr, err := address.NewAddressPubKeyHash(hash, params)
	if err != nil {
		return errfResult("fromPubKeyHash: %s", err)
	}
	return okResult(addr.EncodeAddress())
}

func addressFromScriptHash(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "hexHash"); e != nil {
		return e
	}
	hash, e := bytesFromArg(args[0])
	if e != nil {
		return e
	}
	params, e := getNetwork(optString(args, 1, "mainnet"))
	if e != nil {
		return e
	}
	addr, err := address.NewAddressScriptHashFromHash(hash, params)
	if err != nil {
		return errfResult("fromScriptHash: %s", err)
	}
	return okResult(addr.EncodeAddress())
}

func addressFromScript(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "hexScript"); e != nil {
		return e
	}
	script, e := bytesFromArg(args[0])
	if e != nil {
		return e
	}
	params, e := getNetwork(optString(args, 1, "mainnet"))
	if e != nil {
		return e
	}
	addr, err := address.NewAddressScriptHash(script, params)
	if err != nil {
		return errfResult("fromScript: %s", err)
	}
	return okResult(addr.EncodeAddress())
}

func addressFromWitnessPubKeyHash(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "hexProgram"); e != nil {
		return e
	}
	prog, e := bytesFromArg(args[0])
	if e != nil {
		return e
	}
	params, e := getNetwork(optString(args, 1, "mainnet"))
	if e != nil {
		return e
	}
	addr, err := address.NewAddressWitnessPubKeyHash(prog, params)
	if err != nil {
		return errfResult("fromWitnessPubKeyHash: %s", err)
	}
	return okResult(addr.EncodeAddress())
}

func addressFromWitnessScriptHash(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "hexProgram"); e != nil {
		return e
	}
	prog, e := bytesFromArg(args[0])
	if e != nil {
		return e
	}
	params, e := getNetwork(optString(args, 1, "mainnet"))
	if e != nil {
		return e
	}
	addr, err := address.NewAddressWitnessScriptHash(prog, params)
	if err != nil {
		return errfResult("fromWitnessScriptHash: %s", err)
	}
	return okResult(addr.EncodeAddress())
}

func addressFromTaproot(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "hexProgram"); e != nil {
		return e
	}
	prog, e := bytesFromArg(args[0])
	if e != nil {
		return e
	}
	params, e := getNetwork(optString(args, 1, "mainnet"))
	if e != nil {
		return e
	}
	addr, err := address.NewAddressTaproot(prog, params)
	if err != nil {
		return errfResult("fromTaproot: %s", err)
	}
	return okResult(addr.EncodeAddress())
}

func addressFromPubKey(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "hexPubKey"); e != nil {
		return e
	}
	pub, e := bytesFromArg(args[0])
	if e != nil {
		return e
	}
	params, e := getNetwork(optString(args, 1, "mainnet"))
	if e != nil {
		return e
	}
	addr, err := address.NewAddressPubKey(pub, params)
	if err != nil {
		return errfResult("fromPubKey: %s", err)
	}
	return okResult(addr.EncodeAddress())
}
