//go:build js && wasm

package main

import (
	"fmt"
	"syscall/js"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/bip322"
)

func bip322VerifyMessage(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 3, "message, address, signature"); e != nil {
		return map[string]any{"valid": false, "error": e["error"]}
	}

	message := args[0].String()
	addrStr := args[1].String()
	sig := args[2].String()
	network := optString(args, 3, "mainnet")

	params, ok := networkParams[network]
	if !ok {
		return map[string]any{
			"valid": false,
			"error": fmt.Sprintf("unknown network: %s", network),
		}
	}

	addr, err := btcutil.DecodeAddress(addrStr, params)
	if err != nil {
		return map[string]any{
			"valid": false,
			"error": fmt.Sprintf("decode address: %s", err),
		}
	}

	valid, err := bip322.VerifyMessage(message, addr, sig)
	result := map[string]any{"valid": valid}
	if err != nil {
		result["error"] = err.Error()
	}
	return result
}
