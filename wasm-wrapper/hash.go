//go:build js && wasm

package main

import (
	"syscall/js"

	"github.com/btcsuite/btcd/address/v2"
)

func hashHash160(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "hexData"); e != nil {
		return e
	}
	b, e := bytesFromArg(args[0])
	if e != nil {
		return e
	}
	return okResult(bytesToJS(address.Hash160(b)))
}
