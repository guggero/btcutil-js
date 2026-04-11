//go:build js && wasm

package main

import (
	"syscall/js"

	"github.com/btcsuite/btcd/btcutil"
)

func hashHash160(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "hexData"); e != nil {
		return e
	}
	b, e := hexDecode(args[0].String())
	if e != nil {
		return e
	}
	return okResult(bytesToJS(btcutil.Hash160(b)))
}
