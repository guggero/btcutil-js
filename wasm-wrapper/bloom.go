//go:build js && wasm

package main

import (
	"syscall/js"

	"github.com/btcsuite/btcd/btcutil/bloom"
)

func bloomMurmurHash3(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 2, "seed, hexData"); e != nil {
		return e
	}
	data, e := bytesFromArg(args[1])
	if e != nil {
		return e
	}
	return okResult(int(bloom.MurmurHash3(uint32(args[0].Int()), data)))
}
