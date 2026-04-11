//go:build js && wasm

package main

import (
	"syscall/js"

	"github.com/btcsuite/btcd/btcutil/txsort"
)

func txsortSort(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "hexRawTx"); e != nil {
		return e
	}
	msgTx, e := deserializeTx(args[0].String())
	if e != nil {
		return e
	}
	sorted := txsort.Sort(msgTx)
	return okResult(serializeTx(sorted))
}

func txsortIsSorted(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "hexRawTx"); e != nil {
		return e
	}
	msgTx, e := deserializeTx(args[0].String())
	if e != nil {
		return e
	}
	return okResult(txsort.IsSorted(msgTx))
}
