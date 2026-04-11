//go:build js && wasm

package main

import (
	"syscall/js"

	"github.com/btcsuite/btcd/btcutil"
)

func amountFromBTC(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "btcAmount"); e != nil {
		return e
	}
	a, err := btcutil.NewAmount(args[0].Float())
	if err != nil {
		return errfResult("invalid amount: %s", err)
	}
	return okResult(int64(a))
}

func amountToBTC(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "satoshis"); e != nil {
		return e
	}
	a := btcutil.Amount(int64(args[0].Float()))
	return okResult(a.ToBTC())
}

func amountFormat(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "satoshis"); e != nil {
		return e
	}
	a := btcutil.Amount(int64(args[0].Float()))
	unit := btcutil.AmountBTC
	if len(args) > 1 && args[1].Type() == js.TypeString {
		u, ok := amountUnits[args[1].String()]
		if !ok {
			return errfResult("unknown unit: %s", args[1].String())
		}
		unit = u
	}
	return okResult(a.Format(unit))
}
