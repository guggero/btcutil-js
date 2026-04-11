//go:build js && wasm

package main

import (
	"encoding/hex"
	"syscall/js"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

func chainhashHashB(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "hexData"); e != nil {
		return e
	}
	b, e := hexDecode(args[0].String())
	if e != nil {
		return e
	}
	return okResult(bytesToJS(chainhash.HashB(b)))
}

func chainhashDoubleHashB(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "hexData"); e != nil {
		return e
	}
	b, e := hexDecode(args[0].String())
	if e != nil {
		return e
	}
	return okResult(bytesToJS(chainhash.DoubleHashB(b)))
}

func chainhashTaggedHash(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 2, "hexTag, hexMsgs..."); e != nil {
		return e
	}
	tag, e := hexDecode(args[0].String())
	if e != nil {
		return e
	}
	msgs := make([][]byte, args[1].Length())
	for i := 0; i < args[1].Length(); i++ {
		m, err := hex.DecodeString(args[1].Index(i).String())
		if err != nil {
			return errfResult("invalid msg[%d]: %s", i, err)
		}
		msgs[i] = m
	}
	h := chainhash.TaggedHash(tag, msgs...)
	return okResult(bytesToJS(h[:]))
}

func chainhashNewHashFromStr(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "hashStr"); e != nil {
		return e
	}
	h, err := chainhash.NewHashFromStr(args[0].String())
	if err != nil {
		return errfResult("newHashFromStr: %s", err)
	}
	return okResult(bytesToJS(h[:]))
}

func chainhashHashToString(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "hexHash"); e != nil {
		return e
	}
	b, e := hexDecode(args[0].String())
	if e != nil {
		return e
	}
	h, err := chainhash.NewHash(b)
	if err != nil {
		return errfResult("newHash: %s", err)
	}
	return okResult(h.String())
}
