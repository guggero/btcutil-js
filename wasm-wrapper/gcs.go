//go:build js && wasm

package main

import (
	"encoding/hex"
	"syscall/js"

	"github.com/btcsuite/btcd/btcutil/gcs"
)

func gcsBuildFilter(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 4, "p, m, hexKey, hexDataItems"); e != nil {
		return e
	}
	p := uint8(args[0].Int())
	m := uint64(args[1].Float())

	keyBytes, e := hexDecode(args[2].String())
	if e != nil {
		return e
	}
	if len(keyBytes) != gcs.KeySize {
		return errfResult(
			"key must be %d bytes, got %d", gcs.KeySize, len(keyBytes),
		)
	}
	var key [gcs.KeySize]byte
	copy(key[:], keyBytes)

	dataLen := args[3].Length()
	data := make([][]byte, dataLen)
	for i := 0; i < dataLen; i++ {
		item, err := hex.DecodeString(args[3].Index(i).String())
		if err != nil {
			return errfResult("invalid hex item[%d]: %s", i, err)
		}
		data[i] = item
	}

	filter, err := gcs.BuildGCSFilter(p, m, key, data)
	if err != nil {
		return errfResult("buildFilter: %s", err)
	}

	filterBytes, err := filter.Bytes()
	if err != nil {
		return errfResult("serialize filter: %s", err)
	}

	return okResult(map[string]any{
		"filter": hex.EncodeToString(filterBytes),
		"n":      int(filter.N()),
	})
}

func gcsMatch(_ js.Value, args []js.Value) any {
	if e := checkArgs(
		args, 6, "hexFilter, n, p, m, hexKey, hexTarget",
	); e != nil {
		return e
	}

	filterBytes, e := hexDecode(args[0].String())
	if e != nil {
		return e
	}
	n := uint32(args[1].Int())
	p := uint8(args[2].Int())
	m := uint64(args[3].Float())

	keyBytes, e := hexDecode(args[4].String())
	if e != nil {
		return e
	}
	var key [gcs.KeySize]byte
	copy(key[:], keyBytes)

	target, e := hexDecode(args[5].String())
	if e != nil {
		return e
	}

	filter, err := gcs.FromBytes(n, p, m, filterBytes)
	if err != nil {
		return errfResult("parse filter: %s", err)
	}

	matched, err := filter.Match(key, target)
	if err != nil {
		return errfResult("match: %s", err)
	}
	return okResult(matched)
}

func gcsMatchAny(_ js.Value, args []js.Value) any {
	if e := checkArgs(
		args, 6, "hexFilter, n, p, m, hexKey, hexTargets",
	); e != nil {
		return e
	}

	filterBytes, e := hexDecode(args[0].String())
	if e != nil {
		return e
	}
	n := uint32(args[1].Int())
	p := uint8(args[2].Int())
	m := uint64(args[3].Float())

	keyBytes, e := hexDecode(args[4].String())
	if e != nil {
		return e
	}
	var key [gcs.KeySize]byte
	copy(key[:], keyBytes)

	targetsLen := args[5].Length()
	targets := make([][]byte, targetsLen)
	for i := 0; i < targetsLen; i++ {
		t, err := hex.DecodeString(args[5].Index(i).String())
		if err != nil {
			return errfResult("invalid hex target[%d]: %s", i, err)
		}
		targets[i] = t
	}

	filter, err := gcs.FromBytes(n, p, m, filterBytes)
	if err != nil {
		return errfResult("parse filter: %s", err)
	}

	matched, err := filter.MatchAny(key, targets)
	if err != nil {
		return errfResult("matchAny: %s", err)
	}
	return okResult(matched)
}
