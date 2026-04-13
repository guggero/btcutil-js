//go:build js && wasm

package main

import (
	"encoding/hex"
	"syscall/js"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/bip322"
	"github.com/btcsuite/btcd/wire"
)

func bip322VerifyMessage(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 3, "message, address, signature"); e != nil {
		return e
	}

	message := args[0].String()
	addrStr := args[1].String()
	sig := args[2].String()
	network := optString(args, 3, "mainnet")

	params, ok := networkParams[network]
	if !ok {
		return errfResult("unknown network: %s", network)
	}

	addr, err := btcutil.DecodeAddress(addrStr, params)
	if err != nil {
		return errfResult("decode address: %s", err)
	}

	valid, err := bip322.VerifyMessage(message, addr, sig)
	result := map[string]any{"valid": valid}
	if err != nil {
		result["error"] = err.Error()
	}
	return okResult(result)
}

// bip322BuildToSignPacketSimple wraps bip322.BuildToSignPacketSimple.
// Args: message (string), pkScript (Bytes)
// Returns: base64 PSBT string
func bip322BuildToSignPacketSimple(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 2, "message, pkScript"); e != nil {
		return e
	}
	pkScript, e := bytesFromArg(args[1])
	if e != nil {
		return e
	}
	pkt, err := bip322.BuildToSignPacketSimple(
		[]byte(args[0].String()), pkScript,
	)
	if err != nil {
		return errfResult("buildToSignPacketSimple: %s", err)
	}
	b64, err := pkt.B64Encode()
	if err != nil {
		return errfResult("encode: %s", err)
	}
	return okResult(b64)
}

// bip322BuildToSignPacketFull wraps bip322.BuildToSignPacketFull.
// Args: message (string), pkScript (Bytes), txVersion (int), lockTime (int), sequence (int)
// Returns: base64 PSBT string
func bip322BuildToSignPacketFull(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 5,
		"message, pkScript, txVersion, lockTime, sequence"); e != nil {
		return e
	}
	pkScript, e := bytesFromArg(args[1])
	if e != nil {
		return e
	}
	pkt := bip322.BuildToSignPacketFull(
		[]byte(args[0].String()), pkScript,
		int32(args[2].Int()),
		uint32(args[3].Int()),
		uint32(args[4].Int()),
	)
	b64, err := pkt.B64Encode()
	if err != nil {
		return errfResult("encode: %s", err)
	}
	return okResult(b64)
}

// bip322SerializeTxWitness wraps bip322.SerializeTxWitness.
// Args: witness (array of Bytes)
// Returns: Uint8Array
func bip322SerializeTxWitness(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "witness[]"); e != nil {
		return e
	}
	n := args[0].Length()
	witness := make(wire.TxWitness, n)
	for i := 0; i < n; i++ {
		item := args[0].Index(i)
		if item.InstanceOf(js.Global().Get("Uint8Array")) {
			buf := make([]byte, item.Length())
			if len(buf) > 0 {
				js.CopyBytesToGo(buf, item)
			}
			witness[i] = buf
		} else {
			b, err := hex.DecodeString(item.String())
			if err != nil {
				return errfResult("invalid witness[%d]: %s",
					i, err)
			}
			witness[i] = b
		}
	}
	serialized, err := bip322.SerializeTxWitness(witness)
	if err != nil {
		return errfResult("serializeTxWitness: %s", err)
	}
	return okResult(bytesToJS(serialized))
}

// bip322ParseTxWitness wraps bip322.ParseTxWitness.
// Args: rawWitness (Bytes)
// Returns: array of Uint8Array (witness stack items)
func bip322ParseTxWitness(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "rawWitness"); e != nil {
		return e
	}
	raw, e := bytesFromArg(args[0])
	if e != nil {
		return e
	}
	witness, err := bip322.ParseTxWitness(raw)
	if err != nil {
		return errfResult("parseTxWitness: %s", err)
	}
	items := make([]any, len(witness))
	for i, w := range witness {
		items[i] = bytesToJS(w)
	}
	return okResult(items)
}
