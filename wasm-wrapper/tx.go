//go:build js && wasm

package main

import (
	"encoding/hex"
	"syscall/js"

	"github.com/btcsuite/btcd/btcutil"
)

func txHash(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "hexRawTx"); e != nil {
		return e
	}
	msgTx, e := deserializeTx(args[0].String())
	if e != nil {
		return e
	}
	t := btcutil.NewTx(msgTx)
	return okResult(t.Hash().String())
}

func txWitnessHash(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "hexRawTx"); e != nil {
		return e
	}
	msgTx, e := deserializeTx(args[0].String())
	if e != nil {
		return e
	}
	t := btcutil.NewTx(msgTx)
	return okResult(t.WitnessHash().String())
}

func txHasWitness(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "hexRawTx"); e != nil {
		return e
	}
	msgTx, e := deserializeTx(args[0].String())
	if e != nil {
		return e
	}
	t := btcutil.NewTx(msgTx)
	return okResult(t.HasWitness())
}

func txDecode(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "hexRawTx"); e != nil {
		return e
	}
	msgTx, e := deserializeTx(args[0].String())
	if e != nil {
		return e
	}
	t := btcutil.NewTx(msgTx)

	inputs := make([]any, len(msgTx.TxIn))
	for i, txIn := range msgTx.TxIn {
		witness := make([]any, len(txIn.Witness))
		for j, w := range txIn.Witness {
			witness[j] = hex.EncodeToString(w)
		}
		inputs[i] = map[string]any{
			"txid":      txIn.PreviousOutPoint.Hash.String(),
			"vout":      int(txIn.PreviousOutPoint.Index),
			"scriptSig": hex.EncodeToString(txIn.SignatureScript),
			"sequence":  int64(txIn.Sequence),
			"witness":   witness,
		}
	}

	outputs := make([]any, len(msgTx.TxOut))
	for i, txOut := range msgTx.TxOut {
		outputs[i] = map[string]any{
			"value":        txOut.Value,
			"scriptPubKey": hex.EncodeToString(txOut.PkScript),
		}
	}

	return okResult(map[string]any{
		"txid":     t.Hash().String(),
		"wtxid":    t.WitnessHash().String(),
		"version":  int(msgTx.Version),
		"locktime": int64(msgTx.LockTime),
		"inputs":   inputs,
		"outputs":  outputs,
	})
}
