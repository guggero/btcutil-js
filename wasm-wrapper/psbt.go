//go:build js && wasm

package main

import (
	"bytes"
	"syscall/js"

	btcpsbt "github.com/btcsuite/btcd/btcutil/psbt"
)

func psbtDecode(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "base64Psbt"); e != nil {
		return e
	}
	pkt, e := parsePsbt(args[0].String())
	if e != nil {
		return e
	}

	inputs := make([]any, len(pkt.Inputs))
	for i, pIn := range pkt.Inputs {
		inp := map[string]any{
			"previousTxid":          pkt.UnsignedTx.TxIn[i].PreviousOutPoint.Hash.String(),
			"previousVout":          int(pkt.UnsignedTx.TxIn[i].PreviousOutPoint.Index),
			"hasNonWitnessUtxo":     pIn.NonWitnessUtxo != nil,
			"hasFinalScriptSig":     len(pIn.FinalScriptSig) > 0,
			"hasFinalScriptWitness": len(pIn.FinalScriptWitness) > 0,
			"partialSigCount":       len(pIn.PartialSigs),
		}
		if pIn.WitnessUtxo != nil {
			inp["witnessUtxoValue"] = pIn.WitnessUtxo.Value
			inp["witnessUtxoScript"] = bytesToJS(
				pIn.WitnessUtxo.PkScript,
			)
		}
		inputs[i] = inp
	}

	outputs := make([]any, len(pkt.UnsignedTx.TxOut))
	for i, txOut := range pkt.UnsignedTx.TxOut {
		outputs[i] = map[string]any{
			"value":        txOut.Value,
			"scriptPubKey": bytesToJS(txOut.PkScript),
		}
	}

	fee := int64(-1)
	if f, err := pkt.GetTxFee(); err == nil {
		fee = int64(f)
	}

	return okResult(map[string]any{
		"version":     int(pkt.UnsignedTx.Version),
		"locktime":    int64(pkt.UnsignedTx.LockTime),
		"inputCount":  len(pkt.Inputs),
		"outputCount": len(pkt.Outputs),
		"isComplete":  pkt.IsComplete(),
		"fee":         fee,
		"inputs":      inputs,
		"outputs":     outputs,
	})
}

func psbtIsComplete(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "base64Psbt"); e != nil {
		return e
	}
	pkt, e := parsePsbt(args[0].String())
	if e != nil {
		return e
	}
	return okResult(pkt.IsComplete())
}

func psbtExtract(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "base64Psbt"); e != nil {
		return e
	}
	pkt, e := parsePsbt(args[0].String())
	if e != nil {
		return e
	}
	finalTx, err := btcpsbt.Extract(pkt)
	if err != nil {
		return errfResult("extract: %s", err)
	}
	return okResult(serializeTx(finalTx))
}

func psbtGetFee(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "base64Psbt"); e != nil {
		return e
	}
	pkt, e := parsePsbt(args[0].String())
	if e != nil {
		return e
	}
	fee, err := pkt.GetTxFee()
	if err != nil {
		return errfResult("getFee: %s", err)
	}
	return okResult(int64(fee))
}

func psbtFromBase64(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "base64Psbt"); e != nil {
		return e
	}
	pkt, e := parsePsbt(args[0].String())
	if e != nil {
		return e
	}
	var buf bytes.Buffer
	if err := pkt.Serialize(&buf); err != nil {
		return errfResult("serialize: %s", err)
	}
	return okResult(bytesToJS(buf.Bytes()))
}

func psbtToBase64(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "hexPsbt"); e != nil {
		return e
	}
	raw, e := bytesFromArg(args[0])
	if e != nil {
		return e
	}
	pkt, err := btcpsbt.NewFromRawBytes(bytes.NewReader(raw), false)
	if err != nil {
		return errfResult("parse raw PSBT: %s", err)
	}
	b64, err := pkt.B64Encode()
	if err != nil {
		return errfResult("b64Encode: %s", err)
	}
	return okResult(b64)
}
