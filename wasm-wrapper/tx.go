//go:build js && wasm

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"syscall/js"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

// txToJSON builds the decode-shape TxJSON (data + derived txid/wtxid).
func txToJSON(msgTx *wire.MsgTx) TxJSON {
	t := btcutil.NewTx(msgTx)
	return TxJSON{
		TxDataJSON: txDataToJSON(msgTx),
		Txid:       t.Hash().String(),
		Wtxid:      t.WitnessHash().String(),
	}
}

// txDataToJSON builds just the encode-shape (no derived txid/wtxid).
func txDataToJSON(msgTx *wire.MsgTx) TxDataJSON {
	inputs := make([]TxInputJSON, len(msgTx.TxIn))
	for i, txIn := range msgTx.TxIn {
		var witness []HexBytes
		if len(txIn.Witness) > 0 {
			witness = make([]HexBytes, len(txIn.Witness))
			for j, w := range txIn.Witness {
				witness[j] = HexBytes(w)
			}
		}
		inputs[i] = TxInputJSON{
			Txid:      txIn.PreviousOutPoint.Hash.String(),
			Vout:      txIn.PreviousOutPoint.Index,
			ScriptSig: HexBytes(txIn.SignatureScript),
			Sequence:  txIn.Sequence,
			Witness:   witness,
		}
	}
	outputs := make([]TxOutputJSON, len(msgTx.TxOut))
	for i, txOut := range msgTx.TxOut {
		outputs[i] = TxOutputJSON{
			Value:        txOut.Value,
			ScriptPubKey: HexBytes(txOut.PkScript),
		}
	}
	return TxDataJSON{
		Version:  msgTx.Version,
		LockTime: msgTx.LockTime,
		Inputs:   inputs,
		Outputs:  outputs,
	}
}

// txFromData reconstructs a wire.MsgTx from the encode-input shape.
func txFromData(j TxDataJSON) (*wire.MsgTx, error) {
	msgTx := wire.NewMsgTx(j.Version)
	msgTx.LockTime = j.LockTime
	for i, in := range j.Inputs {
		hash, err := chainhash.NewHashFromStr(in.Txid)
		if err != nil {
			return nil, fmt.Errorf("input[%d] txid: %w", i, err)
		}
		var witness wire.TxWitness
		if len(in.Witness) > 0 {
			witness = make(wire.TxWitness, len(in.Witness))
			for j, w := range in.Witness {
				witness[j] = []byte(w)
			}
		}
		txIn := wire.NewTxIn(
			wire.NewOutPoint(hash, in.Vout),
			[]byte(in.ScriptSig),
			witness,
		)
		txIn.Sequence = in.Sequence
		msgTx.AddTxIn(txIn)
	}
	for _, out := range j.Outputs {
		msgTx.AddTxOut(wire.NewTxOut(
			out.Value, []byte(out.ScriptPubKey),
		))
	}
	return msgTx, nil
}

// marshalJSON returns either an okResult containing the JSON string or an
// errfResult on failure.
func marshalJSON(v any) map[string]any {
	b, err := json.Marshal(v)
	if err != nil {
		return errfResult("marshal: %s", err)
	}
	return okResult(string(b))
}

// unmarshalArg parses a string-or-object JS argument as JSON into v.
//
// Accepts both a JSON string (the typical encode→decode→encode path) and a
// plain JS object (caller may skip JSON.stringify; we do it here).
func unmarshalArg(arg js.Value, v any) map[string]any {
	var raw string
	if arg.Type() == js.TypeString {
		raw = arg.String()
	} else {
		stringify := js.Global().Get("JSON").Get("stringify")
		raw = stringify.Invoke(arg).String()
	}
	if err := json.Unmarshal([]byte(raw), v); err != nil {
		return errfResult("unmarshal: %s", err)
	}
	return nil
}

func txHash(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "hexRawTx"); e != nil {
		return e
	}
	msgTx, e := deserializeTxArg(args[0])
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
	msgTx, e := deserializeTxArg(args[0])
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
	msgTx, e := deserializeTxArg(args[0])
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
	msgTx, e := deserializeTxArg(args[0])
	if e != nil {
		return e
	}
	return marshalJSON(txToJSON(msgTx))
}

// txEncode takes a JSON string (or plain object) shaped like TxDataJSON and
// serializes it back into raw transaction bytes.
func txEncode(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "decoded"); e != nil {
		return e
	}
	var j TxDataJSON
	if e := unmarshalArg(args[0], &j); e != nil {
		return e
	}
	msgTx, err := txFromData(j)
	if err != nil {
		return errfResult("%s", err)
	}
	var buf bytes.Buffer
	if err := msgTx.Serialize(&buf); err != nil {
		return errfResult("serialize: %s", err)
	}
	return okResult(bytesToJS(buf.Bytes()))
}
