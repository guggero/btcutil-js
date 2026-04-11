//go:build js && wasm

package main

import (
	"bytes"
	"syscall/js"

	btcpsbt "github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/wire"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// reserialize encodes a modified packet back to base64.
func reserialize(pkt *btcpsbt.Packet) map[string]any {
	b64, err := pkt.B64Encode()
	if err != nil {
		return errfResult("encode: %s", err)
	}
	return okResult(b64)
}

func serializeBip32Derivation(d []*btcpsbt.Bip32Derivation) []any {
	out := make([]any, len(d))
	for i, bd := range d {
		path := make([]any, len(bd.Bip32Path))
		for j, p := range bd.Bip32Path {
			path[j] = int64(p)
		}
		out[i] = map[string]any{
			"pubKey":               bytesToJS(bd.PubKey),
			"masterKeyFingerprint": int64(bd.MasterKeyFingerprint),
			"path":                 path,
		}
	}
	return out
}

func serializeTaprootBip32Derivation(
	d []*btcpsbt.TaprootBip32Derivation,
) []any {
	out := make([]any, len(d))
	for i, td := range d {
		leafHashes := make([]any, len(td.LeafHashes))
		for j, lh := range td.LeafHashes {
			leafHashes[j] = bytesToJS(lh)
		}
		path := make([]any, len(td.Bip32Path))
		for j, p := range td.Bip32Path {
			path[j] = int64(p)
		}
		out[i] = map[string]any{
			"xOnlyPubKey":          bytesToJS(td.XOnlyPubKey),
			"leafHashes":           leafHashes,
			"masterKeyFingerprint": int64(td.MasterKeyFingerprint),
			"path":                 path,
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// decode (enhanced)
// ---------------------------------------------------------------------------

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
			"previousTxid":  pkt.UnsignedTx.TxIn[i].PreviousOutPoint.Hash.String(),
			"previousVout":  int(pkt.UnsignedTx.TxIn[i].PreviousOutPoint.Index),
			"sequence":      int64(pkt.UnsignedTx.TxIn[i].Sequence),
			"sighashType":   int(pIn.SighashType),
			"redeemScript":  bytesToJS(pIn.RedeemScript),
			"witnessScript": bytesToJS(pIn.WitnessScript),
		}

		inp["hasNonWitnessUtxo"] = pIn.NonWitnessUtxo != nil
		if pIn.NonWitnessUtxo != nil {
			inp["nonWitnessUtxo"] = serializeTx(pIn.NonWitnessUtxo)
		}

		if pIn.WitnessUtxo != nil {
			inp["witnessUtxoValue"] = pIn.WitnessUtxo.Value
			inp["witnessUtxoScript"] = bytesToJS(pIn.WitnessUtxo.PkScript)
		}

		// Partial signatures.
		partialSigs := make([]any, len(pIn.PartialSigs))
		for j, ps := range pIn.PartialSigs {
			partialSigs[j] = map[string]any{
				"pubKey":    bytesToJS(ps.PubKey),
				"signature": bytesToJS(ps.Signature),
			}
		}
		inp["partialSigs"] = partialSigs

		// Final scripts.
		inp["finalScriptSig"] = bytesToJS(pIn.FinalScriptSig)
		inp["finalScriptWitness"] = bytesToJS(pIn.FinalScriptWitness)

		// BIP-32 derivation.
		inp["bip32Derivation"] = serializeBip32Derivation(
			pIn.Bip32Derivation,
		)

		// Taproot fields.
		inp["taprootKeySpendSig"] = bytesToJS(pIn.TaprootKeySpendSig)
		inp["taprootInternalKey"] = bytesToJS(pIn.TaprootInternalKey)
		inp["taprootMerkleRoot"] = bytesToJS(pIn.TaprootMerkleRoot)

		trSigs := make([]any, len(pIn.TaprootScriptSpendSig))
		for j, ss := range pIn.TaprootScriptSpendSig {
			trSigs[j] = map[string]any{
				"xOnlyPubKey": bytesToJS(ss.XOnlyPubKey),
				"leafHash":    bytesToJS(ss.LeafHash),
				"signature":   bytesToJS(ss.Signature),
				"sigHash":     int(ss.SigHash),
			}
		}
		inp["taprootScriptSpendSigs"] = trSigs

		trLeaves := make([]any, len(pIn.TaprootLeafScript))
		for j, ls := range pIn.TaprootLeafScript {
			trLeaves[j] = map[string]any{
				"controlBlock": bytesToJS(ls.ControlBlock),
				"script":       bytesToJS(ls.Script),
				"leafVersion":  int(ls.LeafVersion),
			}
		}
		inp["taprootLeafScripts"] = trLeaves

		inp["taprootBip32Derivation"] = serializeTaprootBip32Derivation(
			pIn.TaprootBip32Derivation,
		)

		inputs[i] = inp
	}

	outputs := make([]any, len(pkt.UnsignedTx.TxOut))
	for i, txOut := range pkt.UnsignedTx.TxOut {
		pOut := pkt.Outputs[i]
		out := map[string]any{
			"value":        txOut.Value,
			"scriptPubKey": bytesToJS(txOut.PkScript),
		}

		out["redeemScript"] = bytesToJS(pOut.RedeemScript)
		out["witnessScript"] = bytesToJS(pOut.WitnessScript)
		out["bip32Derivation"] = serializeBip32Derivation(
			pOut.Bip32Derivation,
		)
		out["taprootInternalKey"] = bytesToJS(pOut.TaprootInternalKey)
		out["taprootTapTree"] = bytesToJS(pOut.TaprootTapTree)
		out["taprootBip32Derivation"] = serializeTaprootBip32Derivation(
			pOut.TaprootBip32Derivation,
		)

		outputs[i] = out
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

// ---------------------------------------------------------------------------
// existing read-only functions
// ---------------------------------------------------------------------------

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
	if e := checkArgs(args, 1, "psbtData"); e != nil {
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

// ---------------------------------------------------------------------------
// creation
// ---------------------------------------------------------------------------

func psbtCreate(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 2, "inputs[], outputs[]"); e != nil {
		return e
	}

	// Parse inputs: [{txid, vout}]
	nIn := args[0].Length()
	inputs := make([]*wire.OutPoint, nIn)
	sequences := make([]uint32, nIn)
	for i := 0; i < nIn; i++ {
		entry := args[0].Index(i)
		txidStr := entry.Get("txid").String()
		hash, err := newHashFromString(txidStr)
		if err != nil {
			return errfResult("invalid txid[%d]: %s", i, err)
		}
		vout := uint32(entry.Get("vout").Int())
		inputs[i] = wire.NewOutPoint(hash, vout)

		seq := uint32(0xffffffff)
		if s := entry.Get("sequence"); s.Type() == js.TypeNumber {
			seq = uint32(s.Int())
		}
		sequences[i] = seq
	}

	// Parse outputs: [{value, script}]
	nOut := args[1].Length()
	txOuts := make([]*wire.TxOut, nOut)
	for i := 0; i < nOut; i++ {
		entry := args[1].Index(i)
		value := int64(entry.Get("value").Float())
		script, e := bytesFromArg(entry.Get("script"))
		if e != nil {
			return e
		}
		txOuts[i] = wire.NewTxOut(value, script)
	}

	version := int32(2)
	if len(args) > 2 && args[2].Type() == js.TypeNumber {
		version = int32(args[2].Int())
	}
	lockTime := uint32(0)
	if len(args) > 3 && args[3].Type() == js.TypeNumber {
		lockTime = uint32(args[3].Int())
	}

	pkt, err := btcpsbt.New(
		inputs, txOuts, version, lockTime, sequences,
	)
	if err != nil {
		return errfResult("create: %s", err)
	}
	return reserialize(pkt)
}

func psbtFromUnsignedTx(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "rawTx"); e != nil {
		return e
	}
	raw, e := bytesFromArg(args[0])
	if e != nil {
		return e
	}
	msgTx := wire.NewMsgTx(wire.TxVersion)
	if err := msgTx.Deserialize(bytes.NewReader(raw)); err != nil {
		return errfResult("parse tx: %s", err)
	}
	pkt, err := btcpsbt.NewFromUnsignedTx(msgTx)
	if err != nil {
		return errfResult("fromUnsignedTx: %s", err)
	}
	return reserialize(pkt)
}

// ---------------------------------------------------------------------------
// updater — inputs
// ---------------------------------------------------------------------------

func psbtAddInNonWitnessUtxo(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 3, "base64Psbt, inIndex, rawTx"); e != nil {
		return e
	}
	pkt, e := parsePsbt(args[0].String())
	if e != nil {
		return e
	}
	updater, err := btcpsbt.NewUpdater(pkt)
	if err != nil {
		return errfResult("newUpdater: %s", err)
	}
	raw, e := bytesFromArg(args[2])
	if e != nil {
		return e
	}
	tx := wire.NewMsgTx(wire.TxVersion)
	if err := tx.Deserialize(bytes.NewReader(raw)); err != nil {
		return errfResult("parse tx: %s", err)
	}
	if err := updater.AddInNonWitnessUtxo(tx, args[1].Int()); err != nil {
		return errfResult("addInNonWitnessUtxo: %s", err)
	}
	return reserialize(pkt)
}

func psbtAddInWitnessUtxo(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 4,
		"base64Psbt, inIndex, value, pkScript"); e != nil {
		return e
	}
	pkt, e := parsePsbt(args[0].String())
	if e != nil {
		return e
	}
	updater, err := btcpsbt.NewUpdater(pkt)
	if err != nil {
		return errfResult("newUpdater: %s", err)
	}
	pkScript, e := bytesFromArg(args[3])
	if e != nil {
		return e
	}
	txout := wire.NewTxOut(int64(args[2].Float()), pkScript)
	if err := updater.AddInWitnessUtxo(txout, args[1].Int()); err != nil {
		return errfResult("addInWitnessUtxo: %s", err)
	}
	return reserialize(pkt)
}

func psbtAddInSighashType(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 3,
		"base64Psbt, inIndex, sighashType"); e != nil {
		return e
	}
	pkt, e := parsePsbt(args[0].String())
	if e != nil {
		return e
	}
	updater, err := btcpsbt.NewUpdater(pkt)
	if err != nil {
		return errfResult("newUpdater: %s", err)
	}
	if err := updater.AddInSighashType(
		txscriptSigHashType(args[2].Int()), args[1].Int(),
	); err != nil {
		return errfResult("addInSighashType: %s", err)
	}
	return reserialize(pkt)
}

func psbtAddInRedeemScript(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 3,
		"base64Psbt, inIndex, redeemScript"); e != nil {
		return e
	}
	pkt, e := parsePsbt(args[0].String())
	if e != nil {
		return e
	}
	updater, err := btcpsbt.NewUpdater(pkt)
	if err != nil {
		return errfResult("newUpdater: %s", err)
	}
	script, e := bytesFromArg(args[2])
	if e != nil {
		return e
	}
	if err := updater.AddInRedeemScript(script, args[1].Int()); err != nil {
		return errfResult("addInRedeemScript: %s", err)
	}
	return reserialize(pkt)
}

func psbtAddInWitnessScript(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 3,
		"base64Psbt, inIndex, witnessScript"); e != nil {
		return e
	}
	pkt, e := parsePsbt(args[0].String())
	if e != nil {
		return e
	}
	updater, err := btcpsbt.NewUpdater(pkt)
	if err != nil {
		return errfResult("newUpdater: %s", err)
	}
	script, e := bytesFromArg(args[2])
	if e != nil {
		return e
	}
	if err := updater.AddInWitnessScript(script, args[1].Int()); err != nil {
		return errfResult("addInWitnessScript: %s", err)
	}
	return reserialize(pkt)
}

func psbtAddInBip32Derivation(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 5,
		"base64Psbt, inIndex, fingerprint, path[], pubKey"); e != nil {
		return e
	}
	pkt, e := parsePsbt(args[0].String())
	if e != nil {
		return e
	}
	updater, err := btcpsbt.NewUpdater(pkt)
	if err != nil {
		return errfResult("newUpdater: %s", err)
	}
	fp := uint32(args[2].Int())
	pathLen := args[3].Length()
	path := make([]uint32, pathLen)
	for i := 0; i < pathLen; i++ {
		path[i] = uint32(args[3].Index(i).Int())
	}
	pubKey, e := bytesFromArg(args[4])
	if e != nil {
		return e
	}
	if err := updater.AddInBip32Derivation(
		fp, path, pubKey, args[1].Int(),
	); err != nil {
		return errfResult("addInBip32Derivation: %s", err)
	}
	return reserialize(pkt)
}

// ---------------------------------------------------------------------------
// updater — outputs
// ---------------------------------------------------------------------------

func psbtAddOutBip32Derivation(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 5,
		"base64Psbt, outIndex, fingerprint, path[], pubKey"); e != nil {
		return e
	}
	pkt, e := parsePsbt(args[0].String())
	if e != nil {
		return e
	}
	updater, err := btcpsbt.NewUpdater(pkt)
	if err != nil {
		return errfResult("newUpdater: %s", err)
	}
	fp := uint32(args[2].Int())
	pathLen := args[3].Length()
	path := make([]uint32, pathLen)
	for i := 0; i < pathLen; i++ {
		path[i] = uint32(args[3].Index(i).Int())
	}
	pubKey, e := bytesFromArg(args[4])
	if e != nil {
		return e
	}
	if err := updater.AddOutBip32Derivation(
		fp, path, pubKey, args[1].Int(),
	); err != nil {
		return errfResult("addOutBip32Derivation: %s", err)
	}
	return reserialize(pkt)
}

func psbtAddOutRedeemScript(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 3,
		"base64Psbt, outIndex, redeemScript"); e != nil {
		return e
	}
	pkt, e := parsePsbt(args[0].String())
	if e != nil {
		return e
	}
	updater, err := btcpsbt.NewUpdater(pkt)
	if err != nil {
		return errfResult("newUpdater: %s", err)
	}
	script, e := bytesFromArg(args[2])
	if e != nil {
		return e
	}
	if err := updater.AddOutRedeemScript(script, args[1].Int()); err != nil {
		return errfResult("addOutRedeemScript: %s", err)
	}
	return reserialize(pkt)
}

func psbtAddOutWitnessScript(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 3,
		"base64Psbt, outIndex, witnessScript"); e != nil {
		return e
	}
	pkt, e := parsePsbt(args[0].String())
	if e != nil {
		return e
	}
	updater, err := btcpsbt.NewUpdater(pkt)
	if err != nil {
		return errfResult("newUpdater: %s", err)
	}
	script, e := bytesFromArg(args[2])
	if e != nil {
		return e
	}
	if err := updater.AddOutWitnessScript(script, args[1].Int()); err != nil {
		return errfResult("addOutWitnessScript: %s", err)
	}
	return reserialize(pkt)
}

// ---------------------------------------------------------------------------
// signing
// ---------------------------------------------------------------------------

func psbtSign(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 4,
		"base64Psbt, inIndex, sig, pubKey"); e != nil {
		return e
	}
	pkt, e := parsePsbt(args[0].String())
	if e != nil {
		return e
	}
	updater, err := btcpsbt.NewUpdater(pkt)
	if err != nil {
		return errfResult("newUpdater: %s", err)
	}
	sig, e := bytesFromArg(args[2])
	if e != nil {
		return e
	}
	pubKey, e := bytesFromArg(args[3])
	if e != nil {
		return e
	}

	var redeemScript, witnessScript []byte
	if len(args) > 4 && args[4].Type() != js.TypeUndefined &&
		args[4].Type() != js.TypeNull {
		redeemScript, e = bytesFromArg(args[4])
		if e != nil {
			return e
		}
	}
	if len(args) > 5 && args[5].Type() != js.TypeUndefined &&
		args[5].Type() != js.TypeNull {
		witnessScript, e = bytesFromArg(args[5])
		if e != nil {
			return e
		}
	}

	outcome, err := updater.Sign(
		args[1].Int(), sig, pubKey, redeemScript, witnessScript,
	)
	if err != nil {
		return errfResult("sign: %s", err)
	}

	b64, err := pkt.B64Encode()
	if err != nil {
		return errfResult("encode: %s", err)
	}
	return okResult(map[string]any{
		"psbt":    b64,
		"outcome": int(outcome),
	})
}

// ---------------------------------------------------------------------------
// finalization
// ---------------------------------------------------------------------------

func psbtFinalize(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 2, "base64Psbt, inIndex"); e != nil {
		return e
	}
	pkt, e := parsePsbt(args[0].String())
	if e != nil {
		return e
	}
	if err := btcpsbt.Finalize(pkt, args[1].Int()); err != nil {
		return errfResult("finalize: %s", err)
	}
	return reserialize(pkt)
}

func psbtMaybeFinalize(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 2, "base64Psbt, inIndex"); e != nil {
		return e
	}
	pkt, e := parsePsbt(args[0].String())
	if e != nil {
		return e
	}
	finalized, err := btcpsbt.MaybeFinalize(pkt, args[1].Int())
	if err != nil {
		return errfResult("maybeFinalize: %s", err)
	}
	b64, err := pkt.B64Encode()
	if err != nil {
		return errfResult("encode: %s", err)
	}
	return okResult(map[string]any{
		"psbt":      b64,
		"finalized": finalized,
	})
}

func psbtMaybeFinalizeAll(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "base64Psbt"); e != nil {
		return e
	}
	pkt, e := parsePsbt(args[0].String())
	if e != nil {
		return e
	}
	if err := btcpsbt.MaybeFinalizeAll(pkt); err != nil {
		return errfResult("maybeFinalizeAll: %s", err)
	}
	return reserialize(pkt)
}

// ---------------------------------------------------------------------------
// sorting & validation
// ---------------------------------------------------------------------------

func psbtInPlaceSort(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "base64Psbt"); e != nil {
		return e
	}
	pkt, e := parsePsbt(args[0].String())
	if e != nil {
		return e
	}
	if err := btcpsbt.InPlaceSort(pkt); err != nil {
		return errfResult("inPlaceSort: %s", err)
	}
	return reserialize(pkt)
}

func psbtSumUtxoInputValues(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "base64Psbt"); e != nil {
		return e
	}
	pkt, e := parsePsbt(args[0].String())
	if e != nil {
		return e
	}
	sum, err := btcpsbt.SumUtxoInputValues(pkt)
	if err != nil {
		return errfResult("sumUtxoInputValues: %s", err)
	}
	return okResult(sum)
}

func psbtInputsReadyToSign(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "base64Psbt"); e != nil {
		return e
	}
	pkt, e := parsePsbt(args[0].String())
	if e != nil {
		return e
	}
	if err := btcpsbt.InputsReadyToSign(pkt); err != nil {
		return errfResult("inputsReadyToSign: %s", err)
	}
	return okResult(true)
}

func psbtSanityCheck(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "base64Psbt"); e != nil {
		return e
	}
	pkt, e := parsePsbt(args[0].String())
	if e != nil {
		return e
	}
	if err := pkt.SanityCheck(); err != nil {
		return errfResult("sanityCheck: %s", err)
	}
	return okResult(true)
}
