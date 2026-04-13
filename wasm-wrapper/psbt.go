//go:build js && wasm

package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"syscall/js"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
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

// nonNilBytes returns nil if the slice is empty, otherwise a non-aliased copy.
// PSBT TLV encoding distinguishes "field absent" (nil) from "field present
// with an empty value".
func nonNilBytes(b HexBytes) []byte {
	if len(b) == 0 {
		return nil
	}
	return []byte(b)
}

// ---------------------------------------------------------------------------
// btcpsbt → JSON
// ---------------------------------------------------------------------------

func bip32DerivationToJSON(d []*btcpsbt.Bip32Derivation) []Bip32DerivationJSON {
	if len(d) == 0 {
		return nil
	}
	out := make([]Bip32DerivationJSON, len(d))
	for i, bd := range d {
		out[i] = Bip32DerivationJSON{
			PubKey:               HexBytes(bd.PubKey),
			MasterKeyFingerprint: HexUint32(bd.MasterKeyFingerprint),
			Path:                 bd.Bip32Path,
			PathStr:              formatBip32Path(bd.Bip32Path),
		}
	}
	return out
}

func bip32DerivationFromJSON(
	d []Bip32DerivationJSON,
) []*btcpsbt.Bip32Derivation {

	if len(d) == 0 {
		return nil
	}
	out := make([]*btcpsbt.Bip32Derivation, len(d))
	for i := range d {
		bd := &d[i]
		out[i] = &btcpsbt.Bip32Derivation{
			PubKey:               []byte(bd.PubKey),
			MasterKeyFingerprint: uint32(bd.MasterKeyFingerprint),
			Bip32Path:            bd.effectivePath(),
		}
	}
	return out
}

func taprootBip32DerivationToJSON(
	d []*btcpsbt.TaprootBip32Derivation,
) []TaprootBip32DerivationJSON {

	if len(d) == 0 {
		return nil
	}
	out := make([]TaprootBip32DerivationJSON, len(d))
	for i, td := range d {
		leafHashes := make([]HexBytes, len(td.LeafHashes))
		for j, lh := range td.LeafHashes {
			leafHashes[j] = HexBytes(lh)
		}
		out[i] = TaprootBip32DerivationJSON{
			XOnlyPubKey:          HexBytes(td.XOnlyPubKey),
			LeafHashes:           leafHashes,
			MasterKeyFingerprint: HexUint32(td.MasterKeyFingerprint),
			Path:                 td.Bip32Path,
			PathStr:              formatBip32Path(td.Bip32Path),
		}
	}
	return out
}

func taprootBip32DerivationFromJSON(
	d []TaprootBip32DerivationJSON,
) []*btcpsbt.TaprootBip32Derivation {

	if len(d) == 0 {
		return nil
	}
	out := make([]*btcpsbt.TaprootBip32Derivation, len(d))
	for i := range d {
		td := &d[i]
		var leafHashes [][]byte
		if len(td.LeafHashes) > 0 {
			leafHashes = make([][]byte, len(td.LeafHashes))
			for j, lh := range td.LeafHashes {
				leafHashes[j] = []byte(lh)
			}
		}
		out[i] = &btcpsbt.TaprootBip32Derivation{
			XOnlyPubKey:          []byte(td.XOnlyPubKey),
			LeafHashes:           leafHashes,
			MasterKeyFingerprint: uint32(td.MasterKeyFingerprint),
			Bip32Path:            td.effectivePath(),
		}
	}
	return out
}

func unknownsToJSON(unknowns []*btcpsbt.Unknown) []UnknownJSON {
	if len(unknowns) == 0 {
		return nil
	}
	out := make([]UnknownJSON, len(unknowns))
	for i, u := range unknowns {
		out[i] = UnknownJSON{
			Key:   HexBytes(u.Key),
			Value: HexBytes(u.Value),
		}
	}
	return out
}

func unknownsFromJSON(unknowns []UnknownJSON) []*btcpsbt.Unknown {
	if len(unknowns) == 0 {
		return nil
	}
	out := make([]*btcpsbt.Unknown, len(unknowns))
	for i, u := range unknowns {
		out[i] = &btcpsbt.Unknown{
			Key:   []byte(u.Key),
			Value: []byte(u.Value),
		}
	}
	return out
}

func partialSigsToJSON(sigs []*btcpsbt.PartialSig) []PartialSigJSON {
	if len(sigs) == 0 {
		return nil
	}
	out := make([]PartialSigJSON, len(sigs))
	for i, ps := range sigs {
		out[i] = PartialSigJSON{
			PubKey:    HexBytes(ps.PubKey),
			Signature: HexBytes(ps.Signature),
		}
	}
	return out
}

func partialSigsFromJSON(sigs []PartialSigJSON) []*btcpsbt.PartialSig {
	if len(sigs) == 0 {
		return nil
	}
	out := make([]*btcpsbt.PartialSig, len(sigs))
	for i, ps := range sigs {
		out[i] = &btcpsbt.PartialSig{
			PubKey:    []byte(ps.PubKey),
			Signature: []byte(ps.Signature),
		}
	}
	return out
}

func taprootScriptSpendSigsToJSON(
	sigs []*btcpsbt.TaprootScriptSpendSig,
) []TaprootScriptSpendSigJSON {

	if len(sigs) == 0 {
		return nil
	}
	out := make([]TaprootScriptSpendSigJSON, len(sigs))
	for i, ss := range sigs {
		out[i] = TaprootScriptSpendSigJSON{
			XOnlyPubKey: HexBytes(ss.XOnlyPubKey),
			LeafHash:    HexBytes(ss.LeafHash),
			Signature:   HexBytes(ss.Signature),
			SigHash:     uint32(ss.SigHash),
		}
	}
	return out
}

func taprootScriptSpendSigsFromJSON(
	sigs []TaprootScriptSpendSigJSON,
) []*btcpsbt.TaprootScriptSpendSig {

	if len(sigs) == 0 {
		return nil
	}
	out := make([]*btcpsbt.TaprootScriptSpendSig, len(sigs))
	for i, ss := range sigs {
		out[i] = &btcpsbt.TaprootScriptSpendSig{
			XOnlyPubKey: []byte(ss.XOnlyPubKey),
			LeafHash:    []byte(ss.LeafHash),
			Signature:   []byte(ss.Signature),
			SigHash:     txscriptSigHashType(int(ss.SigHash)),
		}
	}
	return out
}

func taprootLeafScriptsToJSON(
	leaves []*btcpsbt.TaprootTapLeafScript,
) []TaprootLeafScriptJSON {

	if len(leaves) == 0 {
		return nil
	}
	out := make([]TaprootLeafScriptJSON, len(leaves))
	for i, ls := range leaves {
		out[i] = TaprootLeafScriptJSON{
			ControlBlock: HexBytes(ls.ControlBlock),
			Script:       HexBytes(ls.Script),
			LeafVersion:  uint8(ls.LeafVersion),
		}
	}
	return out
}

func taprootLeafScriptsFromJSON(
	leaves []TaprootLeafScriptJSON,
) []*btcpsbt.TaprootTapLeafScript {

	if len(leaves) == 0 {
		return nil
	}
	out := make([]*btcpsbt.TaprootTapLeafScript, len(leaves))
	for i, ls := range leaves {
		out[i] = &btcpsbt.TaprootTapLeafScript{
			ControlBlock: []byte(ls.ControlBlock),
			Script:       []byte(ls.Script),
			LeafVersion:  txscriptLeafVersion(int(ls.LeafVersion)),
		}
	}
	return out
}

func xpubsToJSON(xpubs []btcpsbt.XPub) []XPubJSON {
	if len(xpubs) == 0 {
		return nil
	}
	out := make([]XPubJSON, len(xpubs))
	for i, xp := range xpubs {
		// Convert the 78-byte PSBT-wire form to a base58 xpub/xprv
		// string. If the bytes are malformed we still emit the entry
		// (with an empty string) so the round-trip surfaces the issue
		// downstream rather than panicking here.
		var ext string
		if k, err := btcpsbt.DecodeExtendedKey(xp.ExtendedKey); err == nil {
			ext = k.String()
		}
		out[i] = XPubJSON{
			ExtendedKey:          ext,
			MasterKeyFingerprint: HexUint32(xp.MasterKeyFingerprint),
			Path:                 xp.Bip32Path,
			PathStr:              formatBip32Path(xp.Bip32Path),
		}
	}
	return out
}

func xpubsFromJSON(xpubs []XPubJSON) []btcpsbt.XPub {
	if len(xpubs) == 0 {
		return nil
	}
	out := make([]btcpsbt.XPub, len(xpubs))
	for i := range xpubs {
		xp := &xpubs[i]
		var keyBytes []byte
		if xp.ExtendedKey != "" {
			if k, err := hdkeychain.NewKeyFromString(
				xp.ExtendedKey,
			); err == nil {
				keyBytes = btcpsbt.EncodeExtendedKey(k)
			}
		}
		out[i] = btcpsbt.XPub{
			ExtendedKey:          keyBytes,
			MasterKeyFingerprint: uint32(xp.MasterKeyFingerprint),
			Bip32Path:            xp.effectivePath(),
		}
	}
	return out
}

// psbtToJSON builds the full decode-shape PsbtJSON.
func psbtToJSON(pkt *btcpsbt.Packet) PsbtJSON {
	inputs := make([]PsbtInputJSON, len(pkt.Inputs))
	for i, pIn := range pkt.Inputs {
		inp := PsbtInputJSON{
			RedeemScript:           HexBytes(pIn.RedeemScript),
			WitnessScript:          HexBytes(pIn.WitnessScript),
			PartialSigs:            partialSigsToJSON(pIn.PartialSigs),
			FinalScriptSig:         HexBytes(pIn.FinalScriptSig),
			FinalScriptWitness:     HexBytes(pIn.FinalScriptWitness),
			Bip32Derivation:        bip32DerivationToJSON(pIn.Bip32Derivation),
			TaprootKeySpendSig:     HexBytes(pIn.TaprootKeySpendSig),
			TaprootInternalKey:     HexBytes(pIn.TaprootInternalKey),
			TaprootMerkleRoot:      HexBytes(pIn.TaprootMerkleRoot),
			TaprootScriptSpendSigs: taprootScriptSpendSigsToJSON(pIn.TaprootScriptSpendSig),
			TaprootLeafScripts:     taprootLeafScriptsToJSON(pIn.TaprootLeafScript),
			TaprootBip32Derivation: taprootBip32DerivationToJSON(pIn.TaprootBip32Derivation),
			Unknowns:               unknownsToJSON(pIn.Unknowns),
		}
		if pIn.SighashType != 0 {
			sh := uint32(pIn.SighashType)
			inp.SighashType = &sh
		}
		if pIn.NonWitnessUtxo != nil {
			var buf bytes.Buffer
			_ = pIn.NonWitnessUtxo.Serialize(&buf)
			inp.NonWitnessUtxo = HexBytes(buf.Bytes())
		}
		if pIn.WitnessUtxo != nil {
			inp.WitnessUtxo = &WitnessUtxoJSON{
				Value:  pIn.WitnessUtxo.Value,
				Script: HexBytes(pIn.WitnessUtxo.PkScript),
			}
		}
		inputs[i] = inp
	}

	outputs := make([]PsbtOutputJSON, len(pkt.Outputs))
	for i, pOut := range pkt.Outputs {
		outputs[i] = PsbtOutputJSON{
			RedeemScript:           HexBytes(pOut.RedeemScript),
			WitnessScript:          HexBytes(pOut.WitnessScript),
			Bip32Derivation:        bip32DerivationToJSON(pOut.Bip32Derivation),
			TaprootInternalKey:     HexBytes(pOut.TaprootInternalKey),
			TaprootTapTree:         HexBytes(pOut.TaprootTapTree),
			TaprootBip32Derivation: taprootBip32DerivationToJSON(pOut.TaprootBip32Derivation),
			Unknowns:               unknownsToJSON(pOut.Unknowns),
		}
	}

	fee := int64(-1)
	if f, err := pkt.GetTxFee(); err == nil {
		fee = int64(f)
	}

	return PsbtJSON{
		UnsignedTx: txToJSON(pkt.UnsignedTx),
		XPubs:      xpubsToJSON(pkt.XPubs),
		Unknowns:   unknownsToJSON(pkt.Unknowns),
		Inputs:     inputs,
		Outputs:    outputs,
		IsComplete: pkt.IsComplete(),
		Fee:        fee,
	}
}

// psbtFromData builds a *btcpsbt.Packet from the encode-input shape. Bypasses
// btcpsbt.NewFromUnsignedTx's zero-input/zero-output check so fully empty
// PSBTs (useful when building a PSBT from scratch in an editor) can round-
// trip through encode.
func psbtFromData(j PsbtDataJSON) (*btcpsbt.Packet, error) {
	msgTx, err := txFromData(j.UnsignedTx)
	if err != nil {
		return nil, err
	}
	pkt := &btcpsbt.Packet{
		UnsignedTx: msgTx,
		Inputs:     make([]btcpsbt.PInput, len(msgTx.TxIn)),
		Outputs:    make([]btcpsbt.POutput, len(msgTx.TxOut)),
	}

	pkt.XPubs = xpubsFromJSON(j.XPubs)
	pkt.Unknowns = unknownsFromJSON(j.Unknowns)

	for i := 0; i < len(j.Inputs) && i < len(pkt.Inputs); i++ {
		jIn := j.Inputs[i]
		pIn := &pkt.Inputs[i]

		if len(jIn.NonWitnessUtxo) > 0 {
			tx := wire.NewMsgTx(wire.TxVersion)
			if err := tx.Deserialize(
				bytes.NewReader(jIn.NonWitnessUtxo),
			); err != nil {
				return nil, fmt.Errorf(
					"input[%d] nonWitnessUtxo: %w", i, err,
				)
			}
			pIn.NonWitnessUtxo = tx
		}

		if jIn.WitnessUtxo != nil && len(jIn.WitnessUtxo.Script) > 0 {
			pIn.WitnessUtxo = wire.NewTxOut(
				jIn.WitnessUtxo.Value,
				[]byte(jIn.WitnessUtxo.Script),
			)
		}

		if jIn.SighashType != nil {
			pIn.SighashType = txscriptSigHashType(
				int(*jIn.SighashType),
			)
		}
		pIn.RedeemScript = nonNilBytes(jIn.RedeemScript)
		pIn.WitnessScript = nonNilBytes(jIn.WitnessScript)
		pIn.FinalScriptSig = nonNilBytes(jIn.FinalScriptSig)
		pIn.FinalScriptWitness = nonNilBytes(jIn.FinalScriptWitness)
		pIn.PartialSigs = partialSigsFromJSON(jIn.PartialSigs)
		pIn.Bip32Derivation = bip32DerivationFromJSON(jIn.Bip32Derivation)
		pIn.TaprootKeySpendSig = nonNilBytes(jIn.TaprootKeySpendSig)
		pIn.TaprootInternalKey = nonNilBytes(jIn.TaprootInternalKey)
		pIn.TaprootMerkleRoot = nonNilBytes(jIn.TaprootMerkleRoot)
		pIn.TaprootScriptSpendSig = taprootScriptSpendSigsFromJSON(
			jIn.TaprootScriptSpendSigs,
		)
		pIn.TaprootLeafScript = taprootLeafScriptsFromJSON(
			jIn.TaprootLeafScripts,
		)
		pIn.TaprootBip32Derivation = taprootBip32DerivationFromJSON(
			jIn.TaprootBip32Derivation,
		)
		pIn.Unknowns = unknownsFromJSON(jIn.Unknowns)
	}

	for i := 0; i < len(j.Outputs) && i < len(pkt.Outputs); i++ {
		jOut := j.Outputs[i]
		pOut := &pkt.Outputs[i]

		pOut.RedeemScript = nonNilBytes(jOut.RedeemScript)
		pOut.WitnessScript = nonNilBytes(jOut.WitnessScript)
		pOut.Bip32Derivation = bip32DerivationFromJSON(jOut.Bip32Derivation)
		pOut.TaprootInternalKey = nonNilBytes(jOut.TaprootInternalKey)
		pOut.TaprootTapTree = nonNilBytes(jOut.TaprootTapTree)
		pOut.TaprootBip32Derivation = taprootBip32DerivationFromJSON(
			jOut.TaprootBip32Derivation,
		)
		pOut.Unknowns = unknownsFromJSON(jOut.Unknowns)
	}

	return pkt, nil
}

// ---------------------------------------------------------------------------
// decode / encode
// ---------------------------------------------------------------------------

func psbtDecode(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "base64Psbt"); e != nil {
		return e
	}
	pkt, e := parsePsbt(args[0].String())
	if e != nil {
		return e
	}
	return marshalJSON(psbtToJSON(pkt))
}

// psbtEncode reconstructs a PSBT from a JSON-shaped PsbtDataJSON value and
// returns the base64-encoded PSBT string.
func psbtEncode(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "data"); e != nil {
		return e
	}
	var j PsbtDataJSON
	if e := unmarshalArg(args[0], &j); e != nil {
		return e
	}
	pkt, err := psbtFromData(j)
	if err != nil {
		return errfResult("%s", err)
	}
	var buf bytes.Buffer
	if err := pkt.Serialize(&buf); err != nil {
		return errfResult("encode: %s", err)
	}
	// Base64-encode the raw PSBT bytes directly (bypasses btcpsbt's
	// B64Encode, which goes through SanityCheck and would reject empty
	// PSBTs).
	return okResult(base64.StdEncoding.EncodeToString(buf.Bytes()))
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

// ---------------------------------------------------------------------------
// allUnknowns helper — unify the three levels (global/input/output) into a
// single flat stream.
// ---------------------------------------------------------------------------

// psbtEncodeExtendedKey wraps btcpsbt.EncodeExtendedKey: take a base58
// xpub/xprv string and return the 78-byte PSBT-format byte slice (the
// checksum-less form stored in PSBT_GLOBAL_XPUB).
func psbtEncodeExtendedKey(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "extendedKey"); e != nil {
		return e
	}
	xkey, err := hdkeychain.NewKeyFromString(args[0].String())
	if err != nil {
		return errfResult("invalid extended key: %s", err)
	}
	return okResult(bytesToJS(btcpsbt.EncodeExtendedKey(xkey)))
}

// psbtDecodeExtendedKey wraps btcpsbt.DecodeExtendedKey: take the 78-byte
// PSBT-format byte slice and return the base58 xpub/xprv string.
func psbtDecodeExtendedKey(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "extendedKey"); e != nil {
		return e
	}
	raw, e := bytesFromArg(args[0])
	if e != nil {
		return e
	}
	xkey, err := btcpsbt.DecodeExtendedKey(raw)
	if err != nil {
		return errfResult("decode extended key: %s", err)
	}
	return okResult(xkey.String())
}

// psbtAllUnknowns returns [{level: 'global'|'input'|'output', index, key, value}]
// for every unknown TLV entry at any level. -1 index for global. Convenience
// helper for editors that want to show a unified view.
func psbtAllUnknowns(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "base64Psbt"); e != nil {
		return e
	}
	pkt, e := parsePsbt(args[0].String())
	if e != nil {
		return e
	}

	entries := []any{}
	for _, u := range pkt.Unknowns {
		entries = append(entries, map[string]any{
			"level": "global",
			"index": -1,
			"key":   bytesToJS(u.Key),
			"value": bytesToJS(u.Value),
		})
	}
	for i, in := range pkt.Inputs {
		for _, u := range in.Unknowns {
			entries = append(entries, map[string]any{
				"level": "input",
				"index": i,
				"key":   bytesToJS(u.Key),
				"value": bytesToJS(u.Value),
			})
		}
	}
	for i, out := range pkt.Outputs {
		for _, u := range out.Unknowns {
			entries = append(entries, map[string]any{
				"level": "output",
				"index": i,
				"key":   bytesToJS(u.Key),
				"value": bytesToJS(u.Value),
			})
		}
	}
	return okResult(entries)
}
