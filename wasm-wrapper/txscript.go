//go:build js && wasm

package main

import (
	"encoding/hex"
	"syscall/js"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func buildPrevOutFetcher(
	msgTx *wire.MsgTx, prevOutsArg js.Value,
) (*txscript.MultiPrevOutFetcher, map[string]any) {

	n := prevOutsArg.Length()
	prevOuts := make(map[wire.OutPoint]*wire.TxOut, n)
	for i := 0; i < n && i < len(msgTx.TxIn); i++ {
		entry := prevOutsArg.Index(i)
		script, err := hex.DecodeString(entry.Get("script").String())
		if err != nil {
			return nil, errfResult("invalid prevOut script[%d]: %s",
				i, err)
		}
		amt := int64(entry.Get("amount").Float())
		prevOuts[msgTx.TxIn[i].PreviousOutPoint] = &wire.TxOut{
			PkScript: script,
			Value:    amt,
		}
	}
	return txscript.NewMultiPrevOutFetcher(prevOuts), nil
}

// ---------------------------------------------------------------------------
// script type checks
// ---------------------------------------------------------------------------

func txscriptIsPayToPubKey(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "hexScript"); e != nil {
		return e
	}
	b, e := hexDecode(args[0].String())
	if e != nil {
		return e
	}
	return okResult(txscript.IsPayToPubKey(b))
}

func txscriptIsPayToPubKeyHash(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "hexScript"); e != nil {
		return e
	}
	b, e := hexDecode(args[0].String())
	if e != nil {
		return e
	}
	return okResult(txscript.IsPayToPubKeyHash(b))
}

func txscriptIsPayToScriptHash(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "hexScript"); e != nil {
		return e
	}
	b, e := hexDecode(args[0].String())
	if e != nil {
		return e
	}
	return okResult(txscript.IsPayToScriptHash(b))
}

func txscriptIsPayToWitnessPubKeyHash(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "hexScript"); e != nil {
		return e
	}
	b, e := hexDecode(args[0].String())
	if e != nil {
		return e
	}
	return okResult(txscript.IsPayToWitnessPubKeyHash(b))
}

func txscriptIsPayToWitnessScriptHash(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "hexScript"); e != nil {
		return e
	}
	b, e := hexDecode(args[0].String())
	if e != nil {
		return e
	}
	return okResult(txscript.IsPayToWitnessScriptHash(b))
}

func txscriptIsPayToTaproot(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "hexScript"); e != nil {
		return e
	}
	b, e := hexDecode(args[0].String())
	if e != nil {
		return e
	}
	return okResult(txscript.IsPayToTaproot(b))
}

func txscriptIsWitnessProgram(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "hexScript"); e != nil {
		return e
	}
	b, e := hexDecode(args[0].String())
	if e != nil {
		return e
	}
	return okResult(txscript.IsWitnessProgram(b))
}

func txscriptIsNullData(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "hexScript"); e != nil {
		return e
	}
	b, e := hexDecode(args[0].String())
	if e != nil {
		return e
	}
	return okResult(txscript.IsNullData(b))
}

func txscriptIsMultisigScript(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "hexScript"); e != nil {
		return e
	}
	b, e := hexDecode(args[0].String())
	if e != nil {
		return e
	}
	is, err := txscript.IsMultisigScript(b)
	if err != nil {
		return errfResult("isMultisigScript: %s", err)
	}
	return okResult(is)
}

func txscriptIsUnspendable(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "hexScript"); e != nil {
		return e
	}
	b, e := hexDecode(args[0].String())
	if e != nil {
		return e
	}
	return okResult(txscript.IsUnspendable(b))
}

func txscriptIsPushOnlyScript(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "hexScript"); e != nil {
		return e
	}
	b, e := hexDecode(args[0].String())
	if e != nil {
		return e
	}
	return okResult(txscript.IsPushOnlyScript(b))
}

func txscriptScriptHasOpSuccess(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "hexScript"); e != nil {
		return e
	}
	b, e := hexDecode(args[0].String())
	if e != nil {
		return e
	}
	return okResult(txscript.ScriptHasOpSuccess(b))
}

// ---------------------------------------------------------------------------
// script parsing / analysis
// ---------------------------------------------------------------------------

func txscriptDisasmString(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "hexScript"); e != nil {
		return e
	}
	b, e := hexDecode(args[0].String())
	if e != nil {
		return e
	}
	s, err := txscript.DisasmString(b)
	if err != nil {
		return errfResult("disasmString: %s", err)
	}
	return okResult(s)
}

func txscriptGetScriptClass(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "hexScript"); e != nil {
		return e
	}
	b, e := hexDecode(args[0].String())
	if e != nil {
		return e
	}
	return okResult(txscript.GetScriptClass(b).String())
}

func txscriptExtractWitnessProgramInfo(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "hexScript"); e != nil {
		return e
	}
	b, e := hexDecode(args[0].String())
	if e != nil {
		return e
	}
	version, program, err := txscript.ExtractWitnessProgramInfo(b)
	if err != nil {
		return errfResult("extractWitnessProgramInfo: %s", err)
	}
	return okResult(map[string]any{
		"version": version,
		"program": bytesToJS(program),
	})
}

func txscriptExtractPkScriptAddrs(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "hexScript"); e != nil {
		return e
	}
	b, e := hexDecode(args[0].String())
	if e != nil {
		return e
	}
	params, e := getNetwork(optString(args, 1, "mainnet"))
	if e != nil {
		return e
	}
	class, addrs, reqSigs, err := txscript.ExtractPkScriptAddrs(b, params)
	if err != nil {
		return errfResult("extractPkScriptAddrs: %s", err)
	}
	addrStrs := make([]any, len(addrs))
	for i, a := range addrs {
		addrStrs[i] = a.EncodeAddress()
	}
	return okResult(map[string]any{
		"scriptClass": class.String(),
		"addresses":   addrStrs,
		"reqSigs":     reqSigs,
	})
}

func txscriptPushedData(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "hexScript"); e != nil {
		return e
	}
	b, e := hexDecode(args[0].String())
	if e != nil {
		return e
	}
	data, err := txscript.PushedData(b)
	if err != nil {
		return errfResult("pushedData: %s", err)
	}
	items := make([]any, len(data))
	for i, d := range data {
		items[i] = bytesToJS(d)
	}
	return okResult(items)
}

func txscriptGetSigOpCount(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "hexScript"); e != nil {
		return e
	}
	b, e := hexDecode(args[0].String())
	if e != nil {
		return e
	}
	return okResult(txscript.GetSigOpCount(b))
}

func txscriptCalcMultiSigStats(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "hexScript"); e != nil {
		return e
	}
	b, e := hexDecode(args[0].String())
	if e != nil {
		return e
	}
	numPubKeys, numSigs, err := txscript.CalcMultiSigStats(b)
	if err != nil {
		return errfResult("calcMultiSigStats: %s", err)
	}
	return okResult(map[string]any{
		"numPubKeys": numPubKeys,
		"numSigs":    numSigs,
	})
}

func txscriptParsePkScript(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "hexScript"); e != nil {
		return e
	}
	b, e := hexDecode(args[0].String())
	if e != nil {
		return e
	}
	pkScript, err := txscript.ParsePkScript(b)
	if err != nil {
		return errfResult("parsePkScript: %s", err)
	}

	result := map[string]any{
		"class":  pkScript.Class().String(),
		"script": bytesToJS(pkScript.Script()),
	}

	params, e := getNetwork(optString(args, 1, "mainnet"))
	if e == nil {
		if addr, err := pkScript.Address(params); err == nil {
			result["address"] = addr.EncodeAddress()
		}
	}

	return okResult(result)
}

func txscriptComputePkScript(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 2, "hexSigScript, hexWitness[]"); e != nil {
		return e
	}
	sigScript, e := hexDecode(args[0].String())
	if e != nil {
		return e
	}

	witnessLen := args[1].Length()
	witness := make(wire.TxWitness, witnessLen)
	for i := 0; i < witnessLen; i++ {
		w, err := hex.DecodeString(args[1].Index(i).String())
		if err != nil {
			return errfResult("invalid witness[%d]: %s", i, err)
		}
		witness[i] = w
	}

	pkScript, err := txscript.ComputePkScript(sigScript, witness)
	if err != nil {
		return errfResult("computePkScript: %s", err)
	}

	result := map[string]any{
		"class":  pkScript.Class().String(),
		"script": bytesToJS(pkScript.Script()),
	}

	params, e := getNetwork(optString(args, 2, "mainnet"))
	if e == nil {
		if addr, err := pkScript.Address(params); err == nil {
			result["address"] = addr.EncodeAddress()
		}
	}

	return okResult(result)
}

// ---------------------------------------------------------------------------
// script creation
// ---------------------------------------------------------------------------

func txscriptPayToAddrScript(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "address"); e != nil {
		return e
	}
	params, e := getNetwork(optString(args, 1, "mainnet"))
	if e != nil {
		return e
	}
	addr, err := btcutil.DecodeAddress(args[0].String(), params)
	if err != nil {
		return errfResult("decode address: %s", err)
	}
	script, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return errfResult("payToAddrScript: %s", err)
	}
	return okResult(bytesToJS(script))
}

func txscriptNullDataScript(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "hexData"); e != nil {
		return e
	}
	data, e := hexDecode(args[0].String())
	if e != nil {
		return e
	}
	script, err := txscript.NullDataScript(data)
	if err != nil {
		return errfResult("nullDataScript: %s", err)
	}
	return okResult(bytesToJS(script))
}

func txscriptPayToTaprootScript(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "hexPubKey"); e != nil {
		return e
	}
	b, e := hexDecode(args[0].String())
	if e != nil {
		return e
	}
	key, err := schnorr.ParsePubKey(b)
	if err != nil {
		key, err = btcec.ParsePubKey(b)
		if err != nil {
			return errfResult("invalid public key: %s", err)
		}
	}
	script, err := txscript.PayToTaprootScript(key)
	if err != nil {
		return errfResult("payToTaprootScript: %s", err)
	}
	return okResult(bytesToJS(script))
}

func txscriptMultiSigScript(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 2, "hexPubKeys[], nRequired"); e != nil {
		return e
	}
	params, e := getNetwork(optString(args, 2, "mainnet"))
	if e != nil {
		return e
	}

	n := args[0].Length()
	pubkeys := make([]*btcutil.AddressPubKey, n)
	for i := 0; i < n; i++ {
		b, err := hex.DecodeString(args[0].Index(i).String())
		if err != nil {
			return errfResult("invalid pubkey[%d]: %s", i, err)
		}
		addr, err := btcutil.NewAddressPubKey(b, params)
		if err != nil {
			return errfResult("newAddressPubKey[%d]: %s", i, err)
		}
		pubkeys[i] = addr
	}

	nRequired := args[1].Int()
	script, err := txscript.MultiSigScript(pubkeys, nRequired)
	if err != nil {
		return errfResult("multiSigScript: %s", err)
	}
	return okResult(bytesToJS(script))
}

// ---------------------------------------------------------------------------
// taproot utilities
// ---------------------------------------------------------------------------

func txscriptComputeTaprootOutputKey(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "hexInternalKey"); e != nil {
		return e
	}
	b, e := hexDecode(args[0].String())
	if e != nil {
		return e
	}
	key, err := schnorr.ParsePubKey(b)
	if err != nil {
		key, err = btcec.ParsePubKey(b)
		if err != nil {
			return errfResult("invalid key: %s", err)
		}
	}

	var scriptRoot []byte
	if len(args) > 1 && args[1].Type() == js.TypeString &&
		args[1].String() != "" {

		scriptRoot, e = hexDecode(args[1].String())
		if e != nil {
			return e
		}
	}

	outKey := txscript.ComputeTaprootOutputKey(key, scriptRoot)
	return okResult(bytesToJS(schnorr.SerializePubKey(outKey)))
}

func txscriptComputeTaprootKeyNoScript(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "hexInternalKey"); e != nil {
		return e
	}
	b, e := hexDecode(args[0].String())
	if e != nil {
		return e
	}
	key, err := schnorr.ParsePubKey(b)
	if err != nil {
		key, err = btcec.ParsePubKey(b)
		if err != nil {
			return errfResult("invalid key: %s", err)
		}
	}
	outKey := txscript.ComputeTaprootKeyNoScript(key)
	return okResult(bytesToJS(schnorr.SerializePubKey(outKey)))
}

func txscriptTweakTaprootPrivKey(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "hexPrivKey"); e != nil {
		return e
	}
	privBytes, e := hexDecode(args[0].String())
	if e != nil {
		return e
	}
	privKey, _ := btcec.PrivKeyFromBytes(privBytes)

	var scriptRoot []byte
	if len(args) > 1 && args[1].Type() == js.TypeString &&
		args[1].String() != "" {

		scriptRoot, e = hexDecode(args[1].String())
		if e != nil {
			return e
		}
	}

	tweaked := txscript.TweakTaprootPrivKey(*privKey, scriptRoot)
	return okResult(bytesToJS(tweaked.Serialize()))
}

func txscriptParseControlBlock(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "hexControlBlock"); e != nil {
		return e
	}
	b, e := hexDecode(args[0].String())
	if e != nil {
		return e
	}
	cb, err := txscript.ParseControlBlock(b)
	if err != nil {
		return errfResult("parseControlBlock: %s", err)
	}
	return okResult(map[string]any{
		"internalKey":     bytesToJS(schnorr.SerializePubKey(cb.InternalKey)),
		"leafVersion":     int(cb.LeafVersion),
		"outputKeyYIsOdd": cb.OutputKeyYIsOdd,
		"inclusionProof":  bytesToJS(cb.InclusionProof),
	})
}

func txscriptAssembleTaprootScriptTree(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 2, "hexInternalKey, leaves[]"); e != nil {
		return e
	}
	ikBytes, e := hexDecode(args[0].String())
	if e != nil {
		return e
	}
	ik, err := schnorr.ParsePubKey(ikBytes)
	if err != nil {
		ik, err = btcec.ParsePubKey(ikBytes)
		if err != nil {
			return errfResult("invalid internal key: %s", err)
		}
	}

	n := args[1].Length()
	leaves := make([]txscript.TapLeaf, n)
	for i := 0; i < n; i++ {
		entry := args[1].Index(i)
		script, err := hex.DecodeString(entry.Get("script").String())
		if err != nil {
			return errfResult("invalid leaf script[%d]: %s", i, err)
		}
		ver := txscript.BaseLeafVersion
		if v := entry.Get("version"); v.Type() == js.TypeNumber {
			ver = txscript.TapscriptLeafVersion(byte(v.Int()))
		}
		leaves[i] = txscript.NewTapLeaf(ver, script)
	}

	tree := txscript.AssembleTaprootScriptTree(leaves...)
	rootHash := tree.RootNode.TapHash()
	outKey := txscript.ComputeTaprootOutputKey(ik, rootHash[:])
	outKeyBytes := outKey.SerializeCompressed()
	yIsOdd := outKeyBytes[0] == 0x03

	leafInfos := make([]any, n)
	for i, proof := range tree.LeafMerkleProofs {
		lh := proof.TapHash()
		cb := txscript.ControlBlock{
			InternalKey:     ik,
			OutputKeyYIsOdd: yIsOdd,
			LeafVersion:     proof.TapLeaf.LeafVersion,
			InclusionProof:  proof.InclusionProof,
		}
		cbBytes, _ := cb.ToBytes()
		leafInfos[i] = map[string]any{
			"leafHash":     bytesToJS(lh[:]),
			"script":       bytesToJS(proof.TapLeaf.Script),
			"controlBlock": bytesToJS(cbBytes),
		}
	}

	return okResult(map[string]any{
		"outputKey":   bytesToJS(schnorr.SerializePubKey(outKey)),
		"internalKey": bytesToJS(schnorr.SerializePubKey(ik)),
		"merkleRoot":  bytesToJS(rootHash[:]),
		"leaves":      leafInfos,
	})
}

// ---------------------------------------------------------------------------
// sighash computation
// ---------------------------------------------------------------------------

func txscriptCalcSignatureHash(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 4, "hexScript, hashType, hexRawTx, idx"); e != nil {
		return e
	}
	script, e := hexDecode(args[0].String())
	if e != nil {
		return e
	}
	hashType := txscript.SigHashType(args[1].Int())
	msgTx, e := deserializeTx(args[2].String())
	if e != nil {
		return e
	}
	idx := args[3].Int()

	h, err := txscript.CalcSignatureHash(script, hashType, msgTx, idx)
	if err != nil {
		return errfResult("calcSignatureHash: %s", err)
	}
	return okResult(bytesToJS(h))
}

func txscriptCalcWitnessSigHash(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 5,
		"hexScript, hashType, hexRawTx, idx, amount"); e != nil {
		return e
	}
	script, e := hexDecode(args[0].String())
	if e != nil {
		return e
	}
	hashType := txscript.SigHashType(args[1].Int())
	msgTx, e := deserializeTx(args[2].String())
	if e != nil {
		return e
	}
	idx := args[3].Int()
	amt := int64(args[4].Float())

	fetcher := txscript.NewCannedPrevOutputFetcher(script, amt)
	sigHashes := txscript.NewTxSigHashes(msgTx, fetcher)

	h, err := txscript.CalcWitnessSigHash(
		script, sigHashes, hashType, msgTx, idx, amt,
	)
	if err != nil {
		return errfResult("calcWitnessSigHash: %s", err)
	}
	return okResult(bytesToJS(h))
}

func txscriptCalcTaprootSignatureHash(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 4,
		"hashType, hexRawTx, idx, prevOuts[]"); e != nil {
		return e
	}
	hashType := txscript.SigHashType(args[0].Int())
	msgTx, e := deserializeTx(args[1].String())
	if e != nil {
		return e
	}
	idx := args[2].Int()

	fetcher, e := buildPrevOutFetcher(msgTx, args[3])
	if e != nil {
		return e
	}
	sigHashes := txscript.NewTxSigHashes(msgTx, fetcher)

	h, err := txscript.CalcTaprootSignatureHash(
		sigHashes, hashType, msgTx, idx, fetcher,
	)
	if err != nil {
		return errfResult("calcTaprootSignatureHash: %s", err)
	}
	return okResult(bytesToJS(h))
}

// ---------------------------------------------------------------------------
// signing helpers
// ---------------------------------------------------------------------------

func txscriptRawTxInSignature(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 5,
		"hexRawTx, idx, hexSubScript, hashType, hexPrivKey"); e != nil {
		return e
	}
	msgTx, e := deserializeTx(args[0].String())
	if e != nil {
		return e
	}
	idx := args[1].Int()
	subScript, e := hexDecode(args[2].String())
	if e != nil {
		return e
	}
	hashType := txscript.SigHashType(args[3].Int())
	privBytes, e := hexDecode(args[4].String())
	if e != nil {
		return e
	}
	privKey, _ := btcec.PrivKeyFromBytes(privBytes)

	sig, err := txscript.RawTxInSignature(
		msgTx, idx, subScript, hashType, privKey,
	)
	if err != nil {
		return errfResult("rawTxInSignature: %s", err)
	}
	return okResult(bytesToJS(sig))
}

func txscriptRawTxInWitnessSignature(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 6,
		"hexRawTx, idx, amount, hexSubScript, hashType, hexPrivKey"); e != nil {
		return e
	}
	msgTx, e := deserializeTx(args[0].String())
	if e != nil {
		return e
	}
	idx := args[1].Int()
	amt := int64(args[2].Float())
	subScript, e := hexDecode(args[3].String())
	if e != nil {
		return e
	}
	hashType := txscript.SigHashType(args[4].Int())
	privBytes, e := hexDecode(args[5].String())
	if e != nil {
		return e
	}
	privKey, _ := btcec.PrivKeyFromBytes(privBytes)

	fetcher := txscript.NewCannedPrevOutputFetcher(subScript, amt)
	sigHashes := txscript.NewTxSigHashes(msgTx, fetcher)

	sig, err := txscript.RawTxInWitnessSignature(
		msgTx, sigHashes, idx, amt, subScript, hashType, privKey,
	)
	if err != nil {
		return errfResult("rawTxInWitnessSignature: %s", err)
	}
	return okResult(bytesToJS(sig))
}

func txscriptWitnessSignature(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 7,
		"hexRawTx, idx, amount, hexSubScript, hashType, hexPrivKey, compress"); e != nil {
		return e
	}
	msgTx, e := deserializeTx(args[0].String())
	if e != nil {
		return e
	}
	idx := args[1].Int()
	amt := int64(args[2].Float())
	subScript, e := hexDecode(args[3].String())
	if e != nil {
		return e
	}
	hashType := txscript.SigHashType(args[4].Int())
	privBytes, e := hexDecode(args[5].String())
	if e != nil {
		return e
	}
	privKey, _ := btcec.PrivKeyFromBytes(privBytes)
	compress := args[6].Bool()

	fetcher := txscript.NewCannedPrevOutputFetcher(subScript, amt)
	sigHashes := txscript.NewTxSigHashes(msgTx, fetcher)

	wit, err := txscript.WitnessSignature(
		msgTx, sigHashes, idx, amt, subScript, hashType, privKey, compress,
	)
	if err != nil {
		return errfResult("witnessSignature: %s", err)
	}
	items := make([]any, len(wit))
	for i, w := range wit {
		items[i] = bytesToJS(w)
	}
	return okResult(items)
}

func txscriptRawTxInTaprootSignature(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 6,
		"hexRawTx, idx, hexMerkleRoot, hashType, hexPrivKey, prevOuts[]"); e != nil {
		return e
	}
	msgTx, e := deserializeTx(args[0].String())
	if e != nil {
		return e
	}
	idx := args[1].Int()

	var merkleRoot []byte
	if args[2].Type() == js.TypeString && args[2].String() != "" {
		merkleRoot, e = hexDecode(args[2].String())
		if e != nil {
			return e
		}
	}

	hashType := txscript.SigHashType(args[3].Int())
	privBytes, e := hexDecode(args[4].String())
	if e != nil {
		return e
	}
	privKey, _ := btcec.PrivKeyFromBytes(privBytes)

	fetcher, e := buildPrevOutFetcher(msgTx, args[5])
	if e != nil {
		return e
	}
	sigHashes := txscript.NewTxSigHashes(msgTx, fetcher)

	// For key-spend the pkScript is obtained from prevOuts for the idx.
	prevOut := fetcher.FetchPrevOutput(msgTx.TxIn[idx].PreviousOutPoint)

	sig, err := txscript.RawTxInTaprootSignature(
		msgTx, sigHashes, idx, prevOut.Value, prevOut.PkScript,
		merkleRoot, hashType, privKey,
	)
	if err != nil {
		return errfResult("rawTxInTaprootSignature: %s", err)
	}
	return okResult(bytesToJS(sig))
}
