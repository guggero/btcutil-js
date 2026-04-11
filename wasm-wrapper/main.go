//go:build js && wasm

// Build with:
//
//	./build-wrapper.sh

package main

import "syscall/js"

func main() {
	js.Global().Set("btcutil", map[string]any{
		"base58": map[string]any{
			"encode":      js.FuncOf(base58Encode),
			"decode":      js.FuncOf(base58Decode),
			"checkEncode": js.FuncOf(base58CheckEncode),
			"checkDecode": js.FuncOf(base58CheckDecode),
		},
		"bech32": map[string]any{
			"encode":            js.FuncOf(bech32Encode),
			"encodeM":           js.FuncOf(bech32EncodeM),
			"decode":            js.FuncOf(bech32Decode),
			"decodeNoLimit":     js.FuncOf(bech32DecodeNoLimit),
			"encodeFromBase256": js.FuncOf(bech32EncodeFromBase256),
			"decodeToBase256":   js.FuncOf(bech32DecodeToBase256),
			"convertBits":       js.FuncOf(bech32ConvertBits),
		},
		"address": map[string]any{
			"decode":                js.FuncOf(addressDecode),
			"fromPubKeyHash":       js.FuncOf(addressFromPubKeyHash),
			"fromScriptHash":       js.FuncOf(addressFromScriptHash),
			"fromScript":           js.FuncOf(addressFromScript),
			"fromWitnessPubKeyHash": js.FuncOf(addressFromWitnessPubKeyHash),
			"fromWitnessScriptHash": js.FuncOf(addressFromWitnessScriptHash),
			"fromTaproot":          js.FuncOf(addressFromTaproot),
			"fromPubKey":           js.FuncOf(addressFromPubKey),
		},
		"amount": map[string]any{
			"fromBTC": js.FuncOf(amountFromBTC),
			"toBTC":   js.FuncOf(amountToBTC),
			"format":  js.FuncOf(amountFormat),
		},
		"hash": map[string]any{
			"hash160": js.FuncOf(hashHash160),
		},
		"wif": map[string]any{
			"decode": js.FuncOf(wifDecode),
			"encode": js.FuncOf(wifEncode),
		},
		"hdkeychain": map[string]any{
			"newMaster":      js.FuncOf(hdNewMaster),
			"fromString":     js.FuncOf(hdFromString),
			"derive":         js.FuncOf(hdDerive),
			"deriveHardened": js.FuncOf(hdDeriveHardened),
			"derivePath":     js.FuncOf(hdDerivePath),
			"neuter":         js.FuncOf(hdNeuter),
			"generateSeed":   js.FuncOf(hdGenerateSeed),
			"publicKey":      js.FuncOf(hdPublicKey),
			"address":        js.FuncOf(hdAddress),
		},
		"bip322": map[string]any{
			"verifyMessage": js.FuncOf(bip322VerifyMessage),
		},
		"txsort": map[string]any{
			"sort":     js.FuncOf(txsortSort),
			"isSorted": js.FuncOf(txsortIsSorted),
		},
		"tx": map[string]any{
			"hash":        js.FuncOf(txHash),
			"witnessHash": js.FuncOf(txWitnessHash),
			"hasWitness":  js.FuncOf(txHasWitness),
			"decode":      js.FuncOf(txDecode),
		},
		"psbt": map[string]any{
			"decode":     js.FuncOf(psbtDecode),
			"isComplete": js.FuncOf(psbtIsComplete),
			"extract":    js.FuncOf(psbtExtract),
			"getFee":     js.FuncOf(psbtGetFee),
			"fromBase64": js.FuncOf(psbtFromBase64),
			"toBase64":            js.FuncOf(psbtToBase64),
			"create":              js.FuncOf(psbtCreate),
			"fromUnsignedTx":     js.FuncOf(psbtFromUnsignedTx),
			"addInNonWitnessUtxo": js.FuncOf(psbtAddInNonWitnessUtxo),
			"addInWitnessUtxo":   js.FuncOf(psbtAddInWitnessUtxo),
			"addInSighashType":   js.FuncOf(psbtAddInSighashType),
			"addInRedeemScript":  js.FuncOf(psbtAddInRedeemScript),
			"addInWitnessScript": js.FuncOf(psbtAddInWitnessScript),
			"addInBip32Derivation": js.FuncOf(psbtAddInBip32Derivation),
			"addOutBip32Derivation": js.FuncOf(psbtAddOutBip32Derivation),
			"addOutRedeemScript": js.FuncOf(psbtAddOutRedeemScript),
			"addOutWitnessScript": js.FuncOf(psbtAddOutWitnessScript),
			"sign":               js.FuncOf(psbtSign),
			"finalize":           js.FuncOf(psbtFinalize),
			"maybeFinalize":      js.FuncOf(psbtMaybeFinalize),
			"maybeFinalizeAll":   js.FuncOf(psbtMaybeFinalizeAll),
			"inPlaceSort":        js.FuncOf(psbtInPlaceSort),
			"sumUtxoInputValues": js.FuncOf(psbtSumUtxoInputValues),
			"inputsReadyToSign":  js.FuncOf(psbtInputsReadyToSign),
			"sanityCheck":        js.FuncOf(psbtSanityCheck),
		},
		"gcs": map[string]any{
			"buildFilter": js.FuncOf(gcsBuildFilter),
			"match":       js.FuncOf(gcsMatch),
			"matchAny":    js.FuncOf(gcsMatchAny),
		},
		"bloom": map[string]any{
			"murmurHash3": js.FuncOf(bloomMurmurHash3),
		},
		"txscript": map[string]any{
			"isPayToPubKey":            js.FuncOf(txscriptIsPayToPubKey),
			"isPayToPubKeyHash":        js.FuncOf(txscriptIsPayToPubKeyHash),
			"isPayToScriptHash":        js.FuncOf(txscriptIsPayToScriptHash),
			"isPayToWitnessPubKeyHash": js.FuncOf(txscriptIsPayToWitnessPubKeyHash),
			"isPayToWitnessScriptHash": js.FuncOf(txscriptIsPayToWitnessScriptHash),
			"isPayToTaproot":           js.FuncOf(txscriptIsPayToTaproot),
			"isWitnessProgram":         js.FuncOf(txscriptIsWitnessProgram),
			"isNullData":               js.FuncOf(txscriptIsNullData),
			"isMultisigScript":         js.FuncOf(txscriptIsMultisigScript),
			"isUnspendable":            js.FuncOf(txscriptIsUnspendable),
			"isPushOnlyScript":         js.FuncOf(txscriptIsPushOnlyScript),
			"scriptHasOpSuccess":       js.FuncOf(txscriptScriptHasOpSuccess),
			"disasmString":             js.FuncOf(txscriptDisasmString),
			"getScriptClass":           js.FuncOf(txscriptGetScriptClass),
			"extractWitnessProgramInfo": js.FuncOf(txscriptExtractWitnessProgramInfo),
			"extractPkScriptAddrs":     js.FuncOf(txscriptExtractPkScriptAddrs),
			"pushedData":               js.FuncOf(txscriptPushedData),
			"getSigOpCount":            js.FuncOf(txscriptGetSigOpCount),
			"calcMultiSigStats":        js.FuncOf(txscriptCalcMultiSigStats),
			"parsePkScript":            js.FuncOf(txscriptParsePkScript),
			"computePkScript":          js.FuncOf(txscriptComputePkScript),
			"payToAddrScript":          js.FuncOf(txscriptPayToAddrScript),
			"nullDataScript":           js.FuncOf(txscriptNullDataScript),
			"payToTaprootScript":       js.FuncOf(txscriptPayToTaprootScript),
			"multiSigScript":           js.FuncOf(txscriptMultiSigScript),
			"computeTaprootOutputKey":   js.FuncOf(txscriptComputeTaprootOutputKey),
			"computeTaprootKeyNoScript": js.FuncOf(txscriptComputeTaprootKeyNoScript),
			"tweakTaprootPrivKey":       js.FuncOf(txscriptTweakTaprootPrivKey),
			"parseControlBlock":         js.FuncOf(txscriptParseControlBlock),
			"assembleTaprootScriptTree": js.FuncOf(txscriptAssembleTaprootScriptTree),
			"calcSignatureHash":         js.FuncOf(txscriptCalcSignatureHash),
			"calcWitnessSigHash":        js.FuncOf(txscriptCalcWitnessSigHash),
			"calcTaprootSignatureHash":  js.FuncOf(txscriptCalcTaprootSignatureHash),
			"rawTxInSignature":          js.FuncOf(txscriptRawTxInSignature),
			"rawTxInWitnessSignature":   js.FuncOf(txscriptRawTxInWitnessSignature),
			"witnessSignature":          js.FuncOf(txscriptWitnessSignature),
			"rawTxInTaprootSignature":   js.FuncOf(txscriptRawTxInTaprootSignature),
		},
		"btcec": map[string]any{
			"newPrivateKey":          js.FuncOf(btcecNewPrivateKey),
			"privKeyFromBytes":      js.FuncOf(btcecPrivKeyFromBytes),
			"pubKeyFromBytes":       js.FuncOf(btcecPubKeyFromBytes),
			"isCompressedPubKey":    js.FuncOf(btcecIsCompressedPubKey),
			"serializeUncompressed": js.FuncOf(btcecSerializeUncompressed),
			"serializeCompressed":   js.FuncOf(btcecSerializeCompressed),
			"generateSharedSecret":  js.FuncOf(btcecGenerateSharedSecret),
			"ecdsaSign":             js.FuncOf(btcecEcdsaSign),
			"ecdsaVerify":           js.FuncOf(btcecEcdsaVerify),
			"ecdsaSignCompact":      js.FuncOf(btcecEcdsaSignCompact),
			"ecdsaRecoverCompact":   js.FuncOf(btcecEcdsaRecoverCompact),
			"ecdsaParseSignature":   js.FuncOf(btcecEcdsaParseSignature),
			"ecdsaParseDERSignature": js.FuncOf(btcecEcdsaParseDERSignature),
			"schnorrSign":            js.FuncOf(btcecSchnorrSign),
			"schnorrVerify":          js.FuncOf(btcecSchnorrVerify),
			"schnorrParsePubKey":     js.FuncOf(btcecSchnorrParsePubKey),
			"schnorrSerializePubKey": js.FuncOf(btcecSchnorrSerializePubKey),
			"schnorrParseSignature":  js.FuncOf(btcecSchnorrParseSignature),
		},
		"chaincfg": map[string]any{
			"getParams":                  js.FuncOf(chaincfgGetParams),
			"isPubKeyHashAddrID":         js.FuncOf(chaincfgIsPubKeyHashAddrID),
			"isScriptHashAddrID":         js.FuncOf(chaincfgIsScriptHashAddrID),
			"isBech32SegwitPrefix":       js.FuncOf(chaincfgIsBech32SegwitPrefix),
			"hdPrivateKeyToPublicKeyID":  js.FuncOf(chaincfgHDPrivateKeyToPublicKeyID),
		},
		"chainhash": map[string]any{
			"hash":           js.FuncOf(chainhashHashB),
			"doubleHash":     js.FuncOf(chainhashDoubleHashB),
			"taggedHash":     js.FuncOf(chainhashTaggedHash),
			"newHashFromStr": js.FuncOf(chainhashNewHashFromStr),
			"hashToString":   js.FuncOf(chainhashHashToString),
		},
	})

	// Signal readiness.
	if cb := js.Global().Get("onBtcutilReady"); cb.Type() == js.TypeFunction {
		cb.Invoke()
	}

	// Block forever to keep the Go runtime alive.
	select {}
}
