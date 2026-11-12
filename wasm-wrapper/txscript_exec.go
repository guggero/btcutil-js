//go:build js && wasm

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"sort"
	"strconv"
	"strings"
	"syscall/js"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
)

// ---------------------------------------------------------------------------
// script verification flags
// ---------------------------------------------------------------------------

// scriptFlagNames maps the name of a script verification flag to its value.
// The names are the ones Bitcoin Core uses for its SCRIPT_VERIFY_* flags, with
// the prefix removed.
var scriptFlagNames = map[string]txscript.ScriptFlags{
	"P2SH":                                  txscript.ScriptBip16,
	"STRICTENC":                             txscript.ScriptVerifyStrictEncoding,
	"DERSIG":                                txscript.ScriptVerifyDERSignatures,
	"LOW_S":                                 txscript.ScriptVerifyLowS,
	"NULLDUMMY":                             txscript.ScriptStrictMultiSig,
	"SIGPUSHONLY":                           txscript.ScriptVerifySigPushOnly,
	"MINIMALDATA":                           txscript.ScriptVerifyMinimalData,
	"DISCOURAGE_UPGRADABLE_NOPS":            txscript.ScriptDiscourageUpgradableNops,
	"CLEANSTACK":                            txscript.ScriptVerifyCleanStack,
	"CHECKLOCKTIMEVERIFY":                   txscript.ScriptVerifyCheckLockTimeVerify,
	"CHECKSEQUENCEVERIFY":                   txscript.ScriptVerifyCheckSequenceVerify,
	"WITNESS":                               txscript.ScriptVerifyWitness,
	"DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM": txscript.ScriptVerifyDiscourageUpgradeableWitnessProgram,
	"MINIMALIF":                             txscript.ScriptVerifyMinimalIf,
	"NULLFAIL":                              txscript.ScriptVerifyNullFail,
	"WITNESS_PUBKEYTYPE":                    txscript.ScriptVerifyWitnessPubKeyType,
	"CONST_SCRIPTCODE":                      txscript.ScriptVerifyConstScriptCode,
	"TAPROOT":                               txscript.ScriptVerifyTaproot,
	"DISCOURAGE_UPGRADABLE_TAPROOT_VERSION": txscript.ScriptVerifyDiscourageUpgradeableTaprootVersion,
	"DISCOURAGE_OP_SUCCESS":                 txscript.ScriptVerifyDiscourageOpSuccess,
	"DISCOURAGE_UPGRADABLE_PUBKEYTYPE":      txscript.ScriptVerifyDiscourageUpgradeablePubkeyType,
	"RESTRICT_SIGHASH":                      txscript.ScriptVerifyRestrictSigHash,
	"MINIMALIF_ALL":                         txscript.ScriptVerifyMinimalIfAll,
	"TEMPLATEHASH":                          txscript.ScriptVerifyTemplateHash,
	"DISCOURAGE_TEMPLATEHASH":               txscript.ScriptVerifyDiscourageTemplateHash,
	"CHECKSIGFROMSTACK":                     txscript.ScriptVerifyCheckSigFromStack,
	"DISCOURAGE_CHECKSIGFROMSTACK":          txscript.ScriptVerifyDiscourageCheckSigFromStack,
	"INTERNALKEY":                           txscript.ScriptVerifyInternalKey,
	"DISCOURAGE_INTERNALKEY":                txscript.ScriptVerifyDiscourageInternalKey,
}

// flagNames returns the sorted names of the flags that are set in the given
// flag set.
func flagNames(flags txscript.ScriptFlags) []any {
	names := make([]string, 0, len(scriptFlagNames))
	for name, flag := range scriptFlagNames {
		if flags&flag == flag {
			names = append(names, name)
		}
	}
	sort.Strings(names)

	result := make([]any, len(names))
	for i, name := range names {
		result[i] = name
	}
	return result
}

// scriptFlagsFromArg parses the optional flags argument at position i. An
// absent, null or undefined argument selects the standard verification flags;
// an array of flag names selects exactly the named flags, so an empty array
// means no flags at all.
func scriptFlagsFromArg(args []js.Value, i int) (txscript.ScriptFlags,
	map[string]any) {

	if i >= len(args) {
		return txscript.StandardVerifyFlags, nil
	}

	arg := args[i]
	switch arg.Type() {
	case js.TypeUndefined, js.TypeNull:
		return txscript.StandardVerifyFlags, nil

	case js.TypeObject:
		if !arg.InstanceOf(js.Global().Get("Array")) {
			return 0, errResult("flags must be an array of flag " +
				"names")
		}

	default:
		return 0, errResult("flags must be an array of flag names")
	}

	var flags txscript.ScriptFlags
	for j := 0; j < arg.Length(); j++ {
		entry := arg.Index(j)
		if entry.Type() != js.TypeString {
			return 0, errResult("flags must be an array of flag " +
				"names")
		}

		flag, ok := scriptFlagNames[entry.String()]
		if !ok {
			return 0, errfResult("unknown script flag: %s",
				entry.String())
		}
		flags |= flag
	}

	return flags, nil
}

// txscriptScriptFlagNames returns the names of all script verification flags
// that verifyScript and traceScript accept.
func txscriptScriptFlagNames(_ js.Value, _ []js.Value) any {
	var all txscript.ScriptFlags
	for _, flag := range scriptFlagNames {
		all |= flag
	}
	return okResult(flagNames(all))
}

// txscriptStandardScriptFlags returns the names of the flags that make up the
// standard verification flags, which is what a node applies to transactions
// entering its mempool before any of the tapscript op code upgrades is active.
// Calls Go: txscript.StandardVerifyFlags from txscript.
func txscriptStandardScriptFlags(_ js.Value, _ []js.Value) any {
	return okResult(flagNames(txscript.StandardVerifyFlags))
}

// ---------------------------------------------------------------------------
// script execution
// ---------------------------------------------------------------------------

// scriptRun is everything needed to execute the script pair of one input.
type scriptRun struct {
	tx        *wire.MsgTx
	idx       int
	prevOut   *wire.TxOut
	fetcher   *txscript.MultiPrevOutFetcher
	sigHashes *txscript.TxSigHashes
	flags     txscript.ScriptFlags
}

// scriptRunFromArgs parses the arguments shared by verifyScript and
// traceScript: rawTx, idx, prevOuts[] and the optional flags[].
func scriptRunFromArgs(args []js.Value) (*scriptRun, map[string]any) {
	if e := checkArgs(args, 3, "hexRawTx, idx, prevOuts[]"); e != nil {
		return nil, e
	}
	msgTx, e := deserializeTxArg(args[0])
	if e != nil {
		return nil, e
	}
	idx := args[1].Int()
	if idx < 0 || idx >= len(msgTx.TxIn) {
		return nil, errfResult("input index %d out of range", idx)
	}

	if args[2].Length() != len(msgTx.TxIn) {
		return nil, errfResult("expected %d previous outputs, got %d",
			len(msgTx.TxIn), args[2].Length())
	}
	fetcher, e := buildPrevOutFetcher(msgTx, args[2])
	if e != nil {
		return nil, e
	}

	prevOut := fetcher.FetchPrevOutput(msgTx.TxIn[idx].PreviousOutPoint)
	if prevOut == nil {
		return nil, errfResult("missing previous output of input %d",
			idx)
	}

	flags, e := scriptFlagsFromArg(args, 3)
	if e != nil {
		return nil, e
	}

	return &scriptRun{
		tx:        msgTx,
		idx:       idx,
		prevOut:   prevOut,
		fetcher:   fetcher,
		sigHashes: txscript.NewTxSigHashes(msgTx, fetcher),
		flags:     flags,
	}, nil
}

// addScriptError adds the reason a script was rejected to a result object: the
// human-readable description and, for script errors, the name of the error
// code.
func addScriptError(result map[string]any, err error) {
	result["valid"] = false
	result["error"] = err.Error()

	var scriptErr txscript.Error
	if errors.As(err, &scriptErr) {
		result["errorCode"] = scriptErr.ErrorCode.String()
	}
}

// txscriptVerifyScript executes the script pair of one input of a transaction,
// reporting whether the input is a valid spend of its previous output. The
// transaction must already carry the input's signature script and witness;
// prevOuts supplies the previous output of every input (in input order), which
// taproot sighashes commit to. The optional flags argument is an array of
// script flag names; without it the standard verification flags are used.
//
// A rejection is a result, not an error: both a failure to set up the engine
// and a failure to execute mean the spend is invalid, and both are reported as
// {valid: false, error: "...", errorCode: "..."}. Only malformed arguments
// produce an error result.
// Calls Go: txscript.NewEngine() and Engine.Execute() from txscript.
func txscriptVerifyScript(_ js.Value, args []js.Value) any {
	run, e := scriptRunFromArgs(args)
	if e != nil {
		return e
	}

	result := map[string]any{"valid": true}
	engine, err := txscript.NewEngine(
		run.prevOut.PkScript, run.tx, run.idx, run.flags, nil,
		run.sigHashes, run.prevOut.Value, run.fetcher,
	)
	if err != nil {
		addScriptError(result, err)
		return okResult(result)
	}

	if err := engine.Execute(); err != nil {
		addScriptError(result, err)
	}

	return okResult(result)
}

// stackToJS converts a script stack to a JS array of Uint8Array, bottom of the
// stack first.
func stackToJS(stack [][]byte) []any {
	items := make([]any, len(stack))
	for i, item := range stack {
		items[i] = bytesToJS(item)
	}
	return items
}

// trimDisasmPrefix removes the "ss:oooo: " script and op code index prefix the
// engine puts in front of every disassembled op code.
func trimDisasmPrefix(line string) string {
	const prefixLen = len("00:0000: ")
	if len(line) >= prefixLen && line[2] == ':' && line[7] == ':' {
		return line[prefixLen:]
	}
	return line
}

// txscriptTraceScript executes the script pair of one input like verifyScript
// does, and records the state of the engine before every op code. It takes the
// same arguments as verifyScript.
//
// The result holds the outcome ({valid, error?, errorCode?}), the disassembly
// of every script the engine got to execute (scripts[scriptIndex][opcodeIndex])
// and the steps. A step is the state before the op code at (scriptIndex,
// opcodeIndex) runs; the last step of a successful run points one past the
// final op code. When the execution fails, the last step is the state the
// failing op code was run on.
//
// The scripts are, in order, the signature script, the public key script and,
// where there is one, the redeem or witness script. A tapscript that isn't
// executed because it contains an OP_SUCCESS op code doesn't show up, in which
// case opSuccess is true. Every step of a taproot input also carries what is
// left of its signature operation budget.
// Calls Go: txscript.NewDebugEngine() and Engine.Execute() from txscript.
func txscriptTraceScript(_ js.Value, args []js.Value) any {
	run, e := scriptRunFromArgs(args)
	if e != nil {
		return e
	}

	var (
		engine *txscript.Engine
		steps  []any
	)
	callback := func(info *txscript.StepInfo) error {
		step := map[string]any{
			"scriptIndex": info.ScriptIndex,
			"opcodeIndex": info.OpcodeIndex,
			"stack":       stackToJS(info.Stack),
			"altStack":    stackToJS(info.AltStack),
		}

		// What is left of the BIP 342 signature operation budget, once
		// the engine got to the witness program of a taproot input.
		if budget, ok := engine.TapscriptSigOpsBudget(); ok {
			step["sigOpsBudget"] = int(budget)
		}

		// The op code that runs next. There is none once the execution
		// is done, in which case the disassembly fails.
		if next, err := engine.DisasmPC(); err == nil {
			step["opcode"] = trimDisasmPrefix(next)
		}

		steps = append(steps, step)
		return nil
	}

	result := map[string]any{"valid": true}
	engine, err := txscript.NewDebugEngine(
		run.prevOut.PkScript, run.tx, run.idx, run.flags, nil,
		run.sigHashes, run.prevOut.Value, run.fetcher, callback,
	)
	if err != nil {
		addScriptError(result, err)
		result["scripts"] = []any{}
		result["steps"] = []any{}
		result["opSuccess"] = false
		return okResult(result)
	}

	if err := engine.Execute(); err != nil {
		addScriptError(result, err)
	}

	// Collect the scripts after the execution: the redeem, witness or tap
	// script only becomes known to the engine while it runs.
	var scripts []any
	for i := 0; ; i++ {
		disasm, err := engine.DisasmScript(i)
		if err != nil {
			break
		}

		var ops []any
		for _, line := range strings.Split(disasm, "\n") {
			if line == "" {
				continue
			}
			ops = append(ops, trimDisasmPrefix(line))
		}
		if ops == nil {
			ops = []any{}
		}
		scripts = append(scripts, ops)
	}
	if scripts == nil {
		scripts = []any{}
	}
	if steps == nil {
		steps = []any{}
	}

	result["scripts"] = scripts
	result["steps"] = steps
	result["opSuccess"] = engine.TapscriptOpSuccess()

	return okResult(result)
}

// ---------------------------------------------------------------------------
// script assembly
// ---------------------------------------------------------------------------

// txscriptAssembleScript turns a human-readable script into its serialized
// form. It accepts what disasmString produces, tokens separated by whitespace:
//
//   - an op code name such as OP_DUP, OP_CHECKSIGFROMSTACK or OP_TEMPLATEHASH
//   - the numbers -1 and 0 to 16, which become OP_1NEGATE and OP_0 to OP_16
//   - hex data, which becomes the smallest push of those bytes; a 0x prefix
//     marks a token as data that would otherwise be read as a number
//
// Calls Go: txscript.ScriptBuilder and txscript.OpcodeByName from txscript.
func txscriptAssembleScript(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "asm"); e != nil {
		return e
	}
	if args[0].Type() != js.TypeString {
		return errResult("asm must be a string")
	}

	// The limits of the builder are those of a tapscript element, there is
	// no limit on the size of the script itself.
	builder := txscript.NewScriptBuilder(
		txscript.WithScriptAllocSize(len(args[0].String())),
	)
	for _, token := range strings.Fields(args[0].String()) {
		if strings.HasPrefix(token, "OP_") {
			op, ok := txscript.OpcodeByName[token]
			if !ok {
				return errfResult("unknown op code: %s", token)
			}

			// A push op code needs its data, which a name alone
			// doesn't carry.
			if op >= txscript.OP_DATA_1 &&
				op <= txscript.OP_PUSHDATA4 {

				return errfResult("%s needs data, write the "+
					"data as hex instead", token)
			}

			builder.AddOp(op)
			continue
		}

		// The small numbers have an op code of their own. Anything
		// longer than two digits is hex data.
		if num, err := strconv.ParseInt(token, 10, 8); err == nil &&
			num >= -1 && num <= 16 && len(token) <= 2 {

			builder.AddInt64(num)
			continue
		}

		data, err := hex.DecodeString(strings.TrimPrefix(token, "0x"))
		if err != nil {
			return errfResult("invalid token %q: not an op code, "+
				"a number from -1 to 16 or hex data", token)
		}
		builder.AddData(data)
	}

	script, err := builder.Script()
	if err != nil {
		return errfResult("assembleScript: %s", err)
	}

	return okResult(bytesToJS(script))
}

// ---------------------------------------------------------------------------
// BIP 446 template hash
// ---------------------------------------------------------------------------

// templateHashArgs parses the arguments shared by calcTemplateHash and
// templateHashPreimage: rawTx, idx and the optional annex.
func templateHashArgs(args []js.Value) (*wire.MsgTx, int, []byte,
	map[string]any) {

	if e := checkArgs(args, 2, "hexRawTx, idx"); e != nil {
		return nil, 0, nil, e
	}
	msgTx, e := deserializeTxArg(args[0])
	if e != nil {
		return nil, 0, nil, e
	}
	idx := args[1].Int()
	if idx < 0 || idx >= len(msgTx.TxIn) {
		return nil, 0, nil, errfResult("input index %d out of range",
			idx)
	}

	annex, e := optBytesFromArg(args, 2)
	if e != nil {
		return nil, 0, nil, e
	}
	if annex != nil && annex[0] != txscript.TaprootAnnexTag {
		return nil, 0, nil, errfResult("an annex must start with "+
			"0x%02x", txscript.TaprootAnnexTag)
	}

	return msgTx, idx, annex, nil
}

// txscriptCalcTemplateHash computes the BIP 446 template hash of an input,
// which is what OP_TEMPLATEHASH pushes when that input is spent through a
// tapscript. The optional annex is the full annex of the input, including the
// 0x50 tag.
// Calls Go: txscript.CalcTemplateHash() from txscript.
func txscriptCalcTemplateHash(_ js.Value, args []js.Value) any {
	msgTx, idx, annex, e := templateHashArgs(args)
	if e != nil {
		return e
	}

	templateHash, err := txscript.CalcTemplateHash(nil, msgTx, idx, annex)
	if err != nil {
		return errfResult("calcTemplateHash: %s", err)
	}

	return okResult(bytesToJS(templateHash))
}

// txscriptTemplateHashPreimage returns the BIP 446 template hash of an input
// together with the message it is the tagged hash of, split into its fields.
// It takes the same arguments as calcTemplateHash.
//
// The fields are assembled here, as txscript only exposes the final hash. To
// make sure the two never disagree, the hash of the assembled message is
// compared with the one txscript computes.
// Calls Go: txscript.CalcTemplateHash() and chainhash.TaggedHash().
func txscriptTemplateHashPreimage(_ js.Value, args []js.Value) any {
	msgTx, idx, annex, e := templateHashArgs(args)
	if e != nil {
		return e
	}

	version := binary.LittleEndian.AppendUint32(
		nil, uint32(msgTx.Version),
	)
	lockTime := binary.LittleEndian.AppendUint32(nil, msgTx.LockTime)
	inputIndex := binary.LittleEndian.AppendUint32(nil, uint32(idx))

	// The sha_sequences and sha_outputs digests of BIP 341.
	var sequences, outputs bytes.Buffer
	for _, txIn := range msgTx.TxIn {
		_ = binary.Write(&sequences, binary.LittleEndian, txIn.Sequence)
	}
	for _, txOut := range msgTx.TxOut {
		_ = wire.WriteTxOut(&outputs, 0, 0, txOut)
	}
	shaSequences := chainhash.HashB(sequences.Bytes())
	shaOutputs := chainhash.HashB(outputs.Bytes())

	annexPresent := []byte{0}
	var shaAnnex []byte
	if annex != nil {
		annexPresent[0] = 1

		var annexBuf bytes.Buffer
		_ = wire.WriteVarBytes(&annexBuf, 0, annex)
		shaAnnex = chainhash.HashB(annexBuf.Bytes())
	}

	message := bytes.Join([][]byte{
		version, lockTime, shaSequences, shaOutputs, annexPresent,
		inputIndex, shaAnnex,
	}, nil)

	const tag = "TemplateHash"
	templateHash := chainhash.TaggedHash([]byte(tag), message)

	reference, err := txscript.CalcTemplateHash(nil, msgTx, idx, annex)
	if err != nil {
		return errfResult("calcTemplateHash: %s", err)
	}
	if !bytes.Equal(reference, templateHash[:]) {
		return errResult("internal error: template hash preimage " +
			"doesn't match the template hash")
	}

	result := map[string]any{
		"hash":         bytesToJS(templateHash[:]),
		"tag":          tag,
		"message":      bytesToJS(message),
		"version":      bytesToJS(version),
		"lockTime":     bytesToJS(lockTime),
		"shaSequences": bytesToJS(shaSequences),
		"shaOutputs":   bytesToJS(shaOutputs),
		"annexPresent": bytesToJS(annexPresent),
		"inputIndex":   bytesToJS(inputIndex),
	}
	if shaAnnex != nil {
		result["shaAnnex"] = bytesToJS(shaAnnex)
	}

	return okResult(result)
}

// ---------------------------------------------------------------------------
// tapscript sighash
// ---------------------------------------------------------------------------

// txscriptCalcTapscriptSignatureHash computes the BIP 342 signature hash an
// OP_CHECKSIG in a tapscript leaf checks. It requires the previous outputs of
// all inputs and the script of the leaf being spent. The optional annex is the
// full annex of the input, including the 0x50 tag.
// Calls Go: txscript.CalcTapscriptSignaturehash() from txscript.
func txscriptCalcTapscriptSignatureHash(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 5,
		"hashType, hexRawTx, idx, prevOuts[], hexLeafScript"); e != nil {
		return e
	}
	hashType := txscript.SigHashType(args[0].Int())
	msgTx, e := deserializeTxArg(args[1])
	if e != nil {
		return e
	}
	idx := args[2].Int()
	if idx < 0 || idx >= len(msgTx.TxIn) {
		return errfResult("input index %d out of range", idx)
	}

	if args[3].Length() != len(msgTx.TxIn) {
		return errfResult("expected %d previous outputs, got %d",
			len(msgTx.TxIn), args[3].Length())
	}
	fetcher, e := buildPrevOutFetcher(msgTx, args[3])
	if e != nil {
		return e
	}
	leafScript, e := bytesFromArg(args[4])
	if e != nil {
		return e
	}
	annex, e := optBytesFromArg(args, 5)
	if e != nil {
		return e
	}

	var opts []txscript.TaprootSigHashOption
	if annex != nil {
		opts = append(opts, txscript.WithAnnex(annex))
	}

	sigHash, err := txscript.CalcTapscriptSignaturehash(
		txscript.NewTxSigHashes(msgTx, fetcher), hashType, msgTx, idx,
		fetcher, txscript.NewBaseTapLeaf(leafScript), opts...,
	)
	if err != nil {
		return errfResult("calcTapscriptSignatureHash: %s", err)
	}

	return okResult(bytesToJS(sigHash))
}
