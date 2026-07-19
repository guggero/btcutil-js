//go:build js && wasm

package main

import (
	"syscall/js"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
)

// Header chains and watch lists are long-lived stateful objects, parked in
// handle registries exactly like descriptors (see descriptors.go for the
// rationale). Handles share the descriptor counter so no two live objects of
// any kind ever alias.
var (
	headerChainHandles = map[int]*headerChain{}
	watchListHandles   = map[int]*watchList{}
)

func lookupHeaderChain(arg js.Value) (*headerChain, map[string]any) {
	c, ok := headerChainHandles[arg.Int()]
	if !ok {
		return nil, errResult("unknown header chain handle")
	}

	return c, nil
}

func lookupWatchList(arg js.Value) (*watchList, map[string]any) {
	w, ok := watchListHandles[arg.Int()]
	if !ok {
		return nil, errResult("unknown watch list handle")
	}

	return w, nil
}

// chainStateResult is the JS shape of a header chain's current tip state.
func chainStateResult(c *headerChain) map[string]any {
	tipHash := ""
	tipTime := 0
	if len(c.ring) > 0 {
		tip := c.ring[len(c.ring)-1]
		tipHash = tip.hash.String()
		tipTime = int(tip.time)
	}

	return map[string]any{
		"tipHeight": float64(c.tipHeight),
		"tipHash":   tipHash,
		"tipTime":   tipTime,
		"chainWork": c.chainWork.Text(16),
	}
}

// neutrinoHeaderChainNew creates a header chain for a network, optionally
// restored from a previously exported state.
func neutrinoHeaderChainNew(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "network[, state]"); e != nil {
		return e
	}
	params, e := getNetwork(args[0].String())
	if e != nil {
		return e
	}

	chain := newHeaderChain(params)

	state, e := optBytesFromArg(args, 1)
	if e != nil {
		return e
	}
	if state != nil {
		if err := chain.importState(state); err != nil {
			return errfResult("import state: %s", err)
		}
	}

	h := nextHandle
	nextHandle++
	headerChainHandles[h] = chain

	result := chainStateResult(chain)
	result["handle"] = h

	return okResult(result)
}

// neutrinoHeaderChainAppend validates and appends a batch of raw headers.
func neutrinoHeaderChainAppend(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 2, "handle, rawHeaders"); e != nil {
		return e
	}
	chain, e := lookupHeaderChain(args[0])
	if e != nil {
		return e
	}
	raw, e := bytesFromArg(args[1])
	if e != nil {
		return e
	}

	appended, err := chain.appendHeaders(raw)
	if err != nil {
		return errfResult(
			"append headers (%d appended): %s", appended, err,
		)
	}

	result := chainStateResult(chain)
	result["appended"] = appended

	return okResult(result)
}

// neutrinoHeaderChainState returns the chain's current tip state.
func neutrinoHeaderChainState(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "handle"); e != nil {
		return e
	}
	chain, e := lookupHeaderChain(args[0])
	if e != nil {
		return e
	}

	return okResult(chainStateResult(chain))
}

// neutrinoHeaderChainRollback drops all headers above the given height (tail
// reorg handling).
func neutrinoHeaderChainRollback(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 2, "handle, height"); e != nil {
		return e
	}
	chain, e := lookupHeaderChain(args[0])
	if e != nil {
		return e
	}

	if err := chain.rollback(int64(args[1].Int())); err != nil {
		return errfResult("rollback: %s", err)
	}

	return okResult(chainStateResult(chain))
}

// neutrinoHeaderChainExport returns the compact resume state.
func neutrinoHeaderChainExport(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "handle"); e != nil {
		return e
	}
	chain, e := lookupHeaderChain(args[0])
	if e != nil {
		return e
	}

	return okResult(bytesToJS(chain.exportState()))
}

// neutrinoHeaderChainFree drops a header chain handle. Freeing an unknown
// handle is a no-op.
func neutrinoHeaderChainFree(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "handle"); e != nil {
		return e
	}

	delete(headerChainHandles, args[0].Int())

	return okResult(true)
}

// neutrinoWatchListNew creates a watch list, optionally seeded with scripts.
func neutrinoWatchListNew(_ js.Value, args []js.Value) any {
	watch := newWatchList()

	if len(args) > 0 && args[0].Type() == js.TypeObject {
		scripts, e := scriptsFromArg(args[0])
		if e != nil {
			return e
		}
		watch.addScripts(scripts)
	}

	h := nextHandle
	nextHandle++
	watchListHandles[h] = watch

	return okResult(map[string]any{
		"handle":     h,
		"numScripts": len(watch.scripts),
	})
}

// neutrinoWatchListAddScripts adds watched output scripts.
func neutrinoWatchListAddScripts(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 2, "handle, scripts"); e != nil {
		return e
	}
	watch, e := lookupWatchList(args[0])
	if e != nil {
		return e
	}
	scripts, e := scriptsFromArg(args[1])
	if e != nil {
		return e
	}

	watch.addScripts(scripts)

	return okResult(len(watch.scripts))
}

// neutrinoWatchListAddOutpoint adds a watched outpoint for spend detection.
func neutrinoWatchListAddOutpoint(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 3, "handle, txid, vout"); e != nil {
		return e
	}
	watch, e := lookupWatchList(args[0])
	if e != nil {
		return e
	}
	op, e := outpointFromArgs(args[1], args[2])
	if e != nil {
		return e
	}

	watch.addOutpoint(op)

	return okResult(len(watch.outpoints))
}

// neutrinoWatchListRemoveOutpoint removes a watched outpoint.
func neutrinoWatchListRemoveOutpoint(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 3, "handle, txid, vout"); e != nil {
		return e
	}
	watch, e := lookupWatchList(args[0])
	if e != nil {
		return e
	}
	op, e := outpointFromArgs(args[1], args[2])
	if e != nil {
		return e
	}

	watch.removeOutpoint(op)

	return okResult(len(watch.outpoints))
}

// neutrinoWatchListFree drops a watch list handle. Freeing an unknown handle
// is a no-op.
func neutrinoWatchListFree(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "handle"); e != nil {
		return e
	}

	delete(watchListHandles, args[0].Int())

	return okResult(true)
}

// neutrinoMatchFilters verifies one block-dn filter file against the
// committed filter-header chain and matches it against the watch list.
func neutrinoMatchFilters(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 6, "watchHandle, startHeight, filterFile, "+
		"headers, filterHeaders, prevFilterHeader[, onBlocks]"); e != nil {

		return e
	}

	// An optional progress callback, invoked with the number of blocks
	// processed so far.
	var onBlocks func(int)
	if len(args) > 6 && args[6].Type() == js.TypeFunction {
		callback := args[6]
		onBlocks = func(blocks int) {
			callback.Invoke(blocks)
		}
	}
	watch, e := lookupWatchList(args[0])
	if e != nil {
		return e
	}
	startHeight := int64(args[1].Int())
	filterFile, e := bytesFromArg(args[2])
	if e != nil {
		return e
	}
	headers, e := bytesFromArg(args[3])
	if e != nil {
		return e
	}
	filterHeaders, e := bytesFromArg(args[4])
	if e != nil {
		return e
	}

	// The previous filter header is passed in display (reversed hex)
	// order, like all hashes crossing this API.
	var prevFilterHeader chainhash.Hash
	if args[5].Type() == js.TypeString && args[5].String() != "" {
		hash, err := chainhash.NewHashFromStr(args[5].String())
		if err != nil {
			return errfResult("prevFilterHeader: %s", err)
		}
		prevFilterHeader = *hash
	}

	matches, err := matchFiltersImpl(
		watch, startHeight, filterFile, headers, filterHeaders,
		prevFilterHeader, onBlocks,
	)
	if err != nil {
		return errfResult("match filters: %s", err)
	}

	jsMatches := make([]any, len(matches))
	for i, m := range matches {
		jsMatches[i] = map[string]any{
			"height":    float64(m.height),
			"blockHash": m.blockHash.String(),
		}
	}

	return okResult(jsMatches)
}

// neutrinoScanBlock extracts watched outputs and spends from a full block.
func neutrinoScanBlock(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 2, "watchHandle, blockBytes"); e != nil {
		return e
	}
	watch, e := lookupWatchList(args[0])
	if e != nil {
		return e
	}
	blockBytes, e := bytesFromArg(args[1])
	if e != nil {
		return e
	}

	outputs, spends, err := scanBlockImpl(watch, blockBytes)
	if err != nil {
		return errfResult("scan block: %s", err)
	}

	jsOutputs := make([]any, len(outputs))
	for i, out := range outputs {
		jsOutputs[i] = map[string]any{
			"txid":     out.txid.String(),
			"vout":     int(out.vout),
			"value":    float64(out.value),
			"pkScript": bytesToJS(out.pkScript),
		}
	}

	jsSpends := make([]any, len(spends))
	for i, spend := range spends {
		jsSpends[i] = map[string]any{
			"prevTxid": spend.prevTxid.String(),
			"prevVout": int(spend.prevVout),
			"txid":     spend.txid.String(),
		}
	}

	return okResult(map[string]any{
		"outputs": jsOutputs,
		"spends":  jsSpends,
	})
}

// scriptsFromArg converts a JS array of scripts (hex strings or Uint8Arrays)
// to byte slices.
func scriptsFromArg(arg js.Value) ([][]byte, map[string]any) {
	n := arg.Length()
	scripts := make([][]byte, n)
	for i := 0; i < n; i++ {
		script, e := bytesFromArg(arg.Index(i))
		if e != nil {
			return nil, e
		}
		scripts[i] = script
	}

	return scripts, nil
}

// outpointFromArgs builds a wire.OutPoint from a display-order txid string
// and an output index.
func outpointFromArgs(txidArg, voutArg js.Value) (wire.OutPoint,
	map[string]any) {

	hash, err := chainhash.NewHashFromStr(txidArg.String())
	if err != nil {
		return wire.OutPoint{}, errfResult("invalid txid: %s", err)
	}

	return wire.OutPoint{Hash: *hash, Index: uint32(voutArg.Int())}, nil
}
