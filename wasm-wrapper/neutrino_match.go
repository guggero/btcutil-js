//go:build js && wasm

package main

import (
	"bytes"
	"fmt"

	"github.com/btcsuite/btcd/btcutil/v2/gcs"
	"github.com/btcsuite/btcd/btcutil/v2/gcs/builder"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
)

// maxFilterSize bounds a single compact filter read from a filter file. A
// filter is a compressed digest of one block, so it can never legitimately
// approach the maximum block size.
const maxFilterSize = 4_000_000

// watchList is the set of watched output scripts (receive detection) and
// outpoints (spend detection) a scan matches against. It lives Go-side so
// per-filter-file match calls don't re-marshal the script set across the JS
// boundary.
type watchList struct {
	// scripts maps the raw script bytes (as string key) to themselves,
	// deduplicating watched scripts.
	scripts map[string][]byte

	// scriptSlice is the cached slice view of scripts, invalidated on
	// mutation; gcs.MatchAny wants a [][]byte.
	scriptSlice [][]byte

	// outpoints is the set of watched outpoints, i.e. UTXOs whose spend
	// should be detected by scanBlock.
	outpoints map[wire.OutPoint]struct{}
}

func newWatchList() *watchList {
	return &watchList{
		scripts:   make(map[string][]byte),
		outpoints: make(map[wire.OutPoint]struct{}),
	}
}

// addScripts adds raw output scripts to the watch list.
func (w *watchList) addScripts(scripts [][]byte) {
	for _, script := range scripts {
		if len(script) == 0 {
			continue
		}
		w.scripts[string(script)] = script
	}
	w.scriptSlice = nil
}

// addOutpoint adds a single watched outpoint.
func (w *watchList) addOutpoint(op wire.OutPoint) {
	w.outpoints[op] = struct{}{}
}

// removeOutpoint drops a watched outpoint (e.g. once its spend was found).
func (w *watchList) removeOutpoint(op wire.OutPoint) {
	delete(w.outpoints, op)
}

// scriptTargets returns the watched scripts as a slice for gcs matching.
func (w *watchList) scriptTargets() [][]byte {
	if w.scriptSlice == nil {
		w.scriptSlice = make([][]byte, 0, len(w.scripts))
		for _, script := range w.scripts {
			w.scriptSlice = append(w.scriptSlice, script)
		}
	}

	return w.scriptSlice
}

// filterMatch is one matched block from matchFilters.
type filterMatch struct {
	height    int64
	blockHash chainhash.Hash
}

// matchFilters runs one verify-and-match pass over a block-dn filter file:
// per height it (1) recomputes the block hash from the corresponding raw
// header, (2) verifies the filter hashes into the committed BIP157
// filter-header chain, and (3) matches the filter against the watched
// scripts. All three inputs must cover the same height range starting at
// startHeight; prevFilterHeader is the committed filter header of
// startHeight-1 (zero hash for genesis).
func matchFiltersImpl(watch *watchList, startHeight int64, filterFile,
	headers, filterHeaders []byte, prevFilterHeader chainhash.Hash,
	onBlocks func(int)) ([]filterMatch, error) {

	if len(headers)%headerSize != 0 {
		return nil, fmt.Errorf("header data length %d is not a "+
			"multiple of %d", len(headers), headerSize)
	}
	count := len(headers) / headerSize
	if len(filterHeaders) != count*chainhash.HashSize {
		return nil, fmt.Errorf("expected %d filter headers, got %d "+
			"bytes", count, len(filterHeaders))
	}

	targets := watch.scriptTargets()
	reader := bytes.NewReader(filterFile)

	var matches []filterMatch
	for i := 0; i < count; i++ {
		// Report progress sparsely, so the calls into JS stay
		// negligible next to the per-block work.
		if onBlocks != nil && i > 0 && i%128 == 0 {
			onBlocks(i)
		}

		height := startHeight + int64(i)

		filterBytes, err := wire.ReadVarBytes(
			reader, 0, maxFilterSize, "filter",
		)
		if err != nil {
			return nil, fmt.Errorf("filter at height %d: %w",
				height, err)
		}

		filter, err := gcs.FromNBytes(
			builder.DefaultP, builder.DefaultM, filterBytes,
		)
		if err != nil {
			return nil, fmt.Errorf("filter at height %d: %w",
				height, err)
		}

		// Verify the filter against the committed filter-header
		// chain: filterHeader[h] = dsha(dsha(filter) || header[h-1]).
		// This makes a corrupted or tampered filter file detectable.
		expected, err := builder.MakeHeaderForFilter(
			filter, prevFilterHeader,
		)
		if err != nil {
			return nil, fmt.Errorf("filter at height %d: %w",
				height, err)
		}

		var committed chainhash.Hash
		offset := i * chainhash.HashSize
		copy(committed[:], filterHeaders[offset:])
		if expected != committed {
			return nil, fmt.Errorf("filter at height %d does "+
				"not match its committed filter header",
				height)
		}
		prevFilterHeader = committed

		// Matching is skipped for an empty watch list — the call
		// then only verifies the file's integrity.
		if len(targets) == 0 {
			continue
		}

		// The BIP158 filter key is derived from the block hash,
		// recomputed here from the trusted (already validated) raw
		// header.
		blockHash := chainhash.DoubleHashH(
			headers[i*headerSize : (i+1)*headerSize],
		)
		key := builder.DeriveKey(&blockHash)

		matched, err := filter.MatchAny(key, targets)
		if err != nil {
			return nil, fmt.Errorf("filter at height %d: %w",
				height, err)
		}
		if matched {
			matches = append(matches, filterMatch{
				height:    height,
				blockHash: blockHash,
			})
		}
	}

	if onBlocks != nil && count > 0 {
		onBlocks(count)
	}

	// The filter file may contain more entries than the height range
	// covers (never fewer) — e.g. when scanning a sub-range. Trailing
	// bytes are simply not consumed.
	return matches, nil
}

// foundOutput is a block output paying a watched script.
type foundOutput struct {
	txid     chainhash.Hash
	vout     uint32
	value    int64
	pkScript []byte
}

// foundSpend is a block input spending a watched outpoint.
type foundSpend struct {
	prevTxid chainhash.Hash
	prevVout uint32
	txid     chainhash.Hash
}

// scanBlockImpl extracts watched-script outputs and watched-outpoint spends
// from a full serialized block.
func scanBlockImpl(watch *watchList, blockBytes []byte) ([]foundOutput,
	[]foundSpend, error) {

	var block wire.MsgBlock
	if err := block.Deserialize(bytes.NewReader(blockBytes)); err != nil {
		return nil, nil, fmt.Errorf("failed to parse block: %w", err)
	}

	var (
		outputs []foundOutput
		spends  []foundSpend
	)
	for _, tx := range block.Transactions {
		txid := tx.TxHash()

		for _, in := range tx.TxIn {
			if _, ok := watch.outpoints[in.PreviousOutPoint]; ok {
				spends = append(spends, foundSpend{
					prevTxid: in.PreviousOutPoint.Hash,
					prevVout: in.PreviousOutPoint.Index,
					txid:     txid,
				})
			}
		}

		for vout, out := range tx.TxOut {
			if _, ok := watch.scripts[string(out.PkScript)]; ok {
				outputs = append(outputs, foundOutput{
					txid:     txid,
					vout:     uint32(vout),
					value:    out.Value,
					pkScript: out.PkScript,
				})
			}
		}
	}

	return outputs, spends, nil
}
