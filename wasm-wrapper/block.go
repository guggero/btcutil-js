//go:build js && wasm

package main

import (
	"bytes"
	"encoding/json"
	"syscall/js"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
)

// BlockJSON is the decode-output shape of a full block: the header fields,
// derived sizes, and every transaction in the existing tx decode shape.
type BlockJSON struct {
	Hash       string `json:"hash"`
	Version    int32  `json:"version"`
	PrevBlock  string `json:"prevBlock"`
	MerkleRoot string `json:"merkleRoot"`
	Timestamp  int64  `json:"timestamp"`
	Bits       uint32 `json:"bits"`
	Nonce      uint32 `json:"nonce"`

	// Size is the full serialized size including witness data;
	// LegacySize is the stripped (pre-segwit encoding) size. Weight is
	// the BIP141 block weight: legacySize*3 + size.
	Size       int      `json:"size"`
	LegacySize int      `json:"legacySize"`
	Weight     int      `json:"weight"`
	Txs        []TxJSON `json:"transactions"`
}

// deserializeBlockArg parses a full block from a JS argument (hex string or
// Uint8Array).
func deserializeBlockArg(arg js.Value) (*wire.MsgBlock, map[string]any) {
	raw, e := bytesFromArg(arg)
	if e != nil {
		return nil, e
	}
	var block wire.MsgBlock
	if err := block.Deserialize(bytes.NewReader(raw)); err != nil {
		return nil, errfResult("failed to parse block: %s", err)
	}
	return &block, nil
}

// blockDecode decodes a raw block into its header fields, derived sizes and
// all transactions (as the same JSON shape tx.decode produces).
// Calls Go: wire.MsgBlock.Deserialize() from btcd/wire.
func blockDecode(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "rawBlock"); e != nil {
		return e
	}
	block, e := deserializeBlockArg(args[0])
	if e != nil {
		return e
	}

	txs := make([]TxJSON, len(block.Transactions))
	for i, tx := range block.Transactions {
		txs[i] = txToJSON(tx)
	}

	size := block.SerializeSize()
	legacySize := block.SerializeSizeStripped()

	result := BlockJSON{
		Hash:       block.Header.BlockHash().String(),
		Version:    block.Header.Version,
		PrevBlock:  block.Header.PrevBlock.String(),
		MerkleRoot: block.Header.MerkleRoot.String(),
		Timestamp:  block.Header.Timestamp.Unix(),
		Bits:       block.Header.Bits,
		Nonce:      block.Header.Nonce,
		Size:       size,
		LegacySize: legacySize,
		Weight:     legacySize*3 + size,
		Txs:        txs,
	}

	encoded, err := json.Marshal(result)
	if err != nil {
		return errfResult("marshal block: %s", err)
	}
	return okResult(string(encoded))
}

// blockMerkleTree returns the merkle tree of a raw block bottom-up:
// level 0 holds the txids (display byte order), the last level is the
// merkle root. Odd levels duplicate their last entry for hashing (standard
// Bitcoin duplicate-last semantics) but the duplicate is not included in
// the returned level.
func blockMerkleTree(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "rawBlock"); e != nil {
		return e
	}
	block, e := deserializeBlockArg(args[0])
	if e != nil {
		return e
	}

	level := make([]chainhash.Hash, len(block.Transactions))
	for i, tx := range block.Transactions {
		level[i] = tx.TxHash()
	}

	var levels []any
	appendLevel := func(hashes []chainhash.Hash) {
		display := make([]any, len(hashes))
		for i, h := range hashes {
			display[i] = h.String()
		}
		levels = append(levels, display)
	}
	appendLevel(level)

	for len(level) > 1 {
		next := make([]chainhash.Hash, (len(level)+1)/2)
		for i := range next {
			left := level[2*i]

			// The standard duplicate-last rule for an odd number
			// of entries.
			right := left
			if 2*i+1 < len(level) {
				right = level[2*i+1]
			}

			next[i] = chainhash.DoubleHashH(
				append(left[:], right[:]...),
			)
		}
		level = next
		appendLevel(level)
	}

	return okResult(levels)
}
