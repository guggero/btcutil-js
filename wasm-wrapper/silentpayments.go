//go:build js && wasm

package main

// The silentpayments namespace provides the receiver/scanning side of
// BIP-352 Silent Payments, driven by the tweak-data index a block-dn server
// serves: per eligible transaction the server publishes the 33-byte point
// input_hash*A_sum, from which the scanner derives candidate taproot output
// keys (one ECDH multiplication per tweak) without ever revealing its keys
// to the server.
//
// The flow mirrors the two-phase design of btcd's silentpayments package:
//
//  1. spScanBatch: for every block in a filter-file range, derive the
//     k=0 candidate output keys for the base and change label addresses,
//     and match them (as P2TR scripts) against the block's p2tr custom
//     compact filter, verifying the filter against its committed header
//     chain along the way.
//  2. spScanBlock: for a matched (and downloaded) block, identify the
//     actual wallet outputs across output indexes k = 0, 1, 2, ... per
//     BIP-352 continuation semantics, and report each with its
//     private-key tweak (t_k, plus the label tweak for change outputs).
//
// The served tweak already includes input_hash, while the package's
// CreateOutputKey multiplies its shareSum argument by a separately-passed
// input hash. Passing shareSum = b_scan * tweak with an input hash scalar
// of one makes the two shapes line up without re-deriving input data from
// the block.
//
// Tweak data arrives in block-dn's binary format (/sp/tweaks/<dust>/<h>):
// an 18-byte self-describing header — network magic (uint32 LE), format
// version, file type (2), start height (uint32 LE), dust limit in satoshis
// (uint64 LE) — followed by one record per block in ascending height order:
// a compact-size tweak count plus that many 33-byte compressed tweak keys,
// in transaction order. Transaction indexes are not part of the format;
// identification pairs tweaks with outputs by key equality across the whole
// block, which is sound because a foreign output equal to one of the
// wallet's candidate keys would require a 256-bit collision (and would be
// spendable by the wallet anyway).

import (
	"bytes"
	"encoding/binary"
	"io"
	"sort"
	"syscall/js"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/v2/gcs"
	"github.com/btcsuite/btcd/btcutil/v2/gcs/builder"
	"github.com/btcsuite/btcd/chainhash/v2"
	sp "github.com/btcsuite/btcd/silentpayments"
	"github.com/btcsuite/btcd/wire/v2"
)

const (
	// spTweakHeaderSize is the size of the self-describing header of a
	// block-dn SP tweak data response.
	spTweakHeaderSize = 4 + 1 + 1 + 4 + 8

	// spTweakVersion is the highest binary format version understood.
	spTweakVersion = byte(0)

	// spTweakFileType is block-dn's file type byte for SP tweak data.
	spTweakFileType = byte(2)

	// spTweakKeySize is the size of one compressed tweak public key.
	spTweakKeySize = 33
)

// spScanner is the long-lived scanning context: the scan private key, the
// spend public key and the pre-computed base + change scan addresses.
type spScanner struct {
	scanPriv    *btcec.PrivateKey
	spendPub    *btcec.PublicKey
	changeTweak *btcec.ModNScalar

	// net is the network the scanner's addresses were created for; served
	// tweak data self-describes its network and must match.
	net wire.BitcoinNet

	// addresses holds the base (no label) and change (label m=0) scan
	// addresses, the set every filter candidate is derived for.
	addresses []sp.ScanAddress

	// address and changeAddress are the bech32m encoded silent payment
	// addresses, for display purposes.
	address       string
	changeAddress string
}

var spScannerHandles = map[int]*spScanner{}

func lookupSpScanner(arg js.Value) (*spScanner, map[string]any) {
	s, ok := spScannerHandles[arg.Int()]
	if !ok {
		return nil, errResult("unknown silent payment scanner handle")
	}

	return s, nil
}

// spScannerNew creates a scanner from a 32-byte scan private key and a
// 33-byte compressed spend public key.
// Calls Go: silentpayments.NewAddressForNet() / NewScanAddress() /
// LabelTweak() from btcd/silentpayments.
func spScannerNew(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 2, "scanPrivKey, spendPubKey[, "+
		"network]"); e != nil {

		return e
	}

	scanRaw, e := bytesFromArg(args[0])
	if e != nil {
		return e
	}
	if len(scanRaw) != 32 {
		return errResult("scan private key must be 32 bytes")
	}
	scanPriv, _ := btcec.PrivKeyFromBytes(scanRaw)
	if scanPriv.Key.IsZero() {
		return errResult("scan private key is zero")
	}

	spendRaw, e := bytesFromArg(args[1])
	if e != nil {
		return e
	}
	spendPub, err := btcec.ParsePubKey(spendRaw)
	if err != nil {
		return errfResult("invalid spend public key: %s", err)
	}

	params, e := getNetwork(optString(args, 2, "mainnet"))
	if e != nil {
		return e
	}

	scanPub := scanPriv.PubKey()
	baseAddr, err := sp.NewAddressForNet(params, *scanPub, *spendPub, nil)
	if err != nil {
		return errfResult("create address: %s", err)
	}

	// The change address is the labeled address with m = 0, which
	// BIP-352 reserves for change detection.
	changeTweak := sp.LabelTweak(scanPriv, 0)
	changeAddr, err := sp.NewAddressForNet(
		params, *scanPub, *spendPub, changeTweak,
	)
	if err != nil {
		return errfResult("create change address: %s", err)
	}

	scanner := &spScanner{
		scanPriv:    scanPriv,
		spendPub:    spendPub,
		changeTweak: changeTweak,
		net:         params.Net,
		addresses: []sp.ScanAddress{
			sp.NewScanAddress(*baseAddr, *scanPriv),
			sp.NewScanAddress(*changeAddr, *scanPriv),
		},
		address:       baseAddr.EncodeAddress(),
		changeAddress: changeAddr.EncodeAddress(),
	}

	h := nextHandle
	nextHandle++
	spScannerHandles[h] = scanner

	return okResult(map[string]any{
		"handle":        h,
		"address":       scanner.address,
		"changeAddress": scanner.changeAddress,
	})
}

// spScannerFree drops a scanner handle. Freeing an unknown handle is a
// no-op.
func spScannerFree(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 1, "handle"); e != nil {
		return e
	}

	delete(spScannerHandles, args[0].Int())

	return okResult(true)
}

// candidateKeys derives the k=0 candidate taproot output keys of one served
// transaction tweak, for the scanner's base and change addresses. A tweak
// that is not a valid curve point can never correspond to a real payment,
// so it yields nil keys and no error — callers count and skip it.
func (s *spScanner) candidateKeys(
	tweakRaw []byte) ([]*btcec.PublicKey, error) {

	tweakPub, err := btcec.ParsePubKey(tweakRaw)
	if err != nil {
		return nil, nil
	}

	return sp.TransactionOutputKeysForFilter(*tweakPub, s.addresses)
}

// parseSpTweakHeader validates the self-describing header of a block-dn SP
// tweak data response against the scanner's network and the expected range
// start and dust limit, returning an error map on any mismatch.
func (s *spScanner) parseSpTweakHeader(data []byte, startHeight int64,
	dustLimit uint64) map[string]any {

	if len(data) < spTweakHeaderSize {
		return errfResult("tweak data too short: %d bytes", len(data))
	}

	if magic := binary.LittleEndian.Uint32(data[0:4]); magic !=
		uint32(s.net) {

		return errfResult("tweak data network magic %08x does not "+
			"match scanner network magic %08x", magic,
			uint32(s.net))
	}
	if version := data[4]; version > spTweakVersion {
		return errfResult("unsupported tweak data format version %d",
			version)
	}
	if fileType := data[5]; fileType != spTweakFileType {
		return errfResult("unexpected file type %d in tweak data",
			fileType)
	}
	if start := binary.LittleEndian.Uint32(data[6:10]); int64(start) !=
		startHeight {

		return errfResult("tweak data starts at %d, expected %d",
			start, startHeight)
	}
	if dust := binary.LittleEndian.Uint64(data[10:18]); dust !=
		dustLimit {

		return errfResult("tweak data has dust limit %d, expected %d",
			dust, dustLimit)
	}

	return nil
}

// spScanBatch runs one verify-and-match pass over a block-dn p2tr filter
// file range: for every block, the candidate output keys of all served
// transaction tweaks are matched against the block's filter; every filter
// is verified against the committed p2tr filter-header chain. The tweak
// data is block-dn's binary /sp/tweaks response for the same range and
// dust limit; its self-describing header is validated against all three.
// Each match carries the block's raw tweak keys so the caller can identify
// the outputs of the downloaded block without re-reading the file.
//
// The result carries a per-phase timing breakdown (parse/derive/verify/
// match, in milliseconds) so callers can attribute where scan time goes:
// candidate derivation is the ECDH-heavy part and expected to dominate.
func spScanBatch(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 8, "handle, startHeight, tweakData, "+
		"filterFile, headers, filterHeaders, prevHeader, "+
		"dustLimit"); e != nil {

		return e
	}
	scanner, e := lookupSpScanner(args[0])
	if e != nil {
		return e
	}
	startHeight := int64(args[1].Int())
	dustLimit := uint64(args[7].Float())

	tweakData, e := bytesFromArg(args[2])
	if e != nil {
		return e
	}

	parseStart := time.Now()
	if e := scanner.parseSpTweakHeader(
		tweakData, startHeight, dustLimit,
	); e != nil {
		return e
	}
	tweakReader := bytes.NewReader(tweakData[spTweakHeaderSize:])
	tweakBody := tweakData[spTweakHeaderSize:]
	parseDur := time.Since(parseStart)

	filterFile, e := bytesFromArg(args[3])
	if e != nil {
		return e
	}
	headers, e := bytesFromArg(args[4])
	if e != nil {
		return e
	}
	filterHeaders, e := bytesFromArg(args[5])
	if e != nil {
		return e
	}

	var prevFilterHeader chainhash.Hash
	if args[6].Type() == js.TypeString && args[6].String() != "" {
		hash, err := chainhash.NewHashFromStr(args[6].String())
		if err != nil {
			return errfResult("prevFilterHeader: %s", err)
		}
		prevFilterHeader = *hash
	}

	if len(headers)%headerSize != 0 {
		return errfResult("header data length %d is not a multiple "+
			"of %d", len(headers), headerSize)
	}
	count := len(headers) / headerSize
	if len(filterHeaders) != count*chainhash.HashSize {
		return errfResult("expected %d filter headers, got %d bytes",
			count, len(filterHeaders))
	}

	reader := bytes.NewReader(filterFile)
	var matches []any
	var verifyDur, deriveDur, matchDur time.Duration
	skippedTweaks := 0
	tweakCount := 0
	for i := 0; i < count; i++ {
		height := startHeight + int64(i)

		filterBytes, err := wire.ReadVarBytes(
			reader, 0, maxFilterSize, "filter",
		)
		if err != nil {
			return errfResult("filter at height %d: %s", height,
				err)
		}

		// Verify the filter against the committed p2tr filter-header
		// chain, making corrupted or tampered files detectable.
		verifyStart := time.Now()
		filter, err := gcs.FromNBytes(
			builder.DefaultP, builder.DefaultM, filterBytes,
		)
		if err != nil {
			return errfResult("filter at height %d: %s", height,
				err)
		}
		expected, err := builder.MakeHeaderForFilter(
			filter, prevFilterHeader,
		)
		if err != nil {
			return errfResult("filter at height %d: %s", height,
				err)
		}
		var committed chainhash.Hash
		offset := i * chainhash.HashSize
		copy(committed[:], filterHeaders[offset:])
		if expected != committed {
			return errfResult("filter at height %d does not "+
				"match its committed filter header", height)
		}
		prevFilterHeader = committed
		verifyDur += time.Since(verifyStart)

		// Read the block's tweak record: a compact-size count plus
		// that many 33-byte compressed tweak keys, height implied by
		// position.
		parseStart = time.Now()
		numTweaks, err := wire.ReadVarInt(tweakReader, 0)
		if err != nil {
			return errfResult("tweak data at height %d: %s",
				height, err)
		}
		if numTweaks > uint64(tweakReader.Len()/spTweakKeySize) {
			return errfResult("tweak data at height %d: count "+
				"%d exceeds remaining data", height, numTweaks)
		}
		size := int(numTweaks) * spTweakKeySize
		tweakOffset := len(tweakBody) - tweakReader.Len()
		blockTweaks := tweakBody[tweakOffset : tweakOffset+size]
		if _, err := tweakReader.Seek(
			int64(size), io.SeekCurrent,
		); err != nil {
			return errfResult("tweak data at height %d: %s",
				height, err)
		}
		parseDur += time.Since(parseStart)

		// No eligible transactions above the dust limit: nothing to
		// match.
		if numTweaks == 0 {
			continue
		}

		deriveStart := time.Now()
		keys := make([]*btcec.PublicKey, 0, 2*numTweaks)
		for t := 0; t < int(numTweaks); t++ {
			tweakRaw := blockTweaks[t*spTweakKeySize : (t+1)*
				spTweakKeySize]
			candidates, err := scanner.candidateKeys(tweakRaw)
			if err != nil {
				return errfResult("height %d: %s", height, err)
			}
			if candidates == nil {
				skippedTweaks++
				continue
			}
			keys = append(keys, candidates...)
		}
		tweakCount += int(numTweaks)
		deriveDur += time.Since(deriveStart)
		if len(keys) == 0 {
			continue
		}

		blockHash := chainhash.DoubleHashH(
			headers[i*headerSize : (i+1)*headerSize],
		)
		matchStart := time.Now()
		matched, err := sp.MatchBlock(filter, &blockHash, keys)
		if err != nil {
			return errfResult("filter at height %d: %s", height,
				err)
		}
		matchDur += time.Since(matchStart)
		if matched {
			matches = append(matches, map[string]any{
				"height":    float64(height),
				"blockHash": blockHash.String(),
				"tweaks":    bytesToJS(blockTweaks),
			})
		}
	}

	return okResult(map[string]any{
		"matches":       matches,
		"skippedTweaks": skippedTweaks,
		"timings": map[string]any{
			"parseMs":  durationMs(parseDur),
			"deriveMs": durationMs(deriveDur),
			"verifyMs": durationMs(verifyDur),
			"matchMs":  durationMs(matchDur),
			"tweaks":   tweakCount,
		},
	})
}

// durationMs renders a duration as fractional milliseconds for the JS side.
func durationMs(d time.Duration) float64 {
	return float64(d.Microseconds()) / 1000
}

// spOutputCandidate is one taproot output of a block under scan.
type spOutputCandidate struct {
	txIdx int
	vout  uint32
	value int64
	xOnly [32]byte
}

// spCandidatePool indexes output candidates by x-only output key, so the
// identification loop can pair served tweaks with outputs without knowing
// transaction boundaries (the binary tweak format doesn't carry them). A
// key appearing more than once yields all its instances on a match — every
// instance is spendable with the same private key tweak.
type spCandidatePool struct {
	byKey map[[32]byte][]spOutputCandidate
	size  int
}

func newSpCandidatePool(candidates []spOutputCandidate) *spCandidatePool {
	pool := &spCandidatePool{
		byKey: make(
			map[[32]byte][]spOutputCandidate, len(candidates),
		),
		size: len(candidates),
	}
	for _, candidate := range candidates {
		pool.byKey[candidate.xOnly] = append(
			pool.byKey[candidate.xOnly], candidate,
		)
	}

	return pool
}

// take removes and returns all candidates with the given output key.
func (p *spCandidatePool) take(key [32]byte) []spOutputCandidate {
	found, ok := p.byKey[key]
	if !ok {
		return nil
	}
	delete(p.byKey, key)
	p.size -= len(found)

	return found
}

func (p *spCandidatePool) empty() bool {
	return p.size == 0
}

// spFound is one identified wallet output.
type spFound struct {
	candidate    spOutputCandidate
	label        string
	k            uint32
	privKeyTweak []byte
}

// spIdentifyOutputs runs the BIP-352 output identification loop for one
// transaction tweak against a pool of taproot output candidates: output
// index k advances only while the current k yields a match (base or change
// label), exactly like the reference scanning flow. Matched candidates are
// consumed from the pool, so a sequence of tweaks can share it.
func (s *spScanner) spIdentifyOutputs(tweakRaw []byte,
	pool *spCandidatePool) ([]spFound, error) {

	// An invalid tweak point can never correspond to a real payment; the
	// transaction is simply skipped (see candidateKeys).
	tweakPub, err := btcec.ParsePubKey(tweakRaw)
	if err != nil {
		return nil, nil
	}

	// The served tweak is input_hash*A_sum, so b_scan * tweak is already
	// the full ECDH shared secret; the identity input hash below keeps
	// CreateOutputKey from applying another multiplication.
	shareSum := sp.ScalarMult(s.scanPriv.Key, tweakPub)
	var one btcec.ModNScalar
	one.SetInt(1)

	baseSpend := s.spendPub
	changeSpend := sp.LabelSpendKey(s.changeTweak, s.spendPub)

	var found []spFound
	for k := uint32(0); ; k++ {
		foundAtK := false

		for _, variant := range []struct {
			label    string
			spendKey *btcec.PublicKey
		}{
			{label: "base", spendKey: baseSpend},
			{label: "change", spendKey: changeSpend},
		} {
			outKey, err := sp.CreateOutputKey(
				*shareSum, *variant.spendKey, k, one,
			)
			if err != nil {
				return nil, err
			}
			var want [32]byte
			copy(want[:], schnorr.SerializePubKey(outKey))

			taken := pool.take(want)
			if len(taken) == 0 {
				continue
			}
			foundAtK = true

			privKeyTweak := s.privKeyTweak(
				shareSum, k, variant.label == "change",
			)
			for _, candidate := range taken {
				found = append(found, spFound{
					candidate:    candidate,
					label:        variant.label,
					k:            k,
					privKeyTweak: privKeyTweak,
				})
			}
		}

		if !foundAtK || pool.empty() {
			return found, nil
		}
	}
}

// privKeyTweak computes the BIP-352 private key tweak of a found output:
// t_k = taggedHash(BIP0352/SharedSecret, serP(ecdh) || ser32(k)), plus the
// change label tweak for change outputs. Adding this tweak to the spend
// private key yields the output's key-path signing key.
func (s *spScanner) privKeyTweak(sharedSecret *btcec.PublicKey, k uint32,
	change bool) []byte {

	payload := make([]byte, 33+4)
	copy(payload, sharedSecret.SerializeCompressed())
	binary.BigEndian.PutUint32(payload[33:], k)

	t := chainhash.TaggedHash(sp.TagBIP0352SharedSecret, payload)

	var tweak btcec.ModNScalar
	tweak.SetBytes((*[32]byte)(t))
	if change {
		tweak.Add(s.changeTweak)
	}

	result := tweak.Bytes()
	return result[:]
}

// spScanBlock identifies the wallet's silent payment outputs in a full,
// already-downloaded block. tweakBytes is the block's record from the
// binary tweak data (as returned in a spScanBatch match): the concatenated
// 33-byte compressed tweak keys of the block's eligible transactions, in
// transaction order. Since the format doesn't pair tweaks with
// transactions, identification runs each tweak against the pooled taproot
// outputs of the whole block; see the file comment for why that is sound.
func spScanBlock(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 3, "handle, blockBytes, tweakBytes"); e !=
		nil {

		return e
	}
	scanner, e := lookupSpScanner(args[0])
	if e != nil {
		return e
	}
	blockBytes, e := bytesFromArg(args[1])
	if e != nil {
		return e
	}
	tweakBytes, e := bytesFromArg(args[2])
	if e != nil {
		return e
	}
	if len(tweakBytes)%spTweakKeySize != 0 {
		return errfResult("tweak data length %d is not a multiple "+
			"of %d", len(tweakBytes), spTweakKeySize)
	}

	var block wire.MsgBlock
	if err := block.Deserialize(bytes.NewReader(blockBytes)); err != nil {
		return errfResult("failed to parse block: %s", err)
	}

	var candidates []spOutputCandidate
	for txIdx, tx := range block.Transactions {
		for vout, txOut := range tx.TxOut {
			if len(txOut.PkScript) != 34 ||
				txOut.PkScript[0] != 0x51 ||
				txOut.PkScript[1] != 0x20 {

				continue
			}
			candidate := spOutputCandidate{
				txIdx: txIdx,
				vout:  uint32(vout),
				value: txOut.Value,
			}
			copy(candidate.xOnly[:], txOut.PkScript[2:])
			candidates = append(candidates, candidate)
		}
	}
	pool := newSpCandidatePool(candidates)

	var all []spFound
	for t := 0; t*spTweakKeySize < len(tweakBytes) &&
		!pool.empty(); t++ {

		tweakRaw := tweakBytes[t*spTweakKeySize : (t+1)*spTweakKeySize]
		found, err := scanner.spIdentifyOutputs(tweakRaw, pool)
		if err != nil {
			return errfResult("tweak %d: %s", t, err)
		}
		all = append(all, found...)
	}

	// Report in block order so results are deterministic regardless of
	// which tweak claimed an output.
	sort.Slice(all, func(i, j int) bool {
		if all[i].candidate.txIdx != all[j].candidate.txIdx {
			return all[i].candidate.txIdx < all[j].candidate.txIdx
		}
		return all[i].candidate.vout < all[j].candidate.vout
	})

	txids := make(map[int]string, len(all))
	results := make([]any, len(all))
	for i, out := range all {
		txid, ok := txids[out.candidate.txIdx]
		if !ok {
			txid = block.Transactions[out.candidate.txIdx].
				TxHash().String()
			txids[out.candidate.txIdx] = txid
		}
		results[i] = map[string]any{
			"txid":         txid,
			"vout":         int(out.candidate.vout),
			"value":        float64(out.candidate.value),
			"xOnlyPubKey":  bytesToJS(out.candidate.xOnly[:]),
			"label":        out.label,
			"k":            int(out.k),
			"privKeyTweak": bytesToJS(out.privKeyTweak),
		}
	}

	return okResult(results)
}

// spScanOutputs is the pure, block-free variant of the identification loop
// used by unit tests: given one transaction tweak and a list of 32-byte
// x-only taproot output keys, it reports which belong to the scanner. The
// result indexes refer to the input list.
func spScanOutputs(_ js.Value, args []js.Value) any {
	if e := checkArgs(args, 3, "handle, tweak, xOnlyKeys"); e != nil {
		return e
	}
	scanner, e := lookupSpScanner(args[0])
	if e != nil {
		return e
	}
	tweakRaw, e := bytesFromArg(args[1])
	if e != nil {
		return e
	}

	n := args[2].Length()
	candidates := make([]spOutputCandidate, n)
	for i := 0; i < n; i++ {
		xOnly, e := bytesFromArg(args[2].Index(i))
		if e != nil {
			return e
		}
		if len(xOnly) != 32 {
			return errfResult("x-only key %d must be 32 bytes", i)
		}
		candidates[i] = spOutputCandidate{vout: uint32(i)}
		copy(candidates[i].xOnly[:], xOnly)
	}

	found, err := scanner.spIdentifyOutputs(
		tweakRaw, newSpCandidatePool(candidates),
	)
	if err != nil {
		return errfResult("scan outputs: %s", err)
	}

	results := make([]any, len(found))
	for i, out := range found {
		results[i] = map[string]any{
			"index":        int(out.candidate.vout),
			"xOnlyPubKey":  bytesToJS(out.candidate.xOnly[:]),
			"label":        out.label,
			"k":            int(out.k),
			"privKeyTweak": bytesToJS(out.privKeyTweak),
		}
	}

	return okResult(results)
}
