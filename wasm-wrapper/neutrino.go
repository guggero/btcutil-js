//go:build js && wasm

package main

// The neutrino namespace provides the CPU- and consensus-critical primitives
// of a browser-based BIP157/158 light client ("neutrino over HTTP"). The
// orchestration — fetching header/filter files from a block-dn server,
// persisting them, deciding what to scan — lives in TypeScript; this file
// only validates and matches:
//
//   - headerChain: a stateful, handle-registered accumulator (same registry
//     pattern as descriptors.go) that validates raw block headers batch by
//     batch: previous-hash linkage, proof of work, difficulty retargeting and
//     median-time-past. It tracks the accumulated chain work and keeps a
//     sliding window of recent headers so shallow tail reorgs can be rolled
//     back. Its compact state can be exported/imported so a client can resume
//     without re-validating the whole chain.
//
//   - watchList: a handle-registered set of watched output scripts and
//     outpoints, parked Go-side so a scan doesn't re-marshal the (potentially
//     large) script set across the JS boundary for every filter file.
//
//   - matchFilters: stateless one-pass verify-and-match over one block-dn
//     filter file: each filter is checked against the committed BIP157
//     filter-header chain and matched against the watch list.
//
//   - scanBlock: extracts watched outputs (receives) and watched-outpoint
//     spends from a full block once its filter matched.
//
// The difficulty/PoW arithmetic below follows btcd's blockchain package
// (which has no standalone v2 module to import). Known limitations, fine for
// the intended networks (mainnet, signet, regtest): the testnet3/4 minimum-
// difficulty carve-outs are supported via a bounded walk-back, but BIP94
// (testnet4 timewarp/block-storm mitigation) is not enforced.

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"time"

	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
)

const (
	// headerSize is the serialized size of a block header.
	headerSize = 80

	// ringWindow is how many recent headers a chain keeps in memory. It
	// must cover one full difficulty period (2016 blocks) plus the
	// median-time-past window, so both the retarget calculation and a
	// tail rollback always find what they need. 2048 leaves margin.
	ringWindow = 2048

	// medianTimeBlocks is the number of previous blocks considered for
	// the median-time-past timestamp check.
	medianTimeBlocks = 11

	// maxFutureBlockTime is how far a header timestamp may be in the
	// future relative to the local clock (consensus allows 2 hours).
	maxFutureBlockTime = 2 * time.Hour

	// headerStateVersion is the version byte of the exported header
	// chain state format.
	headerStateVersion = 1
)

// recentHeader is one ring-buffer entry of a headerChain.
type recentHeader struct {
	hash chainhash.Hash
	time uint32
	bits uint32
}

// headerChain is a validating accumulator over a chain of block headers.
type headerChain struct {
	params *chaincfg.Params

	// tipHeight is the height of the last appended header, or -1 for an
	// empty chain.
	tipHeight int64

	// chainWork is the accumulated proof of work of all appended headers.
	chainWork *big.Int

	// ring holds the most recent ringWindow headers, oldest first. The
	// last entry is the tip.
	ring []recentHeader

	// workCache memoizes CalcWork per compact-bits value; bits change at
	// most every 2016 blocks, so this avoids a 256-bit division per
	// header.
	workCache map[uint32]*big.Int

	// blocksPerRetarget is the number of blocks per difficulty period
	// (2016 on mainnet).
	blocksPerRetarget int64
}

func newHeaderChain(params *chaincfg.Params) *headerChain {
	return &headerChain{
		params:    params,
		tipHeight: -1,
		chainWork: new(big.Int),
		workCache: make(map[uint32]*big.Int),
		blocksPerRetarget: int64(params.TargetTimespan /
			params.TargetTimePerBlock),
	}
}

// compactToBig converts a compact-bits difficulty representation to a big
// integer target, following btcd's blockchain.CompactToBig.
func compactToBig(compact uint32) *big.Int {
	mantissa := compact & 0x007fffff
	isNegative := compact&0x00800000 != 0
	exponent := uint(compact >> 24)

	var bn *big.Int
	if exponent <= 3 {
		mantissa >>= 8 * (3 - exponent)
		bn = big.NewInt(int64(mantissa))
	} else {
		bn = big.NewInt(int64(mantissa))
		bn.Lsh(bn, 8*(exponent-3))
	}

	if isNegative {
		bn = bn.Neg(bn)
	}

	return bn
}

// bigToCompact converts a big integer target to compact-bits representation,
// following btcd's blockchain.BigToCompact.
func bigToCompact(n *big.Int) uint32 {
	if n.Sign() == 0 {
		return 0
	}

	var mantissa uint32
	exponent := uint(len(n.Bytes()))
	if exponent <= 3 {
		mantissa = uint32(n.Bits()[0])
		mantissa <<= 8 * (3 - exponent)
	} else {
		tn := new(big.Int).Set(n)
		mantissa = uint32(tn.Rsh(tn, 8*(exponent-3)).Bits()[0])
	}

	// A mantissa with the sign bit set must be normalized by shifting it
	// right and bumping the exponent.
	if mantissa&0x00800000 != 0 {
		mantissa >>= 8
		exponent++
	}

	compact := uint32(exponent<<24) | mantissa
	if n.Sign() < 0 {
		compact |= 0x00800000
	}

	return compact
}

// calcWork returns the work value for the given compact-bits difficulty:
// 2^256 / (target + 1), following btcd's blockchain.CalcWork.
func (c *headerChain) calcWork(bits uint32) *big.Int {
	if work, ok := c.workCache[bits]; ok {
		return work
	}

	target := compactToBig(bits)
	if target.Sign() <= 0 {
		zero := new(big.Int)
		c.workCache[bits] = zero
		return zero
	}

	denominator := new(big.Int).Add(target, big.NewInt(1))
	numerator := new(big.Int).Lsh(big.NewInt(1), 256)
	work := numerator.Div(numerator, denominator)
	c.workCache[bits] = work

	return work
}

// medianTimePast returns the median timestamp of the last medianTimeBlocks
// ring entries, following btcd's CalcPastMedianTime.
func (c *headerChain) medianTimePast() uint32 {
	num := len(c.ring)
	if num > medianTimeBlocks {
		num = medianTimeBlocks
	}

	timestamps := make([]uint32, num)
	for i := 0; i < num; i++ {
		timestamps[i] = c.ring[len(c.ring)-1-i].time
	}

	// Simple insertion sort: num is at most 11.
	for i := 1; i < num; i++ {
		for j := i; j > 0 && timestamps[j-1] > timestamps[j]; j-- {
			timestamps[j-1], timestamps[j] =
				timestamps[j], timestamps[j-1]
		}
	}

	return timestamps[num/2]
}

// ringEntry returns the ring entry at the given chain height, or false if it
// has already slid out of the window.
func (c *headerChain) ringEntry(height int64) (*recentHeader, bool) {
	offset := c.tipHeight - height
	if offset < 0 || offset >= int64(len(c.ring)) {
		return nil, false
	}

	return &c.ring[int64(len(c.ring))-1-offset], true
}

// expectedBits returns the required difficulty bits for the next header,
// following btcd's blockchain.calcNextRequiredDifficulty.
func (c *headerChain) expectedBits(newBlockTime uint32) (uint32, error) {
	// Genesis difficulty is fixed by the network definition.
	if c.tipHeight < 0 {
		return c.params.GenesisBlock.Header.Bits, nil
	}

	prev := c.ring[len(c.ring)-1]

	// Networks without retargeting (regtest) keep the previous
	// difficulty forever.
	if c.params.PoWNoRetargeting {
		return prev.bits, nil
	}

	nextHeight := c.tipHeight + 1

	// Not at a retarget boundary: difficulty carries over, except for
	// the test networks' minimum-difficulty carve-out.
	if nextHeight%c.blocksPerRetarget != 0 {
		if c.params.ReduceMinDifficulty {
			reductionTime := uint32(
				c.params.MinDiffReductionTime / time.Second,
			)

			// A block whose timestamp is too far ahead of its
			// parent may use the minimum difficulty.
			if newBlockTime > prev.time+reductionTime {
				return c.params.PowLimitBits, nil
			}

			// Otherwise the required bits are the last
			// non-minimum-difficulty bits in this period. The
			// walk is bounded by the ring window; if the answer
			// slid out of it we accept the previous bits (only
			// reachable on test networks).
			return c.lastRealBits(), nil
		}

		return prev.bits, nil
	}

	// Retarget boundary: scale the old target by the actual duration of
	// the finished period, clamped to 1/4..4x of the desired timespan.
	periodStart, ok := c.ringEntry(nextHeight - c.blocksPerRetarget)
	if !ok {
		return 0, fmt.Errorf("difficulty period start (height %d) "+
			"is outside the header window",
			nextHeight-c.blocksPerRetarget)
	}

	targetTimespan := int64(c.params.TargetTimespan / time.Second)
	adjustment := c.params.RetargetAdjustmentFactor
	minTimespan := targetTimespan / adjustment
	maxTimespan := targetTimespan * adjustment

	actualTimespan := int64(prev.time) - int64(periodStart.time)
	if actualTimespan < minTimespan {
		actualTimespan = minTimespan
	} else if actualTimespan > maxTimespan {
		actualTimespan = maxTimespan
	}

	oldTarget := compactToBig(prev.bits)
	newTarget := new(big.Int).Mul(oldTarget, big.NewInt(actualTimespan))
	newTarget.Div(newTarget, big.NewInt(targetTimespan))
	if newTarget.Cmp(c.params.PowLimit) > 0 {
		newTarget.Set(c.params.PowLimit)
	}

	return bigToCompact(newTarget), nil
}

// lastRealBits walks the ring backwards from the tip and returns the first
// bits value that is not the minimum difficulty, stopping at the current
// difficulty period's start. Used for the test networks' min-difficulty rule.
func (c *headerChain) lastRealBits() uint32 {
	periodStart := c.tipHeight - (c.tipHeight % c.blocksPerRetarget)
	for height := c.tipHeight; height >= periodStart; height-- {
		entry, ok := c.ringEntry(height)
		if !ok {
			break
		}
		if entry.bits != c.params.PowLimitBits {
			return entry.bits
		}
	}

	return c.params.PowLimitBits
}

// appendHeaders validates and appends a batch of serialized headers. It
// returns the number of headers consumed; on error, all headers before the
// offending one remain appended.
func (c *headerChain) appendHeaders(raw []byte) (int, error) {
	if len(raw)%headerSize != 0 {
		return 0, fmt.Errorf("header data length %d is not a "+
			"multiple of %d", len(raw), headerSize)
	}

	count := len(raw) / headerSize
	maxTime := uint32(time.Now().Add(maxFutureBlockTime).Unix())

	for i := 0; i < count; i++ {
		var header wire.BlockHeader
		err := header.Deserialize(
			bytes.NewReader(raw[i*headerSize : (i+1)*headerSize]),
		)
		if err != nil {
			return i, fmt.Errorf("header at offset %d: %w", i, err)
		}

		if err := c.connectHeader(&header, maxTime); err != nil {
			return i, fmt.Errorf("header at height %d: %w",
				c.tipHeight+1, err)
		}
	}

	return count, nil
}

// connectHeader validates a single header against the current tip and
// appends it.
func (c *headerChain) connectHeader(header *wire.BlockHeader,
	maxTime uint32) error {

	blockHash := header.BlockHash()
	headerTime := uint32(header.Timestamp.Unix())

	// Linkage: the header must extend the tip (or be the genesis block
	// of the configured network for an empty chain).
	if c.tipHeight < 0 {
		if blockHash != *c.params.GenesisHash {
			return fmt.Errorf("first header %s is not the %s "+
				"genesis block", blockHash,
				c.params.Name)
		}
	} else {
		tip := c.ring[len(c.ring)-1]
		if header.PrevBlock != tip.hash {
			return fmt.Errorf("previous hash %s does not match "+
				"tip %s", header.PrevBlock, tip.hash)
		}

		// Median time past: consensus requires a strictly later
		// timestamp than the median of the last 11 blocks.
		if headerTime <= c.medianTimePast() {
			return fmt.Errorf("timestamp %d is not after "+
				"median time past", headerTime)
		}

		if headerTime > maxTime {
			return fmt.Errorf("timestamp %d is too far in the "+
				"future", headerTime)
		}
	}

	// Difficulty: the claimed bits must be exactly what the chain rules
	// require at this height.
	expected, err := c.expectedBits(headerTime)
	if err != nil {
		return err
	}
	if header.Bits != expected {
		return fmt.Errorf("difficulty bits %08x do not match "+
			"expected %08x", header.Bits, expected)
	}

	// Proof of work: the header hash interpreted as a number must not
	// exceed the claimed target, which itself must be within the
	// network's limit.
	target := compactToBig(header.Bits)
	if target.Sign() <= 0 || target.Cmp(c.params.PowLimit) > 0 {
		return fmt.Errorf("difficulty target is out of range")
	}
	hashNum := new(big.Int).SetBytes(reversedHash(blockHash))
	if hashNum.Cmp(target) > 0 {
		return fmt.Errorf("block hash %s is above the target",
			blockHash)
	}

	// All checks passed: advance the tip.
	c.tipHeight++
	c.chainWork = new(big.Int).Add(c.chainWork, c.calcWork(header.Bits))
	c.ring = append(c.ring, recentHeader{
		hash: blockHash,
		time: headerTime,
		bits: header.Bits,
	})
	if len(c.ring) > ringWindow {
		c.ring = c.ring[len(c.ring)-ringWindow:]
	}

	return nil
}

// rollback drops all headers above the given height, undoing their chain
// work. Only heights still inside the ring window can be rolled back to.
func (c *headerChain) rollback(height int64) error {
	if height >= c.tipHeight {
		return fmt.Errorf("rollback height %d is not below tip %d",
			height, c.tipHeight)
	}

	drop := c.tipHeight - height
	if drop >= int64(len(c.ring)) {
		return fmt.Errorf("rollback to height %d exceeds the "+
			"in-memory header window", height)
	}

	for i := int64(0); i < drop; i++ {
		entry := c.ring[len(c.ring)-1]
		c.chainWork = new(big.Int).Sub(
			c.chainWork, c.calcWork(entry.bits),
		)
		c.ring = c.ring[:len(c.ring)-1]
	}
	c.tipHeight = height

	return nil
}

// reversedHash returns the big-endian (numeric) byte order of a hash.
func reversedHash(h chainhash.Hash) []byte {
	out := make([]byte, len(h))
	for i := 0; i < len(h); i++ {
		out[i] = h[len(h)-1-i]
	}
	return out
}

// exportState serializes the chain's compact resume state: tip, accumulated
// work and the recent-header ring (about 80 KiB).
func (c *headerChain) exportState() []byte {
	var buf bytes.Buffer
	buf.WriteByte(headerStateVersion)
	_ = binary.Write(&buf, binary.LittleEndian, uint32(c.params.Net))
	_ = binary.Write(&buf, binary.LittleEndian, c.tipHeight)

	work := c.chainWork.Bytes()
	buf.WriteByte(byte(len(work)))
	buf.Write(work)

	_ = binary.Write(&buf, binary.LittleEndian, uint32(len(c.ring)))
	for _, entry := range c.ring {
		buf.Write(entry.hash[:])
		_ = binary.Write(&buf, binary.LittleEndian, entry.time)
		_ = binary.Write(&buf, binary.LittleEndian, entry.bits)
	}

	return buf.Bytes()
}

// importState restores a chain from exportState output.
func (c *headerChain) importState(data []byte) error {
	r := bytes.NewReader(data)

	version, err := r.ReadByte()
	if err != nil || version != headerStateVersion {
		return fmt.Errorf("unsupported header state version")
	}

	var net uint32
	if err := binary.Read(r, binary.LittleEndian, &net); err != nil {
		return fmt.Errorf("invalid header state: %w", err)
	}
	if net != uint32(c.params.Net) {
		return fmt.Errorf("header state is for a different network")
	}

	if err := binary.Read(
		r, binary.LittleEndian, &c.tipHeight,
	); err != nil {
		return fmt.Errorf("invalid header state: %w", err)
	}

	workLen, err := r.ReadByte()
	if err != nil {
		return fmt.Errorf("invalid header state: %w", err)
	}
	work := make([]byte, workLen)
	if _, err := io.ReadFull(r, work); err != nil {
		return fmt.Errorf("invalid header state: %w", err)
	}
	c.chainWork = new(big.Int).SetBytes(work)

	var ringLen uint32
	if err := binary.Read(r, binary.LittleEndian, &ringLen); err != nil {
		return fmt.Errorf("invalid header state: %w", err)
	}
	if ringLen > ringWindow {
		return fmt.Errorf("invalid header state: ring too large")
	}

	c.ring = make([]recentHeader, ringLen)
	for i := range c.ring {
		if _, err := io.ReadFull(r, c.ring[i].hash[:]); err != nil {
			return fmt.Errorf("invalid header state: %w", err)
		}
		if err := binary.Read(
			r, binary.LittleEndian, &c.ring[i].time,
		); err != nil {
			return fmt.Errorf("invalid header state: %w", err)
		}
		if err := binary.Read(
			r, binary.LittleEndian, &c.ring[i].bits,
		); err != nil {
			return fmt.Errorf("invalid header state: %w", err)
		}
	}

	return nil
}
