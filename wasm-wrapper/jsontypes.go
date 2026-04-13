//go:build js && wasm

package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------------------
// HexBytes: a []byte that marshals to/from a lowercase hex string in JSON.
// Empty/nil marshal to "" and "" unmarshals back to nil.
// ---------------------------------------------------------------------------

type HexBytes []byte

func (h HexBytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(hex.EncodeToString(h))
}

func (h *HexBytes) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	if s == "" {
		*h = nil
		return nil
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return fmt.Errorf("HexBytes: %w", err)
	}
	*h = b
	return nil
}

// ---------------------------------------------------------------------------
// HexUint32: a uint32 that marshals to an 8-char lowercase hex string (the
// canonical display form for BIP-32 master-key fingerprints). Unmarshals
// from either a hex string (optionally "0x"-prefixed) or a JSON number.
// ---------------------------------------------------------------------------

type HexUint32 uint32

func (h HexUint32) MarshalJSON() ([]byte, error) {
	return json.Marshal(fmt.Sprintf("%08x", uint32(h)))
}

func (h *HexUint32) UnmarshalJSON(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	// String form: "12345678" or "0x12345678".
	if data[0] == '"' {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		s = strings.TrimPrefix(strings.TrimSpace(s), "0x")
		if s == "" {
			*h = 0
			return nil
		}
		n, err := strconv.ParseUint(s, 16, 32)
		if err != nil {
			return fmt.Errorf("HexUint32: %w", err)
		}
		*h = HexUint32(n)
		return nil
	}
	// Numeric form.
	var n uint32
	if err := json.Unmarshal(data, &n); err != nil {
		return err
	}
	*h = HexUint32(n)
	return nil
}

// ---------------------------------------------------------------------------
// Bip32 path helpers: display form "m/84'/0'/0'/0/0" ↔ []uint32.
// ---------------------------------------------------------------------------

const bip32Hardened = 0x80000000

func formatBip32Path(arr []uint32) string {
	if len(arr) == 0 {
		return "m"
	}
	parts := []string{"m"}
	for _, n := range arr {
		if n >= bip32Hardened {
			parts = append(parts, fmt.Sprintf("%d'", n-bip32Hardened))
		} else {
			parts = append(parts, fmt.Sprintf("%d", n))
		}
	}
	return strings.Join(parts, "/")
}

func parseBip32Path(s string) ([]uint32, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "m" || s == "m/" {
		return nil, nil
	}
	parts := strings.Split(s, "/")
	if parts[0] == "m" {
		parts = parts[1:]
	}
	out := make([]uint32, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		hardened := false
		if strings.HasSuffix(p, "'") || strings.HasSuffix(p, "h") ||
			strings.HasSuffix(p, "H") {

			hardened = true
			p = p[:len(p)-1]
		}
		n, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("bip32 path component %q: %w", p, err)
		}
		v := uint32(n)
		if hardened {
			v += bip32Hardened
		}
		out = append(out, v)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Transaction types — split into encode-input (TxDataJSON) and decode-output
// (TxJSON, which embeds it and adds derived txid/wtxid).
// ---------------------------------------------------------------------------

// Non-numeric / non-boolean fields are tagged `omitempty` throughout so that
// absent optional data is represented by the absence of the key, not an
// empty string or empty array.

type TxInputJSON struct {
	Txid      string     `json:"txid,omitempty"`
	Vout      uint32     `json:"vout"`
	ScriptSig HexBytes   `json:"scriptSig,omitempty"`
	Sequence  uint32     `json:"sequence"`
	Witness   []HexBytes `json:"witness,omitempty"`
}

type TxOutputJSON struct {
	Value        int64    `json:"value"`
	ScriptPubKey HexBytes `json:"scriptPubKey,omitempty"`
}

// TxDataJSON is the encode-input shape: strictly the wire-level fields.
type TxDataJSON struct {
	Version  int32          `json:"version"`
	LockTime uint32         `json:"locktime"`
	Inputs   []TxInputJSON  `json:"inputs,omitempty"`
	Outputs  []TxOutputJSON `json:"outputs,omitempty"`
}

// TxJSON is the decode-output shape: everything in TxDataJSON plus the
// derived txid/wtxid. Ignored on encode.
type TxJSON struct {
	TxDataJSON
	Txid  string `json:"txid,omitempty"`
	Wtxid string `json:"wtxid,omitempty"`
}

// ---------------------------------------------------------------------------
// PSBT sub-types
// ---------------------------------------------------------------------------

// Bip32DerivationJSON mirrors btcpsbt.Bip32Derivation. On marshal, both
// the numeric Path and the display PathStr are emitted; on unmarshal, we
// prefer Path when non-empty and fall back to parsing PathStr.
type Bip32DerivationJSON struct {
	PubKey               HexBytes  `json:"pubKey,omitempty"`
	MasterKeyFingerprint HexUint32 `json:"masterKeyFingerprint"`
	Path                 []uint32  `json:"path,omitempty"`
	PathStr              string    `json:"pathStr,omitempty"`
}

func (b *Bip32DerivationJSON) effectivePath() []uint32 {
	if len(b.Path) > 0 {
		return b.Path
	}
	if b.PathStr != "" {
		p, err := parseBip32Path(b.PathStr)
		if err == nil {
			return p
		}
	}
	return nil
}

type TaprootScriptSpendSigJSON struct {
	XOnlyPubKey HexBytes `json:"xOnlyPubKey,omitempty"`
	LeafHash    HexBytes `json:"leafHash,omitempty"`
	Signature   HexBytes `json:"signature,omitempty"`
	SigHash     uint32   `json:"sigHash"`
}

type TaprootLeafScriptJSON struct {
	ControlBlock HexBytes `json:"controlBlock,omitempty"`
	Script       HexBytes `json:"script,omitempty"`
	LeafVersion  uint8    `json:"leafVersion"`
}

type TaprootBip32DerivationJSON struct {
	XOnlyPubKey          HexBytes   `json:"xOnlyPubKey,omitempty"`
	LeafHashes           []HexBytes `json:"leafHashes,omitempty"`
	MasterKeyFingerprint HexUint32  `json:"masterKeyFingerprint"`
	Path                 []uint32   `json:"path,omitempty"`
	PathStr              string     `json:"pathStr,omitempty"`
}

func (b *TaprootBip32DerivationJSON) effectivePath() []uint32 {
	if len(b.Path) > 0 {
		return b.Path
	}
	if b.PathStr != "" {
		p, err := parseBip32Path(b.PathStr)
		if err == nil {
			return p
		}
	}
	return nil
}

type PartialSigJSON struct {
	PubKey    HexBytes `json:"pubKey,omitempty"`
	Signature HexBytes `json:"signature,omitempty"`
}

type UnknownJSON struct {
	Key   HexBytes `json:"key,omitempty"`
	Value HexBytes `json:"value,omitempty"`
}

// XPubJSON mirrors btcpsbt.XPub. The ExtendedKey is exchanged as a base58
// xpub/xprv string (e.g. "xpub6CUGRUo..."), not raw bytes — that's the
// format users actually paste / read. Conversion to/from the 78-byte
// PSBT-wire representation happens in xpubsToJSON / xpubsFromJSON.
type XPubJSON struct {
	ExtendedKey          string    `json:"extendedKey,omitempty"`
	MasterKeyFingerprint HexUint32 `json:"masterKeyFingerprint"`
	Path                 []uint32  `json:"path,omitempty"`
	PathStr              string    `json:"pathStr,omitempty"`
}

func (x *XPubJSON) effectivePath() []uint32 {
	if len(x.Path) > 0 {
		return x.Path
	}
	if x.PathStr != "" {
		p, err := parseBip32Path(x.PathStr)
		if err == nil {
			return p
		}
	}
	return nil
}

// WitnessUtxoJSON is the paired {value, script} record for the PSBT
// PSBT_IN_WITNESS_UTXO field. Absent (nil pointer) when the PSBT input has
// no witness UTXO attached.
type WitnessUtxoJSON struct {
	Value  int64    `json:"value"`
	Script HexBytes `json:"script,omitempty"`
}

// PsbtInputJSON mirrors btcpsbt.PInput. Outpoint/sequence live on the
// embedded UnsignedTx.Inputs[i] — not duplicated here. Absent optional
// byte fields are omitted entirely.
type PsbtInputJSON struct {
	SighashType            *uint32                      `json:"sighashType,omitempty"`
	RedeemScript           HexBytes                     `json:"redeemScript,omitempty"`
	WitnessScript          HexBytes                     `json:"witnessScript,omitempty"`
	NonWitnessUtxo         HexBytes                     `json:"nonWitnessUtxo,omitempty"`
	WitnessUtxo            *WitnessUtxoJSON             `json:"witnessUtxo,omitempty"`
	PartialSigs            []PartialSigJSON             `json:"partialSigs,omitempty"`
	FinalScriptSig         HexBytes                     `json:"finalScriptSig,omitempty"`
	FinalScriptWitness     HexBytes                     `json:"finalScriptWitness,omitempty"`
	Bip32Derivation        []Bip32DerivationJSON        `json:"bip32Derivation,omitempty"`
	TaprootKeySpendSig     HexBytes                     `json:"taprootKeySpendSig,omitempty"`
	TaprootInternalKey     HexBytes                     `json:"taprootInternalKey,omitempty"`
	TaprootMerkleRoot      HexBytes                     `json:"taprootMerkleRoot,omitempty"`
	TaprootScriptSpendSigs []TaprootScriptSpendSigJSON  `json:"taprootScriptSpendSigs,omitempty"`
	TaprootLeafScripts     []TaprootLeafScriptJSON      `json:"taprootLeafScripts,omitempty"`
	TaprootBip32Derivation []TaprootBip32DerivationJSON `json:"taprootBip32Derivation,omitempty"`
	Unknowns               []UnknownJSON                `json:"unknowns,omitempty"`
}

// PsbtOutputJSON mirrors btcpsbt.POutput. Value/scriptPubKey live on the
// embedded UnsignedTx.Outputs[i] — not duplicated here.
type PsbtOutputJSON struct {
	RedeemScript           HexBytes                     `json:"redeemScript,omitempty"`
	WitnessScript          HexBytes                     `json:"witnessScript,omitempty"`
	Bip32Derivation        []Bip32DerivationJSON        `json:"bip32Derivation,omitempty"`
	TaprootInternalKey     HexBytes                     `json:"taprootInternalKey,omitempty"`
	TaprootTapTree         HexBytes                     `json:"taprootTapTree,omitempty"`
	TaprootBip32Derivation []TaprootBip32DerivationJSON `json:"taprootBip32Derivation,omitempty"`
	Unknowns               []UnknownJSON                `json:"unknowns,omitempty"`
}

// PsbtDataJSON is the encode-input shape: unsignedTx (as TxDataJSON, no
// derived txid), xpubs, unknowns, and the per-index PSBT input/output
// records.
type PsbtDataJSON struct {
	UnsignedTx TxDataJSON       `json:"unsignedTx"`
	XPubs      []XPubJSON       `json:"xpubs,omitempty"`
	Unknowns   []UnknownJSON    `json:"unknowns,omitempty"`
	Inputs     []PsbtInputJSON  `json:"inputs,omitempty"`
	Outputs    []PsbtOutputJSON `json:"outputs,omitempty"`
}

// PsbtJSON is the decode-output shape: PsbtDataJSON plus decode-time
// derived fields (fee, isComplete, and the unsignedTx with txid/wtxid).
type PsbtJSON struct {
	UnsignedTx TxJSON           `json:"unsignedTx"`
	XPubs      []XPubJSON       `json:"xpubs,omitempty"`
	Unknowns   []UnknownJSON    `json:"unknowns,omitempty"`
	Inputs     []PsbtInputJSON  `json:"inputs,omitempty"`
	Outputs    []PsbtOutputJSON `json:"outputs,omitempty"`
	IsComplete bool             `json:"isComplete"`
	Fee        int64            `json:"fee"`
}
