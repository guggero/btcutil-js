//go:build js && wasm

package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
	"syscall/js"

	"github.com/btcsuite/btcd/btcutil"
	btcpsbt "github.com/btcsuite/btcd/btcutil/psbt"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
)

// networkParams maps network name strings to their chaincfg.Params.
var networkParams = map[string]*chaincfg.Params{
	"mainnet":  &chaincfg.MainNetParams,
	"testnet":  &chaincfg.TestNet3Params,
	"testnet3": &chaincfg.TestNet3Params,
	"testnet4": &chaincfg.TestNet4Params,
	"signet":   &chaincfg.SigNetParams,
	"regtest":  &chaincfg.RegressionNetParams,
	"simnet":   &chaincfg.SimNetParams,
}

// amountUnits maps unit name strings to btcutil.AmountUnit values.
var amountUnits = map[string]btcutil.AmountUnit{
	"BTC":     btcutil.AmountBTC,
	"mBTC":    btcutil.AmountMilliBTC,
	"uBTC":    btcutil.AmountMicroBTC,
	"satoshi": btcutil.AmountSatoshi,
	"sat":     btcutil.AmountSatoshi,
}

func errResult(msg string) map[string]any {
	return map[string]any{"error": msg}
}

func errfResult(format string, args ...any) map[string]any {
	return map[string]any{"error": fmt.Sprintf(format, args...)}
}

func okResult(v any) map[string]any {
	return map[string]any{"result": v}
}

func hexDecode(s string) ([]byte, map[string]any) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, errfResult("invalid hex: %s", err)
	}
	return b, nil
}

func getNetwork(name string) (*chaincfg.Params, map[string]any) {
	p, ok := networkParams[name]
	if !ok {
		return nil, errfResult("unknown network: %s", name)
	}
	return p, nil
}

func optString(args []js.Value, i int, def string) string {
	if len(args) > i && args[i].Type() == js.TypeString {
		return args[i].String()
	}
	return def
}

func optBool(args []js.Value, i int, def bool) bool {
	if len(args) > i && args[i].Type() == js.TypeBoolean {
		return args[i].Bool()
	}
	return def
}

func checkArgs(args []js.Value, n int, names string) map[string]any {
	if len(args) < n {
		return errfResult(
			"expected at least %d argument(s): %s", n, names,
		)
	}
	return nil
}

func deserializeTx(hexStr string) (*wire.MsgTx, map[string]any) {
	raw, e := hexDecode(hexStr)
	if e != nil {
		return nil, e
	}
	msgTx := wire.NewMsgTx(wire.TxVersion)
	if err := msgTx.Deserialize(bytes.NewReader(raw)); err != nil {
		return nil, errfResult("failed to parse transaction: %s", err)
	}
	return msgTx, nil
}

func serializeTx(msgTx *wire.MsgTx) string {
	var buf bytes.Buffer
	_ = msgTx.Serialize(&buf)
	return hex.EncodeToString(buf.Bytes())
}

func parsePsbt(b64 string) (*btcpsbt.Packet, map[string]any) {
	p, err := btcpsbt.NewFromRawBytes(
		strings.NewReader(b64), true,
	)
	if err != nil {
		return nil, errfResult("failed to parse PSBT: %s", err)
	}
	return p, nil
}
