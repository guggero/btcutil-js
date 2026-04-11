#!/bin/bash

set -euo pipefail

cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" .

cd wasm-wrapper
GOOS=js GOARCH=wasm go build \
  -ldflags="-s -w -buildid=" \
  -trimpath \
  -buildvcs=false \
  -o btcutil.wasm .
