#!/bin/bash
#
# Generates SHA256SUMS with the Go version and hashes of the WASM blob
# and Go runtime, then creates a detached PGP signature.

set -euo pipefail

cd "$(dirname "$0")/.."

SUMS_FILE="dist/SHA256SUMS"

{
  echo "# btcutil-js build checksums"
  echo "# $(go version)"
  echo "# $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
  echo "#"
  sha256sum dist/btcutil.wasm wasm-wrapper/wasm_exec.js \
    | sed 's|  dist/|  |; s|  wasm-wrapper/|  |'
} > "$SUMS_FILE"

echo "Created $SUMS_FILE"
cat "$SUMS_FILE"

gpg --yes --detach-sign --armor "$SUMS_FILE"
echo "Signed  $SUMS_FILE.asc"
