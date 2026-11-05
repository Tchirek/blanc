#!/bin/sh
# 白き紙
# 窓に収めて
# 持ち出せり
set -eu

out="${1:-dist/web}"
version="${VERSION:-dev}"
commit="${COMMIT:-dev}"
pkg="github.com/Tchirek/blanc/internal/version"

mkdir -p "$out"
GOOS=js GOARCH=wasm CGO_ENABLED=0 go build -trimpath \
  -ldflags "-s -w -X $pkg.Version=$version -X $pkg.Commit=$commit" \
  -o "$out/blanc.wasm" ./cmd/blanc-web

root="$(go env GOROOT)"
if [ -f "$root/lib/wasm/wasm_exec.js" ]; then
  cp "$root/lib/wasm/wasm_exec.js" "$out/"
else
  cp "$root/misc/wasm/wasm_exec.js" "$out/"
fi
cp web/index.html "$out/"
echo "web: $out ($(wc -c < "$out/blanc.wasm") bytes wasm)"
