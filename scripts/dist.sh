#!/bin/sh
# 七つ国
# 一つの札で
# 渡りけり
set -eu

version="${1:?usage: scripts/dist.sh v1.2.3}"
case "$version" in
  v[0-9]*.[0-9]*.[0-9]*) ;;
  *) echo "dist: version must look like v1.2.3 (got $version)" >&2; exit 2 ;;
esac

out="dist"
commit="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
date="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
pkg="github.com/Tchirek/blanc/internal/version"
ldflags="-s -w -X $pkg.Version=$version -X $pkg.Commit=$commit -X $pkg.Date=$date"
targets="linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64 android/arm64"

# 束ね紙
# 手近な具にて
# 綴じにけり
zipdir() {
  if command -v zip >/dev/null 2>&1; then
    (cd "$1" && zip -qr "$2.zip" "$2")
  else
    py="$(command -v python3 || command -v python)"
    (cd "$1" && "$py" -m zipfile -c "$2.zip" "$2")
  fi
}

rm -rf "$out"
mkdir -p "$out"
for target in $targets; do
  os="${target%/*}"
  arch="${target#*/}"
  name="blanc-$version-$os-$arch"
  ext=""
  [ "$os" = windows ] && ext=".exe"
  mkdir -p "$out/$name"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -ldflags "$ldflags" -o "$out/$name/blanc$ext" ./cmd/blanc
  cp LICENSE README.md "$out/$name/"
  cp examples/blanc.yaml "$out/$name/blanc.example.yaml"
  if [ "$os" = windows ]; then
    zipdir "$out" "$name"
  else
    tar -C "$out" -czf "$out/$name.tar.gz" "$name"
  fi
  rm -rf "${out:?}/$name"
  echo "dist: $name"
done

VERSION="$version" COMMIT="$commit" sh scripts/build-web.sh "$out/blanc-$version-web"
zipdir "$out" "blanc-$version-web"
mv "$out/blanc-$version-web" "$out/web"

(cd "$out" && sha256sum -- *.tar.gz *.zip > SHA256SUMS.txt)
cat "$out/SHA256SUMS.txt"
