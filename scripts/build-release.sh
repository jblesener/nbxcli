#!/usr/bin/env bash

set -euo pipefail

version="${1:?release version is required}"
if ! [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "release version must be a semantic version without a v prefix: $version" >&2
    exit 1
fi

mkdir -p dist
rm -f dist/*.tar.gz dist/*.zip dist/checksums.txt dist/nbxcli dist/nbxcli.exe

build_archive() {
  local goos="$1"
  local goarch="$2"
  local archive="$3"
  local extension=""
  local asset="nbxcli_${version}_${goos}_${goarch}"

  if [[ "$goos" == "windows" ]]; then
    extension=".exe"
  fi

  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" go build -trimpath -ldflags="-s -w" -o "dist/nbxcli${extension}" .

  if [[ "$archive" == "tar.gz" ]]; then
    tar -C dist -czf "dist/${asset}.tar.gz" nbxcli
  else
    zip -j "dist/${asset}.zip" "dist/nbxcli.exe"
  fi
}

build_archive linux amd64 tar.gz
build_archive linux arm64 tar.gz
build_archive darwin amd64 tar.gz
build_archive darwin arm64 tar.gz
build_archive windows amd64 zip
build_archive windows arm64 zip

(
  cd dist
  sha256sum *.tar.gz *.zip > checksums.txt
)
