#!/usr/bin/env bash

set -euo pipefail

HUGO_VERSION="${HUGO_VERSION:-0.163.3}"
TOOLS_DIR="${TOOLS_DIR:-.tools}"
HUGO_BIN="$TOOLS_DIR/hugo-$HUGO_VERSION/hugo"

if [[ -x "$HUGO_BIN" ]]; then
  printf '%s\n' "$HUGO_BIN"
  exit 0
fi

if command -v hugo >/dev/null 2>&1; then
  command -v hugo
  exit 0
fi

os="$(uname -s)"
arch="$(uname -m)"
tmpdir="$(mktemp -d)"
mkdir -p "$TOOLS_DIR/hugo-$HUGO_VERSION"

case "$os:$arch" in
Darwin:arm64 | Darwin:x86_64)
  pkg="$tmpdir/hugo.pkg"
  curl -sfL -o "$pkg" "https://github.com/gohugoio/hugo/releases/download/v${HUGO_VERSION}/hugo_extended_${HUGO_VERSION}_darwin-universal.pkg"
  pkgutil --expand-full "$pkg" "$tmpdir/pkg"
  cp "$tmpdir/pkg/Payload/hugo" "$HUGO_BIN"
  ;;
Linux:x86_64)
  archive="$tmpdir/hugo.tar.gz"
  curl -sfL -o "$archive" "https://github.com/gohugoio/hugo/releases/download/v${HUGO_VERSION}/hugo_extended_${HUGO_VERSION}_linux-amd64.tar.gz"
  tar -C "$TOOLS_DIR/hugo-$HUGO_VERSION" -xf "$archive" hugo
  ;;
Linux:aarch64 | Linux:arm64)
  archive="$tmpdir/hugo.tar.gz"
  curl -sfL -o "$archive" "https://github.com/gohugoio/hugo/releases/download/v${HUGO_VERSION}/hugo_extended_${HUGO_VERSION}_linux-arm64.tar.gz"
  tar -C "$TOOLS_DIR/hugo-$HUGO_VERSION" -xf "$archive" hugo
  ;;
*)
  echo "Unsupported platform: $os $arch" >&2
  exit 1
  ;;
esac

chmod +x "$HUGO_BIN"
printf '%s\n' "$HUGO_BIN"
