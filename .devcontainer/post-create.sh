#!/usr/bin/env bash

set -euo pipefail

HUGO_VERSION="${HUGO_VERSION:-0.163.3}"
tmpdir="$(mktemp -d)"

curl -sfL -o "$tmpdir/hugo.tar.gz" \
  "https://github.com/gohugoio/hugo/releases/download/v${HUGO_VERSION}/hugo_extended_${HUGO_VERSION}_linux-amd64.tar.gz"
tar -C "$tmpdir" -xf "$tmpdir/hugo.tar.gz"
sudo install "$tmpdir/hugo" /usr/local/bin/hugo

hugo version
