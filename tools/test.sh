#!/usr/bin/env bash

set -euo pipefail

cd "$(dirname "$0")/.."

rm -rf public
hugo_bin="$(bash tools/hugo-bin.sh)"
"$hugo_bin" --gc --minify
