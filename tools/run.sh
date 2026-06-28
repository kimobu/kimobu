#!/usr/bin/env bash

set -euo pipefail

cd "$(dirname "$0")/.."

host="127.0.0.1"
port="1313"

help() {
  echo "Usage:"
  echo
  echo "   bash tools/run.sh [options]"
  echo
  echo "Options:"
  echo "     -H, --host [HOST]    Host to bind to. Default: 127.0.0.1"
  echo "     -p, --port [PORT]    Port to bind to. Default: 1313"
  echo "     -h, --help           Print this help information."
}

while (($#)); do
  opt="$1"
  case $opt in
  -H | --host)
    host="$2"
    shift 2
    ;;
  -p | --port)
    port="$2"
    shift 2
    ;;
  -h | --help)
    help
    exit 0
    ;;
  *)
    echo "> Unknown option: '$opt'"
    echo
    help
    exit 1
    ;;
  esac
done

hugo_bin="$(bash tools/hugo-bin.sh)"
rm -rf public
"$hugo_bin" server --bind "$host" --port "$port" --buildDrafts
