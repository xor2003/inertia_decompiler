#!/usr/bin/env bash
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
out=${1:-/home/xor/vextest/.cache/cup386/rebuild}
mkdir -p "$out"
out=$(cd "$out" && pwd)

uasm -Zm -c "-Fo=$out/CUP386.obj" "$here/CUP386.asm"
/home/xor/kvikdos/alink/alink -m -o "$out/CUP386-rebuilt.exe" "$out/CUP386.obj"

file "$out/CUP386-rebuilt.exe"
