#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BINARY="${ROOT_DIR}/SORTDEMO.EXE"
LOG_DIR="${ROOT_DIR}/.tmp_sortdemo_60_sweep"
mkdir -p "$LOG_DIR"

TIMEOUT_SECONDS=60
MAX_OUTPUT_LINE=25

export INERTIA_ENABLE_TAIL_VALIDATION=1
export INERTIA_DISABLE_TIMING=1

entries=(
  0x10010:main
  0x10f38:Sleep
  0x109e8:PercolateUp
  0x10970:HeapSort
  0x107b8:Swaps
  0x10768:SwapBars
  0x10678:ReInitBars
  0x10e70:Beep
  0x10ce0:QuickSort
  0x10c18:ShellSort
  0x10b50:ExchangeSort
  0x10a88:PercolateDown
  0x108d0:BubbleSort
  0x10808:InsertionSort
  0x106c8:DrawBar
  0x10560:InitBars
  0x10498:DrawTime
  0x102e0:RunMenu
  0x101f0:DrawFrame
  0x10060:InitMenu
)

echo "function,addr,status,validation,tail"
failures=0
for entry in "${entries[@]}"; do
  addr="${entry%%:*}"
  name="${entry#*:}"
  log_file="${LOG_DIR}/${addr}.log"
  set +e
  nice -n 10 env PYTHON_JIT=1 "${ROOT_DIR}/.venv/bin/python" "${ROOT_DIR}/decompile.py" --brief --alternate-source-c --timeout "$TIMEOUT_SECONDS" --addr "$addr" "$BINARY" >"$log_file" 2>&1
  decompile_rc=$?
  set -e

  if rg -q "Decompilation timeout" "$log_file"; then
    status="timeout"
  elif rg -q "direct failure family" "$log_file"; then
    status="$(rg -o 'direct failure family: status=[a-z_]+' "$log_file" | sed 's/.*status=//' | head -n 1 || true)"
    status="${status:-failed}"
  elif rg -q "non-optimized fallback failed" "$log_file"; then
    status="fallback_failed"
  elif rg -q "whole-tail validation failed" "$log_file"; then
    status="tail_failed"
  else
    status="ok"
  fi
  if [[ "$decompile_rc" -ne 0 && "$status" == "ok" ]]; then
    status="failed"
  fi

  if rg -q "whole-tail validation failed" "$log_file"; then
    tail='failed'
  elif rg -q "whole-tail validation clean" "$log_file"; then
    tail='clean'
  elif rg -q "whole-tail validation uncollected" "$log_file"; then
    tail='uncollected'
  elif rg -q "whole-tail validation unknown" "$log_file"; then
    tail='unknown'
  elif rg -q "whole-tail validation missing" "$log_file"; then
    tail='missing'
  else
    tail='n/a'
  fi

  if rg -q "== asm fallback ==" "$log_file"; then
    validation='asm'
  elif rg -q "== lift break probe ==" "$log_file"; then
    validation='lift'
  elif rg -q "== c (non-optimized fallback) ==" "$log_file"; then
    validation='nonopt'
  elif rg -q "== c (partial timeout) ==" "$log_file"; then
    validation='partial'
  elif rg -q "== c ==" "$log_file"; then
    validation='ok'
  else
    validation='n/a'
  fi

  echo "${name},${addr},${status},${validation},${tail}"
  if [[ "$status" != "ok" || "$validation" != "ok" || "$tail" != "clean" ]]; then
    failures=1
  fi
done

exit "$failures"
