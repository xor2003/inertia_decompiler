# DOS Unit SSA/Z3 Artifacts (egame CRT loop fixes)

Date: 2026-06-13

## Inputs

- Original: `/home/xor/tmp/f15se2-re/bin/egame.exe`
- Rebuilt: `/home/xor/tmp/f15se2-re/build/egame.exe`
- Function catalogs:
  - `/tmp/egame.original.crtloops.functions.json`
  - `/tmp/egame.rebuilt.crtloops.functions.json`
  - `/tmp/egame.crtloops.mapping.json`

## Produced artifacts

- SSA:
  - `/tmp/egame.original.crtloops.defaultfixed.ssa.json`
  - `/tmp/egame.rebuilt.crtloops.defaultfixed.ssa.json`
- Compare results:
  - `/tmp/egame.crtloops.defaultfixed.results.json`
- Failure report:
  - `/tmp/egame.crtloops.defaultfixed.failures.md`

## Key outcome

- `compare-ssa` now passes both previously failing CRT-loop functions after default-safe lowering:
  - `__aNldiv`: `passed`, `transition_system_equal`, `part_count: 17`, `branches: 15`
  - `__amexpand`: `passed`, `transition_system_equal`, `part_count: 13`, `branches: 11`
- Total from this subset compare: `30 passed`, `0 failed`, `0 refused`.
- The reported jump target ambiguity was fixed by displaying control targets as `ip (linear)` in disassembly output.

## What changed (high level)

- VEX low16 target constants are canonicalized to loaded-linear addresses for successor and branch extraction.
- SSA output now renders control target display as `ip (linear)` to avoid the “jump to next instruction” confusion.
- SSA default lowering was updated to:
  - `--max-blocks-per-function 64`
  - `--max-insns-per-function 64`
  - follow direct call fallthrough by default (opt-out via `--no-follow-call-fallthrough`)
- Region comparison now includes direct-cycle transition-system fallback for callable lowered blocks, using proven direct-successor deltas to normalize layout-shifted constants.
- Added/updated regression tests around target normalization and cyclic region equality in `tools/dosunit/tests/test_dosunit_tool.py`.

## Notes

- If you need the same behavior with old call-boundary SSA behavior, use `--no-follow-call-fallthrough`.
- The failure report for the same artifacts contains no failed/refused entries at the function/region level.
