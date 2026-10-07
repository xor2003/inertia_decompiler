# Compiler Coverage Matrix

Frozen finite coverage plan for `reference/compiler-coverage-plan.md`.
Data file: `examples/compiler_coverage/coverage-matrix.json` (`coverage-matrix-1`).
This is planning data, not proof of completion: every round trip is
`not_attempted` and every emitted mechanism is `unverified` unless a receipt
is named.

## How to read it

- `sources[]` — the finite pilot set (36). `state`: `existing` (file read and
  hashed), `planned_not_implemented` (proposal only; path must not exist),
  `generated_retained` (Csmith seed 2, pinned SHA-256). `kind` separates
  `runtime_case`, `compile_probe`, `generated_case`; `oracle` records the
  declared success contract (`exit_code_255`, `exit_code_0`,
  `compile_time_assert`). `compile_run_evidence` is original-compiler
  compile/link/run receipt only — never decompiler roundtrip evidence.
- `cells[]` — required matrix entries. `axis` separates `source_feature`,
  `emitted_pattern`, `configuration`, `boundary`. `covers` lists the obligation
  IDs the cell owns (each admitted obligation belongs to exactly one cell).
  Every cell names a `witness` source, `profiles`, `desired_emitted` mechanism
  and a `corruption_control`.
- `profiles[]` — selected compiler/model configurations, IDs aligned with the
  adapter registry `examples/compiler_coverage/toolchains.json`.
  `msc51-small`, `msc51-large`, `bc31-small`, `bc31-large` are `verified`
  (registry + receipt `.cache/compiler-coverage/toolchain-probes-20261006/`);
  `*-opt` and `*-probe` remain `unverified`/`proposed_pending_probe`;
  `wtc11-*` are `phase_not_started`.
- `phases[]` — `ms_borland_corpus` (planning) then `watcom_11b_same_corpus`
  (`not_started`, applies to the same admitted corpus; not excluded).
- `deferred` — `later` (inventory, no witness this pilot), `excluded`
  (reasons recorded), `undecided` (target-defined, probe-bound where named).
- `negative_controls` — corruption must be detected as **deviation from the
  declared oracle** (255 pass / 1..N deliberate failure; Csmith 0), not a bare
  nonzero exit.

## Exact totals (recomputed by the private checker)

| Measure | Count |
| --- | --- |
| Sources | 36 = 16 existing + 19 planned + 1 generated |
| Runtime sources / compile probes | 32 / 4 |
| Cells | 40 (39 admitted, 1 undecided: `types.plain_char`) |
| Obligations | 202 = 138 covered / 48 later / 8 excluded / 8 undecided |
| MS+Borland case pairs | 78 (64 small + 8 large subset + 6 opt subset) |
| Watcom pairs | 40, all `not_started` |
| First batch | 16 = baseline 8 + directed 6 + csmith 2 |

## First batch (16 cases, all `not_attempted`)

`word_comparisons`=compare16.c, `array_pointer_writes`=pointer_memory.c,
`branches_loops`=simple_control.c, `call_composition`=function_pointers.c,
`struct_value_abi`/`bitfield_neighbors`/`multidim_alias`=
examples/compiler_coverage/*.c, `csmith_seed2`=pinned generator output.
Each × `msc51-small` + `bc31-small`.

## What remains

- All 16 first-batch round trips attempted under the verified profiles.
- 19 planned sources implemented (paths are recorded, files intentionally
  absent), including `library_call_boundary` (blocked on the runtime
  signature boundary) and Csmith runtime-signature resolution.
- `emitted.switch_jump_table` requires observed table emission — a switch in
  source never counts.
- Optimization probes (`msc51-small-opt`, `bc31-small-opt`), the compile
  probes for char signedness/bitfield/aggregate layout, and the full Watcom
  11.0b same-corpus phase.

## Checks

`.cache/compiler-coverage/matrix-20261006/check_matrix.py` verifies: JSON
validity, path/hash links, ID uniqueness, obligation partition, family
coverage, both primary lanes per runtime source, Watcom `not_started`
representation, and all denominators. Last run: all checks passed
(`.cache/compiler-coverage/matrix-20261006/check-output.txt`).
