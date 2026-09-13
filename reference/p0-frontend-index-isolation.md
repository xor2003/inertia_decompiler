# Frontend Index Provenance Isolation

## Cause

The curated two-INC condition regression failed with `ne` instead of the
expected JCC-bound `nonzero`. Its 21-test file passed both independently and
with all tests scheduled sequentially in one worker. Seeding the shared
index-register state with an earlier AX stack value reproduced the failure.
This was a real cross-lift provenance leak, not merely a formatting assertion.

`Instruction_ANY._arithmetic_result_value_from_semantics_8616` can consume
index provenance when no exact block-local value exists. That index map is
keyed by register, not by block. Block-entry reset previously ran only through
the optimized lifting path and did not clear this map. An initial full-path
INC could therefore import another block's AX value into its new condition.

## Fix And Contract

Layer: Frontend. The common instruction-lift boundary now performs block-entry
reset before dispatching either optimized or full semantics. On entry it
clears unproven index provenance and the existing current-block value state.
Within-block evidence remains available to later instructions. Explicit
affine snapshots remain governed by their separate existing mechanism.
Segmented byte-safe access methods were not changed.

Reason: identical code must not acquire operands from a previous independent
lift or test. Test-order changes must not change recovered branch meaning.

DoD: seeded INC and DEC chains refuse stale stack operands; same-block value
and indexed-condition recovery remain green; default decompilation and
external roundtrip lanes show no new failures.

Definition of failure: fixing only pytest fixtures, accepting stale operands,
discarding valid evidence inside a block, or weakening condition validation.

## Evidence

Checkpoint: 2026-09-12 20:16 +02:00. The preceding checkpoint was at 20:00;
engineering and gate-wait time were not measured separately.

- Seeded INC/DEC regressions: 2 failures before the production fix, 6.48s.
- Related provenance/condition/capture surface: 138 passed, 11.97s, `-n 7`.
- Scoped MyPy and full architecture pass.
- Ruff `--fix` was run; the large lifter retains 74 reported findings across
  the checked source/test surface. Global quality-fast remains red. No lint
  exclusions or type/doc removals were added.
- Default preliminary gate: 268 passes. Curated lane: 4,727 passed / 1 failed
  in 267.80s. RunMenu remains failing; InitMenu and the two-INC regression pass.
- QuickC passes in 41.96s; MS C tiny 7/7 roundtrips pass in 90.37s.
- Full collection and expanded acceptance are not refreshed.

The new regression is in the already-enrolled simple-INC/DEC provenance test
file. All sessions are terminal. Logs are under `/home/xor/.cache/` with
prefixes `frontend-condition-` (isolation and seeded reproduction) and
`frontend-index-` (before/after, Ruff, MyPy, architecture, quality, pipeline).

Step 9 remains open for RunMenu, global quality and complete acceptance.
