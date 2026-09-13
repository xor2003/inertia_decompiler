# MS C Runtime GP ABI

Checkpoint: 2026-09-12, approximately 02:11-02:24 +02:00, including investigation
and verification. Step 9 remains open.

## Root Cause And Ownership

Four failing MS C tiny cases compiled successfully but failed linking with
unresolved `inertia_esi` and `inertia_edi`. Preserved register state is now
observable in generated C, but the rebuild runtime supplied no GP storage.

A second defect existed in C89 preparation: extracting function bodies loses
their extern declarations, and generic missing-global handling could omit or
narrow the runtime lanes to `unsigned short`. Inspection of the rebuilt scalar
types and function-pointer sources proved the narrowing. Merely defining the
symbols was insufficient to preserve the ABI.

Lowering now exposes its existing authoritative GP symbol inventory through
`runtime_gp_state_symbols_8616`. The focused tooling module
`scripts/msc6_runtime_support.py` consumes it to provide matching C89 externs
and definitions for all eight lanes. MS C uses 32-bit `unsigned long` for them.
The known ABI declarations precede generic global preparation; there is no
new text-based semantic inference, function repair or instruction emulation.
Existing stack-probe support functions were preserved unchanged.

## Tests And Acceptance

- A regression drives the real runtime writer, then compiles, links and runs a
  separate C consumer of all eight registers. It failed before the definitions.
- A second regression drives actual C89 preparation and rejects missing or
  incompatible externs, including loss of a nonzero high word. It failed before
  the declaration provider. Both are enrolled in the runner and Make inventories.
- Focused tooling tests: 50 passed in 7.63s after both fixes.
- Fresh real MS C round trips: six pass; function_pointers still fails.
  Passing: compare16, simple_control, loops_jumps, storage_classes,
  pointer_memory and scalar_types_io. Compilation, linking, generated execution
  and the original/generated exit-code checks run through the existing pipeline.
- Fresh scalar-types output declares ESI/EDI as `unsigned long`, not short.
- Scoped MyPy passes for the runtime helper, build script and GP owner. The
  architecture check passed. Ruff ran with `--fix`; legacy findings remain in
  larger touched files. `quality-fast` remains red at linters; the 39-module
  mypyc import smoke passed. Its run predates the final header-provider change;
  focused tests, MyPy and the real external lane were rerun afterward.

DoD: generated consumers and runtime definitions agree with the authoritative
GP ABI; all eight symbols link; nonzero high bits survive; the four affected
round trips pass without changing generated function bodies. This is verified.
Failure: narrower/incompatible types, symbol-name special cases, defaulting
away live state, suppressed validation, or a lost required call/return.

## Remaining Blockers

`select_and_apply` emits `apply_twice(...)` but loses its returned value. The
source-contract gate reports `returned_call_missing` and the external lane
correctly stays red. Separately, the latest routine pytest result remains
4,337 passed / three SORTD failures; no full-suite refresh was made here.

Simple binary SI/DI save/restore reductions pass. A stack-probe reduction did
not activate helper recognition, so it does not yet explain the SORTD defect.
Continue tracing actual helper/frame coordinates rather than claiming a root
cause from that incomplete reduction.

Logs under `/home/xor/.cache/`: `msc6-gp-runtime-{before,focused,mypy,ruff,quality,architecture}.log`,
`msc6-gp-runtime-width-{before,after,pipeline}.log`, and
`msc6-gp-runtime-width-pipeline.json`. The final external run used warm caches;
its faster timing is not an optimization claim.
