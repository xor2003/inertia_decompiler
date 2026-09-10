# Stack Execution Width Selection

## Root Cause (2026-09-09)

The instruction-index selector preferred a same-base logical word owner over
an available exact byte execution slice. Lowering then passed the selected
word size to its materializer, widening a byte write into a word write.
Logical storage ownership and execution access width are separate contracts.

The selector now prefers exact execution evidence before a wider same-base
logical owner. Exact logical matches still win. Logical owners remain in the
index and the existing consumer derives owner hints from that inventory.
This is a Types/Lowering projection fix, not new Alias evidence or text cleanup.

## Regression And Verification

- Before: the low-byte case selects size 2 instead of 1; one failed and one
  passed (8.41s). The high-byte case already selected its exact execution slice.
- After: 80 focused tests pass (19.69s), including compiled low/high byte writes
  preserving the untouched byte of an initialized word. The old same-base
  selector test now requires execution size 1; ownership inventory tests remain.
- Scoped Ruff `check --fix`, MyPy and Pyright pass. The new regression module
  is included in routine Make pytest/Ruff and the default test pipeline.
- Fresh isolated byteops still retains EBP, but exits 0 with validation=passed
  and clean whole-tail validation. This is not a complete byteops repair.
- The native anchor-provenance experiment still fails four smoke tests even
  after the frame and width fixes. It stays diagnostic-only, outside the repo.
- Logs: `/tmp/inertia-execution-byte-selection-{before,after,mypy,pyright}.log`;
  byteops: `/tmp/inertia-execution-byte-selection-byteops.{c,log}`;
  rejected combined experiment: `/tmp/inertia-anchor-provenance-exact-width.log`.

## Acceptance

Reason: a storage owner cannot authorize changing the bytes an operation writes.
DoD: exact width/kind and logical-owner tests pass, compiled byte writes preserve
other lanes, tail validation stays clean, quality-fast and default pipeline pass.
`quality-fast` exits 0 with 3,092 passed, seven warnings (161.48s), configured
checks and three executable guards. Log:
`/tmp/inertia-execution-byte-selection-quality-fast.log`.
Default pipeline exits 2: unit 3,092 passed (148.86s); QuickC passes (131.706s);
MSC6 5/7 (118.828s), with unchanged scalar_types_io C2065 for inertia_ebp and
function_pointers L2029 for ESP/EBP. Log:
`/tmp/inertia-execution-byte-selection-test-pipeline.log`.
An unrelated masm2c graph indexer consumed roughly five CPU cores during the
compiler lanes; this is not a controlled performance comparison.
The two MSC6 rebuild failures remain open. Do not claim full acceptance.

## Next Identity Investigation

In the disabled native-anchor experiment, shaped address matching now reports
the correct saved-frame offsets 0/1 and local offsets -2/-1. Selection still
ends with saved-BP expressions using a local word in the rejected C surface.
Tracing a local_1 rename shows a native offset -3 variable renamed by
`reapply_stack_variable_projection_names_8616`; names alone do not prove the
underlying alias transition. The presumed new-slot registry-delta path was
not called: the materializer reused an existing variable first. Do not patch
that unexecuted path as the demonstrated cause.

Next bounded action: trace the existing-variable selection, exact object
identity, and coordinate registry before/after materialization and projection
name rebinding. Reason: prevent a saved-frame carrier from sharing local storage.
DoD: a failing identity regression identifies the first incorrect binding;
the repair preserves smoke tests, tail validation and compiled behavior.
Failure: infer alias identity from generated names, enable the rejected anchor
experiment, or change a projector that the reproducer does not execute.
Evidence: `/tmp/inertia-anchor-{rename,registry-delta}-probe.log`.
Failure: widening an execution slice, discarding logical ownership, using load
evidence for a store, or hiding validation/recompilation failures.
