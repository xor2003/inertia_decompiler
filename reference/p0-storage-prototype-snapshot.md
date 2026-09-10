# Accepted Storage Prototype Snapshot Coherence

## Reason And Root Cause

The scalar_types_io example passed its MS C runtime check but emitted pointer
indirection warnings for pick_ptr. Missing caller evidence was a plausible
hypothesis, not the observed cause: fresh isolated diagnostics show the return
classifier proves pointer use from caller SSA, including spill/reload and a
segmented byte dereference. Collection closes all counters and publishes an
accepted contract. Prototype application installs `(void *, void *, word) ->
void *` on the current function and C AST.

However, the authoritative prototype registry retains the earlier integer
snapshot at CCA_DECOMPILER strength. Later annotated stack materialization
reads that stale snapshot and replaces the accepted pointer interface. A
CFunction.functy mutation trace identifies this exact overwrite in structuring
replay, pre-validation replay and final regeneration.

## Repair And Ownership

The existing Types/Lowering storage-prototype application transaction now also
publishes its materialized interface through the existing authoritative
snapshot owner. This happens after preflight and even when the current
function/AST types need no mutation. The existing snapshot precedence policy
is unchanged. No extra registry, type inference, sidecar requirement, CLI
signature repair or warning-suppressing harness cast was added.

## Evidence (2026-09-09)

- Two regressions fail before repair (8.00s): initial application and an
  already-applied interface with a stale replay snapshot.
- After repair, six snapshot/application tests pass (8.27s). Scoped Ruff
  --fix, MyPy and Pyright pass. Both regressions are in routine Make/pipeline
  lists.
- Fresh pick_ptr retains `void *` arguments and return through final output;
  decompilation exits 0 with validation=passed and clean whole-tail validation.
  No pointer-to-integer prototype overwrite is observed in that run.
- GCC -O0 and -O2 with -Wall -Wextra -Werror compile the generated function
  and both selector cases return the exact original input pointers (exit 0).
- quality-fast exits 0: 3,127 tests pass (150.01s), configured checks and all
  three executable quality guards pass. Log:
  `/tmp/inertia-storage-snapshot-quality-fast.log`.
- Default pipeline exits 0: 3,127 unit tests pass (132.04s; lane 132.465s),
  QuickC passes (45.045s), and MSC6 passes 7/7 (67.955s). Every original and
  recompiled exit code matches at 255. The previous pick_ptr indirection
  warnings are absent from scalar_types_io compiler output; no suppression
  flags or harness casts were added. Log:
  `/tmp/inertia-storage-snapshot-test-pipeline.log`. Mutable detailed reports:
  `angr_platforms/.cache/test_pipeline/summary.json` and
  `examples/build_msc6_tiny/report.json`.
- Logs: `/tmp/inertia-storage-snapshot-{before,after,mypy,pyright}.log`;
  `/tmp/inertia-pickptr-loss-probe.log`;
  `/tmp/inertia-storage-snapshot-pickptr.{c,log}`.

## Acceptance

DoD: accepted types remain coherent across function metadata, argument
variables, C AST and replay snapshot; initial and unchanged application are
covered; fresh pointer identity and validation pass; quality-fast and the
default MS C pipeline pass without the former pick_ptr indirection warnings.
Quality-fast and the default pipeline pass. This bounded coherence repair is
verified; the full SORTD plan and whole-repository test audit remain open.

Definition of Failure: recover pointer class from a source/function name,
repair rendered declarations, ignore stronger snapshot precedence, update only
some projections, suppress compiler warnings, or accept a partial caller census.
