# InitBars Coordinate Ownership Repair

## Reproduction And Root Cause

The sidecar-free InitBars regression at 0x10560 failed both in the routine
pipeline and in an isolated retry after the signed-remainder/SSA-authority
changes. Whole-tail validation found a call argument expected at machine
BP-0x70 but represented as BP-0x72, together with uninitialized reads.

An observational wrapper around final call-argument coordinate resolution
confirmed the transition without changing results:

1. The call-output object had a proven projection: BP-0x70, entry-SP-0x72,
   extent 22 bytes, backed by a one-byte angr carrier.
2. The projection disappeared before Structuring validation.
3. Its surviving C variable then resolved through its raw entry-SP offset,
   incorrectly treating it as machine BP-0x72.

`reset_local_stack_coordinate_projections_8616` cleared every negative-BP
entry when stack-memory SSA Lowering replayed. It erased a distinct
call-output object's evidence along with the entries it intended to refresh.
The focused regression reproduced that deletion: **1 failed in 10.28s**.

## Repair And Boundaries

The coordinate contract now carries `StackCoordinateProducer8616`.
Call-output object publication records its producer explicitly. Registry
aliasing, canonical binding, retention and restored-AST rebinding preserve
that producer. Local stack replay retains call-output projections while
continuing to clear ordinary local-storage projections. Positive argument
projections retain their existing protection.

The regression includes an ordinary scalar entry that must still be cleared,
so turning the reset into a no-op does not satisfy it. No BP offset is guessed,
no validator is relaxed, and no semantic repair is added to Rewrite or CLI.
Coordinate storage remains owned by Types/Lowering; validation consumes it.

The codebase graph transport was unavailable during this investigation;
evidence came from targeted current-source reads and the instrumented run.
No graph-completeness claim is made.

## Verification

- Original InitBars regression plus call-object/rebinding tests:
  **20 passed in 41.05s**, InitBars 31.78s. Its assertions require
  `validation=passed`, clean whole-tail validation, preserved binary stack
  array operations and required calls.
- Routine pipeline: **3,994 passed in 231.62s**, seven dependency warnings.
  All seven MS C compile/decompile/recompile/run examples passed. All three
  lanes passed; none failed, skipped or timed out.
- Full architecture check and scoped MyPy/Pyright passed.
- Touched call-output producer, rebinding helper and regression tests pass
  Ruff. The coordinate registry still has its existing complexity finding;
  global `quality-fast` remains red at Ruff. No suppressions were added.
- The full suite has not been rerun; do not infer its new totals by arithmetic.

Logs under `/home/xor/.cache/`: `inertia-initbars-isolated.log`,
`inertia-initbars-coordinate-probe.{c,log}`,
`inertia-call-coordinate-{before,after,mypy,pyright,architecture,quality-fast,pipeline}.log`.
Step 9 remains open after this repair.
