# DCE Declaration Retirement

Checkpoint: 2026-09-12, approximately 01:54-02:10 +02:00, including gates.
Step 9 is still open. This checkpoint closes the two focused LES compilation
failures, not the whole runtime-preservation candidate.

## Proven Causes

- Control-slot classification compared native entry-SP offsets with a machine-BP
  range. The prior Types/Lowering fix consumes the coordinate owner instead.
  Three before-fix regressions demonstrated wrongly retained control storage
  and wrongly removed projected locals/arguments; six projected controls pass.
- Runtime tracing proved that the control-slot cleanup correctly retained live
  BP-save declarations. Later DCE removed their assignments without recording
  declaration retirement on several deletion paths.
- The old DCE declaration cleanup also removed by name and did not resolve the
  CVariables inside unified declaration entries. A dead `local_1` could collide
  with live storage using the same name. The regression failed before repair.

## Repair And Ownership

DCE now records keys on frame-anchor, proven non-temporary and general temporary
deletion paths. Declaration cleanup consumes those keys only after excluding
all surviving AST references and argument keys. Reads and writes both retain
declarations. Unified entries are checked through their CVariable keys; malformed
entries are retained. No declarations are removed merely because names match.

The focused consumer lives in Rewrite's existing `local_declarations.py`.
It performs declaration cleanup only: no new storage identity, semantic
recovery, call repair or text rewriting. The larger DCE owner shrank by extracting
its map cleanup. The live-segment LES harness now supplies ES runtime state and
checks its preservation, like the existing word-return harness.

## Acceptance Evidence

- Before: declaration regression failed after DCE removed the assignment but
  left its declaration; both LES functions failed generated-C compilation.
- After: 50 focused tests passed in 26.74s, including both compiled LES functions,
  `__fimemset`, same-name live-storage retention and malformed-entry refusal.
- Both LES variants independently passed final semantic and def-use validation.
- Routine run: 268 early contracts passed; 4,337 pytest tests passed and three
  failed in 266.82s. Remaining failures: SORTD InitBars, RunMenu and InitMenu.
- MS C tiny examples: compare16 and loops_jumps passed; simple_control,
  storage_classes, function_pointers, pointer_memory and scalar_types_io failed.
- Scoped MyPy passed for all three changed non-test modules. Ruff was run with
  `--fix`; existing DCE/duplicate-declaration complexity debt remains.
- `quality-fast` is red at linters; the 39-module mypyc import smoke passed.
- Declaration tests are now in the runner and both Make inventories. The
  architecture check passed. Enrollment and stricter malformed-entry arity were
  followed by the 50-test run; the broad run predates those final small changes.

DoD for this repair: preserve live declarations with colliding names, remove
declarations of proven dead assignments, retain unknown entries, compile and
execute both LES variants, and pass their final semantic validation. These
focused obligations pass. Failure means deleting any referenced declaration,
inventing storage identity, bypassing validation, or losing register preservation.

## Remaining Work

Repair SORTD save/restore coherence: current output can restore runtime registers
from uninitialized locals. Close all five failing external round trips, then
repeat routine/expanded pipelines and the full-suite/quality acceptance audit.
The earlier manual control-slot probe also exposed duplicate declaration-key
accounting; that observation is not silently claimed fixed here.

Evidence logs under `/home/xor/.cache/`: `fim-dce-declarations-`
`{before,after,focused,mypy,ruff,pipeline,architecture,quality}.log`,
`fim-dce-enrolled-focused.log`, `fim-les-final-validation.log`,
`fim-les-declaration-timing.log`, and `fim-les-control-removal-owner.log`.
