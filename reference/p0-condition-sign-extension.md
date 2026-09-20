# Condition Sign Extension

## Scope And Contract

Step 9 remains open. This slice corrects CBW/CWDE value provenance in the
frontend/IR boundary. The aggregate follow-up below now establishes focused
sidecar-free InsertionSort acceptance, not completion of Step 9.

Reason: the frontend executed signed extension correctly but its parallel
condition fact replaced a byte value with a word-sized value. That lost the
extension operation. CWDE additionally looked up EAX instead of its AX source.
The binary at `0x1085b` loads a byte, `0x1085f` sign-extends AL into AX, and
`0x10860` compares AX. Source names and addresses are diagnostic evidence only.

DoD: preserve the original storage and load width, express signed extension
using existing typed IR operations, prove byte and word boundaries including
chained conversions, and retain strict downstream validation and compilation.
Function acceptance additionally requires valid compiled C and preserved calls.

Definition of failure: relabeling a byte load as a word load, zero-extending
negative bytes, guessing from comparison signedness, repairing semantics in
Rewrite/CLI, or treating a clean tail verdict as sufficient when C fails to
compile.

## Implementation And Evidence

- IR now represents extension as `((source & mask) ^ sign_bit) - sign_bit`.
  This reuses typed binary values and preserves memory identity and width.
  Masking the source also preserves correctness for chained CBW/CWDE values.
- Six new regressions failed before the fix. Tests cover all 256 byte values,
  nonzero neighboring bytes, word sign boundaries, chained extensions, and
  refusal of unsupported width transitions.
- The existing transfer regression now expects the explicit conversion rather
  than a size-relabeled load. Its normalized-condition assertions remain.
- Final validation then exposed repeated masks in equivalent fingerprints.
  The existing IR fingerprint normalizer now consumes the exact identity
  `(x & m) & m == x & m`; it does not remove the surviving narrowing mask or
  cross conversions. Four controls failed before this change. Different masks,
  unknown constants, OR, and intervening casts remain distinct.
- Focused conversion/mask/transfer tests: 69 passed. The live InsertionSort
  regression still fails; combined run: 1 failed, 69 passed in 41.42s.
  Evidence: `/tmp/step9-extension-mask-after.log`. The whole tail is clean,
  but strict compilation rejects `value >> 8.field_0` in aggregate lowering.
- New IR helpers and focused new tests pass Ruff `check --fix`; both IR modules
  and the touched lifter pass scoped MyPy. The broader lifter/legacy-test Ruff
  run retains 81 findings; no global linter closure is claimed.
- Startup architecture and ownership checks passed before the final mask
  enrollment. Conversion and mask regressions are enrolled in both Make
  routine lists and `scripts/test_pipeline.py`.

## Aggregate Blocker (Now Resolved)

Investigate `lowering/segmented_global_loads.py`:
`_project_two_byte_aggregate_char_casts_8616` can project field zero from a
shift expression whose inherited type still looks like an aggregate. A
high-byte view must project the proven byte field from the original object,
not select a field from an arithmetic expression. Reproduce with an exact
typed aggregate fixture, retain refusal cases, and rerun the unchanged live
function regression. Do not loosen the compile gate.

The live test also contains an unsigned-byte guard formatting expectation;
do not bless that old expectation. Any replacement needs stronger compiled
behavior coverage of signed bar lengths and preserved call arguments.

Observed investigation began on 2026-09-18 and crossed into 2026-09-19.
Active engineering time was not separately measured. Times above are test
wall times, not completion estimates. Full Step 9 acceptance remains unproven.

### Follow-Up Evidence

The earlier blocker above is resolved by the focused Lowering helper
`aggregate_byte_projection.py`. It consumes authoritative two-byte layout
and selects the original object's field for exact integer shifts zero/eight.
Other arithmetic, floating constants, non-byte shifts, and casts refuse.
No semantic recovery was added to Rewrite or CLI.

The obsolete unsigned-guard formatting assertion was replaced with compiled
execution of unchanged generated C over 65,536 signed-byte pairs and 45
array-prefix scenarios. The oracle checks stable ordering, both object bytes,
array state at each call, call order/arguments, wrapping counters, and SI/DI.
Seven deliberately corrupted, compile-valid functions are rejected.

Focused tests: 101 passed in 12.44s. Projection code and new tests pass Ruff;
scoped MyPy passes. The subsequent inventory evidence-helper extraction is
covered by the passing routine pipeline. Legacy lowering/live-test Ruff has
219 findings.
The fresh whole-file gate accepts 17/20 functions, with zero timeouts, empty
functions, or tracebacks. BubbleSort (0x108d0), PercolateDown (0x10a88), and
ShellSort (0x10c18) still fail validation; raw flag-state artifacts also remain.
Evidence: `/tmp/step9-aggregate-whole.json`,
`/tmp/step9-aggregate-final-focused2.log`, `/tmp/step9-insertion-oracle.log`.

## Gate Refresh

Before the aggregate follow-up, `make test-pipeline PYTHON=./.venv/bin/python` passed
all three stages: 5,494 routine tests in 268.95s, four QuickC fixtures in
41.961s, and all seven MS C tiny compile/decompile/recompile/execute cases in
92.413s. The prerequisite stage passed 268 tests in 10.77s. Evidence is
`/tmp/step9-extension-pipeline.log` and
`angr_platforms/.cache/test_pipeline/summary.json`. This is not the expanded
pipeline or exact complete collection.

`make quality-fast` failed in its linter stage: 6,238 Ruff findings and 586
Lizard warnings remain. Later quality-fast prerequisites did not run.
Evidence: `/tmp/step9-extension-quality-fast.log`. `git diff --check` passes.
The IR/SSA and recovery cache source manifests already include all IR modules,
including the new extension helper; no invalidation exemption was introduced.

### Post-Aggregate Gate Refresh

`make test-pipeline PYTHON=./.venv/bin/python` exits zero: 268 prerequisite
tests in 7.63s, 5,524 routine tests in 274.25s, QuickC stage in 37.058s, and
all seven MS C tiny round trips in 92.380s. All three selected stages pass.
The routine stage is over its configured 30-second advisory budget; passing
correctness does not establish performance acceptance. Evidence:
`/tmp/step9-aggregate-pipeline.log` and the pipeline summary JSON.

`make quality-fast` exits two in the linter stage. The log still contains
4,177 magic-value, 1,864 complexity, and 194 Boolean-complexity findings,
among other legacy diagnostics. Compiled import smoke passes for 39 modules.
Evidence: `/tmp/step9-aggregate-quality-fast.log`. `git diff --check` passes.
Exact full collection, expanded pipeline, and hard quality closure remain open.
