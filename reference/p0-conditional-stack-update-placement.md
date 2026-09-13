# Conditional Stack Update Placement

## Accepted Function Checkpoint: 2026-09-12 18:31 +02:00

`goto_accumulate` now uses the generic body-preserving path. Structuring's
`instruction_fragment_placement.py` restores the iterator fragment to the
unique conditional instruction suffix before Lowering merges its storage.
The proof requires exact instruction/block/VEX-statement provenance, ordered
contiguous statements and typed-condition identity. Exactly one branch edge
must reach the fragment block before the next loop/condition evaluation;
missing CFG data and ambiguous joins refuse. The pass moves the existing
statement object, synthesizes no values and deletes no statements. The
Lowering scope guard remains active for unproven cases.

The 240-line accumulator whole-body callback, compatibility wrapper, bootstrap
slot, pass registrations and dead inventory/policy entries are removed.
Rollback/continuation coverage was retained using the remaining global-byte
operation; tests were not discarded just because the callback disappeared.

Normal CLI, without diagnostic hooks, exits zero with `validation=passed` and
clean whole-tail validation. Its generated C passes strict GCC/UBSan compilation
and the independent conditional-accumulation oracle, including SI/DI
preservation. The real MS C `loops_jumps` fixture builds, runs, decompiles,
recompiles and runs with matching original/rebuilt exit code 255. Both
`nested_loops` and `goto_accumulate` report clean final tail validation.

Verification:

- 475 focused tests passed in 14.07s, including placement/refusal/idempotence,
  scope guards, behavioral controls, dispatch and tail-validation rollback.
- Scoped MyPy, new-owner Ruff, and full architecture checks pass.
- `quality-fast` remains red on global lint debt; the 39-module compiled-import
  smoke passes. Legacy files retain their reported findings.
- Default pipeline: preliminary 268 tests pass; curated lane 4,707 passed,
  the same 3 SORTD failures, in 302.08s. QuickC passes. MS C is now 7/7.
- Lane walls: curated 302.61s, QuickC 43.71s, MS C 102.58s. Cache state is warm;
  these are acceptance timings, not controlled performance measurements.
- Full collection and expanded lane were not refreshed. Step 9 is not complete.

Remaining: fix the three SORTD failures, preserve clear worker propagation of
hard layer errors, and audit validation baselines so pre-baseline semantic
loss cannot look like equivalence. Restoration currently refuses unsupported
or ambiguous shapes rather than guessing placement.

Temporary evidence: `goto-accumulate-normal.c/.log`,
`goto-retirement-focused.log`, `goto-retirement-quality.log`,
`goto-retirement-architecture.log`, and `goto-retirement-pipeline.log` under
`/home/xor/.cache`. The earlier diagnostic unhoisting experiment was not landed;
production logic contains no fixture-specific addresses or names.

## Guard Checkpoint: 2026-09-12 18:08 +02:00

Lowering now checks for instruction fragments shared between a conditional
body and a `for` iterator before tagged replacement and duplicate removal.
`stack_update_scope_guard.py` raises `PipelineHardError` with a typed conflict
record before invoking the replacement factory. It does not select a new
execution site and does not claim the function is repaired.

The two fail-first tests reached the replacement factory before the guard;
afterward both conditional and else-arm conflicts fail before mutation.
Unrelated instructions and unconditional bodies are non-conflicting controls.
The oracle tests plus the segmented-runtime lowering module give 253 passed,
7 dependency warnings, in 11.15 seconds under `pytest -n 7`. Scoped MyPy and
Ruff pass for the new guard; Ruff on the legacy materializer still reports
243 existing findings with no automatic fixes. New coverage is enrolled in
Make, the default pipeline and the ownership manifest.

The fresh diagnostic worker now reports `validation_failed`, not `ok`.
In-worker tracing confirms the intended error at rebased instruction 0x1034.
However, the worker result loses the specific exception explanation; it reports
an unset failure stage and no tail-validation details. Clear error propagation
is therefore still incomplete. Do not count refusal as completed decompilation.
Full pipeline and full collection have not been rerun for this guard checkpoint.

Next: prove and materialize the correct structured execution site, then carry
the structured error details through worker reporting and audit priming's
validation baseline. Broad acceptance remains required after the actual fix.

## Checkpoint: 2026-09-12 18:01 +02:00

Step 9 remains open. No production correction is claimed by this checkpoint.
The accumulator whole-body callback is still present; do not retire it until
the generic body preserves conditional execution and saved registers.

## Reproduced Failure

The isolated generic `goto_accumulate` worker returns status `ok`, but its C
fails an independent compiled behavior oracle: input 2 returns 7, expected 5.
The earlier input 4 result was 18, expected 14. Both detect the same unconditional
extra addition. GCC strict warnings and UBSan compilation succeed, so this is
an execution mismatch, not a compiler rejection.

The diagnostic disables only the legacy whole-body accumulator callback and
uses a fresh private cache. It is not evidence that the normal CLI is fixed.

## Exact Mutation

Observed before Inertia priming: angr has placed the high-byte fragment of a
word update in the `for` iterator, while the low-byte fragment remains inside
the conditional body. The iterator's temporaries are populated in that body.

`lowering/real_mode_linear.py::_replace_tagged_assignment_8616` visits
`iterator` before `body`. For the update at diagnostic rebased address 4148,
it replaces the high-byte fragment with the full word `+= 2`. Its duplicate
removal then removes the guarded low-byte store and its same-instruction
temporary assignments. The resulting full-word update executes unconditionally.
Instruction identity is not sufficient proof of interchangeable execution scope.

The graph is stale (generation 2026-08-27); direct current-source reads and
in-worker before/after observations establish this finding. No source addresses
or function names should become production recovery conditions.

## Durable Oracle

`test_x86_16_goto_accumulate_behavior.py` checks signed termination, alternating
branch effects, 16-bit return wrapping and SI/DI preservation. Expected return
bits use an independent arithmetic formula, not the decompiler's loop shape.
Dense small inputs and spaced adjacent large inputs cover both branch edges
without an expensive exhaustive quadratic workload.

Reference plus four deliberately corrupt controls: 5 passed in 1.01 seconds
under `pytest -n 7`. The freshly generated generic output independently fails
this same oracle at input 2. Ruff `check --fix` passes for the new test and
edited pipeline script. The oracle self-tests are enrolled in both Make test
lists and the default pipeline; they do not themselves run the decompiler.
Generated-output acceptance must explicitly invoke the oracle until integration
with the fixture roundtrip is completed.

## Next Proof Obligations

1. Preserve control-flow ownership when materializing a logical word update
   from byte fragments. Prefer coherent storage before structuring where the
   existing architecture permits it; do not change the frontend's required
   independently resolved segmented byte accesses.
2. Add a fail-first layer test for fragments split between conditional body
   and iterator. Ambiguous scope must refuse, never silently widen execution.
3. Require typed CFG/alias evidence for the selected execution site. Merely
   visiting the body first is not a general proof and can leave stale fragments.
4. Require normal CLI validation, the native oracle and the real MS C
   `loops_jumps` roundtrip before removing the whole-body callback.
5. Audit why tail validation accepted the observed change; output compilation
   and instruction-presence checks are insufficient to prove path equivalence.

Definition of done: conditional effects and saved registers survive without
whole-body substitution, normal validation passes, and emitted C matches the
independent oracle and MS C roundtrip. Definition of failure: any silent scope
widening, false validation success, lost fragment effect, or guessed placement.

Temporary evidence: `/home/xor/.cache/goto-accumulate-placement.log` and
`goto-accumulate-placement-worker.json`. Temporary diagnostics are not committed.
