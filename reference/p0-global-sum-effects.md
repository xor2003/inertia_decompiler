# Global Sum Reconstruction Effects

## Status And Timing

Step 9 is open. This checkpoint improves failure detection; it does not fix
`_sum_globals` or restore the `storage_classes` round trip.

First timed probe: 2026-09-12 09:09:37 +02:00. Verification completed at
09:27:19: 17m42s observed elapsed, excluding initial source investigation.
Active work and waiting were not separately measured.

## Evidence And Root Cause

The legacy `_materialize_global_byte_index_sum_loop_8616` replaces the entire
function with an initializer, a loop and a return. Its instruction pattern
proves neither elimination nor consumption of unrelated C storage and calls.
In STORE's `_sum_globals`, this erased the SI/DI projections later required by
the GP stack-restore gate. Four small controls reproduce deletion of unrelated
stack storage, runtime storage, calls, and distinct variables at equal offsets.

Simply refusing this optional-looking replacement is insufficient. A fresh-cache
diagnostic disabled it and produced `validation=passed` and clean whole-tail
validation, but generated C never updated `total` inside the loop. Strict GCC
compilation succeeded; the executable returned 3 instead of the expected 13
for counter=3 and table={1,2,3,4}. ESI/EDI were preserved. This is a demonstrated
validation blind spot, not evidence that compilation or unchanged AST snapshots
prove equivalence to the binary. The precise earlier owner of the lost update
is not established yet.

## Guard Contract

Structuring's shared storage-reconstruction guard accepts a tuple of exact
recovered C variable objects. Writes outside those objects and all calls remain
unconsumed obligations. Names and equal offsets are not identity evidence.
The mask accumulator retains its existing optional-refusal behavior. The global
sum reconstruction uses the required guard: raise `PipelineHardError` before
replacing the body, with the function address, Structuring layer and storage
counts. The original AST remains intact; no successful fallback is inferred.

The compatibility builder imports this refusal-only guard under a documented
architecture exception. No new semantic recovery was added to Rewrite. Remove
the compatibility edge when the legacy builder migrates to its owning layer.

Reason: prevent a shape-based whole-body replacement from deleting effects,
without changing an already failing function into falsely successful wrong C.

DoD for this guard: demonstrate corrupt controls fail before repair; preserve
the valid reconstruction control; retain the original AST on rejection; expose
an early error with function/layer evidence; enroll tests in routine Make,
Python-pipeline and changed-owner selection; refresh scoped and routine gates.

Definition of failure: discard unrelated writes/calls, infer identity from names
or offsets, silently accept the known-invalid native fallback, weaken existing
validation, or call this guard a completed function repair.

## Verification

- Fail-first controls: 4 failed / 1 passed in 5.68s.
- Focused projection/return-chain tests: 81 passed in 6.41s. All individual
  durations below the configured one-second display threshold. This is not
  a controlled end-to-end overhead measurement.
- Scoped projection/new-test Ruff `check --fix`, MyPy and Pyright pass.
  Full architecture passes. Legacy lint debt remains in the compatibility
  orchestrator and architecture checker; global `quality-fast` exits 2.
  The 39-module compiled import smoke passes.
- Direct CLI with the required guard exits 4, reports the unconsumed-effect
  hard error and failed validation. Its partial C is not accepted output.
- Routine pipeline: 268 early checks pass; 4,561 pytest passes / the same
  three SORTD failures in 207.22s; MS C 2/7, QuickC 3/4. No complete-suite audit
  or Step 9 completion is claimed.

Artifacts under `/home/xor/.cache/`: `sum-effects-before.log`,
`sum-effects-final-tests.log`, `sum-effects-ruff-verified.log`,
`sum-effects-mypy-final.log`, `sum-effects-pyright.log`,
`sum-effects-architecture.log`, `sum-effects-quality-fast.log`,
`sum-effects-test-pipeline.log`, `sum-effects-hard-gate.log`,
`sum-effects-native.c`, and `check-sum-effects.c` with its failing executable.

## Next Acceptance Work

The follow-up below supersedes the earlier missing-IR/update-collector lead.
The accumulator exists through the observed AST passes and was deleted from
rendered text. Do not add a second recovery rule to compensate for that loss.

Require binary-to-projection effect coverage to reject a missing live STORE
before accepting a new validation baseline. Extend existing inventories where
possible; add a deliberately removed-update control at the responsible owner.

Function DoD: correct table accumulation, preserved SI/DI effects, passing whole
tail validation, strict generated-C compilation and execution, and the complete
MS C storage fixture round trip. Failure: accept a constant initial total, use
source names or sample addresses as recovery proof, or restore a whole-body
replacement without preserving unrelated effects.

## Follow-Up: CLI Deletion And Split-Store Evaluation

2026-09-12, investigation began 09:29; checkpoint approximately 09:42 +02:00.
Observed elapsed about 13 minutes; active and waiting time not separated.

Private-cache pass probes retain both accumulator STORE assignments through
Structuring and the observed postprocess passes. A text-boundary probe identifies
`cli_c_text_postprocess._prune_non_lvalue_arithmetic_assignments` as the deletion
owner: its regex mistakes `((unsigned char *)&total)[0]` and `[1]` for invalid
arithmetic lvalues and removes both statements after semantic validation.
Thus the confirmed validation gap here is mutation after validation, not proof
that native binary-to-AST collection omitted these stores.

The legacy helper now preserves its input unchanged. It remains a documented
compatibility entry point for existing formatter callers; remove it together
with those callers during formatter migration. Invalid targets must remain
visible to strict recompilation, including calls on their RHS. No replacement
regex and no new semantic recovery were added to the CLI.

Five statement-loss controls fail before repair and two ordinary-store controls
pass (13.64s). All 101 focused CLI tests pass afterward (18.82s), as do MyPy,
full architecture and ownership checks. New-test Ruff passes; the large legacy
text module retains 73 Ruff findings. Tests are enrolled in the routine pipeline,
Make and source-owner selection. The broad 4,561/3 result above predates this
follow-up; it is not a fresh audit of the CLI change.

With only the whole-body rescue disabled in the private diagnostic process,
strict GCC compilation and the counter=3/table={1,2,3,4} runtime oracle now pass:
result=13, ESI/EDI unchanged. Production's required reconstruction guard remains
active; this does not yet close the function or fixture.

A wider compiled-C oracle immediately exposes another real defect:
counter=242 yields 508, expected 252. The low-byte write changes `total` before
the high-byte RHS re-evaluates `total + ax`. Native split-store value evaluation
is not preserved by these C projections. Next: identify the earliest owner
losing the pre-store value, capture it once using typed evidence, and add
carry-boundary/overlap controls. Do not fix the emitted expression with text
substitution or remove the high-byte store.

Artifacts: `/home/xor/.cache/sum-{passes,post-passes,text}.log`,
`assignment-effects-{before-verified,after,mypy,ruff,contracts}.log`,
`sum-text-preserved.log`, and `check-sum-carry.c` with its failing executable.
The latest `sum-effects-native.c` and `check-sum-effects` now contain the
post-repair diagnostic output; the earlier failure is recorded above.

## Carry Oracle And Native Boundary Checkpoint

2026-09-12, approximately 10:00 +02:00. This investigation follows the 09:42
checkpoint; elapsed about 18 minutes, with active/waiting time not separated.

Raw C observed before `_apply_structuring_stable_stack_semantics_8616` already
re-reads the low byte in the high-byte store after changing that byte. It keeps
a separate high-byte snapshot (`v13`). Owned stack lowering subsequently
projects both expressions as `total + ax`. Therefore a Lowering-only diagnosis
is incomplete: native propagation/folding must preserve the loaded low-byte
value, and later projection must not erase captured-value distinctions.

Diagnostic-only experiments, not production changes:

- Filtering native SPropagator load substitutions across stores was observed
  executing and refusing replacements but left the final bad C unchanged.
  Including stack-SSA reads/writes in the diagnostic also left it unchanged.
- Disabling native AILSimplifier local-variable unification and treating
  stack-SSA assignments as StoreStatementFinder barriers independently left
  the output unchanged. These probes did not record per-hook execution counts,
  so they are weaker evidence and do not exclude those mechanisms.
- Do not land these restrictions as a claimed function fix. Next inspect the
  actual native SSA definition/use path for the low-byte read, then preserve
  that value across the first store before variable/storage projections merge.

The MS C fixture and rebuilt-function harness now check counter=242 (252) and
counter=246 (256), in addition to the original counter=3 (13). This keeps the
compile/decompile/recompile/run gate sensitive to byte carries. A compiled-C
corruption control reproduces the observed two-store re-evaluation and proves
the old harness accepted it. Before the new inputs: 1 failed / 1 passed in
23.72s. Afterward: 50 related tests pass, final run 14.91s. All individual test
durations are below the configured one-second display threshold.

Reason: the original tiny input cannot expose stale/pre-store value loss around
byte boundaries. DoD: correct C passes, deliberately corrupted C is rejected,
both source and rebuilt harness exercise the same inputs, routine/ownership
selection includes the oracle, and original MS C compilation/execution remains
green. Definition of failure: change expected results to accept corruption,
skip the mandatory oracle, or count native-only execution as a successful
decompiler round trip.

GCC absence is an explicit test failure, not a skip. New-test Ruff and harness
MyPy pass; the legacy builder retains 12 Ruff findings. Full architecture and
ownership checks pass. The updated source compiles/runs successfully under
MS C in `/home/xor/.cache/storage-carry-native-build`; that command explicitly
skipped decompilation, so it is only native fixture validation. No broad suite
refresh or decompiler acceptance is claimed at this checkpoint.

Artifacts: `sum-store-order{,-stack}.log`, `sum-no-unify.log`,
`sum-fold-barrier.log`, `sum-stack-raw.log`, `storage-carry-oracle-before.log`,
`storage-carry-final-tests.log`, `storage-carry-native-build.log`,
`storage-carry-mypy.log`, `storage-carry-ruff-verified.log`, and
`storage-carry-contracts-final.log`, all under `/home/xor/.cache/`.

### Shared Replacement Boundary Checkpoint (2026-09-12 10:14 +02:00)

The combined consumer and stack-boundary probes distinguish two independent
defects. They are diagnostic experiments, not production fixes:

1. Native SPropagator permits a temporary's load to cross a Store when definition
   and use have the same machine instruction address. Filtering only
   BlockSimplifier._compute_propagation is insufficient: AILSimplifier._fold_exprs
   independently invokes BlockSimplifier.replace_and_build through
   _replace_exprs_in_blocks. The recorded stack trace confirms this caller
   reintroduces the refused low-byte load.
2. Filtering at the shared replace_and_build consumer preserves the captured
   low and high bytes in native C. Immediately before owned stack lowering,
   the high-byte store reads `((v13 | (v14 << 8)) + v11) >> 8`, where v13/v14
   were assigned before either store. Immediately afterward,
   _apply_structuring_stable_stack_semantics_8616 replaces this with
   `(local_2 + v11) >> 8`, after the low-byte store has modified local_2.

The second observation explains why a correct native barrier alone still
produces the same bad final C. Do not infer that the barrier did not execute,
or blame Rust expression mutation: the recorded statement-level replacements
and caller stack explain the earlier bypass without that hypothesis.

Next implementation needs two focused regressions: memory-dependent temporary
propagation across an intervening store, including same-instruction stores and
both native consumers; and captured stack-byte values surviving a partial write
through owned stack lowering. Keep byte-resolved wrapping accesses intact.
Production acceptance still requires preserved SI/DI effects, carry behavior,
strict recompilation, clean validation and the actual MS C round trip. Diagnostic
builder bypasses do not satisfy any production acceptance claim.

Artifacts under `/home/xor/.cache/`: `sum-replacements.log` (block-only filter
bypassed by later consumer), `sum-consumer-filter.log` (confirmed caller stack),
and `sum-consumer-stack.log` (before/after owned stack lowering). All three probe
processes completed successfully; their generated C remains semantically wrong.
No production-code edit or new gate run occurred during this diagnostic interval.

### Native Propagation Guard Checkpoint (2026-09-12 10:24 +02:00)

Implemented `load_propagation.py` at the frontend/native AIL compatibility owner,
called from the existing SPropagator adapter for both block and function models.
It refuses load-bearing temporary substitutions across stores or side-effect
statements and refuses missing definition/use evidence. It preserves original
temporaries and byte-resolved memory accesses rather than inventing non-aliasing.
Typed counters record inspected, classified, consumed and refused candidates.

The new native regression failed before the guard in both same-instruction
modes (2 failed, 6 passed, 15.82s). With the guard and boundary controls, 61 related
tests pass in 13.51s under `pytest -n 7`; individual displayed durations are below
one second. Touched compatibility code and the new test pass Ruff, and both
non-test compatibility modules pass MyPy. Full architecture and ownership pass
after enrollment in both Make test lanes, routine pipeline and typed promotion
registries. The broader touched-script Ruff run reports 70 remaining findings
in the architecture checker; this is not a global lint-green claim.

A fresh real-function boundary probe confirms the production adapter preserves
both captured bytes before stack lowering, with no diagnostic propagation patch.
This refines the preceding investigation: guarding the shared consumer works,
but is unnecessary; the existing model adapter also covers both native consumers.
Earlier adapter experiments looked ineffective only because the later lowering
defect remained. The diagnostic still bypasses the legacy whole-body builder, so
the function is NOT accepted as fixed. Stack lowering still changes the saved
byte expression into a fresh read after a partial write.

Next: isolate the specific lowering subpass inside
`_apply_structuring_stable_stack_semantics_8616` that merges captured values with
current storage, add a failing typed AST regression, and repair that owner.
DoD for the native guard is focused native block/function correctness, safe
propagation controls, refusal controls, typed reporting and gate enrollment.
Failure means accepting same-instruction ordering as alias proof or modifying
the independently wrapped frontend accesses. Overall function and Step 9 DoD
remain unchanged; quality-fast and test-pipeline must still be refreshed before
claiming an accepted decompiler improvement.

Logs under `/home/xor/.cache/`: `load-propagation-before.log`,
`load-propagation-final-tests.log`, `load-propagation-mypy.log`,
`load-propagation-all-ruff.log`, `load-propagation-contracts-enrolled.log`, and
`sum-native-guard.log`. This implementation checkpoint follows the 10:14
diagnostic checkpoint; no complete-suite run or end-to-end function success is
claimed for this interval.

### Captured-Value Repair And Round Trip (2026-09-12 10:44 +02:00)

The responsible Lowering subpass is
`materialize_stack_word_load_recompositions_8616`, called inside stable SS linear
lowering. Its canonical-owner path used an Alias load's instruction provenance
to substitute current stack storage for saved scalar bytes. Provenance proves
the original storage range, not equality of the saved value and current memory.
`stack_word_operand_is_captured_value_8616` now distinguishes non-stack scalar
variables from current stack projections. Such recompositions remain intact,
with a typed CAPTURED_VALUE refusal until value-lifetime evidence exists.

Extended the existing canonical-projection test with captured low/high/both
operands rather than creating a duplicate fixture. Fail-first: 3 failed, 1
passed in 18.46s. Afterward the materialization file has 13 passes; the combined
native-load, global-sum-effect and word-materialization set has 31 passes in
14.59s. An earlier combined command used the wrong path for the carry oracle
and collected zero tests: that command is not passing evidence. The oracle is
enrolled at `angr_platforms/tests/test_msc_storage_carry_oracle.py` and ran in
the subsequent mandatory pipeline.

The legacy sum reconstruction now declines when effects are unconsumed, keeping
the native body rather than requiring destructive reconstruction. This change
follows repair of the native body, not suppression of validation. The regression
still checks original body identity for stack writes, runtime writes, calls and
distinct same-offset variables. Production decompilation without diagnostic
patches now has `validation=passed` and clean whole-tail validation for the one
selected function. Strict GCC compilation passes, and the generated body passes
all 65,536 counter inputs against the binary's modular word-sum result while
preserving full SI/DI parent values. It retains explicit saved byte values across
the low-byte store; no wrapping frontend accesses were changed.

Mandatory acceptance refresh on the stable code:

- Preliminary pipeline contracts: 268 passed, 16.83s.
- Main routine lane: 4,583 passed, the same 3 SORTD failures, 273.33s.
- MS C original compile/run and selected-function decompile/recompile/run:
  storage_classes passes, original/rebuilt exit code 255, two selected functions.
  MS C improves from 2/7 to 3/7: compare16, simple_control, storage_classes green.
  loops_jumps, function_pointers, pointer_memory, scalar_types_io remain red.
- QuickC remains 3/4, with args failing validation.
- Full architecture and ownership pass; all touched Lowering/postprocess modules
  pass MyPy. Touched-surface Ruff reports 194 findings including legacy modules.
- quality-fast remains red on Ruff debt; 39 compiled-module smoke checks pass.
  test-pipeline remains red on the explicitly listed semantic failures.

The main lane's 273.33s is slower than the earlier 207.22s checkpoint; these are
not controlled performance repeats, so neither a speed improvement nor a causal
regression is established. Do not silently omit this timing change. No complete
11k-test suite refresh is claimed. Step 9 still requires the remaining functions,
compiler fixtures, quality acceptance and stable complete-suite audit.

Artifacts under `/home/xor/.cache/`: `sum-lowering-owners.log`,
`word-capture-before.log`, `word-capture-focused-tests.log`,
`word-capture-all-mypy.log`, `word-capture-ruff.log`,
`sum-production-capture.c`, `sum-production-capture.log`, `check-sum-carry.c`,
`word-capture-quality-fast.log`, `word-capture-test-pipeline.log`, and
`word-capture-contracts.log`. Compiler evidence:
`examples/build_msc6_tiny/storage_classes/report.json`.
The investigation began after the 10:24 checkpoint; production output was
verified at 10:30, and the mandatory gate results were collected by 10:42.
