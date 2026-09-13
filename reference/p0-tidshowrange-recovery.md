# TIDShowRange Recovery

## Status

Latest literal-source checkpoint: MapInEMSSprite now receives the binary-proven
arguments `(2, 0)`. Named stack carriers no longer outrank an immediate source
merely through the legacy semantic-quality score. Types/Lowering owns the
literal-source/carrier classifier; existing callsite-binding and mutation
vetoes still own replacement. Both direct and masked controls failed before
the fix. The expanded controls cover missing, malformed and nonliteral sources.
The latest focused run is 37 passed, one live TID failure in 135.93s; TID's
body took 121.05s. Whole-tail now reports 20 uninitialized reads and the same
duplicate final callsite. This is not a performance improvement or a completed
function fix. Logs: `/home/xor/.cache/step9-literal-call-{before,after,live}.log`.
Ruff passes for the changed classifier and runtime-call tests. The 5,087-test
routine result below predates this literal-source change and must be refreshed
before treating it as broad acceptance of that change.

Open Step 9 failure. The latest live reproduction on 2026-09-13 still exits 4,
but passes GP materialization and reaches whole-tail validation (101.73s test
body). Nested-call scheduling now repairs the itoa argument binding; the
function is not fixed.
The earlier pre-fix
reproduction took 101.98s (108.84s including pytest). These runs fail at
different stages; this is not a speedup measurement. Original baseline accounting remains 15 of
47 failures individually resolved, 32 unresolved, without a full-suite refresh.

Source oracle: `cod/f14/COCKPIT.COD`, lines 5556-5856. The function formats
one of five range values, centers the text, copies the text rectangle, then
optionally maps and draws two sprites and copies their rectangle. Five switch
cases share a machine call tail but supply distinct ScaleRotate arguments.

## Current Evidence

- Whole-tail failure now reports 22 uninitialized reads and one duplicate final
  call site. Previously it reported 25 reads and the itoa BP-10/BP-22 mismatch.
  The generated itoa call now consumes the indexed range value, `&s` and 10;
  its argument-storage mismatch no longer appears in whole-tail diagnostics.
- Generated pstrlen, MapInEMSSprite and the shared ScaleRotate call still read
  uninitialized outgoing-stack locals instead of recovered argument values.
- The switch contains constant decisions including `0 == 1` and `-1 != 1`.
  Fixing storage diagnostics alone must not allow those decisions to pass.
- Multiple cleanup passes are rejected before the final failure. These are
  diagnostic symptoms, not evidence that Rewrite owns the recovery defect.
- A duplicated RectCopy call site may be a mutually exclusive shared-tail
  representation. Its actual per-path behavior must be proved before either
  accepting it or changing the multiplicity gate. Do not suppress the finding.

Log: `/home/xor/.cache/step9-tid-current.log`. The run interval was
05:04:44-05:06:33 +02:00 on 2026-09-13. This is execution time, not a measured
engineering estimate. The current failure-details artifact is
`angr_platforms/.cache/tail_validation_details/COCKPIT.a7bc21539c80.tail_validation_surface.tail_validat.json`.

## Nested Call Argument Traversal (2026-09-13)

A fresh isolated-cache diagnostic completed at 06:33:41 +02:00 with exit 4.
The existing call-materialization debug hook executed repeatedly. It attaches
the correct itoa summary at 0x1038, including `("bp_addr", -10)`, but never
reports argument materialization for itoa or pstrlen. RpPrint does reach that
consumer and materializes its BP-10 address. Generated itoa, pstrlen and
MapInEMSSprite remain inside upper-register-preserving OR/AND expressions.

The current compatibility implementation's nested `_call_from_statement`
recognizes only a direct call, a direct statement field containing a call, or
a singleton statement shell. `_rewrite_block_body` skips the statement when
that selector returns None. It therefore misses a call inside a masked RHS;
this is not evidence that the callsite summary lacks the buffer address.

A controlled production-pass reproduction uses the existing runtime-call
fixture and identical typed immediate-argument evidence in two contexts:
a direct expression statement and `runtime_gp_state_assignment_8616`.
The direct control passes; the masked form leaves argument 0 instead of the
proven 37. Result: **1 passed, 1 failed in 5.80s**, using pytest `-n 7`.
Both test bodies take about 0.01s. This is a small reproduction of the traversal
defect, not another resolved baseline failure or a performance comparison.

Artifacts under `/home/xor/.cache/`:
- `step9-tid-call-arguments.log` and `.c`: completed live diagnostic.
- `test_tid_nested_call_probe.py`: controlled reproduction, outside the suite
  until its repair and refusal cases are ready for permanent enrollment.
- `step9-nested-call-controlled.log`: before-fix test result.

Next repair belongs in Types/Lowering: consume proven arguments for nested
call occurrences without changing their evaluation context. Do not simply
broaden the legacy direct-statement selector: its consumers also replace
statements, relocate writes and prune setup, which would be unsafe for an
arbitrary nested call. Keep the enclosing mask, return destination, call
occurrence and ordering intact. Reuse the typed argument proof and mutation
vetoes; do not introduce name-based recovery or a second source of semantics.

DoD: direct and masked forms consume identical proven argument evidence;
missing/conflicting evidence refuses; nested calls are not duplicated or
moved; enclosing register effects survive; new controls are enrolled; the
live buffer mismatch disappears without weakening whole-tail or the compiled
behavior oracle. Failure: fixing only rendered C, allowing setup deletion
without liveness proof, or declaring the entire function fixed while its
uninitialized reads, duplicate-call finding or constant switch remain open.
No production code changed in this diagnostic checkpoint. The latest passing
routine pipeline remains the earlier 5,083-test result, not a fresh full suite.

## Argument-Only Scheduling Repair

Implemented `lowering/call_argument_semantic_gap.py`. The existing argument-only
consumer already traverses nested calls, but its final scheduling condition
checked only argument counts. The new Lowering scheduler consults the existing
semantic classifier for summarized calls regardless of their expression
context. The compatibility bridge only invokes that scheduler; argument proof,
normalization and mutation vetoes remain authoritative existing consumers.
No statement selector was broadened and no setup-deletion permission was added.

Four permanent controls in `test_x86_16_runtime_call_results.py` cover direct
and masked calls with and without source evidence, repeated replay, preservation
of the enclosing RHS and exactly one producer occurrence. Focused acceptance:
27 passed, one live TID failure in 126.06s. The live body took 101.73s; this is
not a controlled performance gain. TID still has 22 uninitialized reads,
duplicate final RectCopy and unresolved constant-switch behavior.

Gate reconciliation also exposed two older enrollment defects. InBoxLng is now
`test_x86_16_inbox_long_live.py`, preserving its validation, compiled behavior,
compact-comparison and forbidden-output assertions without fixture/timeout
skips. Its old matrix entry was removed, so this does not duplicate the live
case. Pytest source lookup now resolves parameterized IDs consistently for
source existence, skip evidence and assertion facts; the exact runtime case
remains pytest collection's responsibility. Its new skip-preservation control
failed before the fix; all 14 source-index tests pass afterward.

Current verification:
- Full architecture check and project MyPy pass.
- New Lowering module, GP reload header, runtime-call controls and dedicated
  InBoxLng test pass Ruff with `--fix`; legacy source-index tests retain seven
  magic-value findings. Global quality-fast remains red on lint debt.
- Routine pipeline: 268 preliminary checks; 5,087 curated tests in 238.49s;
  QuickC 37.660s; all seven MS C tiny round trips 103.489s. Three stages passed,
  zero failed/skipped/timed out. InBoxLng passes in 23.54s under this batch.
- Latest quality run reused the existing compiled-import attestation; it did
  not execute a new import smoke. The earlier smoke covered 39 modules.
- No complete-suite, expanded or quality-hard success is claimed. Original
  closure accounting stays 15 of 47; no additional function is closed.

Logs under `/home/xor/.cache/`: `step9-nested-call-live.log`,
`step9-nested-call-pipeline.log`, `step9-nested-call-architecture.log`,
`step9-nested-call-mypy.log`, `step9-nested-call-quality-final.log`, and
`step9-param-selector-{before,after}.log`. Next investigate why the remaining
outgoing-stack argument values survive semantic classification, then the
shared switch tail. Do not repeat the now-resolved arity-only scheduling probe.

## Durable Oracle

`tests/x86_16_tidshowrange_behavior.py` compiles unchanged C with strict GCC,
AddressSanitizer and UndefinedBehaviorSanitizer. It checks 180 combinations:
five scale cases, four mapping results (including zero and high-bit segments),
and nine signed text widths. Library stubs verify every call's order and
arguments, itoa return-pointer flow, printed contents, both copy rectangles,
per-case sprite coordinates, and unchanged input globals.

Nine compile-valid corruptions are rejected: constant switch, wrong case
coordinates, unsigned division, lost high-bit mapping result, wrong mapping
arguments, wrong text surface, lost final copy, wrong returned-buffer pointer,
and a duplicate copy. All ten TID oracle tests pass; with SetGear's six controls,
the focused run is 16 passed in 1.83s. New files are Ruff-clean; the legacy CLI
test file retains lint debt. Logs: `step9-tid-oracle-final.log` and
`step9-tid-cli-ruff.log` under `/home/xor/.cache/`.

The oracle tests are enrolled in Make and the routine pipeline. The existing
slow live TID test now requires the oracle instead of textual call counts and
a particular positive-if layout. Return-code, validation, whole-tail and
no-assembly-fallback checks are retained. The slow live test remains in the
complete suite; it was not added to every routine invocation while recovery
is still failing. The full pipeline was not rerun for this test-only checkpoint;
the previous 5,035-test green result predates this new oracle.

## Whole-Local GP Binding Repair

Implemented `lowering/gp_stack_local_reload.py`, consuming existing Alias facts
without mutating C. It accepts complete, uniquely written word locals from
either exact register-byte stores or an already folded call-result assignment
whose typed callsite summary proves the same store instruction, register,
width and machine-BP destination. The latter was the actual TID representation:
the pstrlen call at 0x1043 incorporates the store at 0x1049. The assignment's
upper-EAX mask contributes no bits to its proven 16-bit destination; only
that exact, side-effect-free upper-word form is admitted.

Every matching runtime reload must have unconditional dominating stores.
Transparent child lists may revisit the same statement without its parent's
prefix; candidate/verified statement identities retain the parent proof while
still rejecting a distinct corrupted copy. Missing bytes, wrong values or
masks, conflicting writes, escapes, intervening calls and missing/wrong
call-store evidence refuse. The existing central GP evidence counters and
hard failure remain unchanged. The GP check now runs after runtime SS memory
and scalar-lvalue projection, when its required C storage bindings exist.
Reordering alone was insufficient; both representation binding and the
transparent-container dominance repair were required.

Twenty controls in `test_x86_16_gp_stack_local_reload.py` are enrolled in
Make, routine tests, ownership and architecture checks. The initial production
regression failed at the GP gate; the transparent-child regression separately
failed before its fix. Final live TID passes that gate, then reports the
original 25 uninitialized reads, one duplicate callsite and one argument
storage mismatch. No baseline failure closure is claimed.

Verification logs under `/home/xor/.cache/`:
- `step9-local-reload-before.log`: one failed, eight passed before integration.
- `step9-local-reload-dominance-before.log`: transparent-child failure.
- `step9-local-reload-dominance-live.log`: 18 focused passes, live TID failure
  at whole-tail validation, 108.79s total; two further refusal controls are
  included in the final routine run.
- `step9-local-reload-pipeline.log`: 268 preliminary passes, **5,083 curated
  passes in 250.21s**, QuickC 34.432s and seven MS C tiny round trips 80.508s;
  three stages passed, none failed/skipped/timed out.
- `step9-local-reload-quality.log`: global lint debt remains; 39 compiled
  import smokes pass. Its new optional-callsite typing error was fixed, and
  the complete project MyPy rerun `step9-local-reload-mypy.log` exits zero.

New owner and tests are Ruff-clean. Existing debt in the larger touched
orchestrators remains reported. No full-suite refresh or Step 9 completion.

## Synthetic ABI Correction

Microsoft C 6.0 Advanced Programming Techniques, sections 12.8.3-12.8.5,
requires preservation of BP, SI and DI. BX is not callee-saved. Primary manual:
[C calls to assembly language](https://www.pcjs.org/documents/books/mspl13/c/cadvprg/).
The existing synthetic-register contract incorrectly preserved BX and refused
BP. Corrected that contract and connected its exact BP verdict to call-stack
Semantics before Alias. Only frontend-registered synthetic targets under the
registered MS C convention qualify. Real bodies, unknown conventions, EBP,
SP, corrupt registries, mismatched callsites and refused stack effects do not
gain this proof. Stack cleanup alone still cannot prove BP preservation.

The new test module `test_x86_16_synthetic_frame_call_effects.py` has eighteen
controls and is enrolled in Make and the routine pipeline. Before the fix,
the first sixteen controls had seven failures and nine passes. Initial related
post-fix checks passed 64 tests; the expanded run passed 69 and failed only
the live TIDShowRange test. Logs under `/home/xor/.cache/`:
`step9-synthetic-bp-before.log`, `step9-synthetic-bp-after.log`, and
`step9-synthetic-bp-live.log`.

Post-fix routine pipeline: 268 preliminary tests; 5,063 curated tests in
232.97s; QuickC 38.230s; all seven MS C tiny full round trips 83.107s.
Three stages passed, none failed/skipped/timed out. The curated stage still
exceeds its recorded 30-second budget. Log: `step9-synthetic-bp-pipeline.log`.
Quality-fast remains red on legacy global lint findings; no MyPy errors and
39 compiled-import smokes passed. The changed register/stack-effect owners
and new tests are Ruff-clean. The publication module's existing unrelated
apply function retains complexity debt. Log: `step9-synthetic-bp-quality.log`.

The latest diagnostic observer executed and retained production decisions:
`/home/xor/.cache/probe-tid-gp-binding.py`, output
`step9-tid-gp-binding.log`. Alias proves AX saved at 0x1049 and reloaded at
0x1054 from entry-SP bytes (-16, -15). This corresponds to the ordinary local
`l` store/reload, not a PUSH/POP pair or the SI epilogue. The materializer finds
an insertion point, but candidate word operands have no C-variable entry-SP
binding at this boundary. It correctly refuses rather than claiming success.
Next inspect whether ordinary local reloads need a distinct existing-binding
consumer and whether the GP gate is scheduled before its required memory
projection. Do not invent a saved-register snapshot or remove this live value.

### Reordering Experiment: Insufficient

A diagnostic wrapper deferred GP binding until after the existing runtime
memory projection, then invoked the same mandatory GP materializer. Both
defer and final-check hooks executed; the gate still failed. Do not implement
a production ordering change or relax the gate on this evidence. The first
attempt did not intercept the imported driver binding and is not evidence
about ordering. Caller tracing identified the actual path:
Structuring priming -> `segment_global_materialization` ->
`apply_runtime_segment_lowering_8616` -> GP binding.

At restore 0x1054, after memory projection, recognized byte recompositions
contain `SimRegisterVariable` operands of size one, not stack variables.
Their missing entry-SP coordinates are therefore expected, not a faulty
coordinate conversion. The actual stack reload has become a whole local
value, outside the materializer's byte-recomposition path. Diagnostic output
also declares `local_e` as `char` while storing bytes zero and one through
its address and later reading it as the restored word. This storage/type
inconsistency must be repaired before accepting a whole-local reload binding.
This output came from the experimental scheduling run and is not an accepted
decompilation or a claim about final normal-mode output.

Evidence: `/home/xor/.cache/step9-tid-gp-order-active.log` confirms the deferred
and final checks; `step9-tid-gp-projection-coordinates.log` records exact
operand kinds and sizes; `step9-tid-gp-projection-coordinates.c` retains the
diagnostic output. All probes terminated with exit 4. No production changes,
gate suppressions or additional failure closures in this experiment.

### Direct Storage Construction Probe

A standalone call to `materialize_stack_cvar_at_offset_from_facts_8616`
with entry-SP offset -16, machine BP offset -14 and size two, followed by
the same coordinates with size one, returns two different C variables.
`variables_in_use` retains both: a two-byte unsigned short and a one-byte
char at entry-SP -16. This is reproduced directly from the current owner,
without running the decompiler. The construction loop considers only owners
whose size is less than or equal to the request, so a later byte request
does not reuse the earlier word owner.

This is a candidate source of overlapping declarations, not yet a proven
explanation of the live TID projection. Confirm the caller and ordering in
the actual function before changing behavior. Returning the wider variable
unchanged would also be wrong for a byte read; consumers need an explicit
contained byte value or writable byte view, with existing padding and
ambiguous-owner refusals retained. `stack_value_projection.py` already owns
such views. Prefer routing through that owner to inventing another overlap
or cast mechanism in the raw stack-variable constructor.

### Live Counterevidence To The Narrow-Local Hypothesis

Further observers after the experimental memory projection found both relevant
locals (entry-SP -16 and -14) have variable size two, `variable_type` and
expression type unsigned short, and matching unsigned-short entries in
`cfunc.unified_local_vars`. Thus the live binding and declaration metadata
are coherent at the failing GP gate. The earlier `char` text from the failed
run does not prove these in-memory projections are narrow; it is rejected-run
output, not an accepted regenerated translation unit. Do not change the type
or declaration owner based only on that output.

The instrumented real-mode stack constructor did not create either target
local in this run. The standalone overlap reproducer remains separate debt,
not the demonstrated cause of this failure. Logs:
`/home/xor/.cache/step9-tid-stack-creation.log`,
`step9-tid-stack-bindings.log`, and `step9-tid-stack-declarations.log`.
Each probe executed and terminated with exit 4; no production code changed.

Resume with the proven whole-word local reload at 0x1054. The current GP
materializer recognizes byte recompositions; its existing whole-local
consumer is restricted to terminal returns. TID's AX reload feeds arithmetic,
not a return. Any extension must prove the exact local's complete stores,
their saved-register value, and dominance over every consumed reload, without
accepting unrelated register-byte recompositions or hiding missing bindings.

## Next Work

### Offline SSA Replay, 2026-09-13

The captured Semantics artifact at
`/home/xor/.cache/tid-semantic-ssa-1.pkl` was replayed through the existing
Alias block transfer without changing any instruction or call effect. The
first seven blocks form the straight-line prefix under investigation; this
is not a whole-CFG proof. Tracking general-register byte origins gives:

| Block | Exit SP relative to entry | Exit BP | Saved bytes |
| --- | ---: | --- | ---: |
| 0x1000 | -30 | unknown | 14 |
| 0x1023 | -24 | unknown | 12 |
| 0x103b | -22 | unknown | 10 |
| 0x1046 | -26 | unknown | 6 |
| 0x106b | -34 | unknown | 12 |
| 0x108a | -22 | unknown | 12 |
| 0x1097 | -18 | unknown | 0 |

Before the first call, BP is correctly established at entry-SP minus two.
Call 0x101e has complete zero-net-SP effects but `bp_preserved=False`.
The first store at 0x109a, SS:BP-12 with width one, then clears all twelve
remaining saved bytes because its BP coordinate is unknown. This establishes
one concrete loss of evidence; it does not establish the cause of the earlier
itoa pointer mismatch or the constant switch conditions. Running the transfer
with its default segment-only tracking reports no general-register bytes and
must not be interpreted as failure to track PUSH instructions.

The current ordinary `_effect_from_summary_8616` constructor in Semantics
does not publish BP preservation. The existing synthetic-call register-effect
classifier proves BX/SI/DI preservation only, not BP. Investigate extending and
consuming that authoritative contract for exact registered synthetic targets;
real callees still require binary evidence. Neither a zero stack delta nor
placeholder RET bytes prove BP preservation. Do not import the Lowering
callee-save heuristic into Semantics or weaken Alias's unknown-store refusal.

Existing small controls already cover this refusal and its explicit-proof
counterpart. Reused them instead of adding duplicates: stack-frame register
Alias plus call-stack allocation proof tests, **29 passed in 6.22s**, seven
dependency warnings. Log: `/home/xor/.cache/step9-tid-bp-proof-controls.log`.
No production changes or additional baseline failure closures in this replay.

### Remaining Acceptance

1. Trace the Alias stack state and typed call facts across the first far call,
   its caller cleanup, and the following itoa call. Establish where the BP-10
   buffer value becomes BP-22 and outgoing-stack values become unresolved.
   DoD: reproduce the first divergent fact in a small layer-owned test and fix
   the authoritative owner. Failure: substituting names, constants or guessed
   frame offsets in Rewrite or the CLI.
2. Trace the Tscale load and successive DEC/JCC definitions through IR and
   Structuring. DoD: retain distinct dynamic case decisions and exact arguments
   through the shared call tail. Failure: constant conditions or lost cases,
   even if the existing tail report stops complaining.
3. Prove the duplicated final copy's path multiplicity and retained register
   saves. DoD: exact observable calls per execution and valid storage effects.
   Failure: weakening the multiplicity or initialization gates without proof.
4. Close only after the live test passes validation, strict recompilation and
   the independent oracle, with focused refusals and routine regression gates.
   Reason: each current failure class could otherwise conceal another one.
