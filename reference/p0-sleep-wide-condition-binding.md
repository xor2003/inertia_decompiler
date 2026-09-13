# Sleep Wide-Condition Binding

## Exit-Proof Checkpoint (2026-09-13)

Broad checkpoint after the origin-ownership guard: `make test-pipeline`
completed with exit 0 on the unchanged source tree. Preliminary checks:
268 passed (8.22s); curated unit stage: 4,929 passed (246.85s pytest,
247.325s stage); QuickC fixtures passed (34.907s); MSC6 tiny full
compile/decompile/recompile execution pipeline passed (86.262s).
`make quality-fast` exited 2: 6,242 Ruff findings remain; no MyPy errors
were reported; compiled import smoke passed for all 39 modules. These are
routine gates, not the exact complete pytest audit or Sleep acceptance.
Logs: `/home/xor/.cache/step9-wide-loop-pipeline.log` and
`/home/xor/.cache/step9-wide-loop-quality-fast.log`.

Architecture investigation found existing loop-aware consumers in
`structuring/loop_break_jcc.py` and `loop_condition_materialization.py`.
The former currently constructs scalar predicates before guard facts; the
latter can consume leading pretest guards. Sleep's clock precedes its guard,
so promoting the guard to a loop header would move call execution and is not
acceptable. Extend the in-body loop-exit proof/consumer; avoid a competing
CFG ownership implementation or generic origin-tag inference.

Latest ownership finding: generic single-branch orientation interpreted the
source tag on a `CBreak` as its destination. Sleep's tag is the loop header,
so that path selected `clock <= goal` for a break, reversing the intended
exit. Generic ownership now refuses sole break/continue bodies (including
nested singleton statement containers); loop-aware ownership must determine
their destinations. Eight fail-first controls cover both jump kinds and both
tagged branch sides. Existing condition-chain refusal tests are already in
the routine pipeline. Related checks: 54 passed in 9.12s; scoped MyPy passes;
Ruff reports 12 existing findings in the large materialization owner and none
in the changed test file.

The unchanged Sleep regression still fails (8.47s call, 22.42s combined run),
so no function is accepted. Next: connect wide planning to loop-aware
break/continuation ownership, and track why subsequent materialization
reconstructs scalar DX/AX predicates and the captured temporary declaration.
Do not reinstate generic origin-as-destination inference or bypass validation.
Evidence: `/home/xor/.cache/sleep-wide-rematerialization.log`,
`/home/xor/.cache/step9-loop-origin-before.log` (8 failed, 12 passed),
`/home/xor/.cache/step9-loop-origin-after.log`, and
`/home/xor/.cache/step9-loop-origin-related.log`.

Follow-up: wide-call planning now normalizes every intermediate path against
SSA before evaluating ordering. The evaluator receives only normalized typed
condition edges, never unchecked intermediate CFG blocks. Six new cases cover
the two-jump path, effects, refusals, absent evidence, mismatched edges and
cycles. Original condition facts remain the plan's provenance.

The live path now reaches capture. Its original call is an AX assignment, not
a standalone expression. Capture preserves that assignment after a wide
temporary at the same position and records ownership for reuse on repeated
materialization. Two new controls cover standalone/register forms, speculative
no-op, single call occurrence, declaration registration and repeated capture.
Final focused set: 29 passed in 8.35s; scoped Ruff/MyPy pass. New owners/tests
are enrolled in Make, the architecture gate and the routine pipeline.

Sleep is still rejected: latest unchanged executable regression fails in
7.12s with two uninitialized DX reads. The capture ownership exception no
longer occurs. Investigate subsequent scalar rematerialization and retained
condition provenance; do not relax validation. Evidence:
`/home/xor/.cache/step9-wide-capture-unit.log`,
`/home/xor/.cache/step9-sleep-reused-capture.log`.
No full-suite failure is closed, and broad gates remain pending.

The fresh-cache probe isolated two separate refusals. First, an empty SSA
block at 69466 leads to effectful block 69485. The normalizer previously
discarded the empty-prefix proof because the destination has unresolved stack
memory effects. It now stops before that destination without bypassing it;
unknown effects in an otherwise empty traversed block still refuse. Two new
destination-refusal regressions failed before the fix (2 failed, 11 passed)
and passed afterward (21 passed including wide-plan checks, 14.28s). Scoped
Ruff and MyPy pass. The normalizer regression file is already in the routine
pipeline and Make gates.

Sleep is NOT fixed: its unchanged executable-only regression still fails
(8.85s total, 7.91s call) with the same three uninitialized register reads.
The next probe shows a selected typed chain, but abstract high-word relation
-1 yields UNKNOWN for every low-word relation: path 69471 -> 69482 -> 69458
contains two intermediate jump blocks, whereas the shared evaluator handles
only one. The remaining six ordering outcomes are collected. Next work must
prove intermediate blocks empty using SSA before evaluating the complete
decision graph; do not merely raise a hop limit over unchecked CFG edges.
The early wide-call plan and deferred capture implementation remain pending
acceptance, including capture ownership tests and routine-gate enrollment.

Evidence: `/home/xor/.cache/step9-exit-boundary-before.log`,
`/home/xor/.cache/step9-exit-boundary-after.log`,
`/home/xor/.cache/step9-sleep-exit-boundary.log`, and
`/home/xor/.cache/sleep-wide-outcomes.log`. No full-suite failure is closed by
this checkpoint and no broad gate was rerun on this change.

## Verified Failure

2026-09-13, executable-only focused regression:
`test_sortd_sleep_preserves_both_wide_clock_calls_sidecar_free` fails in 9.10s.
The second call remains a statement; the emitted guard reads uninitialized
DX/AX. Tail Validation rejects three reads. The existing deadline behavior
oracle and semantic assertions must remain unchanged.

Fresh-cache in-process probes confirm a dependency cycle, not merely an
unsupported spelling of an equivalent Boolean expression:

1. Structuring's `_materialize_cfg_condition_chain_expr_8616` tries to lower the
   first scalar `sle` condition. Exact register-definition binding cannot find
   a reaching C definition for the wide call's DX result and returns `None`.
2. The CFG-expression builder consequently refuses the chain before Boolean
   composition. Debug events are `cfg-chain-expression-refused` and
   `cfg-chain-result-refused` for instruction 69464, block 69461.
3. `_materialize_existing_wide_call_return_conditions_8616` later finds the
   complete typed `sle/sge/ule` DX:AX versus adjacent BP-word chain, but receives
   only the first scalar C comparison (`dx <= high-word`).
4. Types/Lowering's `lower_wide_call_return_condition_chain_8616` requires an
   already-composed Boolean C expression to recover its stack operands. It
   reports raw=1, normalized=0, classified=0, materialized=0, failure=1.

The typed chain is available, but its wide lowering depends on a scalar C
representation that cannot be safely constructed first. Do not restore the
old unproven-register fallback or merely accept another rendered C shape.
Statement-level disappearance of a stored call result was not established by
these probes; the observed refusal alone is sufficient to explain why the
wide recovery route does not run.

## Next Implementation Boundary

### 2026-09-13 00:16 +02:00: Ordering Proof Extracted

`structuring/wide_condition_ordering.py` now owns the representation-independent
high/low outcome classifier. Its existing stack consumer delegates to it, so
this is used production code, not a second unused implementation. It accepts
one operator only after all nine ordering outcomes match. Unknown paths,
constant or incomplete comparisons, and order comparisons without proven
signedness refuse. It neither constructs C operands nor discovers storage or
call identity. Sleep's call-result consumer is still pending.

The original stack tests passed 15 tests before extraction. Related stack,
call-output, condition and new ordering tests pass 102 tests in 14.56s. The
final proof/stack/pipeline-selection gate passes 100 tests in 10.22s. New owner
and tests pass Ruff; both proof owners pass scoped MyPy; full architecture
checks pass. Routine test lists and typed-owner admission include the new
module. The old stack owner is reduced below 350 lines; named word-size and
traversal-budget constants remove three lint findings, leaving two existing
complexity findings there. Architecture-script lint debt remains visible.

Logs: `/home/xor/.cache/step9-wide-ordering-{before,after,final,mypy,ruff,architecture}.log`
and `step9-wide-ordering-owner-ruff.log`. This is a verified prerequisite, not
Sleep or Step 9 acceptance. No new corpus improvement is claimed; default,
expanded and complete-suite gates remain outstanding. Approximate observed
interval 00:12-00:16 +02:00 includes test waits; active work was not separately
timed.

### Remaining Implementation

### 2026-09-13 00:36 +02:00: Call-Source Proof Connected

The existing wide-call lowerer no longer selects the numerically nearest call.
`lowering/wide_call_condition_source.py` consumes Alias reaching definitions
for every typed register operand at its producer boundary. All must resolve
to the same typed DX:AX call candidate; missing CFG, partial/full clobbers,
unknown calls and conflicting definitions refuse. The Alias solver remains
the sole owner of register effects and CFG joins. The consumer is wired into
`call_output_stack_objects.py`, not left as an unused helper.

Five real decoded-instruction controls reproduced four incorrect acceptances
before the fix: overwriting AX, DX, DL or executing another call still selected
the old wide result. Those now refuse while a NOP preservation control passes.
Additional controls check missing inventory and an AX clobber after the first
high-word comparison, preventing reuse of only the first boundary's proof.
Positive legacy fixtures now supply decoded CFG evidence rather than relying
on call addresses alone. No positive semantic assertions were weakened.

A second fail-first check found that refused call provenance still changed
the stack object's signed type. Stack preparation now runs only after call
proof. All four clobber cases retain the original unsigned type on refusal.
Final related surface: **70 passed, 7.93s**; scoped MyPy and full architecture
checks pass. New owner/tests pass Ruff. Legacy owner/test lint remains visible.

Before the final refusal-type guard, the default pipeline passed **4,903**
curated tests (251.68s), **268** preliminary tests, QuickC (33.355s) and all seven
MS C tiny round trips (92.099s). The last guard has focused verification, not a
second broad refresh. `quality-fast` remains red on **6,245 Ruff findings**;
its MyPy and 39-module compiled-import smoke passed. No lint rules were relaxed.

Sleep's original wide/scalar dependency cycle is still unresolved. This closes
an unsafe source-selection prerequisite, not Sleep or a retained full-suite
failure. The next change must consume this call proof together with the
ordering proof before scalar binding, preserving evaluation position and
exactly one dynamic call. Do not inline a call across unproven effects or
delete its carrier before the replacement is committed.

Logs under `/home/xor/.cache/`: `step9-wide-call-source-{before,after,related,final,`
`ruff,final-ruff,mypy,final-mypy,pipeline,quality,architecture}.log` and
`step9-wide-call-refusal-before.log`. Observed interval approximately
00:17-00:36 +02:00 includes the pipeline and gate waits; active work was not
separately measured. Complete-suite and expanded acceptance remain open.

Reason: break the proof/materialization cycle while keeping one call evaluation
and exact condition polarity. Structuring already has target-directed CFG
ordering proof in `wide_stack_condition_chains.py`, but its operand candidate
model accepts stack pairs only. Types/Lowering already consumes typed DX:AX
callsite summaries in `call_output_stack_objects.py`. Reuse these owners and
their proof contracts rather than adding semantic recovery in Rewrite or CLI.

1. Prove and represent a complete wide call-result/stack predicate from typed
   call-return, storage and CFG evidence before scalar C register binding.
   DoD: unique reaching call output, exact wide stack identity, exhaustive
   high/low ordering proof and target-directed polarity. Failure: numeric
   nearest-call selection as sole proof, missing clobber/CFG checks or guessed
   width/storage.
2. Lower the proven predicate atomically, retaining exactly one dynamic call
   evaluation and all intervening effects. DoD: no temporary uninitialized
   AX/DX escapes, both continuation and exit polarity controls, unknown proof
   leaves existing code untouched. Failure: duplicating calls, deleting a live
   call, or using raw-register placeholders as a successful result.
3. Verify against the existing sidecar-free Sleep regression and independent
   deadline/clock-count oracle, then related wide-condition and routine gates.
   DoD: validation=passed, strict generated-C compilation, preserved signed
   deadline behavior and corrupted-control rejection. Failure: weaker test
   expectations, baseline-only equivalence, or selective success claimed as
   full Step 9 completion.

This is an implementation direction, not completed production work. Existing
new exact-definition refusal stays intact. The full audit still has 42
unresolved retained failures after the five separately verified fixture fixes.

## Evidence

Logs outside the repository:

- `/home/xor/.cache/step9-sleep-before.log`
- `/home/xor/.cache/sleep-wide-probe.log`
- `/home/xor/.cache/sleep-wide-probe-debug.log`

The observer is `/home/xor/.cache/probe-sleep-wide.py`. It uses a temporary cache
namespace and `PYTHON_JIT=1 PYTHONHASHSEED=0`, with
`INERTIA_OTEL_PROFILE_IN_PROCESS=1` and `INERTIA_DIRECT_ADDR_FORCE_THREAD=1`.
Observed hooks ran inside analysis; both probe processes ended with exit 4.
Probe-only expression rendering is diagnostic, never recovery evidence.
Investigation interval approximately 00:05-00:11 +02:00, including probe waits;
active work was not separately timed. No production edit or acceptance claim.
