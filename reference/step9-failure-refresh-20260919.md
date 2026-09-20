# Step 9 Failure Refresh: 2026-09-19

## Captured Return Publication And Dispatch

Lowering now recognizes an exact adjacent temporary capture followed by its
low-word GP publication. Width, type, expression identity, callsite uniqueness
and subsequent clobber checks remain mandatory. Calls are neither moved nor
re-executed. Four valid cases failed before this owner change; related owner,
inventory and GP reload controls passed afterward (95 in 18.12s).

A consumer integration regression then exposed a separate dispatch problem:
the legacy folding path consumed the captured producer before consulting this
proof. The compatibility bridge now consults the Lowering owner first; no
recognition or semantic recovery was added to the bridge. The integration
regression fails before this wiring change and passes afterward. The broader
call tests yield 221 passes and two failures in 8.71s. Both failures also
reproduce with the previous dispatch order (2 failed in 10.98s): typed probe
stores versus push sources, and renamed-register stack-probe carriers. They
remain open; the broader surface is not green.

The live TIDShowRange retry finished at 20:26:35 +02:00, exit 4, still rejected
for unassigned stack locals. Its pstrlen candidate retains the wrong return
carrier and loses the quality-score comparison. Thus the bounded publication
fix is proven by tests but does not close the live function. Next investigation
must inspect the producer/capture representation at argument materialization,
not infer it from the later rendered GP publication, and must preserve the
existing call/clobber vetoes.

The architecture gate exposed two missing QA_PYTEST_TARGETS enrollments for
the runtime artifact tests and the focused LoadProg regression; both are now
included and architecture-check passes. Global quality-fast exits 2 on Ruff
debt; the 39-module mypyc import smoke passes. Scoped checks including the
legacy call bridge remain Ruff-blocked, although the new Lowering owner and
runtime-result tests were clean. Final architecture-check and diff whitespace
checks pass after the bridge wiring change.

Default pipeline refresh completed successfully: 268 preliminary checks in
11.57s, then 5,791 routine tests in 308.86s. All three lanes passed with zero
lane failures, skips or timeouts: unit-focused 309.421s, QuickC 42.018s and
all seven MS C tiny round trips 89.426s. The unit lane still exceeds its
configured 30-second advisory budget; this is not a performance-budget pass.
Slowest routine cases were sidecar-free RunMenu (75.39s), InitMenu (73.17s)
and InitBars (57.75s); the newly enrolled LoadProg took 53.40s. SetGear passed
in 31.09s. This is curated acceptance, not a refreshed complete collection.

Evidence: `.cache/step9-captured-call-integration{,-after}.log`,
`.cache/step9-call-probe-baseline.log`,
`.cache/step9-tid-captured-dispatch.{c,log}`,
`.cache/step9-enrollment-architecture.log`,
`.cache/step9-captured-call-dispatch-linters.log`, and
`.cache/step9-captured-publication-{quality-fast,pipeline}.log`.

## Latest: Real Scalar Acceptance And TID Source Trace

The real MS C fixture retry after artifact-lifetime repair produced one pass
(sub_ulong) and one failure (add_sc's blanket numbered-variable ban), in 62.45s.
The fixture's scalar runtime gate had passed; its files now remain readable.
The COD bytes explicitly push/pop SI and DI, so the emitted byte locals are
legitimate ABI preservation, not proof of failed recovery.

The obsolete name ban is replaced by strict compiled execution of unchanged
add_sc C: all 65,536 input byte pairs under 16 independent SI/DI states, including
upper-register words. Byte-width signature, return arithmetic, whole-tail and
DOS runtime-gate assertions remain. Nine oracle controls accept direct and
saved-local implementations and reject seven arithmetic/ABI corruptions.
The oracle is enrolled in Make, routine tests and ownership. Related controls:
119 passed in 1.99s. Real add_sc/sub_ulong plus oracle controls: **11 passed in
68.55s**, including 67.11s fixture setup. Scoped parallel Ruff --fix, MyPy and
type/doc checks pass, including the edited MS C regression file. Two more nodes
from the 20-failure inventory pass individually; this is not a refreshed count
for the complete suite or proof that all other 18 failures still reproduce.

TID source diagnostic: started at 20:07:27 +02:00, final output at 20:08:38;
observed interval 71s, not a controlled performance measurement. It used
`--no-alternate-source-c`, the existing 240-second analysis budget, and
`INERTIA_DEBUG_CALL_MATERIALIZATION=1`; it exits 4. The pstrlen summary proves
push sources `ret_reg(0x1038, ax)` and `global(28672, 2)`. Replacement is skipped
because the existing stack carriers score 12 while the candidate scores 7.
The candidate already has the correct global argument but retains the wrong
return carrier. The emitted producer is captured into a temporary before AX
publication. Source review shows `runtime_call_results.py` only proves direct
masked-call publication; a focused regression is still needed to establish the
capture/publication gap at that boundary. Preserve all placement, clobber and
duplicate-call vetoes when investigating it. TID is not fixed.

Evidence: `.cache/step9-runtime-artifact-live.log`,
`.cache/step9-byte-add-oracle-{controls,ruff,linters}.log`,
`.cache/step9-scalar-live-after.log`, and
`.cache/step9-tid-call-source-refresh.{c,log}`.

## Latest: Failure Inventory And Runtime Artifact Lifetime

At 19:59:56 +02:00, the last 22 failing nodes have been retried: **2 passed,
20 failed in 600.90s**. LoadProg and Overlay pass. This is a targeted inventory,
not a complete-suite result. Main now times out at its existing recovery budget;
its earlier reporting repair does not guarantee acceptance under this run.
SetGear separately passes its later unchanged retry, including compiled behavior
(13.94s call, 41.65s pytest wall), but its earlier cold/load failures are unresolved.

Remaining groups: TIDShowRange semantic validation; LIFE/HeapSort/main timeouts;
output-shape, declaration and call/store assertions in strlen, indexed aggregates,
SwapBars, DrawBar, BubbleSort, HeapSort, InitMenu, DrawFrame, ReInitBars, InitBars,
Beep and MS C add_sc; and the MS C sub_ulong missing-artifact race. These are
observed assertions, not permission to label them cosmetic without proof.
Slowest cases: MS C fixture setup 385.52s/326.24s, TIDShowRange 320.29s,
InitBars 245.81s, two InitMenu cases 120.16s/118.96s.

The runtime artifact cache had a proven lifetime defect: a partially failed batch
returned successful sibling files from a shared uncommitted cache directory.
A second producer deleted those files while retrying. Incomplete batches now
move under a unique caller-owned directory before releasing the producer lock;
uncacheable runs likewise use separate attempt directories. Failure statuses
and cache eligibility are unchanged. Four deterministic regression cases cover
failed/timed-out siblings with cacheable/uncacheable inputs; both pairs failed
before their respective corrections. The cache tests are now in the routine
pipeline. Related cache/pipeline/ownership tests: **121 passed in 12.91s**.
Scoped parallel Ruff --fix, MyPy and type/doc gates pass. The cache module stays
below 350 lines. No real MS C retry or full pipeline has yet been rerun after
this tooling repair, so the 20-failure inventory is not reduced speculatively.

Evidence: `.cache/step9-outstanding-22-refresh.log`,
`.cache/step9-setgear-warm-retry.log`,
`.cache/step9-runtime-artifact-lifetime-{before,controls,linters}.log`, and
`.cache/step9-runtime-artifact-uncached-before.log`.

## LoadProg Routine Enrollment And SetGear Timeout Refresh

Follow-up on September 19: the default pipeline completed with 5,752 routine
tests passing and one SetGear subprocess timeout (45 seconds); routine wall
time was 558.60s. QuickC passed in 105.627s and MS C tiny full round trips in
177.608s. The pipeline is failed, not green. Configured global `make mypy`
exited 0; global quality remains Ruff-blocked.

SetGear also times out in an isolated pytest retry at its unchanged limit
(76.60s pytest wall). A direct CLI diagnostic, with the same 30-second analysis
limit, exits 0 and reports clean whole-tail validation; its logged recovery and
decompilation interval is 19:42:25-19:42:50 +02:00. This does not establish a
performance fix or explain the test timeout. Startup, cache state and environment
remain to be separated; no timeout was increased in the test.

LoadProg now explicitly disables alternate-source C and is enrolled in the
routine pipeline. Its strengthened live test plus pipeline tests pass: 51 passed
in 46.27s, LoadProg call 15.33s. Ruff --fix reports 35 remaining findings in the
legacy COD test file and none in the pipeline selection file. No whole-suite
completion is claimed.

Evidence: `.cache/step9-byte-binding-and-projection-pipeline.log`,
`.cache/step9-byte-binding-and-projection-mypy-all.log`,
`.cache/step9-setgear-timeout-retry.log`, `.cache/step9-setgear-diagnostic.{c,log}`,
and `.cache/step9-loadprog-enrollment-{tests,ruff}.log`.

## Latest: LoadProg Byte-Source And Projection Closure

Observed investigation interval: **19:02:55-19:24:19 +02:00**, 21m24s wall
including overlapping focused tests, diagnostics and checks, not pure coding
time. The isolated final run starts at 19:21:34 with a temporary cache namespace
and `--no-alternate-source-c`; it exits 0 with `validation=passed` and clean
whole-tail validation. The existing live LoadProg acceptance test then passes,
including portable-flat C recompilation (24.70s pytest wall, 3.95s test call).

Two generic owners were repaired:

- Alias already proves AL comes from SS:BP+8 and AH is zero on every path to
  both switch comparisons, but whole-AX tracking conservatively lost these
  separate definitions. `alias/condition_register_storage.py` composes those
  existing proofs into a masked byte value. Register layouts come from the
  authoritative architecture; unknown lanes, nonzero upper bytes, conflicting
  paths, stale memory, ES/DS confusion and uncovered EAX bits remain refused.
  Storage conversion was extracted from `condition_register_bindings.py`, which
  shrinks from 358 to 348 lines. No instruction decoding or C recovery was added.
- CLI bitwise flattening rebuilt tagged byte-view expressions without their
  existing Lowering projection facts. Cleanup now delegates term traversal to
  `postprocess/bitwise_terms.py`, which leaves evidence-bearing projections
  atomic. It neither invents facts nor copies a projection onto a changed mask.
  The CLI file shrinks; Validation remains unchanged.

Fail-first evidence: 9 valid byte-binding cases failed and 8 refusal cases
passed before the Alias fix; four low/high-byte projection-preservation cases
failed before cleanup delegation. The related Alias/cleanup/pipeline/ownership
set passes **173 tests in 20.55s**. Two more segment cases are enrolled in the
running pipeline refresh. The live test's old AX-carrier assignment assertion
was replaced by exact low/high `cmdline` assignments verified against the
listing; signature, return counts, forbidden artifacts and recompilation checks
remain mandatory. The acceptance test itself is still outside the routine
selection; add an explicitly no-alternate-source-C variant to the routine lane
at the next coherent test enrollment checkpoint.

Scoped new/edited Alias, cleanup helper and regression Ruff --fix, MyPy and
type/doc gates pass; full architecture passes. The legacy CLI file retains 99
Ruff findings. Its isolated MyPy check reports context-dependent unused
redundant-cast suppressions; do not remove those blindly when imported owners
are omitted. Global `quality-fast` remains Ruff-blocked and its 39-module mypyc
import smoke passes. The default pipeline is being refreshed; do not reuse the
previous 5,720-pass result as evidence for these subsequent edits. Complete
collection, expanded pipeline and Step 9 acceptance remain open.

Evidence: `.cache/step9-loadprog-register-bytes.log`,
`.cache/step9-condition-byte-extension-{before,after,controls,ruff,mypy}.log`,
`.cache/step9-bitwise-projection-before.log`,
`.cache/step9-byte-binding-and-projection-{controls,linters-final,architecture,quality}.log`,
`.cache/step9-loadprog-projection-loss.log`,
`.cache/step9-loadprog-byte-view-final.{c,log}`, and
`.cache/step9-loadprog-byte-view-live-after.log`.

## Earlier: Unproven Comparison Registers

The LoadProg diagnostic traced the undefined AX reads to the legacy JCC
comparison resolver. When current state, instruction-indexed expressions and
prior stack-load evidence all failed, it constructed a new bare physical-register
CVariable. Late cleanup consequently replaced the defined SSA value `v14` with
an uninitialized AX read. The resolver now refuses that fallback, preserving
the existing condition. This removes unsafe recovery from the legacy bridge;
it adds no new semantic recovery to Rewrite or CLI.

The focused refusal regression fails before the fix (1 failed, 3 passed), then
the related condition and pass-order set passes **105 tests in 18.11s**. Positive
legacy decode fixtures now supply instruction-indexed register values rather
than depending on invented registers; their predicate and call-result assertions
remain intact. Missing-evidence refusal and all three existing evidence sources
are covered. The new regression is enrolled in Make, the routine pipeline,
architecture checks and ownership. Full architecture and the new test's Ruff
check pass; touched legacy files still have lint debt, not suppressed.

The isolated-cache live run with `--no-alternate-source-c` removes both
uninitialized AX diagnostics. LoadProg still exits 4 with two missing branch
surfaces (`0x10b1`, `0x10b9`). Existing conditions keep their SSA definitions
but do not carry proven Structuring ownership. Do not add tags merely to
satisfy validation: trace condition materialization and coordinate/polarity
evidence. Function acceptance and Step 9 remain open. The refreshed default
pipeline finishes by 18:58:49 +02:00: **5,720 routine tests pass in 413.24s**,
plus 268 preliminary tests in 25.05s. QuickC and MS C tiny full round trips
pass; three stages pass, none fail, skip or time out. This does not prove
complete-suite or expanded-pipeline acceptance, and is not a speedup claim.
Log: `.cache/step9-jcc-evidence-pipeline.log`.

The optional source/listing oracle independently places `type` at BP+8
(`cod/DOSFUNC.COD`, LoadProg entry), loaded into AL and zero-extended with
`sub ah, ah`. Retained output assigns `v13 = type & 0xffff`, then
`v14 = v13 & 0xff`, before comparisons with 1 and 3. Do not reverse the
BP+4-to-BP+8 projection merely to match an older snapshot; trace the machine
storage and semantic-view identities. The more verbose diagnostic rerun under
concurrent pipeline load timed out at its unchanged 60s limit and adds no
acceptance evidence. Run the next isolated diagnostic after the pipeline.

That isolated diagnostic completed with exit 4 after the pipeline. It narrows
the remaining boundary: the switch's `ConditionIR` at `0x10b1` has a physical
AX operand with `register_bindings=()` and `operand_bind_insn=None`.
`materialize_condition_ir_expression_8616` returns None; same-block projection
reports one raw operand and zero normalized/materialized operands. The existing
C value is defined in the entry block, not the comparison block. The multi-arm
candidate is visited (not a traversal omission), but its first operand cannot
be materialized. The closure publishes three required conditions and only one
materialized condition. Next: trace the exact cross-block SSA value into the
ConditionIR/binding contract, with a generic regression. Do not add bare-register
recovery or unproven coverage tags. Evidence:
`.cache/step9-loadprog-condition-coverage-isolated.log`.

Direct scoped MyPy passes. `quality-fast` exits 2 on global Ruff findings;
its 39-module mypyc import smoke passes. No lint exclusions or validation
requirements were weakened.

Evidence: `.cache/step9-jcc-evidence-{before,after,ruff,linters,architecture}.log`,
`.cache/step9-loadprog-condition-owner.log`, and
`.cache/step9-loadprog-condition-refusal.{c,log}`.

## Current Evidence

After the named Sleep fixes, `make test-pipeline PYTHON=./.venv/bin/python`
passes all three stages, with `PYTHON_JIT=1 PYTHONHASHSEED=0`:

- Prerequisites: 268 passed in 8.02s.
- Routine: 5,544 passed in 297.46s (298.013s stage wall time).
- Four QuickC fixtures: passed, 43.067s.
- Seven MS C tiny compile/decompile/recompile/execute cases: passed, 90.236s.
- No failed, skipped, or timed-out pipeline stages.

Log: `/tmp/step9-current-test-pipeline.log`. Structured stage report:
`angr_platforms/.cache/test_pipeline/summary.json` (overwritten by later runs).
Slowest routine tests: InitBars 107.89s, InitMenu 98.66s, RunMenu 75.19s,
InsertionSort 67.77s. The routine stage remains above its 30s advisory budget.

## Historical Failure Retry

Retried the 47 failed nodes from the September 12 complete audit using
`pytest -n 7 -q --tb=short --no-header --durations=10`. The old InBoxLng
parameter was moved to
`test_x86_16_inbox_long_live.py::test_inbox_long_passes_validation_and_compiled_behavior`;
that stronger live test was used, not dropped. The first unmapped retry
executed no tests; it supplies no acceptance evidence.

Mapped result: **25 passed, 22 failed in 381.32s**.
Log: `/tmp/step9-previous-failures-mapped.log`.
This is a targeted retry, not a full-suite result or a count of every remaining
failure. It does not establish source-stable whole-collection acceptance.

## Prioritized Remaining Groups

| Priority | Observed failures | Next proof obligation |
| --- | --- | --- |
| P0 | Overlay function-address helper: uninitialized stack reads; LoadProg: missing branch surfaces; TidShowRange: failed validation; named SORTDEMO main: failed validation scorecard | Reproduce individually, distinguish failed accepted output from rejected attempts, then fix the earliest semantic owner. Require clean validation and compiled behavior where applicable. |
| P1 | Two MS C scalar tests cannot find `add_sc` / `sub_ulong` captured CLI artifacts | Inspect runtime-gate artifact generation and its cache contract. Preserve the independent CLI width assertions; passing the seven example round trips does not replace these artifacts. |
| P1 | LIFE pause-screen timeout in clinic peephole optimization (8s internal budget) | Rerun alone before attributing to a regression under seven-worker contention. Do not expand into out-of-scope x87/FPU work or weaken timeout enforcement. |
| P1/P2 | Fifteen output-shape/naming assertions across strlen, indexed aggregates, InitMenu, DrawBar, DrawFrame, SwapBars, HeapSort, BubbleSort, ReInitBars, InitBars, and Beep | Check binary/source semantics and current output before updating tests. Some bans now catch legitimate saved-register locals, but this does not prove every mismatch harmless. Replace brittle checks with equivalent or stronger behavior/typed-contract coverage, not broader accepted text. |

No failing test has been deleted, skipped, or declared obsolete by this retry.
No timeout or validation rule was relaxed. Global quality and full-suite
closure remain open. Keep the separate 20/20 SORTD validation and 21/21 C
recompilation evidence in `step9-current-comparison.md`; neither proves all
named/COD paths or all tests pass.

## Follow-Up: Main Reporting Verdict

The isolated named `main` CLI run returned 0 and published clean whole-tail
validation for its accepted sidecar-slice fallback. The scorecard incorrectly
selected `validation=failed` from an earlier rejected attempt. Thus this case
was a reporting defect, not evidence that the accepted body failed validation.
Evidence: `/tmp/step9-main-live.log` and `/tmp/step9-main-live.c`.

The reporting owner now prioritizes the final anchored whole-tail report over
attempt diagnostics, while retaining structured metadata precedence and using
the existing typed display status. This changes neither C recovery nor semantic
acceptance. Fail-first controls also exposed a prior clean report masking a
final unknown/uncollected verdict; those outcomes remain non-passing after the
fix. Malformed structured metadata is not accepted as evidence.

Acceptance: 14 reporting/live-main tests passed in 20.46s; the live test took
14.38s. Another 132 scorecard/pipeline/ownership/Makefile tests passed in 8.78s.
The scorecard file is now explicitly enrolled in routine tests, Make lint/test
lists, and focused ownership. Scoped Ruff `--fix`, MyPy, type/docs, startup
architecture, agent-context, and ownership gates pass. Understand-Anything
auto-update remains disabled; the graph service remains unavailable.

Logs: `/tmp/step9-main-scorecard-final.log`,
`/tmp/step9-scorecard-enrollment.log`, `/tmp/step9-scorecard-all-linters.log`,
and `/tmp/step9-scorecard-contracts.log`.
This individually resolves one of the 22 retry failures. The other 21 are not
rechecked by this focused result, and the pipeline above predates this reporting
change. Next P0: isolate Overlay's uninitialized stack reads, LoadProg's missing
branch surfaces, and TidShowRange's validation failure. No full-suite or Step 9
closure is claimed.

## Follow-Up: Overlay Return Corruption

Overlay reproduces in isolation with CLI exit 4 and uninitialized-stack-read
diagnostics. It also has an independently proven wrong return, so clearing those
diagnostics alone is not acceptance. The binary listing copies SI into DX at
offset 0x1ad, then restores SI at 0x1b1. The emitted return instead reads SI
after restoration. No source/name-specific recovery was added.

The new compiled oracle checks 54 combinations of load segment, slot index,
return segment and return offset, plus preserved SI. Unchanged generated C
compiles but fails its first case: expected `00000000`, actual `56780000`,
preserved SI `12345678`. Oracle controls accept the correct expression and reject
restored-SI-as-return, saved-SI corruption, and wrong table stride (four tests
pass in 5.80s). It is attached to the existing live Overlay acceptance test;
future validation success must also pass execution, not only compilation.

An isolated-cache in-process probe observed 205 custom Structuring/Postprocess
pass applications. The faulty expression already exists at their entry; only
annotation names change afterward. A second probe located the substitution in
initial segment/global Lowering, and 36 component observations narrow it to
`lowering/segmented_memory_lowering.py::apply_runtime_segment_lowering_8616`:
the captured `v14` high word becomes a read of current `inertia_esi`.
Next action: preserve definition-time register values across later restores in
that owner, and separately account for byte-covered stack definitions. Do not
repair return text or relax either validation obligation.

Evidence: `/tmp/step9-overlay-live.c`, `/tmp/step9-overlay-live.log`,
`/tmp/step9-overlay-probe.log`, `/tmp/step9-overlay-boundary.log`, and
`/tmp/step9-overlay-components.log`. No Overlay fix is claimed yet.
Oracle and enrollment checks pass 123 tests in 8.20s. The new test module is
enrolled in the routine pipeline, Make tests/lint, and return-owner checks.
New-module/tooling Ruff, MyPy and type/doc checks pass; the touched legacy COD
test module retains 35 lint findings. Gates were not weakened.

The next probe further isolates the owning operation to
`lowering/gp_register_state.py::lower_architectural_gp_register_state_8616`,
called by runtime segment lowering. Before that call, the AST has distinct
assignments `v14` (`SimRegisterVariable.ident=ir_9`, SI, instruction 0x1029)
and `v15` (`ident=ir_10`, SI, instruction 0x1033). The return uses `v14`,
whereas `v15` restores the incoming saved SI. The transformation projects both
by physical offset/width and the live-in parent name, discarding version identity.
The existing `_c_register_identity_8616` already distinguishes these identities
for live-in analysis, but the rewriting path does not consume that distinction.
Evidence: `/tmp/step9-overlay-gp.log` (`GP_PROBE` records).

Implementation obligation: preserve definition-time values when projecting
versioned register variables to mutable runtime state; publish actual register
writes as well, rather than merely keeping locals and losing architectural
effects. Cover distinct same-register definitions, a later restore, calls,
partial-width writes, and declaration/replay coherence. Do not special-case
SI, Overlay, a return expression, or these instruction addresses. Unknown
ordering/ownership must not authorize a version-collapsing substitution.

## Follow-Up: Version Capture And Byte Coverage

`lowering/gp_register_versions.py` now preserves exact, uniquely defined register
versions in typed temporaries before mutable architectural-state projection.
Each original write still publishes its value to the runtime register, with
partial-width handling left to the existing owner. Captures evaluate the RHS
once, register their declarations/types, retain replay counters, and refuse
unproved dominance before mutation. No register or function is special-cased.

The first implementation regressed DrawBar: it incorrectly required every
definition to occur in the top-level linear sequence. Two fail-first tests
demonstrated branch/loop-local definitions. The proof now accepts a statement
group only when every function-wide use follows the definition within that
group; an escaping read still refuses. All 29 register-state/capture tests pass.
DrawBar's isolated CLI ran 15:18:50-15:19:16 +02:00 (26s), exited zero, passed
Tail Validation, and its unchanged output passes strict GCC syntax checking.
The whole SORTD gate ran 15:19:32-15:23:08 (216s, with other checks overlapping):
**20/20 emitted and validated, zero violations/timeouts/tracebacks**. This is
not a controlled performance measurement or a refresh of the saved C snapshot.

The Overlay return now uses a captured value rather than restored SI. Its
54-case compiled return/ABI oracle passed on the earlier isolated output, but
the full function is still not accepted. A second probe showed that def-use
validation ignored typed byte-pointer indices into scalar locals. The new
`validation_indexed_bytes.py` consumes exact C AST address-of/cast/index facts;
the existing dataflow owner proves containment and credits only that byte.
Both complete byte pairs pass; missing, repeated, conditional, out-of-range,
dynamic, indirect, or unrelated storage cannot prove a complete word. Exact
byte reads are now checked as well, rather than being silently unclassified.

Fail-first byte tests: four failed, six passed. After the fix, the related
validator/oracle surface passes 82 tests; the live Overlay test still fails.
Tail Validation is clean for its machine-storage ranges, but the independent
final C guard correctly rejects `unassigned-stack-local`: `gp_saved_dx_100f`
and `gp_saved_dx_1018` are read while different local objects receive the byte
stores. Physical stack coverage is not C-object initialization. Neither guard
was disabled or treated as equivalent to the other.

New helper/test modules and tooling pass scoped Ruff `--fix`, MyPy and type/doc
checks. The touched legacy dataflow module retains 12 lint findings; global
`quality-fast` still fails at Ruff, while its 39-module mypyc import smoke passes.
That pipeline refresh passed 5,605 routine tests in 446.51s and four QuickC
fixtures, but failed the `pointer_memory` MS C round trip. It predates the
repairs below. Graph discovery/coverage remains unavailable
(`Transport closed`); these findings use exact source and runtime probes.

Evidence: `/tmp/step9-gp-nested-{before,after}.log`,
`/tmp/step9-gp-drawbar-fixed.{c,log}`, `/tmp/step9-gp-sortd-fixed.{json,txt}`,
`/tmp/step9-indexed-before.log`, `/tmp/step9-overlay-fix-tests.log`,
`/tmp/step9-overlay-snapshot.{c,log}`, `/tmp/step9-gp-byte-new-linters.log`,
and `/tmp/step9-gp-byte-quality.log`.

## Follow-Up: Exact Alias Value Identity

The saved-DX locals were a downstream symptom of wrong Alias evidence, not a
reason to weaken C initialization checks. A 12-byte binary reproducer performs
`PUSH AX; PUSH DX; LES SI,[BP-4]`: SI must receive DX, while ES receives AX.
Both imported word expressions have the label `expr:Iop_Or16`, but distinct
`IRValue.source_tmp` identities. Alias incorrectly used the last expression
with that label and claimed that SI restored AX. LDS has the same defect.

`alias/segment_stack_restore.py` now publishes byte fragments under exact
temporary identities as well as legacy names. `segment_stack_fragments.py`
uses the exact identity when present and refuses an absent definition instead
of borrowing a shared expression label. IR already retained the correct facts;
no lifter, Rewrite, Postprocess, CLI, instruction-address or function-name
special case was needed. All three fail-first controls now pass. The related
Alias/register/ownership/live-Overlay set passes **126 tests in 34.10s**.

Overlay's live test now passes: CLI exit zero, Tail Validation clean, no final
C initialization rejection, recompilation successful, and all 54 compiled
far-return/preserved-SI cases pass. A parentheses-only return regex was removed
in favor of that stronger compiled oracle; corrupted return/SI/stride controls
remain enrolled. No semantic assertion was dropped without replacement.

The MS C pointer fixture exposed an additional integration obligation: scalar
snapshots must use the existing guest-pointer-offset projection. More
importantly, a version consumed entirely before the next overwrite needs no
capture. Lowering now proves that lifetime in its dominating statement group;
effectful calls, unknown writes, and compound/backedge overwrites remain
conservative. This preserves the original pointer object when no snapshot is
needed rather than unnecessarily turning it into a numerical memory address.
Two lifetime tests fail before this adjustment and pass afterward. The final
register-state/live-Overlay set passes **33 tests in 35.38s**. The pointer MS C
fixture again passes build, original execution, decompilation, recompilation,
and rebuilt execution with matching exit code 255.

The 20-function SORTD gate also passed after the Alias correction and pointer
projection repair, before the final lifetime narrowing; all 21 exports compile.
Scoped
new-module Ruff/MyPy/type-doc checks pass, and the changed Alias files pass
MyPy. Legacy Ruff findings in the Alias/dataflow owners remain visible.

Evidence: `/tmp/step9-les-restore-proof.log`,
`/tmp/step9-alias-identity-before.log`, `/tmp/step9-alias-pointer-focused.log`,
`/tmp/step9-overlay-pointer-check.log`, `/tmp/step9-version-lifetime-{before,after}.log`,
`/tmp/step9-pointer-lifetime-roundtrip.log`, `/tmp/step9-alias-sortd.{json,txt}`,
and `/tmp/step9-overlay-closed-pipeline.log`.

### Final Batch Gates

The refreshed pipeline on the final semantic sources ran all three lanes:

- Prerequisites: 268 passed in 12.79s.
- Routine: **5,608 passed, three timed out**, 484.36s.
- QuickC: all four fixtures passed, 51.367s.
- MS C tiny: all seven full round trips passed, 150.868s.

The three timed-out tests are InBoxLng's compiled behavior, the DOS load-program
wrapper, and SetGear's guard logic. They all pass in a separate focused rerun
with the same timeout limits and `-n 7` (34.95s overall; call times 10.78s,
13.35s, and 17.16s respectively). That does not turn the broad run green.
Contention/cache sensitivity still needs a controlled investigation; no timeout,
validation rule, test, or gate was weakened. The broad run overlapped targeted
architecture/compile checks and is not a controlled performance benchmark.

Full architecture checks pass after adding the new helpers to the promotion
inventory. New-module scoped lint/type/doc gates and changed Alias MyPy pass.
`quality-fast` still exits 2 on repository Ruff debt; its 39-module mypyc import
smoke passes. `git diff --check` passes. No current whole-pytest-collection pass
or Step 9 completion is claimed. Next: close the remaining named-function
failures and output-contract mismatches from the historical retry, stabilize
the broad timing gate, and complete full-suite/global-quality acceptance.

Final logs: `/tmp/step9-overlay-closed-pipeline.log`,
`/tmp/step9-timeout-recheck.log`, `/tmp/step9-overlay-architecture-final.log`,
`/tmp/step9-lifetime-linters.log`, `/tmp/step9-alias-pointer-mypy.log`, and
`/tmp/step9-overlay-final-quality.log`.

The final-source whole-SORTD run completed at 16:05:10 +02:00, having started
at 16:02:50 (140s observed wall time). It emitted and validated **20/20**
functions with zero violations, timeouts, or tracebacks. All 20 individual
exports and the combined translation unit pass GCC recompilation (**21/21**).
Evidence: `/tmp/step9-overlay-final-sortd.{json,txt}`, the exports in
`/tmp/step9-overlay-final-sortd-functions/`, and
`/tmp/step9-overlay-final-compile.log`. These are fresh acceptance results;
the older checked-in comparison snapshot has not been replaced.

## Captured Register Values And TID Reload Proof

Current-source reproduction of LoadProg and TIDShowRange: both fail, 57.94s
combined. LoadProg reports missing condition surfaces at `0x10b1/0x10b9` and
still splits its command-line pointer argument. TID initially stops earlier:
one Alias-proven AX local reload is classified but not materialized.

An isolated-cache, in-process observer establishes the exact mismatch. The
machine stores AX at `0x1049` and reloads its two bytes at `0x1054`, entry-SP
`-16/-15`. The C projection captures the pstrlen result into a temporary,
publishes that temporary into runtime AX, then stores the same temporary's low
and high bytes into the local. Lowering's existing verifier recognizes direct
AX byte stores, but not that already-materialized equivalent value.

`lowering/gp_stack_local_reload.py` now consumes this representation with an
explicit proof: a uniquely defined unsigned word temporary, no address escape
or self-read, an unconditional dominating exact parent-register publication,
no intervening register clobber/call, and adjacent complete local byte stores.
Unstructured gotos refuse the new proof. Existing Alias storage identity,
instruction identity, address-escape, byte completeness and reload-dominance
checks remain required. No new snapshot, call, memory effect or C rewrite is
introduced, and no gate is weakened. The module remains below 350 lines.

The new positive control fails before the repair (1 failed, 31 passed).
Afterward, the 51-test related register/reload surface passes in 19.36s. Controls
refuse undefined, late, multiply defined, escaped and self-referencing values;
conditional definitions; wrong publications/registers; clobbering calls/writes;
signed snapshots and wrong byte shifts. Scoped Ruff `check --fix`, MyPy and the
type/doc ratchet pass. Existing ownership and routine-pipeline enrollment already
cover this module and test file. `quality-fast` exits 2 on repository lint debt;
its 39-module compiled-import smoke passes.

The live TID test now passes the GP materialization gate and reaches final
validation, but still fails (129.27s test body, 138.85s pytest wall). Its current
absolute guard reports 15 uninitialized reads, one duplicate callsite and three
missing branch surfaces. This is NOT a function fix or a speedup: the previous
run stopped early. The unchanged compiled behavior oracle remains mandatory.
Current output also requires checking signed text-width division and the
ten-byte string buffer, not just clearing diagnostic counts. Next owners:
call-argument Lowering, Alias saved-SI provenance, typed condition Structuring,
and per-path call multiplicity validation. Do not repair these in Rewrite.

Diagnostic/implementation window observed from 16:13:55 through the live result
at approximately 16:20 +02:00 on September 19; this includes test waits and is
not an isolated engineering-time measurement. Broad acceptance refresh follows.
Evidence logs under `/tmp/`: `step9-remaining-named-before.log`,
`step9-tid-restore-probe.log`, `step9-published-snapshot-before.log`,
`step9-published-snapshot-focused.log`, `step9-tid-published-snapshot-live.log`,
`step9-published-snapshot-mypy.log`, `step9-published-snapshot-quality.log`.

Review follow-up: a deliberate register overwrite inside a multi-statement
expression exposed another refusal requirement (one failing new test before
the guard). Publication now refuses nested writes, dirty expressions and
multi-statement effects as well as calls. The final related set passes **52
tests in 17.26s**. Make's scoped linter target also exposed an existing `Any`
return under the project import policy; the Boolean proof now returns an
explicit Boolean. `make linters-files` passes Ruff/MyPy/type-doc checks for the
changed production module and Ruff for its tests. The routine audit collected
before the final extra control and ran during this hardening: **5,624 passed,
one InBoxLng timeout in 411.06s**. This is not a source-stable final audit or a
green broad run. No timeout was changed. Final focused evidence:
`/tmp/step9-snapshot-final-focused.log`,
`/tmp/step9-snapshot-final-linters.log`,
`/tmp/step9-snapshot-nested-before.log`.

The pipeline finishes with QuickC passed (40.244s) and MS C tiny full round
trips passed (128.874s); its overall exit remains failure because of InBoxLng.
Full architecture checks pass on the final source. Logs:
`/tmp/step9-published-snapshot-pipeline.log` and
`/tmp/step9-snapshot-final-architecture.log`. This checkpoint does not close
TID, LoadProg, the full suite, global quality, or Step 9.

Final-source focused recheck: **53 passed in 22.32s**, including InBoxLng with
unchanged timeout limits (10.15s test body). Evidence:
`/tmp/step9-snapshot-final-recheck.log`. The isolated success does not erase
the failed routine run or establish that contention is its only cause.

## Recovered CFG Cache Coherence

Checkpoint: September 19, 16:53 +02:00. Investigation started in the preceding
continuation; the precise active-work duration was not recorded. Do not treat
the intervening elapsed time or live-test durations as engineering-time totals.

Root cause: recovery inserted edges directly into angr's `transition_graph`
after `function.graph` had cached an empty local graph. LoadProg had 21 live
transition edges but zero cached local edges. Its raw IR jump connectors had
correct successors, then the importer correctly consumed the stale frontend
graph and replaced them with empty successors. SSA therefore had no predecessor
edges, and Structuring correctly refused its disconnected condition ladder.
This is graph bookkeeping at the existing recovery owner, not permission to
recover CFG semantics in CLI, Rewrite, or validation.

Both recovery insertion paths now call angr's `_transit_to`, which maintains
the derived cache, and graph reset explicitly clears `_local_transition_graph`.
Real-angr regressions cover warm/cold caches in both paths and reset, checking
the transition graph, local graph, IR successors and SSA predecessor map.
Before the fix: three regressions failed. After correcting a misplaced old
assertion in the test edit: **71 passed in 9.66s**. Enrollment tests:
**110 passed in 4.12s**. The graph regression is in the routine pipeline and
the changed-file ownership manifest. Full architecture checks pass.

Current live tests: **two failed in 111.30s**, not accepted functions:

- TIDShowRange: 15 uninitialized reads and one duplicate callsite remain.
  Missing branch surfaces decrease from three to one (JCC `0x109f`). This is
  evidence of improved CFG delivery, not full semantic or performance closure.
- LoadProg: connected SSA exposes a proven AX save at `0x10cb`, reload at
  `0x10e6`, entry-SP bytes `(-4, -3)`. C already saves the call-result temporary
  as two bytes of a word local, then returns that local. The current terminal
  reload proof refuses: block `0x10e3` reaches the shared return block `0x110d`
  (RET `0x1110`), while the Semantics helper accepts only same-block returns.
  Lowering also requires a single whole-local store in this return path.
  These are separate proof obligations; do not merely mark the fact consumed.

Next work must prove unchanged register flow across exact CFG edges, preserve
per-path ownership at shared returns, and reuse exact initialized byte-store
evidence in Lowering. Other paths returning zero must not be forced to use this
local merely because they share an epilogue. Calls, clobbers, ambiguous paths,
missing stores and escaping storage must continue to refuse.

Scoped Make MyPy/type-doc checks report no errors. Ruff reports 121 findings
across selected files; global `quality-fast` also remains Ruff-blocked, while
the 39-module compiled import smoke passes. No gate was weakened. No
final-source whole-SORTD claim is made.
Graph MCP indexing/coverage calls failed with `Transport closed`; this analysis
uses exact source and live instrumentation, not exhaustive graph evidence.

Evidence: `/tmp/step9-graph-cache-before.log`,
`/tmp/step9-graph-cache-after2.log`, `/tmp/step9-graph-enrollment.log`,
`/tmp/step9-loadprog-graph.log`, `/tmp/step9-graph-cache-live.log`,
`/tmp/step9-loadprog-return.log`, `/tmp/step9-loadprog-return-ir.log`,
`/tmp/step9-graph-cache-linters.log`, `/tmp/step9-graph-architecture.log`,
`/tmp/step9-graph-quality.log`, `/tmp/step9-graph-pipeline.log`.

### Pipeline Result And Binary-Proven Test Correction

At the 17:06 +02:00 checkpoint, the pipeline is terminal (exit 2). Its
prerequisite lane passed 268 tests in 11.98s. Routine pytest reports **5,640
passed, two failed in 375.45s** (376.131s stage wall). QuickC passes in 52.895s;
all MS C tiny compile/decompile/recompile/execute round trips pass in 113.500s.
Slowest routine tests: sidecar-free InitBars 110.54s, InitMenu pause 100.93s,
RunMenu Escape 85.77s, InsertionSort 63.95s, and DrawTime 53.72s. These timings
are from concurrent execution, not isolated optimization measurements.

The two routine failures were InBoxLng's unchanged 17-second effective analysis
budget and an InitBars topology test. The latter first required at least one
IR successor repair, which a coherent frontend graph no longer needs. Replacing
that incidental requirement with exact successors and balanced counters then
exposed its stale predecessor expectation. Live binary decoding proves:

- `0x10654` ends after its color store, then falls through to `0x10666`;
- `0x10647` jumps to `0x10666`;
- `0x10666` alone jumps to the update at `0x105f8`.

The old expectation incorrectly included a direct `0x10654 -> 0x105f8` edge.
The corrected test checks both intermediate predecessors, all three successor
edges, the exact update/guard edges, and closed rewrite counters. Every existing
condition, indexed-address, initializer, increment, dynamic-bound refusal, and
array-materialization refusal assertion remains. No test was deleted or skipped.
Meaningful fixture constants also clear this touched test's seven Ruff findings.
The production implementation did not change during the broad pipeline; these
test corrections happened after its routine stage, so it is not a final-test-tree
green audit.

Final focused retry: **18 passed in 28.36s**, including all graph coherence
regressions, the complete corrected InitBars test (5.22s), and InBoxLng with
unchanged limits (3.86s). An earlier focused InBoxLng retry also passed (7.54s).
This does not establish that contention is the timeout's sole cause or close the
full-suite gate. Evidence: `/tmp/step9-initbars-cfg.log`,
`/tmp/step9-graph-final-focused.log` (exposes the stale edge),
`/tmp/step9-graph-final-focused2.log`, `/tmp/step9-topology-ruff.log` (clean),
and `angr_platforms/.cache/test_pipeline/summary.json` (failed broad run).

## Shared-Epilogue Register Value Proof

Checkpoint: September 19, 17:22 +02:00. The fail-first log completed at
17:10:58; the expanded controls at 17:14:36; the AIL-origin probe at 17:19:30.
These are observed log-completion timestamps, not active engineering time.

`semantics/register_definition_return.py` now produces a typed immutable
`RegisterReturnPath8616`: definition address, register, ordered CFG blocks and
return address. It follows exact single-successor IR edges, including empty
connectors. A shared epilogue is allowed, but the evidence proves only the
selected definition's path, not all predecessors' values or all C projections.
The existing return-site consumer derives its address from this proof.

Four fail-first regressions failed before implementation: a valid cross-block
return was refused; a later CALL or unknown effect with the same instruction
address as the definition was silently ignored; and a RET with an outgoing
edge was accepted. New controls also refuse clobbers of overlapping register
views, malformed widths/definitions, duplicate blocks, missing targets, branches,
cycles, refusal-bearing IR, trailing effects and missing return addresses.
Lowering's shared-return counterexample still rejects a wrong C return copy;
machine path evidence alone must never close that storage/value obligation.

Before: **4 failed, 17 passed in 11.66s**. Related controls: **73 passed in
11.89s**. Final related plus existing enrollment tests: **183 passed in 17.26s**.
The touched Semantics module and tests pass Make's scoped Ruff/MyPy/type-doc
checks. Full architecture passes. `quality-fast` remains blocked by global
Ruff findings; its 39-module compiled import smoke passes. The existing module
and test files were already enrolled in routine, ownership and typed gates.
No broad pipeline was rerun for this incomplete function fix.

Live isolated-cache probes still exit 4 at the GP materialization gate, but
the machine proof now reaches RET `0x1110` from the saved-value reload at
`0x10e6`, through blocks `0x10e3 -> 0x110d`. The next root cause is confirmed
at native AIL-to-C conversion:

| Projection | AIL value origin | C value origin | C return origin |
| --- | --- | --- | --- |
| return 1 | instruction `0x10a7`, block `0x10a4` | retained on constant | `0x1110`, block `0x110d` |
| return saved local | instruction `0x10e6`, block `0x10e3` | empty CVariable tags | `0x1110`, block `0x110d` |
| return 0 | instruction `0x1109`, block `0x1106` | retained on constant | `0x1110`, block `0x110d` |

The native `_handle_Stmt_Return` converts the AIL value and copies only the
return statement's tags to CReturn. A shared CVariable is not a reliable owner
for per-use instruction provenance. Preserve the value origin on the return
projection at conversion, then consume it with the owned machine-path proof
and exact initialized storage evidence in Lowering. Do not infer ownership
from the local's spelling, the printed C, or the shared RET address.

Remaining definition of done: origin survives the relevant conversion/cloning
paths without contaminating another use of the same variable; each returned
value is joined to its exact machine path; Alias-proven byte stores establish
the local's initialized value and dominance; source-equivalent calls, argument
classes, wide arguments and all three return paths survive; LoadProg passes
whole-tail validation and strict recompilation; required broad gates are green.
Definition of failure: treating provenance tags alone as semantic proof,
blessing every shared-RET projection from one definition, accepting missing or
corrupted stores, or repairing these semantics in Rewrite or CLI.

Evidence: `/tmp/step9-return-path-before.log`,
`/tmp/step9-return-path-controls.log`, `/tmp/step9-return-path-final-focused.log`,
`/tmp/step9-return-path-final-linters.log`,
`/tmp/step9-return-path-architecture.log`, `/tmp/step9-return-path-quality.log`,
`/tmp/step9-loadprog-return-path.log`, `/tmp/step9-loadprog-return-origin.log`,
and `/tmp/step9-loadprog-return-ail.log`. Graph MCP remains unavailable
(`Transport closed`); exact source and live instrumentation supplied evidence.

At 17:25 +02:00 the root filesystem is full, while `/home` has 21 GB free.
Test execution is held; this checkpoint is written on `/home`. No source,
uncommitted work, personal files or system logs were removed. No Step 9 or
LoadProg completion is claimed.

## Per-Use Return Origin And Alias Refusal Guard

Checkpoint: September 19, 17:50 +02:00. Disk capacity was rechecked: root has
7.5 GB available and home 15 GB. Tests resumed with TMPDIR under the project's
`.cache/step9-tmp`. This supersedes the disk hold above, not the open acceptance
requirements.

`lowering/codegen_return_origin.py` transports a frozen typed instruction/block/
width record from each native AIL return value to its CReturn. It copies the
native tags dictionary, never modifies shared CVariable tags, rejects malformed
or missing metadata, leaves other architectures unchanged, and installs
idempotently through compat. This is provenance transport only, not recovery.
The new module/test are enrolled in routine, ownership, typing and architecture
gates. Initial fail-first conversion evidence and the 165-test related/enrollment
run are retained in `.cache/step9-return-origin-{before,controls}.log`.

`gp_stack_local_return.py` consumes the record only after joining it to the
Semantics machine path. Another independently proven definition at the same RET
does not own this saved local; an unknown origin refuses. The original
initialization/storage checks remain mandatory. The consumer regression first
failed (1 failed, 16 passed, 12.84s), then the related set passed 97 tests.
A second fail-first regression exposed a missing Alias verdict guard: matching
fields with `UNKNOWN_REFUSE` were accepted. The consumer now requires PROVEN,
matching the existing local-reload boundary. Before: 1 failed in 27.66s. After:
**98 passed in 23.91s**, with durations requested (all reported calls below 1s).
Scoped Make Ruff --fix, MyPy and type/doc checks pass. Full architecture passed
before the final two-line verdict guard. Global quality-fast exits 2 at its
lint gate; the 39-module compiled import smoke passes. No global green claim.

The fresh isolated-cache LoadProg probe still exits 4. It confirms:

- All three CReturn projections retain distinct typed value origins.
- Both saved bytes at `0x10cb` consume the same native SimRegisterVariable,
  architecture offset 0, size 2, unsigned-short C type.
- That variable is defined by the call at `0x10c5` in block `0x10bd`.
- The value is not a SimTemporaryVariable snapshot published to runtime state,
  so `_published_snapshot_stores` does not prove this representation.
- The return is inside a conditional after an intervening call. Immediate
  assignment-prefix checks cannot establish the necessary ancestor dominance.

Next proof obligations: join the native call result to the machine save without
register-name guessing; verify both byte writes, uniqueness and no address
escape; prove their structured dominance over the exact saved-value return.
Unknown/clobbered/partial/late/wrong-value stores must refuse. Calls may not be
blanket-ignored. Whole-tail call/value/control checks and strict compilation
remain mandatory before declaring LoadProg fixed.

Current logs: `.cache/step9-return-origin-binding-before.log`,
`.cache/step9-return-origin-binding-after.log`,
`.cache/step9-return-alias-verdict-{before,after,linters}.log`,
`.cache/step9-return-binding-{architecture,quality}.log`, and
`.cache/step9-loadprog-binding-probe.{c,log}`. The pipeline refresh in
`.cache/step9-return-binding-pipeline.log` exits 0: **5,686 routine tests pass
in 455.62s**, plus 268 preliminary tests in 33.91s. QuickC passes in 60.526s;
MS C tiny full compile/decompile/recompile/execution passes in 116.171s.
The summary records three passed stages, zero failed/skipped/timed-out stages.
Slowest routine tests: InitBars 107.44s, InitMenu 96.93s, RunMenu ESC 85.65s,
InsertionSort 67.35s, DrawTime 49.42s. These are concurrent-run durations, not
isolated performance benchmarks. The machine also had an unrelated C++ build
during part of this session; this run is not a controlled performance comparison.
This supersedes the previous two-failure routine result, not the unresolved
complete-suite audit or live LoadProg/TID failures.
Graph project/coverage calls still fail with Transport closed; direct source
reads and live typed instrumentation are the evidence, not exhaustive graph
coverage. Step 9 remains open.

The subsequent isolated-cache probe (`.cache/step9-loadprog-summary-probe.log`,
exit 4) logs every summary returned by `callsite_summary_inventory_8616` at the
GP restore boundary: the inventory is empty on every observed invocation.
The restore hooks themselves execute, so this is not an unobserved worker or
cache-hit probe. This does not yet distinguish an absent carrier from a
collected-but-empty inventory. First trace the binary summary owner's
construction/publication order. Existing `_callsite_inventory_8616` in
`lowering/call_output_stack_objects.py` builds from native get_call_sites;
legacy postprocess call code also publishes inventories. These are investigation
leads, not proof of the cause. Do not add a duplicate value-recovery path to
compensate for missing upstream evidence.

## Call-Result Storage And Conditional Return Binding

Measured investigation interval: 18:04:33 to 18:19:24 +02:00 (14m51s, including
overlapping focused checks and live probes, not pure coding time). These times
come from creation of the inventory probe log and completion of the detailed
live-binding probe. Acceptance gates continue after that interval.

The inventory probe establishes that the carrier is absent, while native
callsites are available. Rebuilding through the existing binary summary owner
produces AX -> BP-2, width 2, store instruction `0x10cb`, from call `0x10c5`.
No new call/value discovery algorithm was needed. Lowering now shares the
existing call-output inventory initializer in `lowering/callsite_inventory.py`;
the large source module shrinks by 35 lines net. Missing native evidence stays
unknown, malformed published contracts still fail, valid inventories are
reused, and an empty inventory can be retried after discovery. The new owner
and tests are enrolled in routine, typing, architecture and ownership gates.

The missing-inventory folded-store regression fails before the change and
passes afterward. Its related/ownership set passes 142 tests in 17.37s.
Native call-result byte snapshots additionally require a unique initialized
unsigned word value, both exact bytes, exact typed call/store/destination
evidence, no source address escape, no self-reference, and an unconditional
definition-to-store sequence. The fail-first set is 1 failed, 7 passed.

Return binding consumes those existing store proofs and proves the complete
nonescaping local dominates the particular return through statement lists and
conditional branches. It does not infer control flow from generated names or
rendered C. Conditional/incomplete/late/duplicate stores, escaped addresses,
wrong values, gotos, opaque effects, shared return AST nodes, loop-contained
returns and earlier unconditional returns refuse. Transparent statement groups
remain transparent: a separate fail-first case caught losing their prefix.
Final related set: **103 passed in 20.67s**.

The live detailed probe confirms a two-byte unsigned-short local and
`RETURN_PROOF True` for the saved AX value across the shared epilogue. The
earlier char declaration was in rejected output, not the typed object at this
successful proof boundary. No widening by printed shape was added.
LoadProg now passes its GP materialization gate, but still exits 4 with:

- two uninitialized AX reads in the first conditional chain;
- two missing branch-condition surfaces, JCCs `0x10b1` and `0x10b9`.

The function is not fixed: validation=passed, strict compilation and required
call/argument/return equivalence remain unproven. No failure is suppressed.

Scoped Make Ruff --fix, MyPy and type/doc checks pass for the proof modules and
tests. The extracted-from `call_output_stack_objects.py` retains 18 legacy
Ruff findings. Its scoped MyPy no-any-return diagnostic disappears when its
typed imported declaration-projection owner is explicitly included in the same
check; no cast, suppression or code workaround was added. Full architecture
passes; quality-fast remains globally lint-blocked. The refreshed pipeline
finishes successfully by 18:31:45 +02:00: **5,716 routine tests pass in 383.11s**,
plus 268 preliminary tests in 15.61s. QuickC passes in 42.430s; MS C tiny full
round trips pass in 121.639s. Three stages passed, none failed/skipped/timed out.
Slowest routine cases: RunMenu ESC 101.07s, InitBars 91.79s, InitMenu 90.04s,
DrawTime 60.14s, InsertionSort 55.09s. These are concurrent-run measurements;
no performance-gain claim is made. The complete suite and Step 9 stay open.

Next investigation: the structuring comparison changes the mode conditions
from BP+4 to BP+8, while final conditions read AX without an initialization.
Trace the authoritative stack-coordinate/value projection and exact condition
ownership before assuming these four reported errors are independent defects.
The historical Step 9 estimate of 55-76h is explicitly marked stale in the plan;
current failure-family and broader contract closure need recalibration.

Evidence: `.cache/step9-loadprog-inventory-probe.log`,
`.cache/step9-call-inventory-{before,after,controls,linters,focused-linters,mypy-owners}.log`,
`.cache/step9-native-call-bytes-{before,after}.log`,
`.cache/step9-return-byte-dominance-{before,after}.log`,
`.cache/step9-return-byte-control-{before,after,linters}.log`,
`.cache/step9-loadprog-return-binding-detail.{c,log}`, and
`.cache/step9-call-storage-{architecture,quality,pipeline}.log`.
