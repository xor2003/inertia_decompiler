# Step 9 Complete-Suite Audit: 2026-09-12

## Result

### SetGear Behavioral Gate Checkpoint, 2026-09-13 03:08 +02:00

The exact multi-arm condition ownership fix now has focused and routine-pipeline
acceptance evidence. This is individually resolved failure 13 of the original
47; 34 remain unresolved without a complete-suite refresh. The previous C artifact
`/home/xor/.cache/step9-setgear.c` compiles but fails the new behavioral oracle
with `wrong Status result`; the updated live CLI output passes. The oracle
executes 2,304 decision/state combinations, including signed-speed boundaries,
preserved status bits, ejection/damage/altitude guards, and Message arguments
and ordering. Five compile-valid corruptions are rejected.

Live acceptance plus oracle controls: **7 passed in 20.87s**; the live CLI test
took 12.34s. Enrollment and exact-arm ownership checks: **19 passed in 6.36s**.
Logs: `/home/xor/.cache/step9-setgear-acceptance.log` and
`/home/xor/.cache/step9-setgear-enrollment.log`. Ruff `check --fix` passed for
both new oracle files and `scripts/test_pipeline.py`. Both Make's focused test
list and the routine pipeline now include the oracle controls and live SetGear
regression; Ruff's list includes the oracle helper and tests. This is not a
whole-project lint or full-suite pass. Active implementation time was not
separately measured.

Follow-up routine pipeline: **4,969 curated tests passed in 215.85s**, after
268 preliminary passes. QuickC passed in 32.788s and the full MS C tiny
roundtrip stage passed in 81.095s. All three stages passed, none skipped or
timed out (`/home/xor/.cache/step9-setgear-pipeline.log`). Quality-fast found
two new optional CFG target type errors in replay recording. Explicit selected
edge invariants fixed these; the final focused live/ownership/oracle run passed
**17 tests in 21.21s**, including the 12.30s SetGear test. The pipeline preceded
this type-narrowing-only change; it was not rerun afterward. Final quality-fast
still exits 2 with 6,278 Ruff findings, no reported MyPy errors, and 39 compiled
import smokes passing (`/home/xor/.cache/step9-setgear-quality-final.log`).
Full collection, expanded pipeline, and quality-hard acceptance remain open.

### Full Collection Baseline

Small COD follow-up: Ready5 and InBoxLng both reproduced in 16.67s. Ready5
fails only the old spelling without a uint32_t segment cast; its unsigned
16-bit segment value is unchanged by that cast and validation passes. The
fixture now checks the declared segment width and exact i/droll/pdest writes
alongside the unchanged indexed word store. It passes in 14.11s (4.06s call).
This closes baseline failure 14; 33 remain without a full-suite refresh.
CLI-file Ruff still reports legacy findings; no rule was relaxed.

InBoxLng is not merely a validator representation mismatch: its unchanged
generated C fails the independent execution oracle for z=low=high=INT32_MIN,
expected 1, actual 0. Added axis/value/bounds diagnostics to the existing oracle;
eight oracle/provenance tests pass in 6.44s and scoped Ruff passes. Investigate
the inclusive upper-bound equality path and the separately observed high-word
binding mismatch (BP+0x16 versus high16 of BP+0x14). No production recovery
change or InBoxLng closure is claimed. Evidence logs:
`/home/xor/.cache/step9-small-cod-refresh.log`,
`/home/xor/.cache/step9-ready5-after.log`,
`/home/xor/.cache/step9-inbox-independent-detailed.log`, and
`/home/xor/.cache/step9-inbox-diagnostics-tests.log`.

Step 9 remains open. The exact complete collection ran on frozen source:
**12,560 passed, 47 failed, 167 skipped**, 12,774 total, in **1,906.54s**
(31m 47s execution, collection additional). No missing, duplicate or unexpected
nodes or missing outcomes. The controller confirmed source stability across
3,369 files, SHA-256
`ecb5265577b063194a04a2a9db0a89d1e8c4ec58322248f4c3d45f7b1f273fc8`.
Peak aggregate RSS was 1,771,204 KiB; the 2 GiB limit was not exceeded.

Command:

```sh
PYTHON_JIT=1 PYTHONHASHSEED=0 make pytest-all \
  PYTHON=./.venv/bin/python PYTEST_ALL_WORKERS=7
```

Retained evidence outside the repository:

- `/home/xor/.cache/step9-complete-20260912.log`
- `/home/xor/.cache/step9-complete-20260912-summary.json`

The summary preserves every failed node, traceback, skip reason, test duration
and source-stability result. Do not replace these counts with a curated result.

## Failure Inventory

Counts are test failures, not independent root causes. Filenames below are
relative to `angr_platforms/tests/`.

| File | Failed |
| --- | ---: |
| test_test_ownership_manifest.py | 1 |
| test_x86_16_cli.py | 6 |
| test_x86_16_cod_regressions.py | 6 |
| test_x86_16_heapsort_widening_regression.py | 3 |
| test_x86_16_life_decompile_regressions.py | 1 |
| test_x86_16_msc6_regressions.py | 3 |
| test_x86_16_pretest_loop_condition_ownership.py | 1 |
| test_x86_16_sortd_indexed_aggregate_regression.py | 1 |
| test_x86_16_sortd_menu_pointer_table.py | 1 |
| test_x86_16_sortd_sleep_regression.py | 1 |
| test_x86_16_sortdemo_positive_bp_acceptance.py | 2 |
| test_x86_16_sortdemo_regressions.py | 18 |
| test_x86_16_stack_aggregate_objects.py | 2 |
| test_x86_16_stack_prototype_codegen_api.py | 1 |

## Follow-Up And Order

### 2026-09-13 02:50 +02:00: Typed Ordering Views And Routine Gates

SetGear's source/COD confirms signed JG for Knots > 350. Current generated C
declares Knots unsigned and compares it without a signed conversion. This is
a semantic defect for high-bit inputs, independent of its branch-format test.
Two opposite-storage tests failed at the typed condition materialization
boundary before adding required scalar views in Types/Lowering. Structuring
delegates to that owner after operand binding; global storage types are not
mutated, and no recovery was added to Rewrite or the compatibility builder.

The new controls compile generated comparisons with casts hidden and execute
all 65,536 word values for signed/unsigned ordering, with the variable on
either side. Dword controls cover 65,536 sampled values including sign-bit
and threshold regions. Dword views use int32_t/uint32_t, not host-width long.
Existing high-byte projection coverage exposed a mask-proven unsigned view
with incomplete native type metadata; the owner now retains that already
bounded integer expression. InitMenu's acceptance also exposed an old exact
text expectation: its unsigned cszMenu requires a signed cast just like i.
The assertion now checks both declaration-dependent conversions; call,
validation and compilation checks remain unchanged. Forty focused tests
including InitMenu passed, then 43 width/materialization checks passed.

An uncached observed SetGear worker never sends the Knots signed predicate
through this materialization path. Other predicates reach it. Therefore this
fix does NOT close SetGear: investigate the untouched native predicate's
ownership and typed consumption before claiming function acceptance.

Final routine pipeline passes all three stages: 268 preliminary checks
(9.06s), 4,955 curated tests (218.48s), QuickC fixtures (34.055s stage), MSC6
tiny full roundtrips (83.262s stage). Architecture and scoped MyPy pass;
new owner/test Ruff pass. quality-fast remains red: 6,279 Ruff findings,
no reported MyPy errors, 39 compiled import smokes passed. Existing large
Structuring owner retains 12 Ruff findings. No full-suite refresh is implied;
baseline accounting stays 12 individually closed and 35 unresolved.

Evidence: `/home/xor/.cache/step9-condition-sign-{before,after,related,execution,widths,followup,architecture,quality,pipeline-final}.log`,
`step9-setgear-view-probe.log`, `step9-setgear-signed.{c,log}`, and
`step9-initmenu-condition.{c,log}`. New regressions are enrolled in routine
Make/pipeline scopes and the owner is enrolled in architecture checks.

### CLI Failure Refresh (2026-09-13)

Three original CLI failures reproduced in 109.62s. They are not one shared
stdout/stderr defect: SetGear reaches validation=passed but fails the expected
branch-output shape; TIDShowRange still fails validation after rejected
postprocess passes; DrawRadarAlt's permitted bounded-timeout branch expects
obsolete punctuation rather than the current contextual recovery message.

Only the last assertion changed. It now requires the recovery timeout with
its x86-16 context, the terminal no-fallback policy and absence of assembly
fallback. Its existing return-code-3 allowance, subprocess timeout handling
and all successful-recovery assertions are unchanged. The focused check passes
in 26.86s (17.07s test body). This closes a stale test failure, not the timed-out
function. It remains in the complete-suite live lane rather than adding a
bounded-timeout run to every focused pipeline invocation. Ruff was run with
`--fix`; the large existing CLI test file retains 174 findings, none suppressed.

Evidence: `/home/xor/.cache/step9-cli-status-before.log`,
`step9-cli-status-after.log`, and `step9-cli-status-ruff.log`.
Latest baseline accounting: **12 individually resolved, 35 unresolved**.
No fresh complete-suite or Step 9 acceptance is claimed.

### ReInitBars Call-Effect Proof Gap (2026-09-13)

Fresh-cache, in-process diagnostic hooks observed the actual Lowering and
Alias producers. The first byte-consumer hook did not fire; the outer-owner
hook established why: eight facts, zero classified/proven restores, eight
UNKNOWN_REFUSE results, including final SI/DI at rebased 0x104a/0x104b.

Transfer tracing then showed saved bytes at entry-SP offsets -8 through -5
survive the call in block 0x1009, but its call at 0x100b changes BP from -2 to
unknown: `complete=True`, `net_stack_delta=0`, `bp_preserved=False`. The next
block 0x100e loses those bytes while BP remains unknown. This is consistent
with the exact source: `segment_stack_restore._transfer_block` requires
explicit BP preservation; `semantics/call_stack_effects._effect_from_summary_8616`
constructs ordinary complete stack effects without supplying that field.
The allocation-specialized producer does supply it from allocation proof.
Stack cleanup/frame non-escape evidence alone does not prove BP preservation.

The next repair belongs to callee register semantics and its typed call-effect
projection, followed by Alias consumption. Do not bypass UNKNOWN_REFUSE,
force all calls to preserve BP, or remove saved locals in Rewrite. Required
controls include preserving, clobbering and unknown callees, complete paths,
and propagation into saved-byte restore evidence. The existing executable
ReInitBars oracle supplies a downstream preservation check.

Follow-up ruled out directly reusing the synthetic-stub ABI classifier: none
of ReInitBars's three retained targets is recognized as synthetic in this
slice. This does NOT prove real body inspection. In particular the retained
clock target 0x1137e has no function boundary in the rebased project's KB,
so a direct raw-IR lookup cannot inspect it. The program-summary owner retains
caller-indexed facts across projects, but the inspected call-effect interface
does not consume a callee BP-preservation fact. Collect such proof at the
source-project owner and transport it with exact target/callsite identity;
never inspect placeholder bytes or silently create a callee boundary in the
slice. Logs: `step9-reinit-gp-callees.log` and `step9-reinit-callee-ir.log`.
This narrows the implementation order to source-project callee evidence,
cross-project typed retention, then call-effect projection and Alias regression.

Diagnostics only, no semantic override: `/home/xor/.cache/probe-reinit-gp-bytes.py`;
logs `step9-reinit-gp-proof.log`, `step9-reinit-gp-materialize.log`, and
`step9-reinit-gp-transfer.log`. Hooks ran in the analysis worker with isolated
function caches; the generated result retained validation=passed. Graph
coverage was stale/untracked for these owners, so exact source was read.
No additional baseline failure is closed by this investigation.

### 2026-09-13 02:06 +02:00: ReInitBars Harness Separated From Output Debt

The unchanged executable acceptance reproduced missing `inertia_esi` and
`inertia_edi` declarations (17.34s). Its body-extraction harness now defines
the authoritative GP symbol inventory as host `uint32_t`, not host-width
`unsigned long`. Nonzero upper and lower ESI/EDI values are seeded and checked
after each call, retaining clock, copy-before-draw, iteration and untouched
entry checks. The generated body compiles and passes these behavioral checks;
acceptance then fails the unchanged `local_3` absence assertion. That is still
output debt, not a closed baseline failure.

New oracle controls failed before the repair. The valid save/restore body and
five compile-valid corruptions exercise lost clock calls, wrong copies,
draw-before-copy, low-SI corruption and lost high-EDI state. Each corruption
must fail execution specifically, not merely compilation. Expected failures
exit normally with the failed condition rather than invoking abort/Apport;
the latter caused a five-second timeout in one initial control. No timeout
was increased or failure suppressed. All nine oracle/Make-input checks pass
in 6.14s, scoped Ruff and pipeline MyPy pass. New controls are admitted to
Make and the routine pipeline. The prior complete pipeline result predates
this harness-only change; no new broad result is implied.

Logs: `/home/xor/.cache/step9-reinit-harness-before.log`,
`step9-reinit-oracle-before.log`, `step9-reinit-oracle-after.log`, and
`step9-reinit-oracle-final.log`. The original baseline remains 36 unresolved.

### 2026-09-13 02:01 +02:00: Routine Pipeline Refreshed

After the return-type and positive-BP interface fixes, the routine pipeline
initially found one tooling regression: two focused pytest node selectors had
been added to `QA_RUFF_TARGETS`. The existing Make input guard rejected them.
Removed the redundant CLI selector from Ruff's scope (its file was already
included) and replaced the COD selector with its file path. Both focused
selectors remain in the pytest scope. The guard passes all three tests in
0.94s; no assertion or linter rule was relaxed.

The subsequent `make test-pipeline PYTHON=./.venv/bin/python` passes:
268 preliminary checks (8.25s), 4,941 curated tests (175.54s), QuickC fixtures
(2.036s stage) and seven MSC6 tiny constructs through the full roundtrip gate
(33.653s stage). The stage summary reports three passed, zero failed/skipped
or timed out. The focused stage is still over its recorded 30s budget.
This warm-cache run is not a controlled performance comparison.

Evidence: `/home/xor/.cache/step9-type-refresh-pipeline.log` and
`angr_platforms/.cache/test_pipeline/summary.json` (the latter is overwritten
by future runs). The original baseline remains 36 unresolved failures after
11 individually verified closures. No complete-suite, quality-hard or Step 9
completion is claimed. Inspection also identified missing runtime GP globals
in the ReInitBars execution harness; that issue has not been changed here.

### 2026-09-13 00:04 +02:00: Four Fixture Failures Closed

The contradictory loop-ownership fixture used an operand tag as execution
ownership. That conflicts with the documented nested-loop repair: reused
operand provenance cannot claim a body block. The fixture now tags its actual
`CIfBreak` statement, preserving the assertion that contradictory statement
ownership refuses before lowering or mutation. The existing foreign-operand
positive control still passes. Before: one failure/four passes; related loop
and pipeline tests afterward: 71 passes in 8.91s.

Three positive stack-coordinate fixtures expected a global BP-to-entry-SP delta
from a local object binding. They now provide an explicit typed, proven
`FrameAccessArtifact` independently of those local bindings. Exact expected
formal offsets, aggregate widths, regeneration identities and refusal controls
are unchanged. Before: three failures/28 passes; afterward, including no-frame
and no-extrapolation controls: 40 passes in 10.98s. No production behavior or
semantic assertion was weakened.

The omitted pretest and stack-prototype files, plus aggregate coverage, are now
in the routine pipeline; Make's relevant test lists are coherent. Combined
fixture and selection checks pass 104 tests in 14.12s. Pipeline code and the new
typed frame fixture pass Ruff; pipeline code passes MyPy. Legacy aggregate and
prototype test files retain 41 visible magic-value findings after Ruff's import
fixes. No rule was suppressed. Scoped `git diff --check` passes.

Eleven of the original 47 failures are now individually closed, including the
manifest correction. **36 retained failures remain unresolved**; no fresh
complete-suite or expanded result is claimed. Sleep's executable-only failure
was independently reproduced afterward (one failure, 9.10s): the second wide
call remains a statement and the guard reads uninitialized AX/DX. This is a
real semantic blocker, not a test-expectation update. Its owning producer and
condition consumer need tracing before edits.

Logs: `/home/xor/.cache/step9-pretest-{before,after,ruff}.log`,
`step9-frame-fixtures-{before,after,ruff}.log`,
`step9-fixture-admission-{after,ruff,mypy}.log`, and `step9-sleep-before.log`.
Observed follow-up interval: approximately 23:58-00:04, including test waits;
active coding time was not separately recorded.

### Tiny-Helper Fixture Follow-up (2026-09-13)

The CLI tiny-single-call structuring regression failed because its mocked
instructions supplied mnemonics but no typed operands. Return-register
preservation correctly requires the decoded operands. Replaced the inconsistent
NOP byte buffer and mnemonic-only objects with real `push si; call` bytes,
NOP padding and the architecture's Capstone decoder. Structuring-disabled,
successful-status and exact-output assertions remain unchanged. No production
behavior changed. The original failure reproduces in
`/home/xor/.cache/step9-tiny-helper-before.log`; the focused check passes and
all five related `test_decompile_function*` cases pass in 9.30s in
`/home/xor/.cache/step9-tiny-helper-related.log`.

The corrected node is now in routine pipeline and Make test lists. Pipeline
Ruff passes; the large CLI test file retains 174 Ruff findings. The previous
default-pipeline pass predates this fixture-only follow-up; no fresh full-suite
pass is inferred.

### COD Timeout Expectations (2026-09-13)

All three `test_cod_runner_hotspots_fall_back_through_scan_safe_classifier`
cases reproduced the same stale expectation: promoting a timed-out child to
`fallback` because a diagnostic scan completed. Current runner ownership
explicitly keeps child status and tail evidence authoritative; the existing
`test_diagnostic_scan_cannot_promote_failed_child` covers that contract.
Updated the old cases to require `timeout`, the original nonzero return code,
and absent tail-validation records. Existing assertions requiring attached
bounded-recovery diagnostics and rendered timeout attribution remain intact.
No production status handling changed and no test was removed.

Before: three failures. After: 37 passes in 8.09s including the complete runner
parallelism test file. The corrected node is enrolled in routine pipeline and
Make lists. Pipeline MyPy passes; Ruff retains 35 findings in the large COD
test file. Logs: `/home/xor/.cache/step9-cod-fallback-{before,after,ruff}.log`.
These close three stale test expectations, not three decompilation defects.

### MSC Runtime Declarations (2026-09-13)

All three scalar tests initially reproduced the MS C rebuild failure (219.66s).
The runtime harness extracted function bodies but omitted GP ABI declarations,
although it linked the corresponding runtime definitions. `_build_full_source`
now consumes `msc6_runtime_state_declarations()` from the existing runtime
provider. No generated body, register effect, or semantic assertion changed.
The existing runtime-link test now requires every GP declaration before main;
it failed before the fix. All four runtime-gate unit checks pass afterward;
scoped MyPy passes. The touched tool/test surface retains 13 Ruff findings.

Unchanged scalar acceptance rerun: one pass, two failures in 61.38s, using
`pytest -n 7 --dist=loadfile` to share the expensive same-file fixture.
Compilation and execution now pass. `sub_ss` closes; `add_sc` still retains
save/restore locals, and `sub_ulong` emits signed `long` with unsigned arguments.
Keep both expectations until the owning decompiler layers are corrected.
The timing comparison is not controlled: the fix and cache state also changed.

Evidence: `/home/xor/.cache/step9-msc-scalar-{current,after}.log` and
`/home/xor/.cache/step9-runtime-declarations-{before,after,ruff}.log`.
The strengthened unit test is already enrolled through the full
`test_build_msc6_examples.py` routine target. Full-suite/expanded acceptance
remains unrefreshed; the previous default pipeline pass predates this change.

### Wide Return Type Preservation (2026-09-13)

Investigating the remaining `sub_ulong` signature exposed an independent
prototype-promotion defect: terminal width evidence replaced an existing
`SimTypeLong` return with the argument inference's default signedness.
The compatibility prototype owner now preserves an existing wide return type.
Two opposing-signedness regressions failed before the change and pass afterward;
44 related calling-convention/argument-width tests pass in 7.20s. Scoped MyPy
passes; the existing owner retains 16 Ruff findings, while the new test and
pipeline admission pass Ruff. New coverage is enrolled in Make and the routine
pipeline.

This does NOT close `sub_ulong`: its unchanged acceptance test still emits
`long sub_ulong(unsigned long a, unsigned long b)` after a successful runtime
rebuild (92.08s test run). Trace the earlier return-type selection and later
unsigned argument materialization before changing either. No further baseline
failure is closed. Logs: `/home/xor/.cache/step9-wide-return-type-{before,after,ruff}.log`
and `/home/xor/.cache/step9-sub-ulong-type-after.log`.

### Unmaterialized Typed Interfaces (2026-09-13)

A fresh-cache prototype-assignment observer isolated `sub_ulong`'s actual
transition: `(long, long) -> long` becomes `(unsigned long, unsigned long) -> long`
in positive-BP argument materialization. The C argument list was empty even
though a complete typed prototype existed. The old interface check treated
that as missing type ownership and substituted unsigned body-storage defaults.

Types/Lowering now consumes the existing prototype-layout API to preserve
types before CVariable materialization only when every desired storage range
exactly matches the prototype ABI offset and width. It refuses mismatched
offsets/widths and nonpositive sizes. The signed-prototype/unsigned-body
regression failed before the fix; final related set: 36 passed in 7.79s.
Scoped MyPy passes; touched owner/test files retain nine Ruff findings. The
strengthened test file is now enrolled in the routine pipeline and Make gates.

The unchanged `sub_ulong` acceptance test now passes in 91.56s, including its
runtime gate, clean validation and consistent-signature assertions. This closes
one baseline test, not a new whole-suite result or a claim that binary-only
inference recovers source signedness universally. Save/restore cleanup and
Sleep remain open. Evidence: `/home/xor/.cache/sub-ulong-interface.log`,
`/home/xor/.cache/step9-empty-interface-{before,final,ruff}.log`,
`/home/xor/.cache/step9-empty-interface-refusal-before.log`, and
`/home/xor/.cache/step9-sub-ulong-interface-after.log`.

### Ordered Work

1. **Manifest mismatch: fixed after the audit.** The positive-BP ownership rule
   intentionally selected two additional projected/declaration-identity test
   files. Its exact-selection test now requires both rather than removing
   coverage. All 60 manifest tests pass in 1.90s; Ruff `check --fix` passes.
   Logs: `/home/xor/.cache/step9-manifest-{after,ruff}.log`.
   This closes one retained failure separately, not a new complete-suite result.
2. **Check shared storage and condition contracts first.** Three unit failures
   concern BP versus entry-SP coordinates, regenerated aggregate identity and
   formal coordinates. Another permits lowering despite contradictory loop-body
   ownership. Inspect these against authoritative contracts before changing
   implementation or assertions; their current failures do not prove which side
   is wrong. DoD: focused failure-before/pass-after, boundary/refusal controls,
   related corpus acceptance. Failure: weakening coordinate or CFG proof.
3. **Resolve semantic corpus failures at their earliest owner.** Observed
   diagnostics include Sleep's uninitialized AX/DX condition reads, DrawTime's
   classified-but-unmaterialized GP restore, InitMenu's uninitialized saved
   stack bytes and QuickSort's semantic-cast predicate mismatch. Shared root
   causes are not yet proven. DoD: unchanged validation, calls, effects and strict
   C recompilation pass in each fixed function, with generic regressions.
   Failure: changing expected output to bless lost semantics or adding recovery
   in Rewrite/CLI. Also classify the remaining CLI/COD/MSC/LIFE failures; LIFE's
   non-FPU pause-screen path remains in scope.
4. **Close quality and acceptance.** Preserve the recorded Step 9 DoD:
   zero failures in a source-stable complete collection, `quality-hard`, default
   and expanded pipelines passing, and balanced evidence counters. The latest
   global Ruff result still has 6,240 style/complexity findings. No exclusions,
   weaker rules or curated-only substitution. Full-suite runtime is also above
   the user's accepted range; retain timings for measured follow-up rather than
   shortening timeouts or removing unproven duplicates.

Slowest observed nodes: TIDShowRange 161.85s, SORTDEMO file-summary 138.28s,
scalar add_sc 133.73s, InitBars 114.01s, COD openfilewrapper 85.07s.
These are per-test timings, not evidence of redundant coverage.

## Accounting Checkpoint

Before this census, the new-loop refusal fix passed 125 focused tests in 16.01s
and scoped MyPy. Unanchored candidates now retain raw/normalized evidence and
refusal/failure diagnostics but are not counted as classified/materialized
guards. Six existing Ruff findings remain in that legacy owner/test surface.
See [RunMenu Condition Definition Binding](p0-runmenu-condition-definitions.md).

Observed interval: approximately 23:22-23:57 +02:00, including full-suite waits,
result inspection and the manifest correction. Active coding time was not
separately measured. No new completion percentage or finish ETA is established.
