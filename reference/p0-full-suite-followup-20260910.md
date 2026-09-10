# Full-Suite Follow-Up: 2026-09-10

## Verified Baseline

Command: `PYTHON_JIT=1 PYTHONHASHSEED=0 make pytest-all PYTHON=./.venv/bin/python PARALLEL_JOBS=7`.
All 11,625 collected tests were accounted for: **11,420 passed, 35 failed,
170 skipped**. Runner time: **1,257.89 seconds**; peak aggregate RSS:
1,725,376 KiB. Source remained stable, SHA-256
`4d6f0db282e4ae718b317124f1cc6409b22262482abf657dcb7b773cbe5949b0`.
This supersedes the earlier 11,326/40/170 status, not its historical evidence.

Complete machine evidence: `.cache/pytest/partitioned-summary.json`, including
failure tracebacks, node outcomes, timings and skip reasons. Full log:
`/tmp/inertia-full-suite-current.log`. The initial inventory attempt failed on
eight unclassified consolidation-oracle cases; explicit tooling ownership
fixed that gate before the measured execution. No test was excluded.

## Repairs After The Audit

- Two ownership-selector expectations omitted existing regression targets.
  Added the exact targets without weakening equality assertions. Ownership,
  inventory and consolidation-oracle tests: **69 passed**, 13.26s.
- FLAGS cleanup's header omitted the mandatory full prohibition on semantic
  recovery. Restored the boundary text; no checker or behavior change.
  Architecture tests: **371 passed**, 41.29s.
- The old FLAGS fixed-point fixture used an opaque namespace instead of the
  native AIL virtual variable. Corrected the fixture; preserved opaque-payload
  refusal coverage. Both FLAGS modules: **38 passed**, 8.38s.

These close four specific failures in focused reruns, leaving 31 audit failures
unresolved. They do not establish new whole-suite totals. Ruff passes on these
touched files; ownership metadata also passes MyPy and Pyright. Global lint
debt remains independent of pytest results.

## Remaining Repair Order

### Live Segment Effect Blocker

Investigation at 16:43-16:47 CEST found real semantic loss, not merely a brittle
BIOS assertion. VEX retains `PUT(es)` in the BIOS function, while the first
observed pre-postprocess C already lacks it. Thus Rewrite is not where this
effect first disappears.

A sidecar-free two-function regression makes the effect observable:
caller `CALL callee; MOV AX,ES; RET`, callee `XOR BX,BX; MOV ES,BX; RET`.
Native output becomes `sub_1010(); return inertia_es;` with an empty callee.
Unmodified generated functions compile into a shared library, but execution
returned the seeded **4660 instead of 0** before the repair below. The
regression is admitted to the routine runner and ownership manifest, with no
skip or xfail. There has been no refreshed whole-suite audit.

Highest priority is now the segment-output contract at the IR/native analysis
boundary. Existing `lowering/segment_register_state.py` explicitly owns live-in
projection only. Native AIL DCE considers register vvars eliminatable and its
terminal callee-saved census is restricted to general-purpose registers; this
was the candidate loss mechanism and is now confirmed by stage tracing.

### Segment Repair Checkpoint (17:00 CEST)

The stage trace shows ES as `vvar_7{r44|2b}` after SSA level 0. Native
`AILSimplifier._remove_dead_assignments` replaces it with `NoOp` during
pre-SSA-level-1 simplification. Its implicit return-use census does not cover
segment outputs. A diagnostic extension of reaching-definition uses retained
the write and existing lowering emitted `inertia_es = 0;`.

Implemented `ir/native_segment_live_out.py`: observe exact segment versions
reaching each native Return and publish their uses before DCE. The adapter
does not classify segments as general-purpose/callee-saved, resurrect rendered
text, or retain every overwritten definition. Publication is idempotent and
has a typed evidence census. Block-only analyses are unchanged. Interprocedural
call-clobber recovery is explicitly outside this bounded repair.

Focused acceptance: **120 passed**, 15.13s, including original BIOS, four
compiled ES/DS caller cases, overwritten definitions, separate branch returns,
and wiring contracts. Ruff, MyPy and Pyright pass on the new production owner
and compatibility entry point. The failure-before runtime result remains in
the original log; generated C is compiled unchanged in the new tests.
Exact active-work start was not
recorded after continuation, so no synthetic elapsed-time estimate is given.

Logs: `/tmp/inertia-segment-stages.log`, `/tmp/inertia-segment-preserve.log`,
`/tmp/inertia-segment-final-focused.log`, `/tmp/inertia-segment-gates.log`.

### Segment Gates And Remaining CLI Defect

Sequential `make -k quality-fast test-pipeline ... PARALLEL_JOBS=7` finished:
fast **3,583 passed in 177.12s**, default **3,583 passed in 139.84s**;
all three executable quality guards and all three default pipeline lanes
passed, including the MS C tiny-example round trips. Overall exit 2 remains
from global lint debt. These are routine-lane counts, not a refreshed full
suite. Production remained unchanged during this gate.

The gate also caught three pytest selectors accidentally admitted as Ruff
filenames. Replaced them with the full module path without changing pytest
selection. A new Make dry-run regression checks that Ruff/MyPy receive paths,
not `::` selectors, and include the new IR owner. Post-gate wiring/segment
checks pass **123 tests in 11.90s**, now including FS/GS boundary-use cases.
The Make guard and additional register cases postdate the routine-lane counts.
Ruff no longer reports invalid paths; global findings and the ownership
manifest's existing complexity violation remain unsuppressed.

An isolated MZ containing the original BIOS function bytes, with a separate
CALL/exit entry stub, was decompiled at `0x10010` without sidecars or alternate
source C. The output retains `inertia_es = 0`, reports `validation=passed`,
and has a clean whole tail. However, it emits two identical BDA stores and
unused `local_4`/`local_2` carriers; strict gcc (`-std=c11 -Wall -Wextra -Werror
-fsyntax-only`) fails on the unused locals. Its inferred integer signature also
has no explicit return. The native compiled caller regressions pass, but this
CLI artifact is **not fully accepted**. Do not remove those statements merely
to satisfy gcc: trace why the native and direct-address paths disagree, prove
effect ownership, and add a CLI behavioral/strict-compile regression during
that repair. No claim is made that these CLI defects were introduced here.

Next bounded acceptance: reconcile native/direct-address IR and return/effect
projection for this fixture, remove only proven duplicate/dead carriers, and
require both clean whole-tail validation and strict compilation. Failing
definition: cosmetic Rewrite repair, guessed signature, hiding warnings, or
accepting duplicated effects just because the validator currently passes.

Evidence: `/tmp/inertia-bios-segment-callee.c`,
`/tmp/inertia-bios-segment-callee-validation.log`,
`/tmp/inertia-segment-wiring-final.log`, `/tmp/inertia-segment-make-ruff.log`.

### Byte-To-Word Store Projection Repair

In-process worker tracing confirmed two native 8-bit lvalues reaching the
anonymous immediate-store materializer. Both had the same instruction address
and zero RHS. Each independently consumed the same 16-bit store fact, producing
two word writes. Equal values and instruction identity did not prove full
byte coverage. This is a Types/Lowering error, not a Rewrite cleanup problem.

Added a focused typed-width predicate in `lowering/store_projection_width.py`.
Single-store materialization now requires the exact fact width; partial or
unknown widths do not qualify. The existing paired-store path consumes both
byte projections together. Eight regressions cover complete pairs and orphan
bytes for zero, low-only, high-only and all-set values. Before the fix, four
failed and four passed (13.58s); afterward all pass. An older byte-store fixture
now supplies its actual byte lvalue type rather than the helper's default word
type, with all existing behavior assertions retained. Related module and
wiring coverage: **297 passed in 15.21s**.

The isolated sidecar-free BIOS CLI result now emits one BDA word write and
`void sub_10010(void)` with an explicit return. It still reports
`validation=passed` and a clean whole tail. Strict gcc remains red solely on
the two unused local carriers in this probe. That is not permission to delete
unproven stack effects; complete strict-compilation acceptance remains open.

MyPy passes on the touched production modules. Eight pre-existing Pyright
errors in the materializer's query-session guards were resolved by explicitly
checking the required `CStatements` type, preserving the prior guarded runtime
behavior; Pyright now passes. The focused new helper and test are Ruff-clean;
the large existing materializer still has legacy Ruff debt. New production
and regression modules are admitted to Make, ownership and routine pipelines.
Broader quality/executable gates for this repair finished: fast **3,595 passed
in 199.82s**, default **3,595 passed in 139.43s**, all three executable quality
guards passed, and all three default pipeline lanes passed including MS C
round trips. Global Ruff debt remains. The type ratchet caught the new
helper's missing future-annotations import; it was added after the gate,
together with whitespace-only alignment of routine test selectors. These
results do not replace the full-suite audit or close strict BIOS acceptance.
Final follow-up: the changed-module type ratchet passes; 60 focused width,
Make-input and runner tests pass in 10.65s after the annotation/format edits.

Reason: preserve store width, extent and multiplicity from machine evidence.
DoD for this bounded repair: width regressions fail before/pass after, no
orphan byte becomes a word, native/CLI store effects agree, tail validation
passes, and routine executable gates do not regress.
Definition of failure: widening on an immediate-value match, discarding the
second store cosmetically, relaxing byte refusal, or claiming full BIOS
acceptance while strict compilation fails.

Evidence: `/tmp/inertia-bios-stage.log`, `/tmp/inertia-anonymous-width-before.log`,
`/tmp/inertia-anonymous-width-focused.log`, `/tmp/inertia-bios-width-fixed.c`,
`/tmp/inertia-bios-width-fixed.log`, `/tmp/inertia-store-width-gates.log`.
Checkpoints observed at 17:24 CEST; exact active-work start was not captured.

Reason: a caller-visible architectural effect silently disappears.
DoD: prove where ES is dropped, preserve typed terminal segment effects before
native DCE, keep caller/callee projections coherent, pass the compiled regression
and BIOS case, and require validation plus executable pipeline acceptance.
Definition of failure: marking all segments as general-purpose/callee-saved to
force retention, resurrecting assignments from rendered text in Rewrite,
accepting changed/uncollected validation, or weakening the new runtime oracle.

Evidence: `/tmp/inertia-bios-probe.log`, `/tmp/inertia-segment-caller.log`,
`/tmp/inertia-segment-call-regression.log`.

### DOSFUNC Behavioral Acceptance

Observed work window: 16:38-16:41 CEST, approximately three minutes including
test execution. This is the bounded DOSFUNC repair, not an estimate for BIOS.

The BIOS/DOSFUNC focused rerun reproduced both failures (17.89s). DOSFUNC
already passed the exhaustive compiled oracle but failed a rendered-call
substring because the segment argument now has an explicit unsigned-short
cast. The old substring also checked the error message, which the oracle had
not covered. Moved that obligation into the compiled `ERROR` stub with exact
message comparison, retaining checks for segment, result, call multiplicity,
service number, input pointers and return value over all word results and both
carry outcomes. No decompiler behavior was changed or test obligation removed.

Added corrupt-message, corrupt-segment and corrupt-error-value cases. Removing
the new message check makes the corrupt-message case fail as intended (one
failed, two passed, 1.34s). The strengthened oracle plus the live DOSFUNC
regression pass **13 tests**, 13.19s. These oracle cases are already covered by
the module's routine Make/pipeline selection. Helper Ruff, MyPy and Pyright
pass; the older COD sample module retains five unrelated Ruff findings.

BIOS remains open: its bytes explicitly write ES before the memory store.
Do not discard the missing ES assertion until the native register-effect and
segmented-memory projection contracts establish whether this write remains
observable. **22 original audit failures remain unresolved**, not a refreshed
full-suite count. Logs: `/tmp/inertia-cod-sample-before.log`,
`/tmp/inertia-dosfunc-oracle-before.log`, `/tmp/inertia-dosfunc-oracle-final.log`.

### PUSH Consumption Repair (Verified 16:24 CEST)

The conflict trace at 16:09 identified a real memory-effect deletion bug:
`_prune_consumed_direct_push_source_stores_8616` treated a matching count of
nearby stores as proof they had been consumed by the emitted arguments. It
could remove a variable-valued store after emitting an unrelated immediate.

The cleanup consumer now requires unique recorded PUSH instruction addresses
and matching source values for every candidate store. It uses existing summary
facts and source matching; no new argument recovery was added to Rewrite.
Unknown or conflicting stores are retained. Earlier Alias/Widening ownership
is still needed before unproven byte pairs or far-pointer setup can be removed.

Six parameterized checks cover matching/conflicting values and matching,
missing or wrong instruction addresses. With the guard temporarily removed,
five refusal cases fail and the exact-match case passes (8.75s); after restoring
it, the call, caller-cleanup and ownership modules pass **253 tests**, 14.19s.
Two previous fixtures supplied no instruction ownership yet demanded deletion;
they now require retention while preserving their pointer/value call checks.
Renames are recorded in the inventory retirement ledger, not silently dropped.

Both routine lanes pass 3,562 tests (179.88s/136.13s), and all default executable
lanes pass, including QuickC and seven MS C round trips. These runs precede the
selection-only addition of the eight new consumption/retention cases. Subsequent
wiring checks pass **65 tests**, 6.52s. The new cases are selected by both Make
and the pipeline runner. MyPy and Pyright pass for the changed production and
tooling files. Ruff still reports legacy debt (488 findings in the combined
production/test/tooling scope); the aggregate quality command exits 2.

This resolves the last failure in the eight-case call cluster. **23 original
audit failures remain unresolved**, not a new full-suite total. Trace-to-wiring
elapsed time was about 15 minutes, including broad gate waiting. Logs:
`/tmp/inertia-conflict-trace.log`, `/tmp/inertia-consumption-oracle-before.log`,
`/tmp/inertia-consumption-final.log`, `/tmp/inertia-consumption-gates.log`.

### Call Fixture Follow-Up (Verified 15:20 CEST)

The call module reproduced all eight failures (166 passed, 8 failed, 9.62s).
Six were missing explicit word-width facts in native C lvalues. Extracted the
duplicated fixture into `angr_platforms/tests/call_store_fixtures.py`, leaving
their behavioral assertions unchanged and shrinking the large test file by
114 lines. The helper sets the native resolved lvalue type independently of
the address; it does not change production evidence or infer width from the
value being stored. Ruff, MyPy and Pyright pass for the helper. The legacy
test module still has 122 Ruff findings, reported rather than suppressed.

The seventh test expected removal of a stack store merely because its constant
matched a return address. Its updated assertion requires the entire statement
sequence to survive unchanged while the call remains argument-free. This
preserves the no-invented-argument obligation and adds unknown-store retention.

Final call-module plus caller-cleanup run: **188 passed, 1 failed**, 23.61s.
The remaining failure is
`test_materialize_callsite_stack_arguments_prefers_generic_probe_stores_over_push_arg_sources`:
its typed stack store supplies a variable, while its summary supplies immediate
3. The consumer selects 3. Resolve competing evidence and store liveness at
the owning layer; do not restore last-N-store guessing or merely accept this
output. All original width-refusal and caller-loop regressions pass.

Seven additional audit failures are reconciled in focused runs; **24 remain
unresolved**, not a refreshed whole-suite failure total. The complete baseline
above is unchanged. No production semantics changed in this fixture batch.

### Outstanding Tasks

1. Keep the repaired call-consumption guard and its routine regressions green.
   Reason: unknown stores must survive. DoD: missing/conflicting ownership
   refuses deletion and exact instruction/value matches retain consumption.
   Failure: inferring word arguments from byte stores or restoring count-only
   deletion. Further byte-pair/far-pointer cleanup requires earlier owned proof.
2. Corpus semantic failures: CLI condition cases, loadprog/object bindings,
   BIOS/DOSFUNC, indexed aggregates and HeapSort. Reason: generated code and
   semantic preservation outrank formatting. DoD: binary-derived repair at
   the earliest owner, validation passed, required calls/arguments preserved,
   strict compilation where applicable. Failure: source/sidecar dependence,
   hidden validation drift, or deleting live effects.
3. Reconcile output-sensitive SORTDEMO assertions only after inspecting full
   generated bodies. Reason: several failures occur after validation succeeds
   on explicit casts or loop formatting, but this alone is not proof of
   equivalence. DoD: retain value, pointer, iteration and call obligations with
   structural or compiled behavioral checks. Failure: permissive text matching
   that also accepts wrong operands, lost calls or broken loops.
4. Repeat full inventory/execution and routine executable lanes after repairs.
   Reason: focused passes cannot prove whole-suite closure. DoD: zero failures,
   all collected nodes accounted for, stable source and measured timings.
   Failure: presenting curated counts or arithmetic subtraction as a full run.

## Timing And Cost

Audit work started around 14:15 CEST; first post-audit repair batch was verified
by 14:43 CEST. Most elapsed time was collection and full-suite execution, not
active repair. No completion ETA is supported for the semantic backlog yet.
Slowest calls: TidShowRange 114.93s, openFileWrapper 83.57s, InitBars 76.54s,
RunMenu direct 46.91s, named QuickSort 40.45s. The 170 skips include missing
fixtures and two opt-in exhaustive instruction corpora; see machine skip
details. They are not passing tests.
