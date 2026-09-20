# SORTD Inertia/Ghidra Comparison And Improvement Plan

## Scope And Truth Sources

**Steps 10-12 scope approved September 19, 2026:** the
[bounded remaining-step contract](reference/remaining-plan-acceptance.md)
supersedes their historical broad DoD below. Audit the frozen SORTD inventory,
retain accepted readability work, repair demonstrated correctness failures,
measure reproducibility/resources, and close with the specified final gates.
User clarification September 20: this boundary must retain the requested
Ghidra/Reko parity features. Tasks 5 and 7.1-7.4 remain required for the selected
inventory, including new mechanisms where missing. Audit-only closure is not
acceptable; only unrelated generalization and optional optimization are deferred.

**Step 9 scope approved September 19, 2026:** finish acceptance and comparison
for the frozen 20-function SORTD inventory, then stop. The authoritative
[bounded acceptance contract](reference/step9-acceptance-contract.md) supersedes
historical Step 9 dependencies on unrelated COD repairs, all Tasks 3/8, and
pre-existing global quality debt. Those remain explicit
[separate open work](reference/post-step9-backlog.md), not completed work.

This report covers only the 20 non-library functions emitted by Inertia for
sidecar-free `SORTD.EXE`. Ghidra's 138 recovered functions are scanned only to
find bodies corresponding to those 20 functions; runtime/library functions are
not compared.

Correctness priority:

1. binary IR/CFG, typed effects, and whole-tail validation
2. compile and behavior gates
3. `SORTDEMO.C` as an optional comparison oracle
4. Ghidra output as a diagnostic peer, never as truth

Numeric function and global names are acceptable when the executable has no
debug information. Source names below identify addresses for this report only;
they must not become recovery evidence.

User scope clarification (2026-09-11): LIFE's 80387/x87 decompilation is out
of scope. Do not add FPU recovery work to this goal. The integer BIOS keyboard
input path and conditional pointer-output/stack-initialization defects remain
in scope. Preserve existing FPU behavior and tests; unsupported FPU handling
must stay explicit rather than being counted as successful decompilation.

## Current Checkpoint (2026-09-20)

User resumed Steps 11/12 and conditional Step 10 after bounded Step 9 closure.
Current execution and per-slice acceptance: [remaining plan execution](reference/remaining-plan-execution.md).
Step 11's first signed-conversion readability slice is complete: 20/20 SORTD
validation, zero-warning compilation, generated behavior and all default
pipeline lanes pass (5,885 routine tests in 227.61s). The broader step remains
in progress; see [the slice report](reference/step11-signed-casts.md).

The coherent GP word-view slice is now enabled in normal CLI lowering: the
bounded SORTD exports contain zero upper-word preservation assignments (55 in
the baseline). All 20 functions validate and compile with zero warnings; all
19 behavior cases pass. The default pipeline passes all three lanes, including
5,950 pytest cases in 296.99s, four QuickC fixtures and seven MS C round trips.
See the execution ledger for proof boundaries, runtime migration and artifacts.
This does not close the remaining Task 5/7 parity obligations or Step 10.

Step 12 now rejects stale accepted storage contracts when a later collection
refuses, before prototype consumers can reuse them. Scoped checks and 198 tests
pass; SORTD remains byte-identical, 20/20 validated, zero compiler warnings and
19 behavior cases passing. The refreshed default pipeline passes 5,956 pytest
cases plus QuickC and all seven MS C round trips. The
[parity evidence audit](reference/step12-parity-audit.md) records the completed
all-body Step 9 comparison and the still-open live contract/transport, widening
and aggregate proof obligations. This safety guard is not Step 12 completion.

The subsequent live-contract audit fixed memory live-out collection using the
wrong project for caller SSA. It now consumes census-owned caller context,
with conflict and cross-project cache controls. SORTD stays byte-identical and
passes every bounded gate. The following Frontend NOP-entry identity slice
now gives Swaps an accepted unified contract for all nine callsites in-process.
Explicit discarded-return proof now also accepts QuickSort's recursive contract
in-process. Frontend block-witness transport and the Semantics typed-edge adapter
now also produce accepted Swaps and QuickSort contracts in normal clean workers:
nine/five input callsites and 27/five return-memory facts, respectively, without
weakening either solver. Fresh exports validate 20/20, compile without warnings,
and pass all 19 behavior cases; all default pipeline lanes pass.
Current priority: [stability first, correctness next, remaining features last](reference/stability-first-execution.md).
New Ghidra/Reko parity features are explicitly deferred by the user until
stability work is accepted; they are not completed or cancelled. Small source
fixtures from `/home/xor/nndecomp` are preferred over new feature work.
The subsequent caller-range fallback repair replaces summed CFG byte counts
with the same proven Frontend extents; all 20 exports remain byte-identical.
Final gates: 6,023 pytest cases, four QuickC fixtures, seven MS C round trips,
20/20 SORTD validation, zero compiler warnings and 19 behavior cases. The parity
audit records the remaining typed-evidence tasks; Steps 10-12 remain open.

Step 9 closure baseline: all 20 functions validate; strict compilation has zero errors and
zero warnings; the 19-function behavior harness passes. RunMenu's DCE repair
preserves distinct live SSA values while removing both unused carriers.
Focused checks: 229 passed; project-wide MyPy, scoped lint/types/docs,
architecture and ownership pass. Global quality remains Ruff-blocked.
The final default pipeline passed all three lanes: 5,861 routine tests in
352.04s, four QuickC fixtures, and seven MS C tiny round trips. Bounded Step 9
is complete. See the [closure ledger](reference/step9-closure.md).
The saved C, reports and address links use the zero-warning export.
See the [root-cause report](reference/step9-runmenu-dce.md) and semantic review.

Preceding checkpoint: the refreshed 20-function SORTD gate passes; generated sort-core
compilation and behavior pass. Typed local aggregate projection cleanup removes
one unused carrier, reducing strict compilation warnings from four to three
(zero errors). The strict zero-warning gate remains red. Focused DCE: 89 passed;
the refreshed pipeline passes all three lanes, including 5,819 routine tests
in 377.64s and both external compiler lanes. RunMenu's remaining warnings follow
a validator rollback with condition-provenance differences, not call/write loss.
Current artifacts, limitations and evidence: [semantic review](reference/step9-current-comparison.md).
Unrelated debt remains in the separate backlog, not a Step 9 dependency.

### Historical Checkpoints

Latest follow-up: captured-return publication has focused proof and consumer
integration coverage; Lowering is consulted before legacy producer folding.
Related call tests: 221 passed, two stack-probe failures also reproduced with
the previous dispatch order. TID still exits 4 for unassigned stack locals;
the capture fix does not close the live argument-materialization defect.
Two missing test enrollments are repaired and architecture-check passes.
Global quality is Ruff-blocked. See the failure refresh for exact gate evidence.
The refreshed default pipeline passes all three lanes: 5,791 routine tests
in 308.86s, QuickC, and all seven MS C tiny round trips. Complete-suite and
expanded acceptance remain unrefreshed; Step 9 is not complete.

Latest inventory at 19:59 +02:00: retrying the previous 22 failing nodes gives
2 passes (LoadProg, Overlay) and 20 failures in 600.90s. These are not full-suite
totals. A real MS C artifact-lifetime race was then repaired in gate tooling,
with four fail-first cases, 121 related passes and clean scoped lint/type/doc
checks. Its live MS C and broad acceptance remain to rerun. TID semantic errors,
timeouts, output-contract assertions and global quality closure remain open.
See [failure refresh](reference/step9-failure-refresh-20260919.md).

Latest follow-up at 19:24 +02:00: LoadProg now exits 0 with clean whole-tail
validation, including an isolated-cache run with alternate source-C disabled.
Its existing live acceptance test and portable-flat recompilation pass. Alias
composes proven low-byte storage with the proven zero upper byte; cleanup
preserves existing stack-view evidence instead of flattening it away. Related
tests: 173 passed. New module/scoped quality and architecture pass; legacy CLI
lint debt remains. The default pipeline finished with 5,752 routine passes and
one SetGear timeout; QuickC and MS C tiny round trips pass. SetGear repeats the
timeout in isolated pytest, while direct CLI validation passes; investigation
remains open. Global configured MyPy passes. LoadProg is now enrolled in the
routine lane with alternate-source C disabled (51 focused/pipeline tests pass).
Complete collection and expanded acceptance remain open. See the newest
failure-refresh section.

Earlier bounded fix: remove legacy comparison fallback that invented a bare AX
read when no reaching value was proven. LoadProg's two uninitialized AX errors
disappear, but two branch-ownership errors remain and the function still exits
4. Related condition/pass-order tests: 105 passed; architecture passes. Refreshed
default pipeline: 5,720 routine tests pass in 413.24s, with QuickC and all MS C
tiny full round trips passing. Global quality remains lint-blocked; complete
collection and expanded acceptance remain open. See the latest section of the
failure-refresh report below. This is not Step 9 completion.

Earlier gate refresh: **5,544 routine tests pass**, plus all QuickC and MS C tiny
round trips. A mapped retry of the previous complete audit's 47 failures gives
**25 passed, 22 failed**; this is not a full-suite count. Current failure groups
and next proof obligations are in [the September 19 failure refresh](reference/step9-failure-refresh-20260919.md).
Follow-up individually fixes the named `main` scorecard: it reported a rejected
attempt instead of the accepted output's clean validation. Fourteen focused
reporting/live tests and 132 enrollment tests pass, with scoped quality and
architecture gates clean. This closes one retry failure, not the full suite.
Overlay now passes its live validation, recompilation and 54-case far-return/ABI
oracle. Fixes consume exact Alias temporary identities, preserve register
versions at Lowering, and recognize typed indexed-byte storage in Validation.
The introduced DrawBar and MS C pointer-fixture regressions were caught and
repaired. The refreshed pipeline passes all QuickC/MS C round trips; its routine
lane has 5,608 passes and three timeouts, all passing an unchanged-limit focused
retry. The broad run is not green. Physical storage coverage and C initialization
remain separate mandatory guards. See the failure-refresh report for evidence
and limitations; this is not full-suite or Step 9 completion.
Before the graph-cache follow-up, SORTD acceptance passed **20/20** with zero violations; all 21
individual/combined C exports compile (16:02:50-16:05:10 +02:00, 140s CLI wall).

TID reload follow-up: Lowering now proves a saved register's byte stores when
they consume its exact, uniquely defined published temporary. The 52-test
related surface and scoped Ruff/MyPy/type-doc gates pass. TID passes that gate
but remains validation-failed (15 uninitialized reads, three missing branch
surfaces, one duplicate callsite); LoadProg also remains failed. Neither is
counted as fixed. Details and proof refusals are in the failure-refresh report.

Graph-cache follow-up (September 19, 16:53 +02:00): frontend discovery now uses
angr's cache-invalidating transition API and clears its local CFG cache on reset.
Fail-first regressions prove that previously recovered edges disappeared between
`transition_graph`, `function.graph`, IR and SSA. The focused surface passes
71 tests; pipeline enrollment passes 110 tests; architecture passes. Live TID
still fails, but missing branch surfaces decrease from three to one. LoadProg
now reaches a distinct unmaterialized GP-save gate: its return crosses into a
shared epilogue, outside the then-current same-block return proof. Neither function
is fixed. Global quality remains Ruff-blocked. The routine refresh reports
5,640 passes, one InBoxLng timeout and one stale InitBars topology expectation;
QuickC and MS C tiny full round trips pass. Binary decoding proves the InitBars
intermediate jump block; the test now asserts that exact topology and balanced
counters instead of requiring an unnecessary repair. Its entire downstream
Alias/bounds refusal contract and the unchanged-limit InBoxLng retry pass in an
18-test final focused run. This does not erase the failed broad run. The earlier
20/20 SORTD result is not verification of this change.

Return-path follow-up (September 19, 17:22 +02:00): Semantics now retains an
explicit finite CFG path from a register definition to its return. Four
fail-first cases cover the missing cross-block proof and unsafe acceptance of
same-address calls/unknown effects or a return with an outgoing edge. The final
related/enrollment set passes 183 tests; scoped Ruff/MyPy/type-doc and full
architecture checks pass. Global quality remains Ruff-blocked. LoadProg still
fails its GP materialization gate: its machine path is now proven, but native
AIL-to-C conversion drops the returned local's value-definition origin. All
three C returns retain only the same shared return-instruction address. Next:
preserve value origin at that conversion boundary, then join it to the path and
Alias-proven initialized storage in Lowering. No function fix or new broad
acceptance is claimed. Full details and counterexample requirements are in the
failure-refresh report.

Return-origin follow-up (September 19, 17:50 +02:00): native AIL-to-C conversion
now preserves typed per-use value origin on each CReturn, without mutating
shared CVariable or input AIL tags. Lowering joins that origin to the exact
machine path, keeping other proven definitions at a shared RET independent.
It still requires initialized Alias-proven storage. An additional fail-first
test caught acceptance of an `UNKNOWN_REFUSE` Alias fact; the boundary now
rejects it explicitly. The final related set passes **98 tests in 23.91s**;
scoped Ruff/MyPy/type-doc checks pass. Full architecture passed before the
final verdict guard; global quality remains lint-blocked. The fresh pipeline
passes: **5,686 routine tests in 455.62s**, plus 268 preliminary tests and all
QuickC/MS C tiny full round trips. All three pipeline stages pass, with zero
skipped or timed-out stages. This is not the complete pytest collection.

LoadProg still exits 4 at the GP materialization gate. Its saved bytes consume
a native AX variable defined by the call at `0x10c5`, not the published temporary
representation handled by the existing proof. Next: prove that call value
reaches the save at `0x10cb`, and prove the complete nonescaping local stores
dominate the conditional return. No name-based recognition or blanket call
exception is acceptable. A subsequent probe finds the authoritative call-summary
inventory empty at this gate. First trace its construction/publication and
consumption order before adding another recovery path. See the failure-refresh
report for evidence.

Call-storage follow-up (18:20 +02:00): the carrier was absent, not merely empty;
the existing binary summary owner proves the exact AX store at `0x10cb`.
Lowering now shares the previous call-output inventory initializer, verifies
native call-result byte snapshots, and proves complete nonescaping local stores
dominate conditional returns. The live GP return proof now passes. LoadProg
still exits 4 with two uninitialized AX reads and two missing branch surfaces
(`0x10b1`, `0x10b9`); it is not fixed. The final focused set passes 103 tests in
20.67s; scoped Ruff/MyPy/type-doc checks pass for the proof modules/tests.
The extracted-from legacy module retains 18 Ruff findings; MyPy passes when
its typed declaration-projection owner is included. At 18:31 the refreshed
pipeline passes **5,716 routine tests in 383.11s**, 268 preliminary tests, and
all QuickC/MS C tiny round trips (three passed stages; no failed, skipped or
timed-out stages). Full architecture passes; global quality remains lint-blocked.
This is not the complete pytest collection or function/Step 9 completion.

The 17:25 disk interruption has cleared: the latest check finds 7.5 GB free on
`/` and 15 GB on `/home`. Tests use the project's `.cache/step9-tmp` on `/home`.
No source, caches, personal files or system logs were deleted by this agent.
Step 9 remains incomplete.

### Earlier Acceptance Results (Before These Follow-Ups)

Sidecar-free numeric Sleep now passes focused validation and compiled deadline/ABI execution after
terminal proof validation and temporary-declaration preservation fixes. See
[acceptance contract and evidence](reference/p0-terminal-wide-validation.md).
The latest whole-file run emits **20/20** functions with validation passing;
BubbleSort, PercolateDown, and ShellSort now pass after condition-ownership and
precision fixes. There are no timeouts, empty functions, or tracebacks.
The refreshed whole-file acceptance gate passes, including RunMenu execution
and the absence of raw flag-state artifacts. Named/sidecar-assisted Sleep now
passes its two live regressions after branch-provenance preservation and
checked binary-target identity fixes; the combined Sleep set passes 16 tests
including compiled deadline/ABI execution and deliberate register corruption.
The refreshed whole-file gate passes 20/20 with no violations; all 21 C exports
compile, and the combined export is byte-identical to the saved comparison
snapshot. The default pipeline is green; full-suite and quality closure remain outstanding.
The latest full audit ended without a controller summary: saved shard results
contain 6,315 passed, 39 failed, and 124 skipped, not a complete-suite result.
Two stale ownership-manifest expectations have since been corrected (60 tests
pass). Global quality closure remains open; Step 9 is not complete.

Follow-up: CBW/CWDE condition provenance now preserves signed extension and
original load width. InsertionSort now passes whole-tail validation, strict
compilation, and a compiled behavioral oracle covering 65,581 cases. Aggregate
byte projection consumes proven layout at Lowering. See
[current evidence](reference/p0-condition-sign-extension.md).
The focused surface passes 101 tests. The refreshed default pipeline passes
5,536 routine tests (281.30s), four QuickC fixtures, and seven MS C tiny full
round trips. Its routine stage exceeds the configured 30-second advisory
budget. `quality-fast` still fails its global
linter stage. Exact full collection and expanded-pipeline closure are pending.

September 19 follow-up (observed 12:51-13:02 +02:00, approximately 11 minutes
including checks): RunMenu's final whole-file body passes 2,560 compiled
execution cases. The gate now executes that final definition with its exported
declarations and retains exact digest binding, rather than comparing an export
digest against a differently rendered definition. DrawTime's argument gate
accepts the equivalent parenthesized identity cast; corrupted arguments remain
rejected. The flag-artifact gate now includes `inertia_flags`, closing a false
negative. The final focused condition, ownership, and gate surface passes
134 tests in 8.44 seconds. Scoped parallel Ruff/MyPy/types/docs checks,
startup architecture checks, ownership checks, and diff whitespace checks pass.
Re-evaluating the saved whole-file transcript with execution evidence for its
tested final RunMenu body reports only raw flag-state artifacts.

September 19 follow-up (checks completed by 13:22 +02:00): RunMenu now
passes whole-tail validation without `inertia_flags`. IR lift artifacts persist
the existing binary callee status-input summaries; Lowering consumes exact
target evidence to prune closed, pure flag/carrier components. Unknown calls,
flags-reading callees, explicit argument/return consumers, memory effects, and
unrelated definitions remain protected. Narrower retries refresh callee
uncertainty rather than retaining older optimistic summaries. Validation uses
the existing algebraic condition normalizer for immutable precision evidence,
so removing a dead DEC carrier does not invalidate its equivalent predicate.
The focused surface passes 166 tests in 38.14 seconds, including the live
RunMenu compiled behavior and deliberate-corruption checks. Scoped Ruff, MyPy,
types/docs, startup architecture, and ownership checks pass. A fresh whole-file
gate subsequently passed at 13:26:46 +02:00: 20/20 accepted, no violations.
All 20 function exports and their combined translation unit passed the project
GCC recompilation check. The saved comparison artifact and all 20 line anchors
are refreshed; see [current semantic review](reference/step9-current-comparison.md).
`quality-fast` still fails repository-wide Ruff; the default pipeline now
passes all three lanes. Full architecture checking found missing ownership
headers, one missing future-annotations import, an insufficiently labeled
third-party dynamic boundary, and a duplicate Makefile test selection. Those
are corrected; 399 architecture/structuring tests pass (29.56s). Scoped Ruff,
types/docs, configured global MyPy, full architecture, agent context, and test
ownership now pass. These final changes are documentation, annotations, and
test-selection hygiene, not another decompilation semantics change.

At 13:39 +02:00, the current named Sleep check reproduced two failures, while
21 frontend-condition tests passed (47.68s total). Both named/rebased routes
report wide call-output `callsite_missing`, then uninitialized AX/DX and missing
branch surfaces. This is not explained by stale stdout assertions: the CLI
itself returns a validation failure. Next investigate preservation of the
typed callsite/return-binding evidence across exact-region rebasing and
Lowering, without moving semantic recovery into CLI or postprocess.
Evidence: `/tmp/step9-sleep-current.log`. This is not whole-goal completion.
The new condition-delta validator is enrolled in Make, architecture checks,
and test ownership. Full quality closure remains outstanding; Step 9 is open.

### Prior Checkpoint

**Implementation in progress:** terminal composite loop exits now consume the
existing complete wide-decision proof without moving the clock call. Two
Lowering defects exposed by the live integration are corrected: scalar AX
selector replay cannot overwrite DX:AX captures, and captured temporaries keep
their declared 32-bit type. Composite provenance also prevents scalar replay
from replacing the compact predicate with only one comparison half.
The 191-test focused surface passes. Sleep still fails one final branch
fingerprint check, so it is not accepted and no additional SORTD function is
counted complete. See the linked Sleep report for exact refusal controls,
remaining validation-proof work, and gate results.

Baseline revision: `cffd0bb43`; the worktree was clean on resumption.
A fresh complete sidecar-free SORTD gate still accepts **15/20 functions**,
with **five validation failures**, no timeouts, no empty results, and no
tracebacks. Failing addresses: `0x10808`, `0x108d0`, `0x10a88`, `0x10c18`,
`0x10f38`. The raw flag-state artifact check also fails. DrawTime's argument
check and the RunMenu execution gate now pass. This supersedes the older
12/20 checkpoint below; Step 9 is not complete.

The existing Sleep regression fails independently: **1 failed, 17.26s**,
including 14.18s in its executable call. Its wide comparison retains
uninitialized AX/DX reads and three uncovered branch obligations. A fresh-cache
worker-local probe proves the natural loop, its unique exit, and the complete
signed `clock > deadline` comparison; existing Lowering can build the wide
predicate. The missing integration is terminal composite break ownership, not
wide-operator discovery. See
[current Sleep evidence and next implementation boundary](reference/p0-sleep-terminal-composite-exit.md).

Evidence: `/tmp/step9-sep18-whole.{txt,json,log}`,
`/tmp/step9-sep18-sleep-test.log`, and `/tmp/step9-sep18-loop.log`.
Initial investigation checkpoint: `2026-09-18 21:45 +02:00`; active time was not
separately measured. That read-only investigation preceded the implementation
checkpoint above.
The final default test pipeline passes: 5,439 routine tests, QuickC, and MS C
tiny round trips. Startup architecture and test ownership checks pass. Full
pytest and expanded acceptance are not refreshed; quality-fast remains
lint-blocked. This checkpoint does not close Step 9.

## Historical Checkpoints (2026-09-13)

**DrawTime blocker narrowed:** live Alias and C storage disagree by eight bytes
for both SI/DI saved-register restores. The hard gate correctly refuses their
materialization. Both default and explicit-window commands fail. The existing
DrawTime test was absent from the routine selection; it is now enrolled and
uses the default path, so the prior routine-green checkpoint is not current
acceptance of this expanded lane. Hard errors now carry the function address
and exact restore obligations. See
[evidence and remaining ownership investigation](reference/p0-drawtime-stack-coordinate-divergence.md).

**Whole-file recheck and ESC gate reconciliation:** the full-file gate now
executes the shared 2,560-case RunMenu oracle against the exported function,
supplying the canonical portable runtime header and binding successful evidence
to the exact function-definition digest. The current if/break/shared-epilogue
output passes; no switch spelling is required when matching execution evidence
is available. Missing exports, failed compilation/execution, stale evidence and
scalar signatures remain failures. The transcript-only legacy check remains
available for parser tests; the executable gate always requires execution.

Two fresh whole-file runs accepted **12/20 functions**, not 20/20. The final run
has no RunMenu violations. Remaining failing addresses are **0x10060, 0x10498,
0x10808, 0x108d0, 0x10a88, 0x10c18, 0x10e70, 0x10f38**; DrawTime's argument
contract and raw flag artifacts also fail the ratchet. These failures must be
resolved, not hidden by lowering the floor. Evidence:
`/home/xor/.cache/step9-runmenu-whole-fixed.{txt,json,log}`.
The initial exported-artifact compilation missed its runtime prelude; that
harness integration defect was corrected and the complete gate rerun.
Focused gate/RunMenu tests passed **23 tests, 6.83s** before the additional
prelude regression; scoped tooling MyPy passes. Full-suite acceptance remains
open and the prior green routine pipeline does not supersede this result.

**Routine pipeline fully green after branch-origin preservation:**
`make test-pipeline PYTHON=./.venv/bin/python` exits 0: **5,402 routine tests
passed in 326.70s**, plus **268 preliminary passes in 15.27s**. QuickC **4/4**
passes with semantic validation (51.24s). MS C tiny **7/7** passes the complete
original-build/run, decompile, generated-C recompile/run pipeline (105.75s),
including the previously failing `simple_control` and `loops_jumps` fixtures.
The final annotation-protocol regression batch passed **5 tests, 6.55s**;
the new module passes Ruff and scoped MyPy. Quality-fast still exits 2 on
global lint debt; its 39-module compiled-import smoke passes.
Evidence: `/home/xor/.cache/step9-origin-{quality,pipeline}.log` and
`angr_platforms/.cache/test_pipeline/summary.json`.
This is not a full pytest collection or Step 9 completion: the full-file ESC
oracle reconciliation, quality debt and complete-suite audit remain open.
The routine duration increased from the previous 259.13s checkpoint; timings
are not a controlled before/after benchmark, so performance remains to assess.

**Symbolic branch provenance fix (live check 16:07 +02:00):** `nested_loops`
now exits 0 with clean whole-tail validation. Root cause: angr's symbolic
expression-keyed annotation dictionary overwrote the first comparison's source
with a later equal comparison. A focused regression reproduced both recovered
branches carrying the second address. The Structuring AIL-to-symbolic boundary
now preserves complete instruction/block provenance on explicitly requested
branch predicates using immutable, non-relocatable origin annotations. No
predicate, break body, or validation obligation is replaced or removed.
Focused loop/topology/origin checks: **42 passed, 7.85s** before the final
typed annotation-protocol adaptation; the new owner passes scoped MyPy/Ruff.
Routine test, ownership, architecture and typing lists include the new surface.
Full round-trip, quality and performance acceptance remains pending; do not
count the live function result as Step 9 closure.

**Remaining tiny-loop branch diagnosis:** fresh read-only worker probes confirm
both natural-loop owners are now proven. The inner break statement retains
source `0x1043`, but its condition carries the outer comparison's identity
`(0x105d, 0x1059)`; linked-address execution reproduces the same mismatch.
The emitted inner `total > 40` break survives, but validation correctly refuses
missing coverage for its own branch. Do not repair this by accepting expression
equality or copying statement tags without CFG proof. Trace the upstream
condition-origin conflation and preserve distinct branch occurrences there.
Evidence: `/home/xor/.cache/step9-guard-site.{c,log}` (exit 4).
The storage-OR regression is now enrolled in both routine Make lists, the
pipeline, and test ownership. The individual switch-fold command passed; full
tiny round trips and broad gates still need refreshing after these changes.

**QuickC fixture lane green (15:36 +02:00):** routine pytest **5,385 passed,
259.13s**, plus **268 preliminary passes, 9.66s**. QuickC **4/4 passed,
35.88s**, including `args`; generated-C contract and semantic validation pass.
MS C tiny remains **5/7, 136.94s**, with `simple_control` and `loops_jumps`
failing. Quality-fast remains lint-blocked; scoped MyPy and 39-module compiled
import smoke pass. This is not the full pytest collection or Step 9 closure.

**QuickC call predicates (15:28 +02:00):** exact bound-call Boolean
normalization and validation proof ordering remove the live `args` branch
coverage failure. **50 focused tests pass, 6.63s**; a fresh live command exits
successfully with passed semantic and whole-tail validation. Scoped MyPy and
the new helper's Ruff pass. Broad pipeline refresh is pending; quality-fast
is lint-blocked with the 39-module compiled-import smoke passing.
See [cause, DoD, failure criteria and remaining fixture diagnoses](reference/p0-quickc-call-condition-ownership.md).

**Routine pytest green (15:14 +02:00):** after the InitBars composite-root
repair, **5,376 passed in 221.11s**, plus **268 preliminary passes in 9.58s**.
This is the routine collection, not the complete pytest suite. The separate
round-trip lanes remain QuickC **3/4 (36.04s)** and MS C tiny **5/7 (139.55s)**;
`args`, `simple_control`, and `loops_jumps` remain unresolved. Quality-fast is
still lint-blocked. Step 9 remains active; no gates were disabled or weakened.

**InitBars composite-root repair (15:06 +02:00):** entry-owned composite
selection now reaches the existing stack-object lowering without bypassing
CFG-chain proof. Fresh InitBars reports `validation=passed` and clean tail
validation; typed pointer/field output matches the source guard. **79 related
tests pass, 38.99s**, including InitBars and RunMenu. Ownership tests are now
explicitly enrolled in routine gates. Scoped MyPy and ownership Ruff pass;
quality-fast remains lint-blocked with compiled-import smoke green. Routine
pipeline refresh is running. No whole-suite or Step 9 completion is claimed.
See [cause, DoD, failure criteria and timing](reference/p0-initbars-composite-root.md).

**InitBars investigation / validator cleanup (14:58 +02:00):** the shared-exit
validator now separates literal-case checks, retains all refusal behavior,
and passes Ruff and scoped MyPy; **44 focused tests pass, 6.12s**. A fresh
InitBars run still fails. Diagnostic tracing finds that its combined guard
uses the last JCC's origin (`0x105b1`, block `0x105ad`) while the enclosing
node is tagged at entry `0x10560`. Ownership rejects this pair before
call-output stack-object lowering runs. The binary linear entry reaches the
first predicate at `0x10598`; subsequent branches form the combined guard.
Next: prove complete composite-root ownership and all consumed predicates
with refusal tests, then recheck stack-object lowering and initialization.
Do not bypass ownership, initialize unknown locals, or add rendered-C repair.
Evidence: `/home/xor/.cache/step9-initbars-debug.{c,log}`. Broad gates have
not been rerun after the behavior-preserving validator extraction.

**RunMenu execution checkpoint (14:53 +02:00):** unchanged generated C passes
2,560 key/pause/sound scenarios, including correct call order/arguments, ESC,
default keys, counter resets and preserved SI/DI. Deliberate lost-call,
lost-break and wrong-argument controls compile but are rejected at execution.
The live regression, including mutation controls, passes in **7.60s**.
Routine pipeline refreshed: **5,364 passed / 1 failed, 237.61s**, plus
**268 preliminary passes, 9.09s**. InitBars remains the single routine pytest
failure, with unchanged uninitialized storage and missing condition owners.
QuickC remains **3/4, 43.44s**. MS C tiny lane remains failing (**138.36s**).
Quality-fast is lint-blocked; 39-module compiled-import smoke passes.
The full-file transcript ratchet still requires a literal ESC switch case;
reconcile it with equivalent behavioral evidence before full-file acceptance.
This is not a full-suite or Step 9 closure. Details and oracle obligations:
[RunMenu evidence](reference/p0-runmenu-switch-coverage.md).

**RunMenu validation checkpoint (14:40 +02:00):** the shared-epilogue exit
proof and void-return preservation now survive final validation. Exact unit
decrement fingerprint normalization removes the four remaining predicate
mismatches without relocating ordered comparisons across wrapping arithmetic.
Fail-first decrement regressions: **12 failed / 1 passed, 6.00s**. After the
fix, the combined focused run is **105 passed / 1 failed, 36.30s**: RunMenu
passes semantic and whole-tail validation, then fails the legacy literal
`sub_11278(local_2)` assertion. Generated-call and dispatch behavior still need
verification before replacing any output-shape assertions. No function closure
or Step 9 closure is claimed. New shared-exit and decrement tests are enrolled
in routine gates; broad gates have not been refreshed. Ruff reports existing
fingerprint-module complexity/constant debt; the new decrement test is clean.

**RunMenu branch ownership (14:02 +02:00):** all remaining missing branch-owner diagnostics
are gone after exact unconditional-loop, label/nested-entry and conditional-goto
proofs in Structuring. The function still fails the separate switch-exit
obligation; no validator was relaxed. Related surface: **158 passed, 7.41s**.
Scoped/promoted typing and compiled-import smoke pass; quality-fast remains
lint-blocked. Routine pipeline: **5,338 passed / 2 failed, 241.36s**;
QuickC **3/4**, MS C tiny **5/7**, unchanged failing fixtures.
Next is a typed proof for
the break/shared-epilogue form, not suppressing `missing-case`. See
[RunMenu Switch Coverage](reference/p0-runmenu-switch-coverage.md).

**Empty connector ownership (13:35 +02:00):** exact Structuring ladder ownership now follows
only SSA-proven empty connectors, retaining physical CFG facts for replay.
RunMenu's missing owners decrease from six to four, but its ESC-exit obligation
and function regression remain red. Focused surface: **33 passed, 5.96s**;
scoped MyPy passes, quality-fast remains lint-blocked. Routine pipeline:
**5,312 passed / 2 failed, 234.82s**, QuickC **3/4**, MS C tiny **5/7**.
No function or Step 9 closure. See
[RunMenu Switch Coverage](reference/p0-runmenu-switch-coverage.md).

**Direct result JCC prerequisite (13:14 +02:00):** adjacent word arithmetic
now supplies direct JE/JNE result tests at the frontend without deleting flag
writes. Thirty-three new tests are enrolled; 79 focused checks pass. Routine
pipeline: **5,302 passed / 2 failed in 267.65s**, with RunMenu and InitBars
still failing. QuickC 3/4 and MS C tiny 5/7 are unchanged. Scoped/promoted
typing and compiled-import smoke pass; lint debt remains. No function closure
or measured speedup is claimed. See
[RunMenu Switch Coverage](reference/p0-runmenu-switch-coverage.md).

**Switch definition-survival gate (12:53 +02:00):** tracing before codegen
identifies Inertia's typed SeqNode replacement as the destructive owner: it
discards ten SSA definitions still read by retained RunMenu code. A new
Structuring gate refuses this loss atomically with exact IDs; it does not
claim the switch fixed. Focused: 26 passed / RunMenu failed. Routine pipeline:
**5,269 passed / 2 failed in 237.67s**; InitBars and RunMenu remain. QuickC
3/4, MS C tiny 5/7, and lint blockers are unchanged. Scoped/promoted typing
and compiled-import smoke pass. Next is definition-preserving switch proof,
not tag-only acceptance. See
[RunMenu Switch Coverage](reference/p0-runmenu-switch-coverage.md).

**IR branch-target prerequisite (12:33 +02:00):** bare VEX exit constants no
longer become unknown CJMP operands; integer values and widths are retained
at IR import. Seven real-pyvex regressions are enrolled. Routine pipeline:
**5,262 passed / 2 failed in 249.00s**, plus 268 preliminary passes. RunMenu
and InitBars remain red; QuickC 3/4 and MS C tiny 5/7 are unchanged. Typing
and compiled-import smoke pass; lint debt still blocks `quality-fast`.
No RunMenu or Step 9 closure. Details:
[RunMenu Switch Coverage](reference/p0-runmenu-switch-coverage.md).

**RunMenu diagnosis (12:18 +02:00):** live constructor tracing locates the
switch in angr's normal codegen, not the optional typed-switch replacement.
Its nine initial cases become ten after the existing return-case repair;
eleven dispatch predicates still lack shared ownership. The focused ESC-exit
regression remains red (1 failed, 30.67s). No production or gate changes and
no additional function closure. See
[RunMenu Switch Coverage](reference/p0-runmenu-switch-coverage.md) for evidence,
the next proof obligations, DoD and failure definition.

**InBoxLng coverage checkpoint (12:08 +02:00):** the proven wide-predicate
producer now publishes shared condition-chain provenance before replacing the
body. Missing/duplicate identities fail atomically; no validation gate was
relaxed. All 12 focused checks pass, including live tail validation, strict C
compilation and signed-wide behavior. Final routine pipeline: **5,255 passed /
2 failed in 242.29s**, plus 268 preliminary passes. Remaining curated failures:
InitBars and RunMenu. QuickC remains 3/4; MS C tiny remains 5/7. Global Ruff
debt keeps `quality-fast` red; promoted MyPy and 39-module mypyc smoke pass.
Full-suite and Step 9 completion remain unproven. See
[Wide Return Condition Coverage](reference/p0-wide-return-condition-coverage.md)
for reason, DoD, failure definition and timings.

**SetGear ownership checkpoint (11:52 +02:00):** the transfer boundary now
checks Alias-normalized operators rather than historical producer labels.
Structuring uses explicit/executed arm entries instead of subtree minimum
addresses, with a separate binary-value proof for cloned return arms. SetGear
passes tail validation and compiled behavior; the LoadProgram regression also
passes. Four intermediate regressions were repaired without weakening their
checks. Final focused set: 60/60. Refreshed routine pipeline: **5,251 passed /
3 failed in 235.33s**, plus 268 preliminary passes. Remaining curated failures:
InitBars, RunMenu, InBoxLng. QuickC remains 3/4; MS C tiny remains 5/7.
Global Ruff debt keeps `quality-fast` red; promoted MyPy and 39-module mypyc
smoke pass. Full-suite and Step 9 completion remain unproven. See
[SetGear Condition Ownership](reference/p0-setgear-condition-ownership.md)
for each repair's reason, DoD, failure definition and measured timings.

**PercolateUp loop-exit proof follow-up (11:15 +02:00):** Structuring now
normalizes only SSA-proven empty exit connectors in a detached topology view,
retaining physical branch edges and header/latch identities. The existing
break receives exact typed CFG ownership; no body replacement or validation
relaxation. Before: one topology regression failed. After: 40 focused checks
pass, including sidecar-free PercolateUp with clean tail validation. Its
caller-cleanup regression now also requires strict GCC compilation: 15/15
pass. Refreshed routine pipeline: **5,232 passed / 5 failed in 329.39s**, plus
268 preliminary passes. Remaining: InitBars, RunMenu, InBoxLng, LoadProgram,
SetGear. QuickC remains 3/4 and MS C tiny 5/7. Global Ruff debt still blocks
`quality-fast`; promoted MyPy and 39-module mypyc smoke pass. Full-suite and
Step 9 completion are not claimed. See
[Existing Loop Exit Proof](reference/p0-existing-loop-exit-proof.md).

**InitMenu precision follow-up:** the isolated producer trace proves its current
masked/shifted global pair and recorded two-word global pair canonicalize to the
same predicate. Precision matching now consumes the existing storage normalizer
before compaction. Eight controls reject wrong masks, shifts and global offsets
under short and default fingerprint limits. The live InitMenu regression and
related checks pass: 57 tests in 40.11s. This closes the InitMenu failure from the
last curated run individually. Refreshed routine pipeline: **5,213 passed /
6 failed in 306.96s**, plus 268 preliminary passes. QuickC remains 3/4 (`args`
fails); MS C tiny remains 5/7 (`simple_control`, `loops_jumps` fail). The six
curated failures are PercolateUp, InitBars, RunMenu, InBoxLng, LoadProgram and
SetGear. `quality-fast` remains red on Ruff; promoted typing and the 39-module
mypyc smoke pass. No full-suite or Step 9 completion is claimed.

**QuickSort focused acceptance is now green:** both named and sidecar-free live
regressions pass validation, strict gcc, compiled sorting/call-effect checks,
and preserved-call assertions. The oracle also checks empty/singleton ranges.
Validation now records an immutable integer-view fingerprint alongside the exact
fingerprint: explicit same-width casts match later declarations only when width
and signedness agree. Operator changes and removal of non-identity casts remain
rejected. This replaces the unsuccessful identity-projection-only experiment.
Obsolete guard-shape assertions were replaced by behavioral proof, not disabled
semantic checks. Final focused run: 38 passed in 9.00s (warm cached live outputs);
the preceding producer run was 37 passed / one obsolete pivot-copy assertion in
33.35s. Focused MyPy and full architecture pass. This closes two more original
failure cases individually: 19 revalidated / 28 unclosed, not a fresh full-suite
result. The broad refresh is red: 5,201 curated tests passed / 10 failed in
262.73s; three unit failures were subsequently corrected (74 related tests
passed in 9.42s). Seven live failures remain unclosed from that run. MS C tiny
remains 5/7; QuickC also fails. Full MyPy reports 25 errors in three legacy
files (`omf_pat.py`, `scripts/verify_borrow_real_mode.py`, and
`scripts/report_compiler_matches.py`). The new composite-owner redundant cast
found by promoted typing was removed. `quality-fast` remains red on lint debt;
39-module mypyc import smoke passes. No refreshed all-green routine or complete
suite is claimed; Step 9 remains open.

**Latest QuickSort checkpoint (supersedes the paragraphs below):** the IR
overlapping-block successor repair and Structuring composite-pretest owner make
sidecar-free QuickSort pass validation, strict recompilation and the ten-case
compiled behavior oracle. Its live test still fails old output-shape assertions;
it is not counted closed. Precision matching now compares compacted tokens
consistently. Named QuickSort additionally exposed CLI binary-expression
reconstruction dropping provenance tags: a new regression fails before and
passes after preserving those tags, and is enrolled in routine gates. Seven
missing-owner failures disappear, but two composite predicate precision failures
remain: declaration-identity cast removal changes immutable fingerprints.
Resolve that with typed constituent evidence, not unconditional acceptance or
new semantic recovery in CLI. Latest focused run: 3 passed / 1 named live failure
in 56.65s. Ruff reports 99 legacy findings in the touched CLI module. Broad gates
have not been refreshed after this batch; Step 9 remains open. Evidence:
[QuickSort checkpoint](reference/p0-quicksort-condition-views.md#provenance-preservation-checkpoint).

**QuickSort correctness blocker:** generated C reports passed validation and
compiles strictly, but compiled execution fails. Single-fact typed/JCC consumers
now preserve both composite partition guards; a fresh isolated trace confirms
the pivot comparisons and break polarity survive. The remaining behavioral
failure is case 8 (`{0, 3, -2}`), where the reconstructed pivot lacks its signed
word interpretation. A diagnostic-only signed conversion at both comparisons
makes all ten cases pass; no rendered-C production repair was applied. Latest
focused controls: 28 passed; architecture passes. Both live cases remain open.
Final validation now rejects missing required condition owners, including stale
complete snapshots. Next lower the constituent typed conditions with correct
signedness. Latest broad pipeline: 5,159 passed / 7 failed; the JCC neutral-root
over-refusal was subsequently fixed (161 related tests pass). Six live cases
remain unclosed from that run. QuickC: 3/4 pass; MS C tiny: 5/7 round trips pass.
Architecture and focused MyPy pass; global lint/MyPy remain red. Details:
[QuickSort behavioral evidence](reference/p0-quicksort-condition-views.md).

QuickSort now passes whole-tail validation in both named and sidecar-free
focused cases. The live producer trace identified shared argument signedness
refinement losing existing array-index views, plus address fingerprints
stripping semantic casts. Repairs are in Types/Lowering and Tail Validation.
The cases still fail later control-flow/pivot output-shape assertions, so
neither is counted closed. Focused controls: 34 passed; project MyPy passes.
Broad gates and lint closure remain open. See the latest lifecycle section in
[QuickSort evidence](reference/p0-quicksort-condition-views.md).

Indexed load-site joins now retain the matched index value expression instead
of replacing a proven unsigned view with a bare signed stack variable. The
new regression fails before and passes after; 180 segmented-load tests pass,
but both QuickSort cases remain open. Routine pipeline: 5,109 passed / one
InitMenu text-assertion failure; QuickC and MS C tiny round trips pass. The
identity-cast assertion is corrected and the sequential focused rerun passes
15 tests. Quality-fast remains red on lint debt; 39-module mypyc smoke passes.
See [the load-site and gate evidence](reference/p0-quicksort-condition-views.md).

QuickSort follow-up: nested declaration-identity projection now traverses
required outer casts without removing them or mutating the AST. Both live
cases still fail, but final diagnostics narrow to the indexed-memory view
mismatch. Related tests: 27 passed; Ruff and project MyPy pass. No additional
original failure is closed. See [condition views](reference/p0-quicksort-condition-views.md).

Original-failure refresh: 15 passed / 32 failed / 0 skipped in 409.12s,
with unchanged source hashes. Subsequent HeapSort harness repair closes two
of those failures in focused checks: 18 passed in 2.45s, including four
register-corruption controls; Ruff passes. Generated C remains unchanged.
This gives 17 individually revalidated original cases, not a fresh full-suite
result or an effort percentage. Thirty original failures remain unclosed.
See [HeapSort runtime contract](reference/p0-heapsort-behavior-oracle.md).

Literal-source follow-up: TID's MapInEMSSprite now receives `(2, 0)`, reducing
uninitialized reads from 22 to 20. The Lowering classifier prevents a named
stack carrier from overriding proven immediate PUSH evidence. Focused checks:
37 passed, live TID still failed (121.05s body); missing/malformed-source
controls are included. The routine result below predates this follow-up.
That literal-source repair alone closed no additional original failure.
The subsequent refresh and HeapSort checkpoint above supersede its failure
count; shared-cause grouping remains the priority for further acceptance work.

Latest repair: Lowering now schedules the existing argument-only consumer for
semantic gaps even when arity is already correct. Four direct/masked-call
controls pass, and TID's itoa now receives the range value, buffer address and
radix. Whole-tail findings fall from 25 uninitialized reads plus one argument
mismatch to 22 reads and no argument mismatch; duplicate-call and switch
defects remain. Routine pipeline passes 5,087 curated tests (238.49s), QuickC
and all seven MS C tiny round trips. Full architecture and MyPy pass;
quality-fast remains red on global lint debt. InBoxLng now has a dedicated
non-skipping live regression, replacing its old matrix entry. Source-index
lookup preserves skip evidence for parameterized nodes. No additional baseline
closure is claimed. See the argument-only scheduling section of the TID report.

TIDShowRange follow-up: corrected the exact synthetic MS C register contract
(BP preserved, BX scratch) and connected its BP proof in Semantics before
Alias. Eighteen ABI controls are enrolled. Also repaired GP Lowering's binding
of whole-local reloads, including typed folded call stores and transparent
container dominance, with twenty new controls. TID now passes GP binding but
still fails whole-tail validation: its argument, storage and constant-switch
defects are not closed. Routine gates pass 5,083 curated tests in 250.21s,
QuickC and seven MS C tiny round trips. Quality-fast remains red on global
lint debt; a follow-up project MyPy run passes and 39 compiled-import smokes
pass. No additional baseline closure is claimed.
The independent 180-input/nine-corruption oracle remains required. See
[TIDShowRange recovery evidence](reference/p0-tidshowrange-recovery.md).

Latest baseline accounting: **15 of 47 failures individually resolved;
32 remain unresolved**, without a complete-suite refresh. InBoxLng now passes
its compact-comparison, whole-tail validation, strict compilation and compiled
behavior gates. A live observer proved the wide-pair proof compared rendered
offsets with machine BP offsets; Types/Lowering now uses the authoritative
projection for both sources. Four regression controls and the live function
are enrolled. The final warm pipeline passes 5,035 curated tests (182.57s),
QuickC and all seven MS C tiny constructs. A first run hit SetGear's analysis
deadline; its bounded per-test budget was adjusted without weakening assertions.
See [closure evidence](reference/p0-inbox-condition-ownership.md) for before/after
proof, cache conditions, timings and remaining global lint failures. DrawRadarAlt's
existing bounded-timeout branch expected an obsolete message; it now checks
the contextual recovery timeout and terminal no-fallback policy (one pass,
26.86s). This is a test-contract correction, not successful function recovery.
SetGear now passes compiled behavior checks, including signed speed boundaries
and exact Message effects; TIDShowRange still fails validation. Intermediate
counts below describe earlier checkpoints.

Typed comparison views checkpoint (02:50 +02:00): the Structuring proof
consumer now delegates scalar ordering views to Types/Lowering rather than
letting a storage declaration override ConditionIR signedness. Opposite-type
operands on both comparison sides pass exhaustive 16-bit and sampled 32-bit
compiled checks. Proven unsigned masks remain intact; 32-bit views use fixed
width C types rather than host-dependent long. InitMenu now casts its unsigned
cszMenu operand for the proven signed comparison; its acceptance passes.
Final routine pipeline passes: 268 preliminary checks, 4,955 curated tests
(218.48s), QuickC fixtures and MSC6 tiny full roundtrips. Architecture and
scoped MyPy pass; new module/test Ruff pass. Global quality-fast remains red
with 6,279 Ruff findings, no reported MyPy errors, 39 compiled import smokes
passed. No full-suite refresh or additional baseline closure is claimed.
SetGear follow-up: exact CFG decision-ladder ownership now includes mixed
taken/fallthrough arms and a final else, using statement block provenance.
This lets the existing typed comparison consumer preserve signed Knots rather
than bypassing it. The old generated C fails the new 2,304-case behavior oracle;
new output and five corruption controls pass. The oracle and live regression
are enrolled in the routine pipeline. Routine gates pass: 268 preliminary,
4,969 curated tests (215.85s), QuickC (32.788s), MSC6 roundtrips (81.095s).
Quality-fast exposed two new optional-target type errors; explicit selected-edge
invariants resolved them. The final focused run passes 17 tests (21.21s).
Global quality-fast still fails with 6,278 Ruff findings; no MyPy errors are
reported and 39 compiled import smokes pass. Full-suite/expanded/hard gates
remain open. Details and exact artifacts are in the full-suite audit document.

Small COD follow-up: Ready5's stale segment-cast spelling is corrected with
stronger exact global-write assertions (one pass, 14.11s). InBoxLng remains
genuinely incorrect: the independent compiled-C oracle rejects z equal to both
bounds at INT32_MIN (expected 1, actual 0). Its diagnostic now prints the axis,
inputs and result; all eight oracle/provenance tests pass. Investigate the
wide comparison's equality-arm polarity and typed high-word storage binding;
do not weaken validation or treat this as formatting debt.
Fresh uncached tracing narrows the first defect to folded single-return guard
ownership: a shared eventual return prevents local continuation classification,
leaving an unsigned high-word predicate. The oracle's reported z case can fail
in its preceding x guard. See [InBoxLng ownership evidence](reference/p0-inbox-condition-ownership.md)
before implementing or repeating probes. InBoxLng is still unresolved.
The local-region proof is now implemented in Structuring: production output
passes the unchanged InBoxLng behavior oracle, with 20 refusal/ownership
controls and 69 related checks passing. Routine pipeline passes 4,989 curated
tests plus QuickC and MSC6 roundtrips. Scoped types and architecture pass;
global quality-fast remains red with 6,278 Ruff findings and no MyPy errors.
InBoxLng still exits 4 on width/subview and predicate-replay validation;
there is no additional baseline closure. Continue from the detailed evidence,
not the superseded diagnostic-only prototype.
Storage-width follow-up prevents sign-only evidence from resizing arguments
and preserves wide source types during high-word extraction. Eleven new
regressions are enrolled. Fresh InBoxLng keeps all dword declarations and
passes compiled behavior; the later coordinate-validation repair below resolves
its two predicate identity mismatches.
Routine pipeline passes 5,000 curated tests (228.06s), QuickC and MSC6;
scoped types and architecture pass. Global lint debt and full acceptance
remain open; the baseline closure count is unchanged.

Validation-coordinate follow-up: InBoxLng now exits 0 with whole-tail
validation passed and passes the unchanged strict compiled behavior oracle.
Machine-BP argument maps and exact word-storage identity are corrected;
high-word normalization requires matching typed evidence, AST mask/shift,
storage owner and source width. Nine focused coordinate/refusal tests pass.
The live test still fails its compact whole-width condition requirement, so
InBoxLng is not counted as closed. Related validation checks pass 396 tests
and expose one indexed-field signed-view mismatch, also reproduced with the
HEAD fingerprint module against current dependencies. Routine pipeline passes
5,009 curated tests in 222.27s plus QuickC and MSC6 roundtrips; quality-fast
remains red on lint debt, with scoped MyPy and startup architecture passing.
See the linked InBoxLng evidence document for logs and remaining acceptance.

Indexed-field validation follow-up is now repaired at the validation layer:
an explicit signed-word segmented load and an equivalent signed struct field
are joined only with matching storage, width, signedness and branch polarity.
The existing failure and two storage-refusal controls pass; eleven additional
view/refusal controls are enrolled along with the previously omitted loop
condition family. Routine pipeline passes 5,030 curated tests (226.50s), QuickC
and all seven MSC6 roundtrips. Project MyPy and architecture pass; quality-fast
remains red on lint debt, with 39 compiled imports and 53 subsequent focused
control-flow tests passing. InBoxLng's compact-condition requirement and the
original full-suite failure inventory remain open; no baseline closure is added.

ReInitBars save/restore investigation now identifies an upstream proof gap:
the ordinary call at rebased 0x100b retains a complete stack effect but lacks
BP preservation. Alias drops its BP coordinate, then an unresolved BP-relative
store clears the saved-byte inventory. All eight restore candidates end as
UNKNOWN_REFUSE, including final SI/DI. Lowering receives no proven snapshots;
changing its byte-acceptance shortcut would not solve this case. Next: derive
BP preservation from authoritative callee register evidence and consume it in
the call-effect contract, with clobbered/unknown callee refusal controls. Do
not infer it from function names, compiler convention or argument cleanup.
No production semantics changed or additional acceptance closed by this probe.

ReInitBars execution harness repaired at 02:06 +02:00: extracted generated
bodies now receive 32-bit GP runtime definitions from the authoritative symbol
inventory. Execution checks additionally prove nonzero ESI/EDI preservation;
five compile-valid corruption controls reject lost clock calls, wrong copies,
draw-before-copy and low/high register corruption. Nine focused checks pass
(6.14s), Ruff and scoped MyPy pass. Actual generated ReInitBars now passes
compiled behavior but still fails the unchanged redundant-local assertion.
No additional baseline failure is closed; **36 remain unresolved**.

Routine verification refreshed at 02:01 +02:00 after the type/interface changes:
`make test-pipeline` passes, including 268 preliminary checks, 4,941 curated
tests (175.54s), QuickC fixtures and all seven MSC6 tiny constructs through
the full roundtrip gate. Its first run caught pytest node selectors incorrectly
enrolled as Ruff paths; Make now passes file paths to Ruff while preserving
the focused pytest selections. The existing three Make input checks pass.
These are warm-cache routine results, not a complete-suite refresh or a
performance improvement claim. The focused stage remains over its recorded
30s budget. Full-suite and quality-hard acceptance remain open.

`sub_ulong` closes its unchanged acceptance test (91.56s) after fixing typed
interface preservation in Types/Lowering. A prototype can exist before its C
argument variables; exact ABI offset/width matches now preserve those types
instead of substituting unsigned body defaults. Fail-first storage controls
and 36 related tests pass; scoped MyPy passes. Eleven original failures are
individually resolved; **36 remain unresolved against the original baseline**.
This is not a complete-suite refresh. See the complete-audit trace and evidence.

### Earlier Checkpoints (Historical, Not Current Counts)

Wide-return preservation: width-only prototype promotion no longer overwrites
an existing 32-bit return signedness. Two fail-first controls and 44 related
tests pass; scoped MyPy passes. The `sub_ulong` acceptance test still fails on
its mixed signature, so the retained unresolved count remains **37**. Trace
initial return inference versus unsigned argument materialization next; no
function or Step 9 acceptance is claimed.

MSC runtime harness fix: assembled generated bodies now receive the GP ABI
declarations corresponding to the linked runtime. Fail-first regression and
four unit checks pass; scoped MyPy passes. Unchanged scalar acceptance now
compiles/executes: `sub_ss` passes, while `add_sc` save/restore locals and
`sub_ulong` return signedness remain failures. Ten original failures are
individually resolved; **37 remain unresolved against the original baseline**.
No complete-suite pass is inferred. See the complete-audit follow-up.

COD runner follow-up closes three stale timeout expectations: a successful
diagnostic scan must not replace the failed child's status. Updated tests
retain diagnostics and explicitly require the nonzero return code and absent
validation evidence. No production behavior changed. Related runner surface:
37 passes (8.09s). Nine original failures are individually resolved;
**38 remain unresolved against the original 47-failure baseline**. No complete
suite refresh or semantic-function acceptance is claimed.

Retained full-suite failure follow-up: the tiny-single-call CLI regression now
uses real decoded operand evidence instead of mnemonic-only instruction mocks.
Its assertions are unchanged; the original failure was reproduced, and all
five related tests pass (9.30s). It is enrolled in routine gates. Six of the
original 47 failures are individually resolved; **41 remain unresolved against
that baseline**. This is not a refreshed complete-suite result. Sleep remains
open. Details: [Complete Audit](reference/p0-full-suite-20260912.md).

Routine gate refresh: `test-pipeline` passed on the current changes:
268 preliminary checks, 4,929 curated tests (246.85s), QuickC fixtures,
and MSC6 tiny full roundtrips. `quality-fast` remains failed with 6,242
Ruff findings; no MyPy errors were reported and 39 compiled import smokes
passed. No exact complete-suite refresh or Sleep acceptance is claimed.

Latest ownership correction: generic branch materialization no longer treats
break/continue source tags as destination proof. This reproduced Sleep's
reversed break polarity. Eight fail-first cases now pass; 54 related checks
pass and scoped MyPy passes. The existing large owner retains 12 Ruff findings.
Sleep remains failing; loop-aware wide-predicate ownership and subsequent
scalar rematerialization are unresolved. See the detailed Sleep checkpoint.

Latest Sleep checkpoint: SSA-proven multi-jump wide planning and reusable
in-place call capture are connected; 29 focused tests pass, scoped Ruff/MyPy
pass. The unchanged executable regression still fails on two DX reads;
capture no longer raises its ownership exception. New owners/regressions are
enrolled in routine gates. No full-suite failure is closed by this checkpoint.

Sleep follow-up: corrected SSA exit normalization to retain an effectful
destination even when that destination has refusals, without bypassing its
effects. Two fail-first controls; 21 focused tests pass; scoped Ruff/MyPy pass.
Sleep still fails its unchanged executable-only regression. A fresh probe
isolates the next refusal to a two-jump comparison path; intermediate blocks
need SSA-backed emptiness proof before wide ordering can be accepted.
See [the exit-proof checkpoint](reference/p0-sleep-wide-condition-binding.md).
Step 9 remains active; no reduction in the unresolved full-suite count.

00:36 +02:00: the existing wide-call selector now consumes Alias proof at every
AX/DX operand boundary instead of choosing the nearest call address. Four
fail-first clobber regressions now refuse; a later check also prevents stack
type mutation on refusal. Final related surface: 70 passes; scoped MyPy and
architecture pass. Before the last refusal-type guard, the default pipeline
passed 4,903 curated tests, 268 preliminary tests, QuickC and all seven tiny
round trips. Quality remains red (6,245 Ruff findings). This is a safety
prerequisite, not Sleep recovery: its early wide-predicate materialization is
still pending, and 42 retained failures remain unresolved. See
[Sleep Wide Binding](reference/p0-sleep-wide-condition-binding.md).

Sleep follow-up: fresh-cache worker probes locate a wide/scalar lowering
dependency cycle. Exact scalar DX binding refuses before CFG composition;
the later wide-call lowerer requires that already-composed C expression and
therefore cannot recover the typed chain. Keep exact-definition refusal;
introduce proven wide-call predicate lowering before scalar binding with
CFG polarity and single-evaluation proof. No production fix or new pass count
is claimed. See [Sleep Wide Binding](reference/p0-sleep-wide-condition-binding.md).

00:04 +02:00: four retained fixture failures now close without production
semantic changes: statement-owned loop evidence replaces an operand provenance
tag, and three positive coordinate cases supply typed frame proof instead of
extrapolating local bindings. Original offset/identity and refusal assertions
remain. Related checks: 104 passes (14.12s); pipeline/helper Ruff and pipeline
MyPy pass, legacy tests retain visible lint debt. Missing files are admitted to
the routine gates. Together with the manifest correction, five of 47 retained
failures are individually closed; **42 remain unresolved**, not a new full-suite
count. Sleep's real uninitialized AX/DX failure is reproduced and remains open.
See [Complete Audit](reference/p0-full-suite-20260912.md). Step 9 is NOT complete.

23:57 +02:00: **Exact complete audit: 12,560 passed / 47 failed / 167 skipped**,
12,774 nodes, 1,906.54s; source stable, complete node accounting, memory under
2 GiB. The manifest-selection mismatch is subsequently fixed (60 focused
passes, Ruff clean); 46 retained failures still require resolution or documented
supersession. Do not treat this as a new full-suite count. The loop-refusal
surface passes 125 tests and scoped MyPy. Expanded and required quality gates
remain open. See [Complete Audit](reference/p0-full-suite-20260912.md) for
failure groups, exact artifacts and ordered next actions. Step 9 is NOT complete.

23:13 +02:00: **RunMenu's original sidecar-free regression and the mandatory
pipeline pass.** Structuring switch analysis was dropping unary zero-test
cases from DEC/JCC ladders; a fail-first parameterized regression proves the
fix. Existing switch, Escape, call and validation assertions are unchanged.
Source-frozen gate: 4,828 curated passes (310.01s), 268 preliminary passes,
QuickC and all seven MS C tiny round trips pass. Wrapper/topology/layer checks:
122 passes. MyPy and the compiled-import smoke pass; quality-fast remains red
on 6,240 style/complexity findings. Complete collection, expanded acceptance,
required quality closure and refusal-counter auditing remain open. Step 9 is
NOT complete. See [RunMenu Definition Binding](reference/p0-runmenu-condition-definitions.md).

22:39 +02:00: new break insertion now requires exact CFG loop-exit evidence,
not absent AST tags. Internal-edge and missing-CFG controls fail before the fix;
28 focused tests pass afterward (15.32s), with new-owner Ruff, scoped MyPy and
architecture passing. RunMenu no longer contains the erroneous early guard,
but its original test still fails. Escape exists as an if/break followed by
register restoration and return, while the current obligation/test requires a
switch case. Trace canonical switch recovery and validate equivalent control
flow without weakening the gate or bypassing restoration. Details:
[RunMenu Definition Binding](reference/p0-runmenu-condition-definitions.md).
Broad/full/expanded acceptance is unrefreshed after this gate; Step 9 stays open.

22:26 +02:00: source-frozen mandatory pipeline: 4,812 passed / 1 failed in
257.38s, plus 268 preliminary passes; QuickC and all seven MS C tiny round trips
pass. RunMenu is the sole curated failure. Subsequent fail-first tests show
loop-break queries also lose Rust-backed Tags through Mapping-only checks;
that boundary is fixed with four routine cases. Loop-specific tests: 22 pass,
RunMenu still fails Escape-case validation. Scoped MyPy passes; quality-fast
remains red on lint findings (39-module compiled import smoke passes).
Broad results predate the final loop-tag fix; full/expanded acceptance remains
open. Step 9 is not complete. Details and logs are in
[RunMenu Definition Binding](reference/p0-runmenu-condition-definitions.md).

22:14 +02:00: caller-cleanup loop regressions are repaired at Structuring's
condition projection index: consume real angr `Tags` and category-proven GP
runtime destinations, reading the stored value without repeating its update.
The compiled countdown oracle and five-file focused set pass: 92 tests, 19.64s.
Eight projection/refusal cases are in both routine test lists. Scoped MyPy and
architecture pass; four legacy lowering lint findings remain. RunMenu still
fails its missing Escape-case gate (45.33s). Earlier broad counts below predate
this repair; full/expanded acceptance remains open. Step 9 is not complete.
See [RunMenu Definition Binding](reference/p0-runmenu-condition-definitions.md).

20:51 +02:00: RunMenu's typed-condition operand lookup now consumes an
Alias CFG reaching-definition proof instead of numeric address proximity.
Five fail-first regressions and three additional boundary controls are covered;
49 focused tests pass. Curated lane: 4,735 passed / 1 failed in 246.50s;
RunMenu remains the failure. QuickC and MS C tiny 7/7 pass. Architecture and
new-owner Ruff/MyPy pass; global quality remains red, full/expanded unrefreshed.
Call-result definition/use coherence and Escape-case validation remain open.
Step 9 is not complete. See [RunMenu Definition Binding](reference/p0-runmenu-condition-definitions.md).

20:16 +02:00: the order-dependent frontend condition failure is reproduced
and fixed at the common lift boundary. Shared register-index provenance from
an earlier block could reach an initial full-path INC. Seeded INC/DEC tests
fail before the fix; 138 focused tests pass afterward. Default curated lane:
4,727 passed / 1 failed in 267.80s, with RunMenu the remaining failure.
InitMenu remains green; QuickC and MS C tiny 7/7 pass. Architecture/scoped
MyPy pass; global quality remains red. Full/expanded acceptance is unrefreshed.
Step 9 stays open. See [Frontend Index Isolation](reference/p0-frontend-index-isolation.md).

20:00 +02:00: InitMenu passes semantic validation, strict C compilation and
its pause-guard oracle, now also checking SI/DI preservation. Types/Lowering
canonicalization incorrectly fell through to raw-offset lookup when its
authoritative projection was already the current node; a fail-first test
now guards that identity case. Default lane: 4,724 passed / 2 failed, 225.49s.
RunMenu remains; the new frontend two-INC failure passes with its full file
in isolation (21 tests), so order/intermittency investigation remains open.
QuickC/MS C pass; architecture/scoped MyPy pass; global quality remains red.
Full collection/expanded acceptance are unrefreshed. Step 9 stays open.
See [Native Return Segment Coherence](reference/p0-native-return-segment.md).

19:20 +02:00: native callee argument cleanup now consumes complete binary
return evidence and reconciles cleanup already applied by angr. The fail-first
near-return regression and prototype/refusal controls pass (36 related tests).
InitMenu advances from uninitialized save reads to stable tail stages, but
strict GCC rejects a buffer pointer incorrectly used as a DI-save byte.
The function remains unaccepted; trace storage coordinates next. Default
pipeline: 4,722 passed / 2 failed in 276.73s; QuickC and MS C tiny 7/7 pass.
Scoped Ruff/MyPy and full architecture pass; global quality remains red.
Full collection/expanded acceptance are not refreshed. Step 9 remains open.
See [Native Return Segment Coherence](reference/p0-native-return-segment.md).

18:59 +02:00: InitBars's missing saved-register bytes traced to an omitted CS
pop for binary-proven PUSH CS/near CALL/far-return sequences. Native tracking
and pre-Alias IR effects now consume the same Semantics proof. The original
InitBars regression passes; 67 related tests pass. Refreshed curated lane:
4,716 passed / 2 failures (RunMenu, InitMenu), 275.32s. QuickC and all seven
MS C tiny roundtrips pass. Scoped typing/new-adapter Ruff and architecture pass;
global quality remains red on lint debt, with compiled-import smoke passing.
Full collection/expanded acceptance remain unrefreshed. Step 9 stays open.
See [Native Return Segment Coherence](reference/p0-native-return-segment.md).

18:31 +02:00: goto_accumulate now preserves its conditional update through
CFG/provenance-owned instruction-fragment placement in Structuring. The
whole-body callback and dispatch hooks are removed; Lowering retains its
refusal guard. Normal CLI validates cleanly and compiled output passes the
independent behavioral oracle with SI/DI preserved. 475 focused tests pass.
MS C returns to 7/7, including loops_jumps with matching exit 255; QuickC passes.
Curated pytest: 4,707 passed / the same three SORTD failures in 302.08s.
Scoped typing/new-owner Ruff and architecture pass; global quality remains red
on lint debt. Full collection/expanded acceptance, clear worker error details
and validation-baseline auditing remain open. Step 9 is not complete. See
[Conditional Stack Update Placement](reference/p0-conditional-stack-update-placement.md).

17:48 +02:00: nested_loops uses the generic body-preserving path. Structuring
binds unique block-origin JCC identities, excludes operand provenance from
body ownership and owns loop-continuation polarity; legacy replay preserves
that contract. The whole-body callback and all dispatch hooks are removed.
Normal CLI validates cleanly and compiled output matches all 65,536 signed
limits with SI/DI preserved. 477 focused tests pass. The MS C fixture now stops
at goto_accumulate's GP-restore invariant. Its isolated generic path validates
but returns 18 for input 4 instead of 14: the parity-controlled continuation is
missing. Fix that producer before retiring its callback. Refreshed curated
pytest: 4,689 passed / the same three SORTD failures in 252.06s; QuickC passes;
MS C remains 6/7. Global quality remains red at linters; full collection and
expanded acceptance are not refreshed. Step 9 stays open.
See [Nested Loop Continuation](reference/p0-nested-loop-continuation.md).

16:54 +02:00: word-sum whole-body substitution is retired. Generic sum_words
passes normal CLI validation and a compiled behavior oracle, preserving SI/DI.
The rebuild harness now consumes Lowering's authoritative pointer-storage
macros; pointer_memory completes the real MS C roundtrip with matching exit
255. Focused tests and architecture gates pass; quality-fast remains red at
global linters. Refreshed curated pytest: 4,679 passed / the same three SORTD
failures in 364.72s. QuickC passes; MS C improves to 6/7, with only loops_jumps
remaining failed. Full collection and expanded acceptance are not refreshed.
See [Word Sum Body Preservation](reference/p0-pointer-sum-body-preservation.md).

16:25 +02:00 checkpoint: fill_bytes now uses the generic body-preserving path.
Near-pointer promotion publishes its recovered type to the authoritative
prototype owner, and GP writes consume the existing pointer-storage projection
before integer masking. The destructive byte-fill callback and dispatch slot
were removed. Normal CLI: validation=passed, clean whole-tail validation and
strict GCC pass. Generated C passes a UBSan behavior oracle for signed counts,
byte values, buffer canaries and SI/DI preservation; corrupt controls fail.
The full pointer_memory MS C fixture still stops at sum_words's GP restore
invariant. Next: trace that function's producer/generic path without bypassing
validation. Final curated pytest: 4,673 passed / the same three SORTD failures
in 381.57s; QuickC passes; MS C remains 5/7. Architecture/context/ownership and
scoped MyPy pass; global quality remains red at linters. Full collection,
expanded acceptance and Step 9 remain open. See
[Pointer Fill Body Preservation](reference/p0-pointer-fill-body-preservation.md).

15:53 +02:00 checkpoint: generic byte indexing now uses exact carrier-register
evidence instead of selecting the first variable in an addition. Copies retain
provenance; adjusted, unknown, mismatched or version-shifted carriers refuse
pointer-base substitution. The real callback-disabled fill_bytes probe now
keeps the induction index and SI/DI effects, but its parameter/type boundary
still fails validation. No production callback bypass was landed. Focused
tests: 279 passed; scoped MyPy and new-module Ruff pass. Architecture/context/
ownership gates pass. Combined pytest: 4,663 passed / the same three SORTD
failures in 358.12s; QuickC passes, MS C remains 5/7. Global quality, full-suite
and expanded acceptance remain open. Next: inspect exact final parameter
type/coordinate ownership, then retire the destructive loop callback only
after the generic function passes. See
[Pointer Fill Body Preservation](reference/p0-pointer-fill-body-preservation.md).

15:29 +02:00 investigation: fill_bytes's GP restore refusal is downstream of
a legacy byte-fill callback replacing the entire function body and discarding
save/restore projections and provenance. An isolated callback-disabled probe
preserves those effects but exposes incorrect generic pointer/index binding
and still fails the pointer-parameter gate. No production bypass was landed.
The next repair must fix that Types/Lowering binding, then retire or replace
the destructive whole-body callback with preserved behavior and tests.
See [Pointer Fill Body Preservation](reference/p0-pointer-fill-body-preservation.md)
for evidence, ordered DoD/failure contracts and reproduction. Step 9 remains
open; the 15:24 combined result below is still the last broad test result.

15:24 +02:00 acceptance refresh: the returned-call oracle repair is confirmed
in the combined pipeline, not only its targeted run. MS C improves to 5/7;
function_pointers validates, recompiles and executes with original/rebuilt exit
code 255. loops_jumps and pointer_memory remain failed. QuickC passes. The
curated pytest lane has 4,647 passes / three failures in 289.42s, preceded by
268 preliminary passes. The three failures remain SORTD InitBars, RunMenu and
InitMenu. quality-fast remains red at global linters; scoped checks pass.
Full collection and expanded acceptance are not refreshed. Step 9 stays open.
Details: [Indirect Call IR Evidence](reference/p0-indirect-call-ir.md).

15:15 +02:00 checkpoint: indirect CALL boundaries now survive typed IR import,
preventing orphaned return-address pushes from producing false GP restore
facts. The apply_twice CLI passes validation and strict GCC. The subsequent
routine lane reports 4,639 passed / three SORTD failures in 312.53s; QuickC
4/4 and MS C 4/7. A separate tooling oracle repair now accepts unchanged local
returned-call results while rejecting corruption. Its 56-test module passes;
the targeted function-pointer MS C compile/decompile/recompile/execute roundtrip
passes for all four functions (24.51s decompilation). Scoped Ruff/MyPy and
architecture/context/ownership checks pass. Remaining SORTD, loops_jumps and
pointer_memory failures, global quality debt and full/expanded acceptance keep
Step 9 open. See [Indirect Call IR Evidence](reference/p0-indirect-call-ir.md).

14:32 +02:00 checkpoint: mset_pos's duplicate byte-local/formal declaration
is repaired in Types/Lowering using exact declaration-member ownership.
Live physical or unified declaration keys, mixed/unknown members and malformed
entries refuse removal. Its native compiled oracle covers all signed-word
inputs; the real CLI passes validation, whole-tail checks and strict GCC.
Final focused run: 43 passed. Both argument-identity modules are enrolled in
the routine pipeline. The broad run before the last refusal guard had 268
preliminary passes and 4,632 passed / four failed in 362.88s: the three SORTD
tests and MONOPRIN __fimemset's uncollected/timeout result. The latter passes
isolated, not proven fixed under broad load. QuickC remains 4/4, MS C 4/7.
Scoped MyPy passes; broader lint debt, full collection and expanded acceptance
remain open. No Step 9 completion or fresh broad result for the last guard.
Details: [Argument Declaration Ownership](reference/p0-argument-declaration-ownership.md).

13:58 +02:00 checkpoint: QuickC args now retains its four saved bytes
and distinct SI/DI restores after excluding SP Phi from machine-write timing
and admitting owned semantic casts through the shared AST boundary. Its CLI
passes validation and strict GCC; the refreshed QuickC lane passes 4/4.
A second consumer-level regression proved Lowering could delete a live
register used beneath a semantic cast; the same shared-boundary correction
closes it. Five focused modules pass 261 tests. The first routine rerun had
4,610 passed / four failed; one obsolete memory-copy expectation has since
been replaced by register-copy and captured-memory preservation cases.
Final routine rerun: 268 preliminary passes; 4,612 passed / five failed in
402.47s. QuickC remains 4/4 and MS C 4/7. The three SORTD failures remain,
plus a reproducible mset_pos byte-local/formal-argument declaration collision
and a dos_loadProgram broad-run timeout. The latter passes isolated; the
two-test recheck is one failed / one passed, not a green broad lane.
Next: trace mset_pos declaration/storage ownership without deleting live code.
Scoped MyPy and architecture/context/ownership pass; quality-fast remains
red on lint debt. No full-suite or Step 9 completion is claimed.
Details: [Captured Restores And Cast Traversal](reference/p0-semantic-cast-traversal.md).

12:43 +02:00: caller-cleanup regressions pass after the legacy argument
placeholder consumer was made to honor Lowering's existing partial-PUSH
refusal. An independent compiled-C check then exposed a temporal condition
defect: DEC's old input boundary was applied to its updated register. Frontend
now publishes an explicit JCC-bound result test when no independent input is
proven; Alias consumes that view for proven decrement dispatch chains.
The final four-module focused run passes 115 tests, including initial CX=0
(65,536 iterations), register preservation, exhaustive repeated INC/DEC word
boundaries, and missing/inexact binding refusals. The normalizer's new
complexity finding is resolved without suppression; scoped MyPy and full
architecture/context/ownership checks pass. Routine acceptance before the
final test-contract updates: 268 preliminary passes; 4,606 passed / 7 failed
(408.64s). Four frontend test failures were subsequently corrected and pass
in the focused run; do not relabel that earlier broad run as green. The three
SORTD failures remain. QuickC stays 3/4 and MS C stays 4/7. quality-fast still
fails on broader lint debt; full-suite and expanded acceptance remain open.
Next shared investigation: QuickC args restores SI/DI from uninitialized byte
locals, similar to the remaining stack-restore family. Details and timing:
`reference/p0-byteops-storage.md`, Caller And Countdown Evidence.

11:56 +02:00: repaired MONOPRIN's false stack-name collision in Types/Lowering
by excluding obsolete intermediate owners from display-name reservations,
without dropping their coordinate evidence. Its CLI, tail validation and
strict compiled behavior oracle pass; 49 related tests pass. Fresh routine
lane: 4,597 passed / 5 failed (327.07s), plus 268 preliminary passes. QuickC
recovers to 3/4 and MS C to 4/7, with storage_classes and scalar_types_io both
reproducing original exit 255. The three SORTD failures remain, alongside two
caller-cleanup failures: the small reproduction incorrectly emits AH and AX
for two PUSH AX values. Architecture/ownership and scoped Ruff/MyPy pass;
broader quality gates and full-suite acceptance remain open. Details and next
owner investigation: `reference/p0-byteops-storage.md`, Live Projection Repair.

11:34 +02:00 focused follow-up: native entry-SP provenance repairs the direct
bump_static and QuickC hello decompilations (validation=passed). MONOPRIN now
passes tail validation but remains rejected by the final unresolved-stack-name
guard. Its unchanged function body passes strict GCC and the existing behavior
oracle; coordinate collision evidence and an additional harness macro-prelude
conflict remain to resolve. No refreshed broad pipeline or Step 9 completion
is claimed. See `reference/p0-byteops-storage.md`, Native Coordinate Follow-up.

11:15 +02:00, unaccepted coordinate change: removing global registry-delta
extrapolation repairs byteops_unsigned and the full scalar-types MS C fixture,
but exposes missing entry-SP versus machine-BP provenance in other callers.
Current main lane: 4,588 passed / 4 failed (286.63s), including a new MONOPRIN
failure reproduced in isolation. MS C remains 3/7 but storage_classes now fails
at bump_static while scalar_types_io passes; sum_globals stays green. QuickC
regresses to 2/4 due to hello's GP restore failure. Do not count this change as
accepted. Next: repair the typed coordinate-domain boundary and recover these
regressions without reinstating unproven extrapolation. See the 11:15 checkpoint
in `reference/p0-byteops-storage.md`. Earlier green-fixture claims below are
historical, not current whole-pipeline status.

10:50 +02:00 investigation: next scalar fixture blocker is byteops_unsigned.
The restore matcher sees C byte coordinates two bytes above Alias's proven
SI/DI ranges; the body still contains saves/restores, so no deletion diagnosis
is assumed. Partial output also loses the word return. Producer-level tracing
and acceptance steps are recorded in `reference/p0-byteops-storage.md`.
No production fix or additional gate result since the 10:44 checkpoint.

10:44 +02:00: storage_classes is repaired through native load-order protection
and Lowering's captured-byte refusal, with no diagnostic bypass in production.
The generated sum passes clean tail validation, strict GCC, all 65,536 counter
inputs and SI/DI preservation. The actual MS C compile/decompile/recompile/run
fixture passes with exit code 255, improving MS C from 2/7 to 3/7.
Refreshed routine pipeline: 268 preliminary passes; main lane 4,583 passed and
the same three SORTD failures in 273.33s; QuickC 3/4. Four MS C fixtures remain
red. Full architecture/ownership and touched-module MyPy pass; quality-fast
remains red on Ruff debt. No full-suite or Step 9 completion is claimed.
Details and remaining obligations: `reference/p0-global-sum-effects.md`,
captured-value repair checkpoint. Older checkpoints below are historical.

10:24 +02:00: native load-order guard implemented in the existing propagation
adapter, covering both block and function models. Fail-first native tests now
pass; 61 related tests pass in 13.51s, compatibility Ruff/MyPy and full
architecture/ownership pass. The real-function probe confirms captured-byte
preservation before owned stack lowering. That lowering still erases captures,
so the function and Step 9 remain incomplete. Broad acceptance gates are not
refreshed; detailed evidence is in `reference/p0-global-sum-effects.md`.

10:14 +02:00 diagnostic update: split-store corruption has two confirmed owners.
Native function-level folding bypasses the earlier block-only load barrier;
guarding the shared replacement consumer preserves captured bytes. Owned stack
lowering then independently erases those captures across a partial write.
See `reference/p0-global-sum-effects.md`, shared replacement boundary checkpoint.
Neither production repair is complete; existing gate totals below are unchanged.

Carry-oracle checkpoint (approximately 10:00 +02:00): original and rebuilt MS C
storage harnesses now check counter=242/246 as well as 3. A compiled corruption
control proves the old harness accepted split-store re-evaluation; the expanded
oracle rejects it. Fifty related tests, new-test Ruff, harness MyPy, architecture
and ownership pass. Original MS C compilation/execution passes in an isolated
output directory; decompilation was explicitly skipped for that source check.
Native raw C already re-reads the low byte before owned stack lowering, which
then merges captured-value expressions. Investigate the native SSA low-byte
definition/use path; diagnostic propagation restrictions did not fix the C and
were not landed. Step 9 and the function remain open. No broad suite refresh.
Details: [carry oracle and native boundary](reference/p0-global-sum-effects.md).

CLI assignment-preservation checkpoint (approximately 09:42 +02:00): traced
the missing sum to post-validation text pruning, not missing native IR. The
legacy helper now preserves all statements; five loss controls fail before
repair, and 101 focused CLI tests pass afterward. MyPy, architecture and
ownership pass; legacy Ruff debt remains. The isolated native-body oracle now
returns 13, but a wider oracle finds split-store re-evaluation: counter=242
returns 508 instead of 252 because the high-byte RHS reads a changed low byte.
Next: preserve the pre-store value at its earliest typed owner. Keep the
required body-reconstruction guard and function/fixture acceptance open.
The routine counts below predate this CLI change; no fresh broad audit or
Step 9 completion is claimed. See the follow-up in
[global-sum evidence](reference/p0-global-sum-effects.md).

Global-sum guard checkpoint (09:27 +02:00): the legacy whole-body sum builder
also erased unrelated storage/calls. Four fail-first controls now pass under a
Structuring-owned required reconstruction gate. A simple refusal was rejected
as insufficient: native C compiled and claimed validation=passed but returned
3 rather than 13 because its loop lost the accumulator update. The real CLI
now fails explicitly before replacement; `_sum_globals` remains unfixed.
Routine pytest: 4,561 passed / the same three SORTD failures in 207.22s; 268
early checks pass, MS C remains 2/7, QuickC 3/4. Scoped Ruff/MyPy/Pyright and
full architecture pass; global lint debt remains. Next: trace the lost update
and close binary-to-projection validation coverage, not a whole-body rescue.
No full-suite or Step 9 completion is claimed. See
[global-sum evidence, DoD and failure definition](reference/p0-global-sum-effects.md).

Mask-effect checkpoint (09:03 +02:00): rel_i16's remaining defect was a
whole-body mask reconstruction dropping SI/DI storage effects. Structuring now
refuses that replacement unless all writes belong to its exact mask object;
calls and other storage keep the original body. Three controls failed before
repair. Direct rel_i16 now has validation=passed, clean whole-tail validation,
strict GCC compilation and 327,680 passing comparison/ESI/EDI-preservation cases.
Routine pytest: 4,556 passed / the same three SORTD failures in 201.98s.
MS C compare16 is restored: 2/7 round trips pass; QuickC remains 3/4.
Focused typing/projection Ruff and full architecture pass; global lint debt
remains. The final type-only annotation adjustment has focused verification,
not a second broad run. Step 9 remains open. See
[mask-effect DoD, failure definition and evidence](reference/p0-mask-accumulator-effects.md).

Native allocation adapter checkpoint (08:45 +02:00): the native tracker now
consumes the same binary/reaching-IR allocation proof as Semantics/Alias, before
successor analysis and variable recovery. The two previously failing allocation
controls pass; 59 related tests, scoped Ruff/MyPy/Pyright and full architecture
checks pass. A fresh rel_i16 probe confirms SP=-4 after the allocating call and
SP=-8/-6 at the SI/DI POPs, matching Alias. rel_i16 still fails GP materialization
because the expected save/restore projections cannot be located; do not weaken
that gate or infer a completed function repair. Routine pytest: 4,550 passed /
the same three SORTD failures in 212.12s; MS C remains 1/7, QuickC 3/4, global
quality-fast remains red on Ruff debt. Step 9 remains open. Next: trace the
missing GP projections/consumption evidence after native coordinates agree.

Native tracker root-cause checkpoint (2026-09-12, after 08:22): live rel_i16
evidence supersedes the non-terminal-spill hypothesis below. Its failing facts
are genuine SI/DI POPs. Alias proves SI at entry-SP -8/-7 and DI at -6/-5, but
the emitted SI bytes are -6/-5. Before C generation, angr's stack tracker keeps
SP=-2 across a binary-proven two-byte allocating call instead of producing -4.
A new native regression has two failures (allocations 2 and 18) and one passing
zero-allocation control. Next: share the authoritative allocation proof with
the native stack-tracking boundary before variable recovery. Do not offset C
variables to hide the disagreement or widen the local-return acceptance path.
No production fix or refreshed corpus result is claimed for this checkpoint.

Local-return binding checkpoint (08:22 +02:00): the three new annotation
regressions below are repaired without removing Alias facts or weakening the
materialization gate. Semantics proves that an exact register definition reaches
its block-local return unchanged; Lowering verifies the existing unique,
initialized word local and every projection of that return. The existing three
smoke tests pass unchanged. Focused/enrollment tests: 150 passes; new-owner Ruff,
MyPy/Pyright and full architecture checks pass. Routine pytest: 4,542 passed /
the original three SORTD failures in 217.43s. MS C tiny remains 1/7 and QuickC
3/4, so BP integration and Step 9 remain unaccepted. Global quality-fast still
fails on Ruff debt. Next: exact consumer bindings for the other evidenced
reloads (start with rel_i16), without blanket BP-load exemptions. Details and
actual elapsed time are in [the proof report](reference/p0-stack-allocation-proof.md).

BP-coordinate checkpoint (08:03 +02:00): this work is **not accepted**.
Alias now tracks explicit SP/BP captures and requires separate callee BP
preservation evidence; allocating-call proofs provide that evidence, ordinary
balanced calls do not. The 182-test focused run passed, but the subsequent
routine lane regressed to 4,514 passes / six failures in 233.57s. Three new
stack-annotation smoke failures reach the GP restore materialization hard gate;
the three SORTD failures remain. MS C tiny regressed to 1/7 (only simple_control
passes); QuickC remains 3/4. Do not use the earlier 7/7 checkpoint as current
acceptance. Global quality-fast remains red on Ruff debt.

The next repair must reconcile ordinary BP-relative register spills with the
PUSH/POP-specific GP snapshot consumer. Keep the hard gate and existing local
annotations; do not discard newly visible storage facts to restore green tests.
Separately, six fail-first controls exposed unproven/narrow frame values being
accepted as address bases. Address resolution now shares the register-value
proof predicate; 44 related tests, scoped Ruff and seven-owner MyPy pass.
The broad pipeline has not been rerun after that small refusal repair.
See [the detailed evidence](reference/p0-stack-allocation-proof.md).

Positive stack-allocation checkpoint (approximately 07:21 +02:00): Semantics
now combines frontend binary evidence with an unclobbered IR AX constant,
including relocated slice/original target identities. The live InitMenu probe
collects the 18-byte proof. Alias now consumes proven nonzero call deltas without
inventing unknown entry SP. Two Semantics and two Alias controls failed before
repair; the expanded focused run has 179 passes. Final routine verification:
4,505 passes / the same three SORTD failures in 208.89s, all seven MS C tiny
round trips pass, QuickC remains 3/4. Four-owner MyPy, new-module Pyright and
full architecture checks pass. Existing Ruff/global quality debt remains.
InitMenu is not fixed: BP-coordinate propagation, callee BP preservation and
saved-register C initialization remain open. No complete-suite or Step 9
completion claim. Evidence and next-owner constraints are in
[the allocation proof report](reference/p0-stack-allocation-proof.md).

Stack-allocation proof checkpoint (approximately 06:53 +02:00): the InitMenu
probe found an allocating prologue CALL carrying a false complete zero-delta
effect before Alias lost SI/DI identities on a BP-relative store. Semantics
now refuses the ordinary balanced-call proof for allocation requests, with
the typed reason `STACK_ALLOCATION_UNPROVEN`. This is a safety guard, not an
InitMenu fix: binary-proven allocation transfer and Alias BP/SP propagation
remain required. Four controls failed before the guard; 135 related tests,
scoped Ruff and MyPy pass. The routine lane has 4,486 passes / the same three
SORTD failures in 210.51s, all seven MS C tiny round trips pass, and QuickC
remains 3/4. Global quality-fast remains red on lint debt. No full-suite refresh
or Step 9 completion is claimed. See
[the evidence and remaining repair order](reference/p0-stack-allocation-proof.md).

Decrement root-edge checkpoint (approximately 06:35 +02:00): fixed switch_fold's
missing case 2 at Alias. Carrier seeds now follow either unique typed CFG
successor and refuse ambiguous roots. Two controls failed before repair; the
64-test related surface passes. Strict generated-C execution covers all 65,536
input patterns and SI/DI preservation: one failing input before, none afterward.
Direct decompilation has validation=passed and clean whole-tail validation.
Routine pipeline: 268 early contracts pass; 4,481 pytest passes / the same three
SORTD failures in 193.41s. All seven MS C tiny round trips pass again; QuickC
remains 3/4 (args fails). Scoped MyPy and full architecture pass; global Ruff is
still red. Both the root-edge tests and selector storage guards ran in this
routine checkpoint. Next: the SORTD storage-provenance failures and QuickC args,
then stable complete-suite and global quality acceptance. Step 9 is not complete.
See [root-edge DoD, proof and timings](reference/p0-decrement-root-edges.md).

Selector storage-effect checkpoint (06:18 +02:00): Structuring now refuses
return-only replacements that discard unconsumed stack, runtime-register or
indirect-memory writes, both at selector entry and in the shared unsafe-effects
predicate. Six fail-first controls cover those two boundaries; 162 related tests
pass. Routine: 268 early contracts pass, then 4,469 pytest passes / the same three
SORTD failures in 197.29s. MS C tiny improves to 6/7; QuickC is 3/4 (args fails).
simple_control recompiles but exits 5, exposing switch_fold's missing case-2
condition. Fix that semantic condition next without weakening storage retention.
The selector tests were missing from the Python routine list despite Make
enrollment; they are now added and protected by an enrollment regression.
Final selector/tooling check: 59 passed in 5.82s. The broad count predates only
that test-list addition. Scoped MyPy and architecture pass; global Ruff stays red.
See [effect-preservation gate, DoD and remaining failure](reference/p0-selector-storage-effects.md).
Step 9 remains open, including the stable complete-suite acceptance audit.

Stack-restore follow-up (05:53 +02:00): Lowering recognizes exact existing byte
saves without duplicate snapshots. __fimemset now passes strict C compilation
and behavioral execution; 46 focused tests pass in 15.58s. Routine pipeline:
268 early contracts pass; 4,469 pytest passes / the same three SORTD failures
in 197.70s. External acceptance regressed to four of seven MS C round trips;
compare16, simple_control and scalar_types_io fail, as does the QuickC lane.
The combined patch remains unaccepted. A normal-worker cmp_i16 probe
identifies selector-return Structuring replacing 13 assignments with a return-only
tree, after which restore replay correctly refuses missing materialization.
Repair that effect-preservation boundary next, without weakening the gate.
Scoped helper Ruff/MyPy and full architecture pass; global Ruff remains red. See
[provenance evidence and next action](reference/p0-stack-restore-provenance.md).
These are current routine counts, not a complete full-suite acceptance audit.

Calling-seed dependency checkpoint: local cache reuse now includes the actual
inspected terminal-callee contracts and observed caller-result use, including
in-place prototype changes. Focused tests: 43 passed; owner MyPy and full
architecture pass. The real four-function FPTR MS C round trip now passes its
returned-call, recompilation, execution and final-tail checks. Direct FPTR type
handling still fails before successful fallback; no direct or whole-Step-9
closure is claimed. Regular gates: 268 traversal/storage tests pass; routine
pytest has 4,440 passed / the same three SORTD failures in 207.44s; all seven
MS C tiny round trips pass. QuickC and global Ruff remain red. See
[dependency evidence](reference/p0-calling-seed-dependencies.md).

Direct FPTR follow-up (05:02 +02:00): the normal forked worker reproduces the
invalid saved-EDI/function-pointer binding, while observed pointer-coordinate
lookups remain correct. No speculative offset adjustment was made. The
in-process probe is not an equivalent reproduction. Preserve the evidence in
[worker storage investigation](reference/p0-fptr-worker-storage-investigation.md);
the three failing SORTD regressions remain the immediate routine-lane blockers.

Jump-completion checkpoint: recovered values stay provisional until the shared
Structuring owner proves their complete jump tail preserves AX/DX. Incomplete
and unresolved paths refuse recovery. Final focused surface: 177 passed;
routine lane: 4,435 passed / the same three SORTD failures; MS C tiny: 6/7.
Scoped MyPy and full architecture pass; lint debt remains. The identified
return-proof follow-ups are addressed; resume the outstanding FPTR/SORTD/QuickC
failures next. See [jump proof and acceptance](reference/p0-return-jump-proof.md).

Branch-return proof checkpoint: the scanner no longer certifies stale AX/DX
values across unconsumed instructions or failed materialization. The real cast
probe preserves `sub_ss` subtraction; 148 focused tests and 327,680 compiled
input cases pass. Routine lane: 4,415 passed / the same three SORTD failures;
MS C tiny remains 6/7. Jump-destination proof remains a related audit item.
See [consumption guard and evidence](reference/p0-branch-return-consumption.md).

Terminal stack-byte checkpoint: `rot_ui` now consumes its proven argument byte
instead of inventing a word local. Actual generated C passes exhaustive word-input
execution, and the strengthened ten-function scalar MS C round trip passes.
Final routine lane: 4,396 passed / the same three SORTD failures; MS C tiny 6/7.
Scoped MyPy and architecture pass; global lint debt remains. An intermediate
exact-read cast expansion exposed a subtraction-loss validation blind spot and
was removed. Step 9 remains open. See
[byte-view evidence and remaining validation risk](reference/p0-terminal-stack-byte-views.md).

Return-proof gates: reject full-width POP result clobbers and unknown register
identity in Semantics; portable GCC acceptance now compiles instead of merely
checking syntax, catching the actual missing FPTR return and an uninitialized
argument-byte read in `rot_ui`. The routine lane has 4,382 passes / the same
three SORTD failures; MS C tiny is 5/7, Ultra QuickC 3/4. The final focused
surface has 84 passes. Global MyPy passes; lint debt remains. A reduced probe proves stale
callee-prototype dependencies in caller seeding. See
[gate evidence and remaining root cause](reference/p0-return-proof-gates.md).

MS C runtime ABI checkpoint: GP definitions and C89 externs now share the
authoritative Lowering inventory. Fresh real round trips improve from two to
six passing out of seven; function_pointers still loses the returned
`apply_twice` result. Fifty tooling tests and scoped MyPy pass. The latest
routine pytest result remains 4,337 passing / three SORTD failures; full-suite
and global quality closure remain open. See [runtime ABI evidence and DoD](reference/p0-msc6-runtime-gp-abi.md).

DCE declaration-retirement checkpoint: both LES variants now compile, execute,
and pass final semantic/def-use validation. The final focused run passes 50
tests; the broad run passes 4,337 with three SORTD failures (266.82s), plus 268
early contracts. MS C tiny remains two passing / five failing round trips;
global linters remain red. The declaration tests are now routinely enrolled.
See [root cause, scope, DoD and remaining blockers](reference/p0-dce-declaration-retirement.md).

Control-slot classification checkpoint (approximately 01:48-01:53 +02:00):
`lowering/stack_declaration_identity.py` now classifies the control-slot range
using the authoritative machine-BP projection, while retaining native storage
identity for body/header overlap checks. Three new controls failed before the
fix: an unreferenced projected control byte was retained, while a projected
argument and local were incorrectly removed. All six projected-coordinate
cases now pass, including live-reference refusal controls. The focused set has
34 passes in 15.46s; scoped Ruff, MyPy and architecture checks pass. Existing
routine enrollment includes the new cases.

This does not close the LES functions: the wider focused run still has 51
passes / two compiled-C failures. A direct end-of-decompilation probe removes
the stale control declaration, whereas the scheduled cleanup left it present.
Investigate cleanup ordering/rebuilding rather than renaming emitted text.
The probe also exposes duplicated declaration identities causing one failed
removal in the accounting; reconcile equivalent map keys without dropping
live owners. The previous broad pipeline result below remains the latest broad
evidence, not a rerun after this classifier change. Logs:
`/home/xor/.cache/fim-control-coordinate-{before,after,focused,ruff,mypy,architecture}.log`
and `/home/xor/.cache/fim-les-{storage-inventory,declaration-prune}.log`.

Runtime-preservation checkpoint (approximately 01:33-01:47 +02:00):
the stable-SS variable reuse path now publishes the selected native variable
through the existing Types/Lowering coordinate owner. Three native-byte reuse
regressions failed before this change and pass afterward. `MONOPRIN.COD`
`__fimemset` now passes final validation and unchanged generated-C execution for
both DF directions and counts 0..3, checking all memory, return value, and
ES/ESI/EDI preservation. Its harness supports byte stores and rejects an
additional deliberately corrupted ESI restore. No validation gate was bypassed.

This is NOT acceptance of the broader runtime-preservation candidate. The
source-stable routine checkpoint is 268 early contracts passing, then 4,329
pytest passes / 5 failures in 268.91s. Failures: two LES compiled-C regressions
(duplicate local declarations, plus an undeclared ES surface), sidecar-free
SORTD InitBars and RunMenu, and InitMenu's zero-pause guard. InitMenu retains
restores from uninitialized locals. The two LES failures were reproduced with
the new reuse-publication change removed, so that change is not their cause.
The seven MS C tiny examples have two successful round trips (compare16,
loops_jumps) and five failures (simple_control, storage_classes,
function_pointers, pointer_memory, scalar_types_io). Restore/save coherence and
declaration ownership remain blockers; do not remove required restores to pass.

Scoped MyPy passes for `real_mode_linear.py`; both modified test modules pass
Ruff. Ruff reports 243 findings in the existing large lowering module.
`quality-fast` remains red at the linter gate; its 39-module mypyc import smoke
passes. Step 9 remains open. Logs: `/home/xor/.cache/fim-reuse-coordinate-`
`{before,after,verified,mypy,ruff,pipeline,quality}.log` and
`/home/xor/.cache/fim-reuse-les-control.log`. Next: repair the missing save/restore
coherence and duplicate declaration owners, repeat focused checks and both
pipelines, then perform the full-suite acceptance audit.

Rewrite binding checkpoint: removed stack/memory word-object invention from
the byte-join simplifier. The constructor trace proved it created the narrowed,
unbound restore object; the earlier type-promotion hypothesis was ruled out.
New compiled-C controls pass; routine pytest has 4,326 passes / the same one
`__fimemset` failure (270.00s), 268 early contracts pass, and both external
lanes pass. Scoped MyPy passes; legacy/global Ruff debt remains. Full ES/EDI
preservation and Step 9 acceptance are still open. See
[binding evidence](reference/p0-rewrite-byte-word-bindings.md).

Native instruction-order checkpoint: the frontend/IR adapter now prevents
pre-instruction SP facts from replacing post-update SSA values within that
instruction. This fixes the proven ES-save/SI-slot collision, not the complete
function. Scoped Ruff/MyPy and 66 focused tests pass. Routine pytest now has
4,324 passes / the same one `__fimemset` failure (251.19s), 268 early contracts
pass, and both external lanes pass. Global Ruff remains red. See
[ordering evidence and remaining validation gap](reference/p0-stack-pointer-instruction-order.md).

Save/restore preflight checkpoint (00:42-00:47 +02:00, approximately five
minutes including focused tests): Types/Lowering now refuses incomplete
structured pairs before deleting or replacing any carrier. Refusal propagates
to pairs sharing a protected instruction, with typed refusal reasons and
closed accounting. The pass consumes shared AST traversal, including switch
bodies, instead of its partial private child walk. Four before-fix controls
failed; the expanded Alias/carrier/traversal/pipeline-wiring surface passes
95 tests in 14.47s. Scoped Ruff and MyPy pass. The carrier tests are now
enrolled in the routine pipeline. This is not register-preservation closure:
the live `__fimemset` oracle still fails (22 sibling passes / one corpus
failure in 15.15s). The broad pipeline checkpoint below predates this guard;
repeat broad acceptance after the preservation fix. Logs:
`/home/xor/.cache/fim-pair-{before,after,focused,ruff,mypy}.log`.

Stack-coordinate collision repair (worker probe started 00:31 +02:00):
`add_long` first published correct BP4/entry-SP2 and BP8/entry-SP6 argument
bindings. Byte materialization then reused those same argument objects by
their raw BP offsets as though they were entry-SP offsets, overwriting the
bindings with BP6/entry-SP4 and BP10/entry-SP8. The Types/Lowering argument
lookup now consumes the registered entry-SP coordinate. Temporary diagnostic
instrumentation was removed. Two new collision controls failed before the
fix; the focused stack surface now passes 64 tests in 13.97s. Scoped MyPy
passes; Ruff reports ten existing findings elsewhere in the large owning
module, not a clean linter gate. Actual `TYPES.EXE:add_long` now has
`validation=passed` and emits `return a + b;`. The scalar MS C round trip
passes all ten functions, including recompilation and execution (decompilation
35.77s). Logs: `/home/xor/.cache/fim-byte-coordinate-{before,after,mypy,ruff}.log`,
`/home/xor/.cache/fim-add-long-coordinate-owner/`, and
`/home/xor/.cache/fim-scalar-coordinate-roundtrip/report.json`.

Preceding narrow native-liveness candidate retains only GP stack-load outputs
with authoritative negative entry-SP anchors that reach a return, rather than
enabling every native callee-saved output. Native restore regression passes.
Its routine checkpoint was 4,303 passes / one `__fimemset` corpus failure in
207.24s, 268 contract checks passing, and the external scalar lane failing
`add_long` (now repaired above). Final coordinate resolution also preserves
registered primary/unified argument identities across interface clones; its
focused coordinate controls pass. The latest architecture check and scoped
native/coordinate MyPy pass. These are partial checks, not Step 9 closure.
`__fimemset` still requires coherent initialized save/restore state for ES/EDI,
and full-suite, routine/expanded pipeline and quality acceptance remain open.

Source-stable acceptance refresh for the coordinate repair (00:31-00:42
+02:00, approximately 11 minutes elapsed including diagnostic and gate waits):
`make test-pipeline` passed 268 early contracts and 4,308 routine pytest tests
with one failure in 232.65s. Both external lanes passed, including the full
MS C tiny lane; aggregate two lanes passed / one failed. The remaining
`__fimemset` failure has correct memory and return values but clobbers ES/EDI
for every direction/count case. `quality-fast` remains red on global Ruff
findings; its 39-module mypyc import smoke passes. No full-suite or expanded
rerun was claimed. Logs: `/home/xor/.cache/fim-coordinate-owner-pipeline.log`
and `/home/xor/.cache/fim-coordinate-owner-quality.log`.

Historical checkpoints follow; their failure counts describe their source
snapshots, not the current tree.

Rejected native-liveness candidate: forcing native callee-saved return uses
retains SI/DI restore definitions after stack SSA conversion (confirmed by exact
AIL statements), but is too broad for the current pipeline. It produced 13
routine failures / 4,286 passes in 214.20s and also failed the external MS C
lane, including carry/borrow materialization and extra runtime-register writes.
The production candidate was removed, not accepted. Keep the new binary native
restore regression as an open obligation; do not re-enable the blanket switch.
After removal, REP-store/BIOS/native tests give 31 passes and that one expected
open regression (8.58s); ALU/segment-call siblings give 22 passes (15.71s).
Scoped Ruff passes. Full pipeline was not rerun after removal; the prior
one-corpus-failure checkpoint predates the new failing native regression.
Logs: `/home/xor/.cache/fim-native-restore-pipeline.log`,
`/home/xor/.cache/fim-native-candidate-reverted.log`, and
`/home/xor/.cache/fim-native-revert-siblings.log`.

Saved-state investigation: the corrected binary-only probe accepts both
positional and keyword arguments in its diagnostic hooks. Disabling segment
restore pruning and generic callee-save pruning together executes one and six
times respectively. With the segment-output DCE guard installed, the ES restore
survives, but its saved stack bytes are uninitialized and Tail Validation rejects
them. DI restoration is still missing. This supersedes any inference from the
earlier combined probe whose callee-save hook did not execute. Log:
`/home/xor/.cache/fim-full-signature-prune-probe.log`.

A separate diagnostic suppressing ES/EDI global-state projection leaves their
body values in C locals, confirming that save removal and runtime-global
projection need a coherent contract. This is not an accepted optimization:
the raw output still has declaration/storage defects and no compiled behavioral
acceptance. Any localization must prove entry/exit preservation and retain
intermediate call-visible effects; never exclude registers by sample address
or simply disable global lowering. Log:
`/home/xor/.cache/fim-local-state-probe.log`. Forcing native callee-saved return
uses executed 32 times but did not repair final C; its native graph needs exact
statement inspection before drawing conclusions about DI.

Segment-output DCE checkpoint: stack-lowered register-carrier pruning no longer
treats an unread segment SSA definition as dead. A diagnostic run identified
the native ES restore (`vvar_id=23`) being classified `definitely_dead` at this
Types/Lowering boundary. Six architecture-register regressions failed before
the change and pass afterward. The carrier module is now enrolled in the
routine pipeline as well as the Make inventory; 69 carrier/wiring tests pass
in 6.16s. Scoped MyPy passes; Ruff reports two existing complexity violations
in the carrier module. Script/test Ruff passes.

The post-change routine run, before carrier-test enrollment, reached 4,281
passed / one corpus failure in 210.84s, with 268 early contracts and the other
two pipeline lanes passing. `quality-fast` remains red on global lint debt;
39-module mypyc import smoke passes. This repairs one independently unsafe DCE
rule, not the whole function: ES/EDI preservation still fails. Logs:
`/home/xor/.cache/fim-segment-dce-before.log`,
`/home/xor/.cache/fim-segment-dce-after.log`,
`/home/xor/.cache/fim-segment-dce-pipeline.log`, and
`/home/xor/.cache/fim-carrier-enrollment.log`.

Register-oracle diagnostics now check every direction/count combination instead
of exiting on the first mismatch. All eight cases pass memory and return checks
but fail both ES and EDI preservation, including count zero. The oracle's valid
control and five independent corruption controls pass (including an EDI-only
mutation); the corpus regression remains red: 6 passed / 1 failed in 6.56s.
Scoped Ruff `check --fix` passes. Evidence:
`/home/xor/.cache/fim-oracle-diagnostics.log`. This is a focused gate improvement,
not a refreshed full-suite result or a semantic fix.

Latest subview checkpoint: the uninitialized high-byte local is repaired at
Types/Lowering. Exact byte projections from proven four-byte arguments now
materialize; writes, address-taking and ambiguous ownership remain refused.
Focused run: 32 passed / one remaining corpus failure (13.89s). `__fimemset`
now passes strict gcc and memory/return checks but fails saved ES/DI preservation.
The generic emitted-variable validation gap remains open despite repairing this
instance. See the newest subview evidence in `reference/p0-far-load-width.md`.
Expanded routine pipeline: 4,280 passed / one saved-register behavioral failure
in 193.68s; 268 early contract checks passed. The other two pipeline lanes pass,
including MS C round trips. Scoped Ruff/MyPy/Pyright and full architecture pass.
Disabling callee-save pruning in a fresh binary-only probe executed six times
but retained saves without restoring the missing register restores. Do not
repeat disabling that pass as a fix; trace the earlier output/state boundary.

Live LES input recovery now passes its binary-only validation and compiled
behavior regression; MOV and dead-segment controls remain green. Lowering
consumes exact logical Alias word owners and resolves unbound types against
the target architecture. A subsequent caller-layout repair accepts body-proven
groups of complete physical PUSH slots, with split/conflicting layouts refused.
Byte-to-dword type promotion now includes SimTypeChar, preserving signedness.
Latest focused surface: 37 passed; the old corpus helper-spelling assertion
failed. Replacing that assertion with strict compilation and memory/register
behavior found a real residual bug, not just obsolete test expectations:
`__fimemset` reports validation success but emits uninitialized `local_5`.
The stronger oracle has 5 passes / 1 corpus failure (6.41s). Step 9 remains open.
That corpus test is now enrolled in routine pipeline and owned-file selection.
Last run before enrollment: 4,268 routine tests passed in 210.95s, 268 early
contracts passed, and all three lanes/seven MS C round trips passed. Full
architecture and scoped MyPy/Pyright passed. This does not describe the newly
expanded lane as green: it now includes the known strict-compilation failure.
Enrollment and oracle verification: 118 passed / one known corpus failure in
7.57s. Scoped gate-file Ruff/MyPy/Pyright pass; refreshed global quality-fast
remains red on lint debt and the 39-module mypyc smoke passes.
Next: repair the argument subview binding and reject unbound emitted locals
even when their storage coordinates overlap initialized argument bytes.
Earlier routine checkpoint: 4,256 passed in 282.09s, 268 early contracts,
three lanes/seven MS C round trips passed. That run predates the caller-group
and byte-to-dword follow-ups. Scoped typing and final architecture passed at
that checkpoint; global quality-fast still reports lint debt.
See [live-segment reduction and DoD](reference/p0-far-load-width.md#live-segment-reduction-open).

Latest ABI follow-up: exact stack-word evidence now rejects non-SS overrides
and BP-indexed addresses. Four new refusal regressions pass. A broader far-load
word expansion was rejected because it created an unused required parameter;
the existing LES compile/run test caught this and is green again after removal.
Final pipeline: 4,250 routine tests passed in 270.07s; 268 early contracts,
all three lanes and seven MS C round trips pass. Scoped typing/full architecture
pass; global lint debt and `__fimemset` remain open. See
[accepted and rejected evidence](reference/p0-far-load-width.md#abi-consumer-follow-up).

Previous Step 9 follow-up: frontend normalization now includes the segment word
in LES/LDS/LSS/LFS/LGS memory extents. All 20 decoder-path/operand-width cases
pass. Routine pipeline: 4,246 passed in 260.28s; all three lanes and seven MS C
round trips pass. Final Make/ownership checks: 83 passed; scoped typing and full
architecture pass. Global lint debt remains, and `__fimemset` still fails
validation. See [evidence, DoD and remaining work](reference/p0-far-load-width.md).

Traversal/storage protection: shared read/replacement child-schema coverage,
native SS container regressions and pre-publication Alias displacement checks
are implemented. Errors identify the failing field or storage ranges early;
Make pipeline targets require the fast contract gate first. See
[scope, DoD and failure definitions](reference/decompiler-contract-gates.md).
Previous traversal checkpoint: 268 early contract checks passed; the routine pytest lane
passed 4,226 tests in 246.26s, and all three pipeline lanes passed, including
all seven MS C round trips. The two stale Makefile assertions from the first
run now require the new prerequisite. Scoped MyPy/Pyright and full architecture
pass. The new storage matrix exposed stack variables incorrectly taking the
generic memory equality branch; base/region identity is now preserved, with
one shared comparator for compatibility consumers. Shared AST utilities are
Ruff-clean; global lint debt remains. A fresh `__fimemset` regression still
fails whole-tail validation. Its native `CVariable.name` setter exception is now
repaired, but BP+5/BP+6 argument-subview reads remain invalid; see
[the naming checkpoint](reference/p0-cod-scan-verdict.md#native-variable-naming-exception).
This is not a full-suite refresh or Step 9 completion.

Prototype reconciliation now uses registry BP coordinates and preflights the
whole proposed layout before mutation. Its initial `_dos_loadProgram` regression
was caught and repaired; validation, compilation and behavior are green again.
See [coordinate/layout evidence and DoD](reference/p0-stack-prototype-layout.md).

Entry-stack validation now initializes only bytes supplied by the declared C
parameter value, not its physical ABI slot or unified owner. This closes a real
false-positive verdict: `__fimemset` had briefly reported validation success
despite byte arguments and uninitialized subviews. It now correctly fails with
BP+5/BP+6/BP+7 coordinates and AST paths. Fourteen focused entry-range tests pass,
including valid byte reads from wider slots; these run in the early gate.
Scoped Ruff/MyPy/Pyright and full architecture pass. `quality-fast` remains
blocked by global lint debt; its 39-module mypyc smoke passes.
Current logs: `/home/xor/.cache/entry-range-{pipeline,quality-fast,architecture,pyright}.log`.

The reduced LES return regression is now green: SS stack-load lowering was
missing `CReturn.retval` traversal. Existing Alias-backed projection now handles
the return, including nonzero SS. Routine gate: 4,001 tests passed in 260.60s,
all three pipeline lanes passed. Full `__fimemset` remains validation-failed;
global Ruff remains red. See the latest section of
[the investigation](reference/p0-cod-scan-verdict.md#return-traversal-repair).

Step 9 reporting repair: diagnostic COD scans can no longer promote a failed
child to success without replacement generated C. All 34 COD batch tests pass;
the real `__fimemset` case now correctly fails the required zero-exit check.
Scoped typing passes; legacy Ruff findings remain. The latest targeted retry
of the 21 full-suite failures was 2 passed / 19 failed in 207.05s, not a new
full-suite audit. See [verdict coherence evidence](reference/p0-cod-scan-verdict.md).
The earlier binary-only LES reduction initially returned the wrong word.
The variable-association displacement and return traversal repairs above now
make both MOV and LES compile/run checks pass. Full `__fimemset` recovery still
fails independently; this is not Step 9 completion.

Latest repair: InitBars' call-output coordinates now survive local stack
replay through explicit producer ownership. Its original regression passes;
routine pipeline: 3,994 passed in 231.62s, all seven MS C round trips passed.
Architecture and scoped typing pass; global Ruff remains red. Full-suite
totals are not refreshed. See [coordinate ownership evidence](reference/p0-initbars-coordinate-ownership.md).

mset_pos follow-up: IR remainder signedness and Lowering SSA precedence now
preserve both arguments; executable checks and CLI whole-tail validation pass.
The broader routine gate found 3,991 passed and two failed (196.25s): the
bootstrap inventory failure was repaired and rerun, but InitBars stack-identity
validation was subsequently repaired as described above. All seven MS C round trips passed;
global Ruff remains red. See [root cause and current evidence](reference/p0-msetpos-signed-remainder.md).

RunMenu diagnostic repair: the original failing regression now passes along
with 16 focused/segment checks. Routine pipeline: 3,982 passed in 207.87s,
all seven MS C round trips passed. Architecture and scoped typing pass;
global Ruff remains red. Step 9 is open; stop after its full acceptance.
See [repair evidence](reference/p0-failure-retry-20260911.md#runmenu-diagnostic-repair).

Earlier targeted retry: all 21 previously failing full-suite nodes still failed
(166.13s, pytest `-n 7`). The later RunMenu repair above supersedes that node. This
is not a refreshed full-suite audit. See [retry evidence and next action](reference/p0-failure-retry-20260911.md).

2026-09-11 return-address safety: fixed-slot return effects now refuse dynamic
BP indexes and incompatible segment overrides instead of dropping them.
Scoped Ruff/types and full architecture pass. Routine pipeline: 3,978 tests
passed in 202.08s and all seven MS C round trips passed; global Ruff remains
red. See [native evidence and boundaries](reference/p0-return-address-evidence.md).

**Latest full audit, 2026-09-11:** 11,750 passed, 21 failed, 170 skipped out of
11,941 tests; 1,180.89s, source stable, no missing/duplicate outcomes, memory
below 2 GiB. This supersedes the historical baseline below. The goal remains
open. See [current failures, repair order and slow tests](reference/p0-full-suite-post-bios-20260911.md).

LIFE follow-up: repaired logical frame-word evidence and false preservation
of escaped word bytes, including wrapped BP pointers. Operand load provenance
now survives direct CMP and stack-expression lowering. Routine pipeline: 3,944
tests (197.70s) and all seven MS C round trips pass; typing and architecture pass.
LIFE still fails: uninitialized-read validation restores the older C snapshot.
Its regression now rejects timeouts. See [evidence and next steps](reference/p0-life-stack-word-evidence.md).

Conditional-output follow-up: Widening no longer combines conditional byte
writes from different blocks merely because they share a return. Native
LIFE input tests preserve both the logical word operand and its byte execution
effects. Latest routine gate: 3,956 passed in 222.01s and all seven MS C round
trips passed. Scoped lint/types and full architecture pass; global Ruff and
the full-suite failures remain open. LIFE still needs return-qualified output
definitions; this safety fix does not close its acceptance.

Return-classification follow-up: shared Semantics self-clear decoding now
recognizes LIFE's AX zero return and AH clear consistently. Latest routine
gate: 3,964 passed in 238.99s and seven/seven MS C round trips passed.
Scoped types and architecture pass; global Ruff remains red. LIFE was rerun
separately and still fails the unresolved-stack-local guard in 23.48s.

2026-09-11 BIOS checkpoint: the previously failing sidecar-free BIOS strict-C
and behavior regression now passes. IR/Alias proves released unread private
stack writes; both DCE and direct-stack Lowering replay consume that proof, so
late rendering no longer recreates dead local stores. Routine pipeline is
green: 3,898 pytest tests (206.58s), all seven MS C round trips, no failed or
timed-out lanes. Global Ruff still fails `quality-fast`; the full-suite baseline
below has not been rerun or arithmetically reduced. See the
[BIOS evidence and remaining acceptance](reference/p0-bios-private-frame-proof.md).

**Full-suite baseline, refreshed after user review:** 11,618 passed, 26 failed,
170 skipped out of 11,814 inventoried tests; 1,360.94s execution, source stable,
no missing or duplicate node IDs. This supersedes the older 23-failure audit.
Three previous failing nodes pass, six additional nodes fail. A curated green
lane would not establish repository-wide acceptance. The immediate priority is
to clear this full list, not add unrelated semantic or performance work. See
[full-suite baseline and repair order](reference/p0-full-suite-baseline-20260910.md).

2026-09-11 follow-up: the full architecture checker now passes (374 related
tests), and the CLI load-program regression passes stronger compiled behavior
acceptance (nine tests including oracle controls, with timeout pass/skip paths
removed). These close two verified failing nodes, not a refreshed full-suite
total. Global lint and the separate COD loadprog failure remain open.

Interrupt-helper follow-up: `_MousePOS` now calls the same runtime helper that
its header declares. Unmodeled interrupt names come from the authoritative
handler class. The wrapper passes strict UBSan execution and validation;
45 focused checks include five corruption controls. Routine pipeline:
3,803 passed, one known BIOS failure in 181.39s; all seven MS C round trips
pass. Architecture/scoped types pass, global lint remains red. DrawRadarAlt
still times out. SetGear completes in 31-36s in private-cache diagnostics with
a larger diagnostic budget, but retains flag equations and fails its CLI
regression even warm; neither function is treated as fixed. Byte TEST frontend
evidence is verified, so follow-up starts at downstream predicate consumption.
See the full-suite
report for evidence and the runtime-ABI scope of the mouse oracle.

SetGear investigation corrected a direct-byte logical access recorded as a word.
32 focused tests pass; routine pipeline is 3,816 passed/one known BIOS failure,
with all seven MS C round trips passing. SetGear C remains byte-identical and
is not fixed. Next investigate derived direction-state ITEs and rejected DCE
changes; see [the investigation](reference/p0-setgear-investigation-20260911.md).

Experimental follow-up: branchless DF synchronization removes SetGear's flag
equations, with clean validation and GCC compilation, but introduces/exposes a
`simple_control` MS C harness failure on undeclared `inertia_flags`. Acceptance
is red: six/seven MS C examples pass, routine pytest is 3,817 passed/one BIOS
failure. Resolve this regression before accepting the direction change; the
investigation records the exact artifacts and remaining proof obligations.
Follow-up found TEST omitted from CFG dead-write proof consumption. That handoff
is corrected, with 95 focused checks passing and scoped lint/types clean, but
the simple_control round trip still exposes a self-dependent unused flag cycle.
That round-trip blocker is now resolved: an observed worker showed the
Lowering purity census omitted the ZF equality comparison. Recognizing `CmpEQ`
with recursively pure operands allows the evidenced dead FLAGS cycle to be
removed, without guessing incoming FLAGS. All seven MS C round trips pass
again; routine pytest is 3,839 passed/one known BIOS failure in 194.43s, with
47 focused FLAGS tests passing. Global lint and SetGear's remaining acceptance
obligations are still open. These are not refreshed full-suite totals.
The remaining routine BIOS failure now has a fresh binary IR/Alias inventory
and bounded implementation obligations in
[private-frame proof](reference/p0-bios-private-frame-proof.md). Its DCE guard
must not be bypassed: allocation/release and read/escape closure remain missing.
Subsequent evidence work now publishes block-local extent verdicts and exact
SSA memory coordinates, and preserves terminal RET markers at VEX import.
Routine pytest is 3,875 passed/one known BIOS failure in 193.83s; all seven
MS C round trips pass. Escape/ownership closure and proof-consuming deletion
remain open, as do global lint and the full-suite baseline refresh.

Wide-predicate follow-up: `_InBoxLng` now retains full-width operands and six
wide parameters. All three derived wide-condition constructors discard stale
word-register bindings while preserving source addresses. Validation and strict
UBSan boundary execution pass; 24 focused checks include corruption controls.
Routine pipeline: 3,797 passed, one known BIOS failure in 253.38s, all seven
MS C round trips passed. Architecture and scoped types pass; global lint and
11 existing Ruff findings in the touched modules remain open. See the
full-suite report for the producer trace, timing ledger and acceptance scope.

Signed arithmetic follow-up: `_mset_pos` exposed undefined negative shifts in
generated C despite passing tail validation. Native Lowering now preserves
explicit dword shift/division types with existing semantic casts; unchanged C
passes exhaustive per-input UBSan execution. Final focused checks: 51 passed.
Routine pipeline: 3,789 passed, one known BIOS failure in 335.71s, all seven
MS C round trips passed. Scoped types/Ruff pass; global lint remains red.
This is a bounded arithmetic fix, not general modulo recovery or full-suite
acceptance. Details and failure-sensitive oracles are in the full-suite report.

ConfigCrts follow-up: Lowering no longer replaces already-defined SSA values
with fresh segmented loads using undefined register carriers. Validation and
strict unchanged-C execution now pass; 20 focused tests include seven oracle
corruptions. The existing exact-temporary-name assertion was replaced by the
executable contract. Scoped types pass; global quality remains red. See the
full-suite report for root cause, acceptance scope and gate evidence.

LIFE follow-up: retained compact string diagnostics but corrected clear_mat's
test to reject partial whole-body replacement, and extended the timer fixture
through its actual RET with CFG coverage assertions. The eight-test module
passes, but timeout-accepting sidecar tests do not prove function recovery.
A longer complete-range timer probe still reaches unresolved stack locals;
timer/pause_screen and clear_mat's normal-path parameter validation remain
open. See the full-suite report for the verified limits of these results.

Current acceptance is red, but the REP infinite-loop kernel is repaired. Eight
sidecar-free executable cases cover both repeat prefixes, zero/one/multiple
iterations, both directions, offset wrapping and return overflow. Each passes
validation, strict compilation and unchanged-C execution. The repair is in
frontend loop shape, pre-SSA return binding and typed native constant lowering,
not Rewrite. MONOPRIN argument recovery and BIOS strict-C remain open.

Latest broad lanes: **3,734 passed / 1 failed** each (234.03s and 164.81s),
verified after the bootstrap inventory and string admission repairs. The
remaining failure is BIOS strict-C. All three MS C tiny round trips and executable
quality guards pass. The pipeline aggregate's one failed lane is pytest, not
an MS C example. Scoped Ruff/MyPy/Pyright pass; global lint remains red.
See [current REP evidence](reference/p0-monoprin-repeat-state.md).

Follow-up: string timeout recovery now shares the normal codegen override's
typed whole-function admission guard. Four previously failing mixed-effect
regressions now refuse replacement; 18 helper tests and three CLI timeout tests
pass, with scoped Ruff/MyPy/Pyright clean. Full fallback soundness remains open:
setup/live-out effect preservation and validation of the replacement itself
still need proof. Broad post-change results are recorded above and in the report.

BIOS acceptance is now executable, not just syntax-only: unchanged C must
preserve ES and the exact two-byte BDA write without unrelated global-memory
or segment changes. Eight positive/mutation oracle controls pass; the real
function still fails strict compilation on its two protected locals. No
production deletion or refreshed broad total is claimed for this test-only
change. See [BIOS execution acceptance](reference/p0-frame-coordinate-coherence.md).

The BIOS proof audit also corrected shared call-range preservation: an escaped
byte now invalidates a containing preserved word even without a separate byte
access in the caller. IR owns the fix; both memory SSA and stack-object widening
consume it. 53 focused tests and scoped Ruff/MyPy/Pyright pass. Broad routine
lanes each report 3,761 passed and one BIOS failure (204.98s / 173.40s); all
three executable quality guards and MS C round trips pass. Global lint remains
red. This is not private-store deletion permission or BIOS completion.

The following entries are historical checkpoints, not current suite totals.
DCE deliberately
protects the exact stack-write facts; the next repair requires earlier
Alias/IR ownership, lifetime and escape evidence, not a weaker DCE guard.
That investigation exposed a preceding SSA register-identity defect, now
fixed with focused regressions. The earlier stable-source full audit reported
**11,478 passed, 23 failed, 170 skipped** (11,671 total) in **1,370.09s**.
Thirteen prior failures pass; the only new failing node is the added BIOS
strict-C test. Four changed architecture findings were subsequently repaired,
with 402 focused tests passing; that is not a refreshed full-suite total.
P0 and the accepted runtime target remain open. See
[SSA register identity](reference/p0-ssa-register-identity.md).
Post-audit routine reruns each report 3,610 passed and the one BIOS strict-C
failure (196.44s/156.44s). All three executable quality guards and the default
MS C round-trip lane pass. Scoped MyPy/Pyright pass; global Ruff remains red.

Subsequently, two stale HeapSort output assertions were replaced with strict
compiled behavior checks on unchanged generated C. The full HeapSort module,
ten oracle mutations and wiring pass (128 tests, 44.90s); no semantic code or
validation was weakened. The measured full-suite total is not recalculated
from these focused repairs. See [HeapSort acceptance](reference/p0-heapsort-behavior-oracle.md).

The BIOS follow-up also found a contradictory-BP storage merge in memory SSA.
An IR-owned guard now refuses those coordinates coherently in memory SSA and
logical Alias storage, without deleting instructions. Machine-byte failures
reproduce before the fix; 143 focused tests pass afterward, including captured
old BP values. BIOS lifetime proof remains open. See
[coordinate conflict evidence](reference/p0-stack-coordinate-conflicts.md).
Its routine gates each report 3,629 passed and the known BIOS strict-C failure
(171.57s/142.80s). All executable quality guards and MS C round trips pass;
global Ruff remains red. No new full-suite total is claimed.
The subsequent ownership-validator cleanup removes its recurring complexity
failure without weakening checks: 124 focused tests and scoped Ruff/MyPy/Pyright
pass, as does the real manifest CLI. Global lint and semantic P0 remain open;
details are in the coordinate report's ownership-gate follow-up.
The BIOS investigation then exposed a live-out validation gap for stack
addresses passed to callees. Direct address exposure now preserves zero and
positive-offset writes, and a new observable retains their values. Deletion
and value-corruption regressions pass with the full focused tail-validation
module (287 tests). Routine gates each report 3,637 passed and the known BIOS
strict-C failure (159.84s/141.34s); all quality executable guards and MS C
round trips pass. Global lint remains red. This is validation
hardening, not BIOS lifetime/DCE completion. See
[address-exposed stack validation](reference/p0-address-exposed-stack-validation.md).

The stale Sleep comparison-text assertion is now a strict compiled deadline
oracle, preserving signed casts and all existing validation guards. Both real
Sleep routes, seven corruption controls, positive stack-validation controls
and wiring pass: 131 tests in 19.05s. No production semantics changed; the
full-suite baseline and BIOS blocker remain open. See
[Sleep acceptance evidence](reference/p0-sleep-behavior-oracle.md).

The stack Alias builder now meets the shared complexity limit while retaining
phi/refusal accounting (136 focused tests, 9.37s). Its quality-dev run reports
3,649 passed and only the known BIOS strict-C failure in 163.25s; all three
executable quality guards pass. A separate MyPy import-scope defect found by
that gate is fixed in shared configuration: direct checking and `make mypy-dev`
now pass, plus 25 scope/anchor tests. Global Ruff and BIOS remain open. See
[stack Alias quality evidence](reference/p0-stack-alias-quality.md).

Frame analysis now consumes the IR captured-BP contradiction census before
publishing its entry-SP relation; previously later rebases left a stale PROVEN
coordinate. Both machine-code failures reproduce before the fix. Afterward,
157 focused tests pass; routine lanes each report 3,653 passed and the known
BIOS strict-C failure (174.84s/143.49s). Executable quality and MS C round trips
pass. No store deletion or lifetime proof is claimed. See
[frame-coordinate coherence](reference/p0-frame-coordinate-coherence.md).

MONOPRIN's unresolved string corpus failure is confirmed semantic, not merely
an obsolete intrinsic spelling. Native SSA chooses pre-update CX/DI on a REP
backedge, and liveness then discards updates. A diagnostic classifier change
restores them but does not pass validation or fix pointer/loop-bound defects;
it was not landed. The corpus test now uses private output instead of mutating
shared `.dec` files. See [repeat-state investigation](reference/p0-monoprin-repeat-state.md)
for exact ownership, rejected partial trials and next acceptance steps.

The repeat-state follow-up now has a sidecar-free executable false-pass
regression: `validation=passed` and strict compilation do not prevent its
infinite loop. It is admitted to routine selection; five oracle corruptions
are rejected. Focused result is 115 passed and this one failure (5.15s).
Experimental native/frontend repairs remain unlanded because they expose
additional index, direction and width defects. Closing this false-pass is the
next semantic priority; see the repeat-state report's executable section.

The REP trial's direction ellipsis was traced to CLI expression-display depth,
not an unsupported instruction. Export now disables that display truncation;
the uncached trial renders the full direction expression but still fails strict
byte-store compilation. This is a rendering-only repair, not REP/P0 closure.
See the repeat-state report's expression-display section for evidence.

The next REP blocker is now localized before SSA: generic Clinic calling-
convention recovery clears the guessed AX return prototype, cannot recover a
convention, and skips ReturnMaker, leaving an empty return despite a live AX
producer. Preserve the independently proven terminal effect without inventing
an ABI. The byte-store narrowing conversion is present in native AIL but loses
its explicit cast during native C simplification. See the repeat-state report's
native width/return section; no partial REP fix has been accepted.

Independent return-binding repair is implemented at native return construction:
the existing typed AL/AH/AX storage proof supplies an AIL operand before SSA,
without inventing a calling convention or changing the prototype. The REP
trial preserved `return 0x1235`; byte narrowing and canonical-loop acceptance
were still open at that checkpoint and are now covered by the executable cases
above. Historical routine tests: 3,685 passed / 2 known failures after
replacing a newly exposed `_dos_loadProgram` spelling assertion with compiled
behavioral coverage. A DOS/KVM compiler crash failed one external case in the
final aggregate; that case passed its isolated full round trip. See the report
for exact counts, timing, refusals and the retained failed-run evidence.

Current P0 follow-up: native SSA DCE was deleting caller-observed ES writes.
The IR/native adapter now publishes segment return-boundary uses before DCE;
existing lowering renders the surviving effects without Rewrite changes.
The compiled ES/DS caller cases, original BIOS regression and focused contracts
pass (120 tests, 15.13s). Both routine lanes pass 3,583 tests; all executable
quality guards and all three default pipeline lanes pass. Global lint still
fails. The next Lowering repair prevents individual byte stores from consuming
a whole-word immediate fact. The BIOS CLI probe now has one store, a void
signature and an explicit return, with tail validation passed; unused locals
still block strict compilation. Eight new width regressions and the related
module/wiring checks pass (297 tests). Both routine lanes now pass 3,595 tests
(199.82s/139.43s), all three executable quality guards pass, and the default
pipeline passes all three lanes including MS C round trips. Global lint and
strict BIOS compilation remain open. This is not full-suite closure. See the
[live segment repair](reference/p0-full-suite-followup-20260910.md).

Full architecture scope reconciliation closes all **29** recorded findings;
all **371 architecture tests pass**, with no checker relaxation. The follow-up
resolves eight Ruff findings across twelve promoted modules; scoped Ruff,
MyPy, Pyright and 96 focused tests pass. Global lint debt and the complete-suite
audit remain separate obligations. The [caller-cleanup investigation](reference/p0-caller-cleanup-loop-investigation.md)
fixes unsafe flag-definition pruning, applies the shared straight-line Clinic
policy to native callers, and preserves required word-carry casts in rendered C.
The addition-duplication follow-up uses an exact unsigned-word carry predicate;
all 37 focused tests pass, with compiled arithmetic evidence and stable native
tail validation. Both routine lanes now pass 3,537 tests (164.15s/143.99s),
all three executable quality guards and all seven MS C round trips pass.
Global Ruff debt, caller argument acceptance and complete-suite closure remain
open. See the
[quality-scope report](reference/p0-architecture-scope-reconciliation.md).

Uncommitted caller-width follow-up: a Lowering-owned width refusal prevents
byte stores becoming word arguments, and the last-N-stores guess was removed.
Exact saved-BP pair ownership now repairs QuickC `hello`; both routine lanes
pass 3,562 tests and the default pipeline passes all three lanes, including
the MS C round trips. Global Ruff debt remains.

The fresh [full-suite follow-up](reference/p0-full-suite-followup-20260910.md)
accounts for all 11,625 tests: 11,420 passed, 35 failed, 170 skipped in 1,257.89s.
Four failures subsequently pass focused reruns; this is not a new full-suite
count. Prioritize the remaining call-argument evidence failures and corpus
acceptance failures without weakening width refusal or validation.
The call-fixture follow-up reconciles seven more audit failures: six explicit
word-width fixtures and one unknown-store retention expectation. Combined call
and caller-cleanup tests report 188 passed, one conflicting-evidence failure.
The last conflict exposed count-only deletion of unmatched argument stores.
Cleanup now requires recorded instruction/value matches; six mutation-tested
cases cover refusal and acceptance. Call/caller/ownership tests pass 253 cases,
and all default executable lanes pass. Twenty-three audit failures remain
unresolved; the full-suite baseline is not recomputed from focused results.
See the follow-up report for remaining lint debt and exact gate timing.
DOSFUNC's cast-sensitive call assertion is now covered by the exhaustive
compiled oracle, strengthened with exact error-message and argument corruption
checks: 13 focused tests pass. BIOS's missing ES write requires effect-contract
review and remains open. Twenty-two original audit failures remain unresolved.

Both sidecar-free DrawTime acceptance cases now pass after permitting an exact
identity cast on the already unsigned-short argument; all wide-return/delay
checks remain. Named/sidecar-free InsertionSort also pass with explicit signed
casts and initialized loop expectations; lost-break oracle tests pass. See
[acceptance evidence](reference/p0-drawtime-acceptance-contract.md).

Seven CLI failures were stale stdout expectations for stderr diagnostics;
[output-contract reconciliation](reference/p0-cli-output-test-contract.md)
passes 13 reporting/fallback/parallel tests without production changes.

Five return-compatibility failures were stale producer-substitution expectations;
the [return contract reconciliation](reference/p0-return-maker-test-contract.md)
preserves source-evidence checks while requiring AX capture at RET. Selected
return/barrier tests pass; this does not refresh the complete audit count.

ExchangeSort's initializer ordering and unsafe stack-probe deletion have focused
repairs: 32 focused tests pass and the uninitialized read is gone. A subsequent
repair preserves Lowering's required signed casts through legacy CLI cleanup:
seven simplifier regressions pass, and ExchangeSort now validates and passes
the CLI compilation gate. The subsequent instruction-local reload repair in
`f37229fa1` closes the outer-loop shape failure: the focused acceptance and reload
suite passes all 26 tests in 30.06 seconds. P0 remains open.
See the [initializer preservation report](reference/p0-exchangesort-initializer-preservation.md)
for the proven causes, owner boundaries, remaining investigation, DoD and
Definition of Failure. This accepts the tested named ExchangeSort function, not
the complete sidecar-free corpus or the full repository suite.
The required-cast follow-up also repaired Structuring's casted-induction matcher;
InitMenu's full compile/behavior regression and QuickSort's acceptance pass.
The committed-source fast/default lanes each pass 3,502 tests (158.24/145.05
seconds); three executable quality guards and seven MS C full round trips pass.
The combined gate still fails on 6,319 promoted-scope Ruff findings; the full repository audit is not
rerun by these lanes.

QuickSort's corrupt partition expression has a focused passing repair: the
legacy structured simplifier reused widening results for discarded temporary
node IDs. Removing that unsafe cache preserves the original subtraction;
the uninstrumented QuickSort acceptance and five focused simplifier tests pass.
See the [root-cause report](reference/p0-quicksort-partition-comparison.md).
MyPy/Pyright pass on the owner; 99 pre-existing Ruff findings under the newly
enabled clarity rules remain. Fast/default suites each pass 3,463 tests, all
three executable guards pass, and seven MS C round trips pass. The combined
quality command still fails on 6,322 promoted-scope Ruff findings. This does not
close the complete audit or wider plan.

The [fresh complete audit](reference/p0-full-suite-audit-20260910.md) accounts for
all 11,536 tests: **11,326 passed, 40 failed, 170 skipped**, in 1,326.65 seconds.
Source was stable, no nodes were missing/duplicated, and peak RSS stayed below
2 GiB. This supersedes the older 52-failure baseline; routine passing counts
must not be presented as a green full suite. Its QuickSort self-comparison was
subsequently repaired as recorded above; the separate sidecar-free QuickSort
guard-shape acceptance now passes after an evidence-backed brace/else expectation
correction (one test, 9.30 seconds with accepted-result cache reuse). Preserve binary partition-size comparisons;
do not suppress warnings or delete branches. The [QuickSort trace](reference/p0-quicksort-partition-comparison.md)
records the investigation and accepted repair. The audit report retains all
40 failing nodes and the slowest tests. The [test-overlap review](reference/p0-test-overlap-review.md)
records the executed deduplication pilot and ordered work with reasons, DoD
and Definitions of Failure; no test removal or full-suite speedup is claimed.

The direction helper's positive IR/SSA cache-source manifest entry was then
added with a failing-before regression. Eight cache tests and scoped
Ruff/MyPy/Pyright pass. This invalidation correction does not constitute a new
full-suite rerun or close the semantic failures above.

The [direction-bit projection](reference/p0-direction-bit-projection.md) removes
InitMenu's remaining SP/BP bookkeeping at the Frontend/IR boundary. The cause
was false liveness through status calculations feeding an unchanged DF bit.
InitMenu's unchanged acceptance and behavior harness now pass; 49 focused tests
pass, live C compiles and validates, and all 18 call inventories are unchanged.
Scoped Ruff/MyPy/Pyright pass. Fast/default gates each pass 3,443 tests;
executable guards, QuickC and seven MS C roundtrips pass. The separate no-sidecar
InitMenu compile/call/validation regression also passes. InitMenu's bookkeeping
checkpoint is closed in both tested modes; the full-repository audit and wider
plan remain open. The default unit lane is still over its configured budget.

The [callee argument-cleanup projection](reference/p0-callee-argument-cleanup.md)
now represents binary-proven cleanup at the native source-call/IR boundary.
InitMenu's eight-byte drift becomes an identity update, with all 18 call
inventories unchanged, strict compilation and validation passed. Sixty-one
focused tests pass; InitMenu's unchanged final `SP - 4` acceptance still fails.
Final fast/default gates each pass 3,402 tests; executable guards, QuickC and
all seven MS C roundtrips pass. Scoped Ruff/MyPy/Pyright pass. The default unit
lane remains over budget; the complete function and full-repository audit stay
open. This is a verified cleanup-projection checkpoint, not full P0 closure.

The [IR register-displacement normalization](reference/p0-ail-register-displacement.md)
now removes redundant constant chains without stack-ownership guessing. InitMenu
has three short SP updates instead of nine long ones; strict C compilation and
validation pass with identical callsite inventories. Forty-five new tests pass;
fast/default gates each pass 3,387 tests, executable guards, QuickC and seven
MS C roundtrips. The remaining bookkeeping acceptance failure stays open.

The [stack-address operand-role guard](reference/p0-stack-address-operand-roles.md)
now refuses nonlinear, subtractive and repeated stack bases before native
propagation. Fifty-seven focused tests pass; fast/default gates each pass 3,342
tests, executable guards, QuickC and seven MS C roundtrips. InitMenu C remains
unchanged with validation passed; its acceptance stays open because the stack
bookkeeping remains. Pre-SSA calls still consume native stack loads.

The [accepted argument-shape publication fix](reference/p0-call-argument-shape-publication.md)
repairs stale inventory metadata using existing Lowering proof. All 18 observed
InitMenu callsites now agree with their node summaries; generated C is unchanged
and validation passes. Fast/default gates each pass 3,321 tests, executable
guards, QuickC and seven MS C roundtrips. InitMenu acceptance still fails its
unchanged bookkeeping assertion; the next step is proven argument-effect consumption.

The [C renderer fix](reference/p0-c-render-parentheses.md) removes InitMenu's
20 strict-GCC parenthesis errors without changing its expression trees.
Strict compilation and tail validation pass; the unchanged stack-bookkeeping
acceptance assertion remains red. Sixteen new routine tests cover warning-clean
grouping, expression values, installation and architecture delegation. Final
fast/default gates each pass 3,273 tests, all executable quality guards, QuickC
and seven MS C tiny roundtrips. The unit lane remains over budget. The
[test-telemetry follow-up](reference/p0-test-telemetry-typing.md) closes all 11
legacy test-file typing diagnostics and passes 3,290 fast tests. The subsequent
[switch-attempt reporting repair](reference/p0-switch-attempt-history.md)
preserves successful Structuring evidence followed by the final idempotent
pre-codegen no-op. All 20 focused tests, including RunMenu, pass; the broader
fast gate passes 3,292 tests and all three executable quality guards. Two
CLI Pyright diagnostics remained at that checkpoint. This reporting fix does not close
output-quality debt or establish a full-repository suite pass.

The [typed stack-declaration snapshot](reference/p0-stack-declaration-snapshot.md)
subsequently removes those two CLI diagnostics while preserving native object
identity and excluding arguments. Four new routine tests pass; InitMenu still
fails the unchanged bookkeeping assertion. Scoped Ruff/MyPy/Pyright pass;
the combined fast/default gate passes 3,296 tests in each lane, all executable
guards, QuickC and seven MS C tiny roundtrips. The default unit lane remains
over budget; full-repository verification and InitMenu acceptance remain open.

The subsequent [pre-SSA caller inventory](reference/p0-call-frame-base-effects.md#pre-ssa-caller-evidence-2026-09-10)
verifies that all 19 InitMenu CALL frames consume their 93 exact effects with
zero failures. The remaining argument PUSH/cleanup effects retain individual
tags at that boundary, including duplicated CFG projections of one cleanup.
The nested-expression follow-up finds complete existing producer keys on all
60 arithmetic nodes across ten retained SP/BP assignments. Reuse those keys
and resolve exact VEX SP-write dependencies; do not build another cross-SSA
provenance transport without evidence that it is needed. Next is argument-effect
consumption after proven argument materialization, not another return-frame patch. The unchanged InitMenu test
still fails; the observation produces byte-identical C with validation passed.

The [exact SP producer-link artifact](reference/p0-stack-pointer-provenance.md)
now connects existing arithmetic tags to physical writes at the pre-SSA IR
boundary. Its 66 published links cover all 60 observed final arithmetic keys,
while one unsupported SP assignment refuses. Seventeen new routine tests and
twelve existing CALL-frame tests pass; InitMenu's unchanged bookkeeping test
remains red. This is provenance publication, not permission to delete code.
Scoped Ruff/MyPy/Pyright and the 3,313-test fast quality gate pass, including
all executable quality guards. The default external pipeline was not rerun
for this metadata-publication step. The next consumer must prove argument
ownership and complete live-use closure.

The [lifted-constant repair](reference/p0-lifted-integer-constants.md) and
[signed-delta preservation](reference/p0-native-stack-tracker-width.md) remain
accepted. Correcting 12 proven return-segment pops in a temporary tracker probe
did not change generated C; do not install that experiment as an InitMenu fix.
Next output work is evidence-backed caller PUSH/cleanup ownership, not deleting
numeric SP state or weakening acceptance. General tracker subview/return-effect
correctness and the full-repository audit remain open.

The [InitMenu return-evidence repair](reference/p0-initmenu-return-evidence.md)
now supplies width-aware binary callee proof through Semantics, following the
exact source-project mapping for callees outside a rebased slice. Twelve
return-segment sequences now classify successfully; generated C improves and
validation passes. Seventeen routine regressions were added; 62 focused tests
pass, but InitMenu's unchanged final SP-bookkeeping assertion still fails and
strict GCC reports 20 parenthesization errors. Scoped Ruff/MyPy/Pyright pass;
final fast/default gates each pass 3,195 tests, all executable guards, QuickC
and the MS C tiny full pipeline. The default unit lane remains over budget.
Next, trace the remaining caller stack effects before native SSA;
do not relax liveness or claim complete InitMenu acceptance.

The [SP carrier safety review](reference/p0-call-frame-base-effects.md) fixes a
CALL-frame classifier that could delete nested evaluation effects with a
carrier. All 21 focused tests and scoped Ruff/MyPy/Pyright pass; six new cases
are routine. Final fast/default gates pass 3,178 tests each, all executable
guards, QuickC and seven MS C tiny roundtrips. An InitMenu probe records 18 callsites
but zero candidate frame assignments at their tags, with byte-identical C and
validation passed. Trace the surviving SP definitions and combined-effect
provenance earlier; do not relax the consumer's external-use refusal.
The follow-up inventory observes ten SP assignment tags outside those 18
callsite tags. Their native value provenance is the next investigation target;
address proximity is not a consumption proof.

InitMenu's double-segmentation of materialized object pointers is corrected in
`lowering/call_argument_expression.py`. The pointer-boundary probe observed
`ach` as `char[16]` and the format constant as a decoded string reference bound
to its active `char*` type; both were wrongly converted through DS a second
time. The existing compatibility bridge now consumes Lowering's concrete
object-address classification before conversion. Numeric constants, ordinary
pointer-typed carriers, wrong-type string references, and integer casts do not
qualify. No rendered-text or function-name rule was added.

Nine focused argument/state tests pass (final rerun 8.20s). The existing expression tests
were absent from routine selection; their five cases now have explicit Make,
test-pipeline, and ownership admission. Ruff, MyPy, and Pyright pass on the
changed surface. `quality-fast` passes 3,143 tests (135.92s pytest) and all
executable guards. The unchanged InitMenu acceptance test now passes validation
and its exact `sprintf(ach, "%3.3u", aNldiv(clPause, 30))` assertion, but still
fails the final pause-zero output-shape assertion (35.76s call / 43.76s pytest).
Register execution carriers remain; do not weaken that assertion or claim the
function fully accepted. Logs: `/tmp/inertia-initmenu-pointer-probe.log`,
`/tmp/inertia-object-address-focused.log`,
`/tmp/inertia-object-address-initmenu.log`, and
`/tmp/inertia-object-address-quality-fast.log`.
The default pipeline passes 3,143 unit tests (113.67s pytest / 114.085s lane),
QuickC (41.158s), and all seven MSC6 full roundtrip examples (64.472s lane).
Its unit lane remains over budget. Broad gates ran on the final production
change; subsequent test-only type-narrowing assertions passed the nine-test
rerun and explicit test-file Pyright. No failing acceptance assertion was
removed. Pipeline log: `/tmp/inertia-object-address-test-pipeline.log`.

InitMenu's embedded division-call loss is now prevented at the Types/Lowering
argument-mutation boundary. The decisive trace showed normalization correctly
embedding the producer in `sprintf` and deleting its standalone carrier; a
later argument candidate then replaced that embedded call with GP-register
expressions. `lowering/call_argument_call_preservation.py` now owns a typed,
occurrence-counted veto for losing exact machine-call instruction identities.
The legacy bridge only consumes this veto, through a documented startup-guard
exception; it does not recover new call semantics. Three routine regressions
cover dropped producers, cloned identities/shared-node multiplicity, and
different callsites with equal target spelling. Twelve focused tests pass.
Ruff (`check --fix`), MyPy, and Pyright pass on the changed Python surface.
`quality-fast` passes 3,138 tests (134.84s pytest) and all executable guards.
The default `test-pipeline` also passes: 3,138 unit tests (114.90s pytest /
115.312s lane), QuickC (41.185s), and all seven MSC6 build/decompile/recompile/run
examples (60.889s lane). The unit lane remains over its configured time budget.
These gates do not supersede the unresolved full-audit failures. Gate logs:
`/tmp/inertia-call-preservation-quality-fast.log` and
`/tmp/inertia-call-preservation-test-pipeline.log`.

The [GP zeroing correction](reference/p0-initmenu-gp-zeroing.md) now normalizes
exact same-register SUB/XOR values at the optimized frontend, retaining original
flag inputs. Native AIL had preserved self-subtraction, and later syntactic C
live-in collection promoted the entire AX parent before cancellation. Fresh
InitMenu output has no EAX runtime state and retains `validation=passed`, the
division call and materialized pointers. Its unchanged acceptance test still
fails on SP/BP carriers; strict GCC reports 22 parenthesization errors there.
New XOR/JNZ execution cases caught an existing flag-publication error: recording
condition metadata suppressed live architectural flags. The frontend now omits
only proven-dead flag writes. All 115 focused arithmetic/condition/liveness
tests pass. The second fast gate reports 3,162 passed and one DOS load-program
wrapper regression: correct direct segment stores now have AX runtime carriers.
Validation still passes, but that acceptance assertion remains red and must
not be weakened. Resolve its newly exposed value dependency without restoring
the unsound flag-elision shortcut. The default pipeline repeats the single unit
failure (3,162 passed, one failed); QuickC and all seven MS C tiny roundtrips
pass. The wrapper probe locates the undefined AX use in a flags-derived native
assignment, not a missing C call-result destination. The subsequent
[definition-preservation repair](reference/p0-call-result-definition-preservation.md)
fixes the actual Structuring mutation: retargeting the call to a stack local
had orphaned old SSA reads. An immediate same-width scalar capture preserves
them without replaying the call. All 14 focused tests, including the unchanged
wrapper regression, pass; scoped Ruff/MyPy/Pyright pass. The new regression
and seven previously non-routine assignment tests are now admitted. A second
regression protects captures with store-instruction tags from artifact pruning.
Final fast/default gates pass 3,172 tests each, all executable quality guards,
QuickC and all seven MS C tiny roundtrips. The unit lane remains over budget.
This closes the introduced DOS wrapper regression, not InitMenu or full-suite
acceptance. See the linked report for exact timings and evidence.
The final InitMenu rerun still fails its unchanged final pause-zero shape
assertion (40.07 seconds call), after passing validation and prior call checks.
SP bookkeeping remains; the subsequent behavioral oracle is not reached.
Neither GP live-in policy nor the acceptance assertion was weakened.

InitMenu call-loss investigation now narrows the remaining division defect:
the call at rebased 0x10d3 to 0x23da (original target 0x1143a) survives
native Clinic callsite construction, SSA, post-SSA simplification, variable
recovery, and extern collection. Native SSA initially represents its result
as a 32-bit register assignment; the primary candidate subsequently narrows
the observed result to 16 bits while retaining the call. This is not evidence
of native SSA deleting the call.
At the C-AST boundary, `_attach_callsite_summaries_8616` clears the callee
binding but initially retains the same constant-target call at that exact
instruction. `_materialize_callsite_stack_arguments_8616` subsequently removes
it. Legacy missing-call recovery also inserts an untagged `aNldiv()`; the
boundary snapshot places that replacement after `return`, not at the original
execution point. Later argument replay reconstructs a tagged call, too late
for the Structuring baseline. Do not repair this by adding a call-count floor
or another replay pass. Next: isolate the destructive argument consumer and
preserve the original call/result dependency in the owning Lowering contract,
with a failing regression before repair. Identity rebinding alone is not call
loss; follow exact instruction provenance and AST membership together.
The separate removed-condition fingerprint is a DF-bit test whose native
rendered arms both return, not evidence that the menu pause condition vanished.
Any acceptance of that removal still needs explicit equivalent-return and
condition-effect evidence; do not suppress arbitrary condition deltas.
Observation-only reruns still exit 4 with Structuring changed. No production
semantic fix or new green gate is claimed for this investigation. Logs:
`/tmp/inertia-initmenu-call-lifetime-3.log`,
`/tmp/inertia-initmenu-c-call-lifetime.log`, and
`/tmp/inertia-initmenu-c-call-lifetime-2.log`.

Call-address object preservation is now corrected in Types/Lowering:
`containing_stack_cvariable_8616` consumes the unique published containing
object extent before falling back to the backing variable's size. A word-sized
address request no longer narrows an existing `char[16]` object to a scalar.
The focused regression reproduced that exact type overwrite before repair;
38 coordinate/validation/replay tests now pass (11.07s). Ruff, MyPy, and Pyright pass.
The current InitMenu rerun has one `ach` buffer, no BP-0x12/BP-0x10 dependency
mismatch, and no missing storage-object failure; postprocess validation is
stable. It still exits 4 because Structuring reports an added helper at 0x1143a
and a removed condition/control-flow effect, and runtime-register carriers
remain. InitMenu is not fixed or accepted yet. See `/tmp/inertia-call-array-after.log`.
After this correction, quality-fast passes 3,135 tests (223.54s), configured
checks, and all three executable guards. Default test-pipeline passes 3,135
unit tests (121.85s pytest / 122.275s lane), QuickC (43.904s), and MSC6 7/7
(65.088s), with matching original/recompiled exit codes at 255. Unit timing
remains above its configured 30s budget. Logs:
`/tmp/inertia-call-object-quality-fast.log` and
`/tmp/inertia-call-object-test-pipeline.log`. These routine gates do not replace
the full audit or close InitMenu's remaining semantic acceptance requirements.

InitMenu investigation baseline after the full audit: focused execution still
fails (68.35s baseline; 64.34s combined rerun with 48 other tests passing).
Binary call sources require BP-0x12, while emitted reads use BP-0x10; writes
and reads split between two C arrays. Narrow-backing aggregate restoration is
now covered: three new cases failed before, and restoration now accepts only
an exact already-materialized array extent on a narrower backing variable.
Wrong extent, untyped backing, and unrelated views refuse. Focused tests and
scoped Ruff/MyPy/Pyright pass, but this alone does not fix InitMenu.

The latest observation-only trace found the remaining destructive transition:
`call_argument_stack_sources.materialize_call_argument_stack_cvariable_8616`
calls `stack_lowering_from_facts.materialize_stack_cvar_at_offset_from_facts_8616`,
whose `_promote_direct_stack_cvariable` overwrites proven `char[16]` with an
unsigned word. The legacy call-argument pass invokes this during address
materialization. Correct the Types/Lowering consumer, not rendered C or the
validator; preserve the aggregate and materialize the requested address/value
view explicitly. Evidence: `/tmp/inertia-initmenu-type.log`,
`/tmp/inertia-initmenu-narrow-after.log`. No InitMenu completion claim yet;
broader gates must be rerun after the remaining correction.

Whole-repository audit started after the routine gates passed. `make pytest-all`
collected 11,230 tests but stopped before execution on missing ownership for
the DOS-free oracle tests and native return-preservation test (10 nodes).
Ownership entries are now explicit; verbose C-source parameter IDs were
replaced with descriptive case IDs without changing cases or assertions.
69 focused tests and Ruff pass. The full rerun completed: 11,008 passed,
52 failed, 170 skipped in 1833.57 seconds; all 11,230 nodes accounted for,
source stable, peak aggregate RSS 1,818,484 KiB. This supersedes routine-gate
counts as the whole-repository status. Failures span 12 modules, including
SORTD validation/output, CLI, native return recovery, and architecture checks.
Do not treat all failures as obsolete expectations or claim the full suite green.
The authoritative audit is `.cache/pytest/partitioned-summary.json`; full log:
`/tmp/inertia-full-suite-audit.log`.

First audit root cause: CLI-first access-hint import enters X86_16 bootstrap,
whose storage-object bridge imports the same partially initialized CLI shim.
The package swallows that ImportError, leaving compatibility hooks absent.
Import the hint contract from its existing Lowering owner instead. Fresh-process
CLI-first/frontend-first RETF cleanup tests must pass without explicit bootstrap;
changing cleanup expectations or explicitly initializing only the test is failure.
Other legacy CLI dependencies of the storage bridge remain separate layer debt.
The CLI-first regression fails before the import correction (cleanup 8, expected
6) and passes afterward. CLI-first/frontend-first plus package/access/return
checks pass 58 tests in 15.53s; scoped Ruff, MyPy, and Pyright pass. Architecture
audit also exposed four missing layer-header markers, four mandatory compiler
tests with optional-GCC skips, and a missing subview ownership entry. These are
corrected without weakening checks: architecture plus compiler regressions pass
404 tests in 37.77s. Full-suite failures have not yet all been rerun or resolved.
Post-fix quality-fast passes 3,129 tests (171.89s), configured checks, and
three executable guards. Default test-pipeline passes 3,129 unit tests
(135.59s pytest / 136.081s lane), QuickC (48.804s), and MSC6 7/7 (74.020s).
All seven original/recompiled exit codes match at 255. The unit lane is still
over its configured 30s budget; no timing gate or assertion was weakened.
Quality-fast reported a fork-from-multithreaded-process deprecation warning in
`inertia_decompiler/fork_timeout.py:187`, in addition to dependency warnings;
this concurrency risk remains open. Logs: `/tmp/inertia-bootstrap-quality-fast.log`
and `/tmp/inertia-bootstrap-test-pipeline.log`.

Audit performance evidence: tidshowrange is the longest test at 130.97s.
Three separate EGAME2 `_openFileWrapper` tests take 88.35s, 85.61s, and 83.48s.
Investigate shared immutable decompilation fixtures with unchanged assertions
before deleting tests: matching function inputs do not establish redundant
behavioral coverage. Performance work must not hide the 52 audit failures.

Step 3 snapshot coherence: the remaining pick_ptr warnings were caused by
annotation replay restoring an integer snapshot after an accepted binary
pointer contract was already applied. Storage-prototype application now
publishes the same interface to the existing authoritative snapshot owner.
Two new regressions fail before repair; six focused tests and scoped linters
pass afterward. Fresh output retains void-pointer parameters/return, validates
cleanly and passes strict GCC -O0/-O2 pointer-identity checks. quality-fast
passes 3,127 tests (150.01s), configured checks and all three executable guards.
The default pipeline passes 3,127 unit tests (132.04s), QuickC (45.045s), and
MSC6 7/7 (67.955s), with matching original/recompiled exit codes. The prior
pick_ptr indirection warnings are gone without suppression or harness casts.
Broader SORTD acceptance and whole-repository checks remain open.
See [snapshot evidence](reference/p0-storage-prototype-snapshot.md).

The function_pointers carrier repair is now implemented in call-argument
Lowering with exact PUSH provenance, materialized argument evidence and a
runtime/native SP suffix-use check. Refusal coverage and adjacent tests pass
(32 tests, 8.85s); scoped Ruff/MyPy/Pyright pass. Fresh select_and_apply has no
ESP/EBP dependency, validates cleanly and runs both selector cases after GCC
-O0/-O2 compilation with callee stubs. Quality-fast passes 3,125 tests
(156.61s), configured checks and three executable guards. The default
pipeline now exits 0: 3,125 unit tests pass (120.71s), QuickC passes
(41.911s), and MSC6 passes 7/7 (70.428s). All original/recompiled exit codes
match. function_pointers no longer has unresolved ESP/EBP; scalar_types_io
still reports pick_ptr indirection warnings. The 6/7 records below are
historical. This closes the routine compiler-lane blocker, not the full
SORTD plan or a whole-repository test audit.

The original function_pointers failure was narrowed to a consumed argument
PUSH whose runtime ESP lvalue is rejected by the legacy native-register
carrier classifier. Its surviving BP read correctly blocks frame deletion.
The next fix must reconcile typed runtime-register identity with consumed
PUSH provenance and liveness, not weaken the frame guard. Fresh runtime
evidence and acceptance/refusal obligations are recorded in
[PUSH carrier investigation](reference/p0-function-pointer-push-carrier.md).

Native stack-anchor provenance is now integrated at the native SSA boundary,
with an IR-owned source coordinate consumed by Lowering only with complete
frame proof. Untagged references keep existing behavior. Two new coordinate
cases fail before repair; 80 focused tests and scoped Ruff/MyPy/Pyright pass.
Fresh production byteops has no EBP reference, validation=passed, and returns
0xC000 after GCC -O0/-O2 compilation without supplied register globals.
Quality-fast passes 3,116 tests (159.91s), configured checks and all three
executable guards. Default pipeline passes 3,116 unit tests (138.04s) and
QuickC (47.890s). MSC6 improves from 5/7 to 6/7 (64.175s): scalar_types_io
now recompiles and runs with exit code 255, though pick_ptr indirection
warnings remain. function_pointers still fails to link unresolved ESP/EBP;
that is the next semantic investigation. The previous 5/7 results below are
historical. See [native anchor evidence](reference/p0-native-stack-anchor.md).

Prerequisite return repair: the compatibility hook overwrote a present native
dereference return with an offset/name-selected stack variable. It now infers
only absent values. One regression fails before repair; 73 focused tests and
scoped Ruff/MyPy/Pyright pass afterward. Combined diagnostic provenance now
passes all four smoke cases, and byteops validates and returns 0xC000 in GCC
-O0/-O2 without EBP references. The native-anchor hook remains diagnostic-only; explicit
native-anchor production integration is still required. Combined `quality-fast`
exits 0: 3,101 tests pass (170.07s), configured checks and three executable
guards pass. Default pipeline exits 2: 3,101 unit tests pass (124.15s),
QuickC passes (43.275s), MSC6 remains 5/7 (64.787s), with the same undefined
EBP in scalar_types_io and unresolved ESP/EBP in function_pointers. The next
implementation is explicit native entry-SP provenance, not blanket rebasing
or dummy runtime-register globals. No whole-suite or P0 completion is claimed.
See [native return evidence](reference/p0-native-return-preservation.md).

Newest identity repair: Widening's subview pass used raw native stack offsets
instead of published BP-coordinate bindings, merging saved-frame bytes into a
local. A read-only coordinate reader now preserves bindings across view, owner,
read and recomposition selection without importing Lowering. Eight new cases
fail before repair; 39 focused tests and scoped Ruff/MyPy/Pyright pass afterward.
At this intermediate revision the disabled anchor experiment passed three of
four smoke cases; the later return repair above resolves the fourth. The
combined quality gate passes, but production anchor integration remains open.
See [binding evidence](reference/p0-subview-coordinate-bindings.md).

Newest projection repair: instruction selection preferred a logical word owner
over an exact byte execution slice. Exact execution width now takes precedence,
while owner evidence stays available. A low-byte regression fails before the
change; 80 focused tests pass afterward, including compiled byte writes. Scoped
Ruff/MyPy/Pyright pass. Fresh byteops retains EBP. `quality-fast` passes 3,092
tests (161.48s), configured checks and three executable guards. Default pipeline
exits 2: 3,092 unit tests pass (148.86s), QuickC passes, MSC6 remains 5/7 with
the same undefined EBP / unresolved ESP+EBP rebuild failures. Timing is not a
controlled performance comparison: an unrelated indexer consumed about five
CPU cores during the compiler lanes.
At this historical checkpoint the native anchor-provenance experiment failed
four smoke tests. Later repairs above resolve those diagnostic failures; the
hook remains undeployed. See [execution-width evidence](reference/p0-stack-execution-width.md).

Newest frame repair: captured SP expressions were treated as current register
reads, double-counting updates and falsely proving ENTER's BP delta as -4.
Captured values now use the existing SSA affine trace. Three new binary tests
fail before repair; 80 frame/address/smoke tests pass afterward, with scoped
Ruff/MyPy/Pyright clean. Fresh byteops still retains EBP. `quality-fast` passes
3,090 tests (138.88s), configured checks and executable guards. The default
pipeline still fails: 3,090 unit tests pass (122.30s), QuickC passes, MSC6 remains
5/7 with the same undefined EBP and unresolved ESP/EBP rebuild failures.
This is not a full-suite pass or completion of P0.
See [captured-SP evidence](reference/p0-captured-stack-frame.md).

Current rejected candidate: unconditional entry-SP anchor conversion improved
`byteops_unsigned`, but `quality-fast` found four stack-annotation/ENTER failures
(3,081 passed, 134.17s). All four pass with the previous resolver behavior in a
controlled diagnostic run. The conversion has been withdrawn: a proven frame
delta alone does not prove an unbound variable's coordinate domain. Preserve
explicit coordinate bindings; establish durable native-anchor provenance before
retrying. The byte example and MSC6 lane remain open. See
[entry-SP consumer evidence](reference/p0-entry-sp-anchor.md).

Verified after withdrawal: `quality-fast` exits 0 with 3,087 tests passing
(133.22s), configured checks and executable guards. Default pipeline exits 2:
3,087 unit tests pass (116.97s), QuickC passes, MSC6 remains 5/7. The two failures
are the existing undefined EBP / unresolved ESP+EBP rebuild failures, not the
four withdrawn-candidate regressions. A scoped `pytest_deduplicate` audit also
ran successfully (7 passed); its one 4ms coverage-overlap pair is retained
because different coordinate values are not redundant assertions.

Newest candidate: direct stack-update AST lookup now uses the active coordinate
registry instead of a snapshot variable's older codegen context. Four failing
context regressions now pass; the focused group passes 110 tests and scoped
Ruff/MyPy/Pyright pass. Broad gates are pending for this revision. This is not
the cause of the MSC6 byte example's retained BP assignment: fresh C remains
byte-identical. The next lead is logical word access versus byte-local projection
at the native AIL boundary. See [context and frame evidence](reference/p0-stack-coordinate-context.md).

Current follow-up: required byte casts lost their typed signedness because the
native unnamed `SimTypeChar` representation is plain `char`. Lowering's required
cast renderer now emits explicit signed/unsigned char from its existing type
contract. Exhaustive compiled conversions reproduce two failures before repair;
25 focused tests pass afterward. Fresh `byteops_unsigned` tail validation passes,
but its fixed-input result passed before too, so it is not the regression oracle.
`quality-fast` passes 3,069 tests (137.24s), static checks and three executable
guards. Default pipeline passes 3,069 unit tests (123.04s), QuickC and five of
seven MSC6 constructs; the same declaration/link failures remain in the other
two. See [byte-cast evidence](reference/p0-byte-cast-contract.md).

Latest bounded follow-up: operand-32 near/far RET immediate cleanup now updates
SP without clearing upper ESP. Four new execution failures were reproduced
before repair; the focused helper/80386/call-return group now passes 237 tests.
Scoped Ruff/MyPy/Pyright pass. The newest `quality-fast` passes 3,058 tests
(160.50s) and three executable guards. The default pipeline passes its 3,058
unit tests (127.37s) and QuickC lane, but still fails the same two MSC6 constructs
below. The register-cleanup repair is focused-test verified; P0 and broad
semantic acceptance remain open. See the linked evidence for logs and timings.

Latest repair: typed return-segment ownership before SSA now fixes the
PUSH CS / near-CALL / RETF numeric-SP mismatch. Extended tests also found and
repaired full-ESP clobbering in dword PUSH/POP and a cancelling LEAVE defect;
implicit stack updates use SP while operand size still controls transfer width.
Byte-safe memory access methods are preserved. **65 focused tests pass**
(17.27s), including ten binary-versus-compiled-C cases with call counts and
upper-ESP checks. Scoped Ruff/MyPy/Pyright pass. Broad acceptance is pending;
unknown prefixes, explicit callee cleanup and unsupported return-frame widths
remain typed refusals. See [repair and evidence](reference/p0-call-return-stack-effects.md).
The subsequent broad gate exposed eight prefixed-RET return regressions
(3,034 passed, 8 failed): native ABI inference counted the extra return-address
bytes as argument cleanup and skipped return-register capture. Decoded return
frames now separate operand width from explicit cleanup; 89 return/smoke tests
and 17 cleanup/prefix contract tests pass. The rerun of `quality-fast` passes:
3,050 unit tests (129.97s), configured linters/types and three executable guards.
The default pipeline still fails: its unit lane passes 3,050 tests (112.67s),
QuickC passes, but two of seven MSC6 tiny constructs fail rebuilding generated C.
`scalar_types_io` loses the standalone EBP declaration during DOS assembly;
`function_pointers` retains ESP/EBP references without runtime definitions.
Stack-local provenance and unsigned-byte expressions also require investigation;
adding register definitions alone is not semantic acceptance. See the
[default-pipeline diagnosis](reference/p0-call-return-stack-effects.md#default-pipeline-checkpoint-2026-09-09).

Previous candidate and failing-gate evidence:

Latest uncommitted CALL-frame candidate: the pre-SSA consumer repairs the
minimal numeric SP return for near and direct far calls. The saved focused
InitMenu, RunMenu ESC and InitBars executable tests all pass (3 passed, 62.83s).
An expanded binary-versus-compiled-C regression exposes the remaining PUSH CS /
near-CALL / RETF mismatch: 0x7ffc instead of 0x7ffe. This is a semantic blocker,
not cosmetic ESP clutter; 2 variants pass and 1 fails. Establish typed
return-segment ownership and callee return behavior before extending consumption.
Do not infer stack-address width from operand width. Details and next acceptance
cases: [CALL-frame evidence](reference/p0-call-return-stack-effects.md).
After repairing ownership wiring, quality-fast reaches pytest: **3,011 passed,
1 failed**, 8 warnings, 104.27s. The sole failure is the new PUSH CS / near-CALL
numeric-SP case. Configured pre-test checks pass; Make exits 2. The executable
regression remains in the routine pipeline and fast ownership selects the
tool-independent adapter tests. This is not a full-suite or green-gate result.

Earlier candidate evidence (superseded where explicitly updated above):

Uncommitted candidate: numeric stack-use preservation plus read/write-aware
stack lowering. Exact byte-write projections now make the InitBars executable
regression pass. A focused sidecar-disabled InitMenu run exits 0 with
validation=passed and clean whole-tail validation in 41.85s. RunMenu still fails
its no-raw-ESP assertion; raw frame-state lifetime and restoration remain open,
including in InitMenu. Ten byte-write tests pass, including six GCC execution
cases for signed/unsigned words. The latest fast gate reports 2,992 passed and one
failed (RunMenu), 135.57s; Make exits 2. This is not full function acceptance or a
green broader gate. Do not treat the verified
committed checkpoint below as evidence that this working-tree candidate passes.
The existing isolated InitMenu call-preservation/compilation regression also
passes (41.98s); whole-binary acceptance and frame-state proof remain open.
The runtime call-frame consumer now refuses deletion when SP/ESP has external
observers, closing six demonstrated unsafe-deletion cases (15 focused tests
pass). This safety prerequisite does not remove RunMenu's retained stack state.
Next: trace surviving frame-state definitions and their call/restoration
consumers, without turning numeric stack offsets into host pointers.
The next defect now has a machine-versus-compiled-C regression: a returning
near call leaks two frame bytes into numeric SP (0x7ffc versus 0x7ffe).
It initially failed and is admitted to the routine lane. Repair call-return
effect projection before SSA/folding, not the lifter or late text cleanup;
see [evidence, repair order and acceptance](reference/p0-call-return-stack-effects.md).
A tracker-checked use-closure prototype was tested and removed: RunMenu C was
byte-identical, and its executable regression still failed. Before retrying,
locate the exact missing/unused frame fact in the actual worker; see the
[experiment and failure criteria](reference/p0-stack-flow-experiment.md).
The frontend now enforces its width-refusal verdict by removing an unproven
16-to-32-bit stack replacement. Both integrated failure cases are covered;
36 stack-compatibility tests and scoped Ruff/MyPy/Pyright pass. The broader gate
counts above precede this additional width fix and are not a fresh full-suite run.
Details and failed experiments: [candidate ledger](reference/p0-return-value-capture.md).

Latest scalar-return repair: [return-time value capture](reference/p0-return-value-capture.md).
Verified checkpoint: the default executable run accepts 19/20 (191.08s, exit 2),
with generated C byte-identical to `c7fe4e0c0`. InitMenu remains rejected.
An intermediate 18/20 regression exposed stale AX producer evidence crossing a
call; refusing that evidence restores DrawBar without weakening validation.
Thirteen return-maker unit cases and the focused DrawBar executable regression
pass, along with scoped Ruff/MyPy/Pyright. See the report for failed experiments
and remaining call-shape/lifetime audit boundaries.
The frontend ReturnMaker hook now captures the actual scalar return register
instead of moving an earlier producer expression past BP restoration, partial
register writes or memory changes. The focused regressions are now
in the routine pipeline. This repairs the numeric-frame diagnostic's stale
return; the experimental propagation filter and full frame ABI remain open.
Hard/dev/fast/default gates pass: 2,936 tests in each unit lane, three executable
quality guards and seven MS C tiny round trips. The report also records an open
width-aware lowering requirement: simplify proven 16-bit-only register uses
without discarding wraparound or mixed-width/call-boundary state.

Latest InitMenu prerequisite: [live frame-carrier preservation](reference/p0-frame-carrier-liveness.md).
An exact removal observer found that canonical-frame pruning deleted the SP
definition while retaining an external numeric use. Lowering now refuses the
whole group when scalar values escape it. Six regressions fail before and pass
after; 69 focused tests and scoped Ruff/MyPy/Pyright pass. The numeric-use
diagnostic now retains the missing decrement, but frame restoration and InitMenu
acceptance remain open. No experimental propagation hook is installed.
Final hard/fast/default gates pass: 2,923 tests per unit lane, three executable
quality guards and seven MS C tiny cases. The first broad run exposed three
stack-storage-versus-scalar classification regressions; those are resolved and
recorded in the report, not suppressed.
The complete default executable rerun confirms 19/20 accepted in 200.03s,
exit 2, with byte-identical generated C versus the preceding checkpoint.
InitMenu remains open; return construction is the next verified lifetime boundary.

New explicit P0 acceptance case: the user's default
`./decompile.py ./SORTDEMO.EXE` run reports 20 shown, 17 decompiled and three
fallback/detail results in `SORTDEMO_.dec`. Reproduce the same invocation with
separate stdout/stderr, identify each rejected function by address and typed
verdict, and repair the responsible decompiler owners. Reason: a passing tiny
pipeline must not conceal failures in the user's complete executable. DoD:
all 20 selected non-library functions produce accepted, recompilable C with
passing validation and preserved calls/effects, and the three failure cases
have durable regressions. Failure: relabeling rejected output as success,
skipping functions, increasing timeouts without evidence, weakening validation,
or using source/sidecar text as replacement semantics. This task is open.
The default command is now reproduced: exit 2, 17/20 accepted, 280.28s wall
(658.86s user CPU, 10.21s system CPU). Exact rejected functions:
PercolateDown `0x10a88` and QuickSort `0x10ce0` have branch-predicate semantic
cast mismatches; InitMenu `0x10060` fails GCC on a pointer used as a numeric
frame offset. Retry slices can add uninitialized-local or helper-prototype
errors, so they are not equivalent diagnoses of the original failure.
Evidence: `/tmp/inertia-sortdemo-default-repro.{c,log}`. The user's output is
preserved. Function names here are diagnostic labels, not recovery rules.

The default executable has now been rerun: **19/20 accepted**, exit 2,
198.47s wall. PercolateDown and QuickSort pass; only InitMenu remains rejected.
Additive fingerprints retain semantic casts (schema 39). The final predicate
validator additionally proves identity casts against exact current declarations,
without rewriting C or changing historical fingerprints. QuickSort's retained
unsigned source view had outlived refinement of its signed local declaration.
The live QuickSort regression and 32 focused validation tests pass; scoped
MyPy/Pyright and Ruff pass. Hard/fast/default gates pass: 2,888 tests in each
unit lane, three executable guards, QuickC and seven MS C tiny round trips.
This is not a new full-suite result. One timeout-in-weakref warning remains
an open investigation; it was not suppressed. See the
[condition-view report](reference/p0-sortdemo-condition-views.md) for the root
cause, refusal tests, rejected experiment, timing evidence, DoD and failure
contract. The next P0 blocker is InitMenu's numeric-frame C, not optimization.

InitMenu prerequisite repair: memory-SSA versioning now preserves exact address
register-read snapshots. The existing IR affine tracer optionally proves entry
SP/BP roots and frame analysis consumes it for indirect setup through registers.
The minimal numeric value is proven as entry SP minus four, with wraparound;
unknown roots and entry backedges refuse. Eighty-nine focused tests and scoped
Ruff/MyPy/Pyright pass. This is not InitMenu C acceptance or a new executable
improvement: a subsequent default-command rerun confirms **19/20**, exit 2,
205.04s wall (480.46s user, 9.32s system, 355,788 KiB peak process RSS).
PercolateDown and QuickSort still validate; InitMenu still fails portable-flat
GCC on numeric operations on a host pointer. See the
[provenance checkpoint and rejected value-context experiment](reference/p0-numeric-frame-reproducer.md#memory-ssa-and-entry-register-provenance-2026-09-09).
Hard/fast/default gates pass with 2,910 tests in each unit lane, three executable
quality guards and all seven MS C tiny cases. Existing complexity warnings and
the broader full-suite/CI debt are not closed by this checkpoint.

Optimized stack helpers now capture symbolic implicit accesses with exact
instruction-entry SP/BP coordinates. The full frontend also preserves 16-bit
stack wrapping under 67h address-size prefixes, including dword operations and
nested ENTER. The minimal frame has four complete logical accesses instead of
one, proving its BP word spill/reload through the existing transfer owner.
Numeric generated C remains unchanged and invalid: next consume the paired
frame evidence through Alias and preserve numeric entry-SP definitions across
SSA Reference projection. Do not retry the rejected origin filter unchanged.
See the [implicit-stack report](reference/p0-implicit-stack-evidence.md) and
[preceding frame-register report](reference/p0-frame-runtime-register-view.md).
IR address decomposition now also retains the exact original register-read
temporary. PUSH stores use the pre-decrement SP version instead of applying
their displacement to an already decremented register. Four before/after
regressions cover PUSH BP, PUSH SP, repeated PUSH and nested ENTER. This is
address provenance, not yet function-wide Alias storage proof. See the
[address-snapshot report](reference/p0-address-base-snapshots.md).
Hard/fast/default gates pass after snapshot and audit regression admission: 2,865 unit tests,
three executable quality guards, QuickC and all seven MS C tiny round trips.
Scoped MyPy/Pyright and global Make MyPy/Ruff pass. This closes register-view
coherence and frontend stack evidence/execution, not numeric-frame C,
complete-suite or remote-CI acceptance.

The latest frozen-source full audit reports **10,794 passed, 37 failed,
170 skipped, 102 warnings in 792.10s**. Ten preceding failures disappeared;
two new failures were the relocated-document policy check and an exact indexed
address trace missing its newly preserved register-read snapshot. Both reproduced
and are corrected with stronger link/provenance assertions; 66 focused tests pass.
Their modules are now admitted to routine gates, which pass: 2,865 fast/default
unit tests, three executable guards, QuickC, and all seven MS C tiny round trips.
This does not establish a new full-suite count or close the remaining failures.

The preceding full frozen-source refresh reported **10,773 passed, 45 failed, 170 skipped,
88 warnings in 756.14s**. Compared with the preceding 48-failure audit, 14 cases
no longer fail and 11 newly fail; this is not a clean regression gate. Seven
new failures were stale logical-memory/RET expectations or inconsistent
fault-injection ledgers; their corrected modules pass all 21 tests. The four
remaining cases pass on unchanged HEAD and on the patched checkout with fresh
cache identities. Existing cached DOSFUNC output retained an EAX merge absent
from fresh output, but both bodies pass 131,072 compiled call/result cases.
The two semicolon-specific assertions have been replaced by that stronger
behavioral oracle; both tests now pass against existing caches. Nine positive
and adversarial oracle tests pass and are admitted to routine gates. Producer
context and generated-text determinism remain open; do not infer a new full-suite
total from focused reruns. See the [DOSFUNC oracle report](reference/p0-dosfunc-behavior-oracle.md).

The last complete production Pyright snapshot reports **176 errors and 37
warnings: 148 X86_16 errors, 28 CLI errors**. The scoped results above do not
refresh that whole-production audit. The preceding VEX-wrapper checkpoint
removed five diagnostics while retaining native widths and DF behavior, with
273 focused frontend/80386 tests passing. Its separate Vulture check passed;
the broader production Pyright audit remains red as stated above.
Numeric-frame semantics, the full pytest suite and remote CI remain open;
the latest verified remote run `34321600834` on `be7f019da` reports 5,063
passed and 42 failed in 537.23s, with 24 Pyright errors in its first failing
batch. Missing kvikdos and semantic generated-C failures remain distinct.
The broad optimization campaign stays deferred, with measured bottleneck fixes
allowed as described below. See the [VEX wrapper report](reference/p0-vex-wrapper-contracts.md).

The next numeric-frame boundary is now verified live: angr SSA rewriting
converts `StackBaseOffset` into a stack-variable `Reference` before C codegen.
The C StackBaseOffset handler is not reached by the minimal reproducer.
Both numeric store bytes retain the LEA source tag, allowing an exact link to
owned SSA; a host-pointer cast cannot restore guest entry SP. Preserve the
numeric entry-state definition alongside the Alias object view, then repair
save/restore coherently. See the [boundary evidence and repair requirements](reference/p0-numeric-frame-reproducer.md#live-ssa-to-object-boundary-2026-09-09).
This investigation does not close the production defect or any acceptance gate.

### Earlier Checkpoints (Historical)

The preceding Make global MyPy phase reached **0 diagnostics**, down from four; `mypy-dev`
also passes after preserving two typed provider imports in `pyproject.toml`.
`quality-fast`, `quality-dev` and `quality-hard` pass; the final hard unit lane
passes 2,736 tests. Global Vulture also passes.
Validation summaries now retain their canonical type through configuration
and transaction state. See the [validation contract report](reference/p0-validation-type-contracts.md).
Pyright's first two root-module batches now pass. The next batch reports
**29 errors**; later batches were not reached. Earlier counts of 31 and eight
were the first failing batch, not repository totals: `make pyright` stops on
failure. The completed `make pyright-all` audit reports **8,031 errors and
37 warnings: 153 X86_16, 28 CLI, 7,850 test errors**. Its configured scope does
not include auxiliary scripts. These are static diagnostics, not pytest
failures. Prioritize the 181 non-test errors; no diagnostics were suppressed.
See the [batch closure and complete audit report](reference/p0-pyright-batch-closure.md).
The bounded eight-error repair and stale final-callsite fixture are verified:
94 focused tests pass, and the default pipeline passes 2,736 unit tests,
QuickC and all seven MS C tiny round trips, with no skips or timeouts.
This adds 91 tests to the routine selection; numeric-frame semantics and
full-suite/CI closure remain open.
Checked native AIL field contracts closed the earlier 23-error subset. Fifty focused tests pass;
`quality-hard` and `quality-fast` pass with 2,645 tests and three executable
quality guards each. The default pipeline also passes: 2,645 unit tests,
QuickC and all seven MS C tiny round trips, no skips or timeouts. See the
[native AIL report](reference/p0-native-ail-contracts.md).
MyPy closure is not full typing, CI, or P0 closure.
Segmented reload replay now refuses missing boundary provenance without
crashing and still checks addressless intermediate-block effects. All 54
focused tests and scoped tools pass; see the
[reload provenance report](reference/p0-reload-provenance-boundaries.md).
Return witness materialization now refuses absent instruction addresses;
split returns consume validated Alias domains in physical output order.
All 85 focused tests, 118 gate-admission tests, and scoped tools pass. See the
[return witness report](reference/p0-return-witness-addresses.md).
Checked symbolic instruction values preserve the lifting-only contract and
refuse unsupported LOOP values before mutation. The instruction corpus passes
1,209 tests (one existing opt-in audit skipped); the edge run passes 182 tests.
See [the boundary report](reference/p0-symbolic-instruction-values.md).
The existing stack-projection compatibility export is now explicit; 98 JCC
tests, scoped tools, and the architecture guard pass without new exceptions.
The CLI now consumes its checked dynamic callee target once and keeps two
distinct replacement collection names; 29 boundary/helper tests, four
rendering tests, and 109 admission tests pass. The preceding tail-fingerprint
cast cleanup passed 408 validation tests. Scoped tools pass. See the
[type-contract report](reference/p0-type-contract-closure.md).

Remote checkpoint CI `34287484156` on `8f5bdd05a` completed: 4,846 selected
tests passed and 42 failed in 536.13s. Pyright reported 32 errors remotely,
versus 31 in the current local audit. Missing kvikdos remains; a private DOS toolchain provisioning
source has been requested; no tests or validation are disabled. See the
[CI report](reference/p0-github-ci.md) for scope and remaining failure groups.

Latest default pipeline: **2,630 unit tests passed in 147.30s**, plus
QuickC and all MS C tiny round trips; three lanes passed, none failed/skipped/
timed out. This follows rejection and reversal of the standalone entry-BP
origin filter described below. Existing stack-compatibility tests are now in
the routine lane, alongside the new interrupt-call boundary regression. These
results do not close full typing, the full
suite, CI, or the numeric-frame defect.

The [tail-transfer origin repair](reference/p0-tail-transfer-origin.md) fixes
generic CFG entries suppressing proven tail evidence. Near/far/stored tail
kind and absent return address now survive duplicate merging; 79 focused
tests pass. All default lanes pass (2,507 unit tests in 130.63s, four QuickC,
seven MS C tiny round trips). Routine gate admission was separately verified
with 68 tests. Global MyPy remains at 29 diagnostics; full-suite/CI and InitMenu
remain open.

The refreshed [InitMenu numeric-frame investigation](reference/p0-initmenu-nested-call-boundary.md)
still finds stable tail stages but failed GCC and no accepted hashes. BP/SP
runtime lanes already exist; the unresolved task is preserving the proven
numeric frame definition separately from the host object view. The attempted
stderr observer was hidden by direct-worker output capture. A file-backed
observer now confirms that frame pruning receives an already pointer-valued
BP definition and removes it. The rejected C is byte-identical with observation.
The next fix point is upstream numeric provenance, not merely retaining or
casting that host pointer. No speculative pruning change was made.
The [16-byte numeric-frame reproducer](reference/p0-numeric-frame-reproducer.md)
now isolates the scalar LEA-store defect without calls. Its executable oracle
covers ordinary and wrapped SP, distinct SS/DS, and BP/SP restoration; 12
focused tests pass. The added SSA regression now evaluates the exact numeric
definition path at all three entry-SP values; 22 related tests pass in 8.84s.
Owned IR arithmetic is correct. The upstream SP/BP-to-StackBaseOffset
replacement is now confirmed live. An entry-BP origin filter was tried and
reverted: despite 35 focused passes it broke MS C tiny `add_sc` tail validation.
Reverting restored `add_sc` to validation passed with a clean whole tail.
Do not repeat that filter without coherent downstream frame handling. Existing
stack compatibility tests are now admitted to the default pipeline.
Global MyPy remains at 29 diagnostics.
The scalar LEA store is still pointer-valued, so generated-C repair stays open.

The [historical failure replay](reference/p0-failure-replay-20260908.md) ran
47 surviving old failure nodes: **44 failed, 3 passed in 315.27s**. Architecture,
MSC6 signed-long comparison, and sidecar-free InitBars now pass. Three obsolete
CLI stream assertions were separately corrected and pass; all selected InitMenu
tests still fail. This is not a refreshed full-suite census or an overall
completion percentage. The same report now records the two runtime switch
fixture repairs: both bridges require actual SSA selector proof, with positive
and missing/mismatched-evidence regressions; 50 focused tests pass. Production
semantics are unchanged, and global MyPy remains at 29 diagnostics.
Four BP-based DOS-call fixture expectations now preserve explicit SS and load
width instead of requiring obsolete assembly placeholders; the sample module
reports eight passed and 15 missing-optional-fixture skips. See the replay
report for scope and skip reasons; this is not whole-function acceptance.

The [split-return type-contract closure](reference/p0-type-contract-closure.md)
removes 19 repeated optional-coordinate diagnostics without changing CFG proof.
The same report records frontend-boundary contract closure with 25 tests passing.
Latest `quality-fast`: still red, **29 MyPy diagnostics**. The
[wide-return proof contract](reference/p0-wide-return-proof-contract.md) now
accepts immutable evidence through read-only properties; 11 focused tests and
scoped tools pass without changing folding semantics. Call-condition
indexing keeps optional lookup types separate, and bridge removal requires a
stack destination; 25 focused tests and scoped tools pass. IR width/effect
consumers now use their owners' return types without redundant casts; 45 focused
tests and scoped tools pass. Unobserved call-result
view contracts now retain explicit width proof; all 14 focused tests pass,
including unknown-view assignment preservation. Binary loop-update
RHS values now use a shared Structuring-owned composer instead of crashing in
the scalar API. Unknown RHS refuses before carrier mutation; 43 focused tests,
full architecture checks and scoped tools pass. The control-register
read contract now describes concrete and VEX values consistently; the write
adapter retains exact 32-bit casts with checked raw expressions. 1,084 focused
frontend tests pass, one existing exhaustive-corpus case is skipped. Condition-view
validation now refuses missing/untyped operands instead of crashing; 40 focused
tests and all three default pipeline lanes pass. The logical-word
write tracer now short-circuits malformed address operands into typed refusal
instead of crashing; both failing-before lane regressions pass. Call-output metadata
and the caller-use enum compatibility export close six diagnostics; 29 focused
tests and scoped Ruff/MyPy/Pyright pass. Stack-memory SSA
projection closes ten typing diagnostics without changing Alias proof; 31
focused Alias/Lowering tests pass, including every overlap/phi refusal position.
Control-stack escape
lowering now uses the existing native/Python tag adapter; five focused tests
and scoped Ruff/MyPy/Pyright pass. Refreshed default pipeline: **2,507 unit
tests passed in 142.40s**, four QuickC fixtures validated, all seven MS C tiny
round trips passed; no failed/skipped/timed-out lanes. The unit lane still
exceeds its advisory budget. This is not a new full-suite census. The unused, unsafe
postprocess condition-strengthening prototype is retired with coherent inventories.
Carry/borrow placement
contracts and replay pass twelve focused tests. The INC/DEC test
contract is reconciled with the established live-flag execution repair; 56
context/execution tests pass, including signed-overflow and carry boundaries.

The [condition-capture repair](reference/p0-condition-capture-refusals.md) preserves
typed recovery refusals through both fast capture and exact-byte relifting.
Updated default unit lane: 2,456 passed in 124.36s; all seven MS C tiny round
trips passed at that checkpoint. The global diagnostic count above supersedes
the historical 92 recorded with that repair.

The [live aggregate replay repair](reference/p0-live-aggregate-replay.md) restores
the exact tracked buffer after coordinate loss, avoiding a second allocation.
All seven InitMenu setup arguments now resolve to registered storage. Four
still fail the bounded machine proof at nested calls; InitMenu remains unaccepted.
The [nested-call investigation](reference/p0-initmenu-nested-call-boundary.md)
finds an indirect call on a conditional path before AX overwrite. Nested-call
traversal alone cannot close this proof. Resolve target/effect evidence or
repair the retained numeric stack-address representation; do not broaden deletion.
The same report records the preceding target/site contract checks: 94 MyPy
diagnostics at that checkpoint; compiled imports passed 39 modules.

The [InitMenu address-projection repair](reference/p0-initmenu-address-projection.md)
prevents Widening from replacing address-of objects with masked value reads.
Three InitMenu setup carriers are proven and removed. Its initial missing
array-identity blocker is superseded by the replay repair above; InitMenu is
still unaccepted at the nested-call evidence boundary.

The [consumed stack-setup repair](reference/p0-consumed-stack-setup.md) closes
the sidecar-free InitBars LEA compilation blocker through generic machine
liveness proof and a Lowering consumer. The normal worker is accepted with
stable whole-tail checks and matching validation/GCC hashes. The named-output
regression, InitMenu, global typing and full-suite/CI closure remain open.

The [validation-site checkpoint](reference/p0-validation-site-contracts.md)
replaces missing-address reload-proof crashes with explicit refusal and closes
scoped IR/Validation typing gaps. Known-site proofs and call-clobber tests pass.

The [worker-evidence codec checkpoint](reference/p0-worker-evidence-codec-types.md)
adds checked schema/enum inputs and closes scoped transport typing diagnostics.
Its focused tests pass; global gate results are tracked separately in the report.

The [register-argument provenance investigation](reference/p0-register-argument-provenance.md)
documents why early GP publication preceded call recovery and later PUSH
cleanup missed the InitBars LEA producer. Its formerly open producer-removal
work is superseded by the proof-backed repair above, not a pointer cast or
classifier-only change. Other InitBars quality requirements and InitMenu remain open.

The [recovered-payload proof repair](reference/p0-recovery-payload-proofs.md)
fixes the CMP32 signed-long acceptance failure: both direct recovery branches
now transport hashes together with their newly accepted C. The focused corpus
and integrity tests pass; no validation gate was relaxed.

The [September 8 full-suite refresh](reference/p0-full-suite-20260908.md)
reports **10,351 passed, 48 failed, 170 skipped in 753.15s**. This supersedes
the older census below. InitMenu is not currently accepted: sidecar-free cases
fail pointer/register compilation and its named case fails whole-tail checks.
Follow the refreshed ordered failure batches; do not infer completion from
historical focused passes.

The [partial-register live-in repair](reference/p0-partial-register-live-ins.md)
moves bit-aware must-reaching analysis into IR: AL/SI writes no longer hide
untouched AH/ESI bits. Focused tests and the default MS C pipeline pass;
InitBars numeric LEA projection and global typing remain open.

The [compatibility-hook checkpoint](reference/p0-compatibility-hook-contracts.md)
closes the local Vulture findings and scoped hook typing errors with 25 focused
tests passing. Full-suite, global typing and remote CI closure remain open.

Scheduling decision (updated 2026-09-09): correctness and quality closure remain
first. The user permits measured performance improvements in either production
code or tests whenever they materially remove a development or execution
bottleneck. Do not wait for all correctness steps to close to address such a
bottleneck. Keep the broad Step 10 campaign secondary, preserve accepted work
and rejected experiments, and measure the current implementation before adding
machinery. Coverage, diagnostics, types and semantic acceptance cannot be traded
for speed. Fixing DCE that deletes live code remains correctness work.

Execution and delegation policy: follow the mandatory
[agent execution rules](reference/agent-execution.md).
Use bounded agents on demand only when their benefit justifies the token cost.

The [accepted-payload contract repair](reference/p0-accepted-payload-contract.md)
makes the verifier consume read-only result fields, matching the frozen worker
result. Eight acceptance tests and scoped Ruff/MyPy/Pyright pass; `cli_core.py`
passes scoped MyPy. No global typing or remote CI closure is claimed.

The [gate-inventory checkpoint](reference/p0-gate-inventory-coherence.md)
closes the four audit failures in Make inventory, ownership expectations, and
quality-module admission under focused tests. The 2,065-test quality-dev and
quality-hard gates pass, including full architecture and executable guards;
non-incremental global MyPy still reports 146 errors. The full census below
has not been rerun. The [RunMenu flag-summary checkpoint](reference/p0-runmenu-callee-flags.md)
removes falsely live stack-adjustment flags. The subsequent
[switch-selector checkpoint](reference/p0-runmenu-switch-selector.md) preserves
the dispatch SSA value and folded call across repeated structuring. Its live
sidecar-free validation and recompilation pass. Final quality-hard passes
2,114 tests and all three executable guards; the default pipeline passes all
three lanes, including seven MS C tiny round trips. The unit lane remains over
its time budget. A generic unreachable-selector-call validation shield remains
open in the checkpoint report; this repair does not close the full audit.

The [InitMenu local-read repair](reference/p0-initmenu-local-reads.md) preserves
its zero initializer by consuming the shared AST child inventory during
dead-local read collection. Its follow-up fixes buffer coordinate rebinding
and high-word guard loss through SSA-proven shared-exit normalization in
Structuring. Named and sidecar-free regressions now pass, including strict
recompilation and executable high-word behavior. The default pipeline passes
2179 unit tests and all three lanes, including seven MS C tiny round trips.
Global quality-fast still fails on 129 MyPy diagnostic lines; this is not full
goal closure or deferred performance work. [Remote CI closure](reference/p0-github-ci.md)
is also required: local focused passes do not replace a green pushed CI run.

The [InitBars replay investigation](reference/p0-initbars-call-replay.md) now
isolates its duplicate to cached return-call replay after a masked producer
assignment is missed by standalone-call matching. Proven runtime-register
result reads now address that case: the live InitBars
duplicate-call diagnostic is gone, while storage/initialization validation
still fails. Its early uninitialized local read is traced to a later register reload
being inserted at the first same-register use. Exact instruction-origin
placement in Lowering removes that failure. Call-output object projection now
corrects a proven two-byte configuration-field coordinate mismatch, with 36
focused tests and scoped Ruff/MyPy/Pyright passing. Live InitBars still fails
on two array reads and a forbidden flattened-segment expression. Next trace
the array's typed reads/writes; do not infer initialization from object layout.
Follow-up tracing identifies generated read helpers incorrectly invalidating
the existing initialized-prefix proof. Tagged helper-effect consumption fixes
that loss (26 focused tests pass); sidecar-free whole-tail validation is now
clean, but the final payload still fails the forbidden `ss << 4` contract.
Next fix indexed stack-address materialization in Lowering, not rendered text.
The subsequent frame-coordinate repair consumes the proven SS/BP-zero anchor
instead of duplicating it beside a C local pointer; a regression also prevents
DS-to-stack conversion. Live whole-tail remains clean and the forbidden SS
flattening is gone, but unresolved byte carriers still prevent final C
acceptance. Next bind indexed carriers to the canonical aggregate object.
The [aggregate binding follow-up](reference/p0-initbars-aggregate-bind.md)
now reconciles proven AST aliases and requires addressable pointer bases.
A compiled regression exposed and fixes hidden casts changing byte stride.
The latest declaration-cache repair keeps the configuration struct in the
rendered C: scoped Lowering publication updates exact declaration entries
without globally rebuilding other objects. Its 32 focused tests and scoped
Ruff/MyPy/Pyright pass. Live whole-tail remains clean; strict GCC now reports
the remaining pointer-to-register conversion error. InitBars is not accepted;
whole-tail alone is insufficient. See the same report for the rejected global
refresh experiment and current gate evidence.
The [LEA/register boundary investigation](reference/p0-initbars-lea-register.md)
traces the remaining expression to binary `LEA AX,[BP-0x70]`: GP Lowering
receives a casted host stack reference, not a proven numeric machine offset.
Repair the typed address/register projection or prove setup liveness before
removal; forcing a C cast is not sufficient. No production fix is claimed yet.
The latest default pipeline passes 2,241 tests and all seven MS C tiny round
trips. Global quality-fast still fails with 121 MyPy diagnostic lines; startup
architecture and scoped Ruff/MyPy/Pyright pass. This is not full-suite or CI
closure.
Frame-repair gates pass 2,231 default unit tests, all seven MS C round trips,
and quality-dev including its three executable guards. Global quality-fast
still reports 121 MyPy errors. This does not close InitBars, the full audit,
or remote CI.
Fresh helper-effect gates: `quality-dev` passes 2,228 tests and all executable
guards; the default pipeline passes 2,228 tests and seven MS C round trips.
Global `quality-fast` remains red with 121 MyPy errors.
A separate replay branch crash is repaired with 181 focused tests passing;
this is not InitBars acceptance or P0 closure.
Prior local gates after runtime result-read binding: `quality-dev` passes
2,196 unit tests and its executable guards; default `test-pipeline` passes
2,196 unit tests and all seven MS C tiny round trips. Global MyPy remains red
with 125 diagnostic lines. After coordinate publication, the fresh default
pipeline passes 2,202 unit tests and seven MS C round trips; global
`quality-fast` still fails with 121 MyPy errors. Full-suite and remote CI
closure remain open.

The [source-stable full audit](reference/p0-full-suite-20260907.md) reports
**10,166 passed, 49 failed, 170 skipped out of 10,385 in 901.38s**. Current
InitBars and other control-flow validation failures mean
the earlier SORTD acceptance below is historical, not a current green claim.
Follow that report's ordered batches, DoD, and failure conditions for the next
P0 work. Global MyPy remains red; see the latest checkpoint above. The weighted 75% and
80-115h figures are historical estimates, not a revalidated forecast.

Current sidecar-free command:

```text
PYTHONHASHSEED=0 PYTHON_JIT=1 ./decompile.py SORTD.EXE \
  --ignore-local-sidecar-hints --no-alternate-source-c -q
```

Earlier accepted output (must be revalidated after the current regressions):

- discovery and execution attempt all 20 non-library functions
- the strict executable-only gate emits validated C for all 20 functions with
  zero discovery failures, empty bodies, fallbacks, timeouts, or tracebacks
- generated C contains no unsupported/unknown-instruction marker and no packed
  parity, overflow, `eflags`, or `cc_op` equation
- a fresh unquiet executable-only run on 2026-08-28 completed in about 202
  seconds, used seven function workers at roughly 1.9 GB aggregate RSS, and
  reported 20/20 decompiled with whole-tail validation clean
- the untouched 723-line portable-flat translation unit passes
  `gcc -std=c11 -fsyntax-only` with no diagnostics; all Swaps callsites render
  typed `g_0B4C[...]` pointers rather than raw assembly or unsupported markers
- `sub_109e8`, DrawFrame `0x101f0`, DrawBar `0x106c8`, DrawTime `0x10498`,
  SwapBars `0x10768`, QuickSort `0x10ce0`, Beep `0x10e70`, and Sleep `0x10f38`
  pass their exact executable-only gates
- DrawBar `0x106c8` now consumes the typed machine-BP address source when
  replaying call arguments, rather than retaining a higher-scoring stale
  scalar-byte expression at the colliding entry-SP coordinate; its whole-tail
  validation passes. The same fix removes DrawFrame `0x101f0`'s call-argument
  mismatches
- DrawFrame's regenerated `mov bp, sp` GP-state carrier is consumed in
  Types/Lowering only when its owned BP write and the decoded canonical entry
  pair agree. This removes the false `inertia_ebp = ... &local_2` statement and
  the `uninitialized-read:stack-local:SS:BP-0x2:size2` failure; all source-
  required calls and loop semantics survive, whole-tail validation passes, and
  the generated function passes strict C11 syntax
- Sleep `0x10f38` passes live Tail Validation and its permanent executable-only
  gate with exactly two binary-proven clock calls, correct loop-exit ownership,
  and the exact four-byte positive-BP parameter materialized by Types/Lowering
- InitMenu `0x10060` now derives its pause guard from the exact block-local
  dword `OR` inputs, preserves both calls in the zero branch, and passes whole-
  tail validation without an unsupported condition or raw flag carrier
- InitMenu's sidecar-assisted output also drops only typed, proven-unobserved
  physical AX/EAX call-result assignments in Types/Lowering; assigned fixed
  stack probes remain owned by the existing typed frame lowering. Both the
  sidecar-free and sidecar-assisted outputs pass strict portable-C compilation
- ReInitBars `0x10678` is ratified with exactly one clock call at binary
  callsite `0x10683`; Lowering recognizes the third-party AIL tag protocol and
  removes only the duplicate carrier statement for that exact callsite
- BubbleSort `0x108d0` is ratified after Types/Lowering retained the adjacent
  unchanged global-to-stack copy
- Beep `0x10e70` is ratified after Types/Lowering
  unified machine-BP call-return storage with the projected entry-SP local;
  the existing `inp(0x61)` call and its argument are preserved unchanged, both
  control guards are correct
- byte-executed slices of typed word stack accesses retain their Alias-owned
  word identity; this closes DrawTime and QuickSort without changing the
  frontend's independently resolved byte execution contract
- caller-observed byte-return signedness is aggregated only after a complete
  Frontend callsite census. Types/Lowering now projects the proven AL return
  class into the callee prototype and final C rendering; incomplete evidence
  and prototype conflicts remain typed refusals
- the `scalar_types_io` gate retains the high-bit case
  `mix_uc(64, 0) == 128`, so a wrongly signed byte return cannot pass through
  integer promotion unnoticed. Its fresh 2026-09-01 run is green: all ten
  selected functions decompile, the translation unit recompiles, and the
  rebuilt executable exits `255`
- the last clean exact repository baseline is 10,137 collected, 9,944 passed,
  23 failed, and 170 skipped in 852.88 seconds with seven pytest workers. A
  2026-09-06 diagnostic audit collected 10,144 tests and reported 9,950 passed,
  24 failed, and 170 skipped in 1,099.15 seconds, but source changed during the
  run and a separate profiler contended for CPU; use its failure inventory for
  triage only, not as a current acceptance or performance baseline. One listed
  Tail Validation failure was a stale entry-SP fixture: the corrected overlap
  test and the complete three-test entry-range module pass. A new clean full
  audit must establish the remaining exact count
- the full-binary to exact-function project boundary now transports validated,
  immutable callee pointer-argument evidence through the existing ABI seeding
  service. HeapSort therefore emits typed `Swaps` pointers, passes Tail
  Validation and strict C11 syntax, and retains the source-required call
  argument classes without semantic recovery in CLI or Rewrite
- Swaps now remains a single three-assignment object exchange after the final
  shared-call codegen regeneration. Lowering removes only the tagged raw
  temporary load already consumed by its unique exact pointer-swap proof;
  unrelated effects and untagged ambiguity remain preserved. Stack-probe
  return-frame cleanup also precedes helper removal, and Tail Validation maps
  exact-region argument slots onto machine-BP ABI coordinates. The live
  function keeps `iSwaps += 1`, emits one `barTmp = bar1[0]`, reports
  `validation=passed`, and passes strict generated-C syntax
- a current-tree stack-object regression inverted the containment predicate and
  selected storage smaller than the requested access. Restoring the owned
  invariant `storage_size >= access_width` preserves byte views of aggregates
  and arrays and keeps wide-return low halves distinct; all 236 segmented
  runtime lowering tests pass
- accepted results are cached and refused functions are revalidated
- ARGS no longer loses its caller-clean argument pushes when the callee returns
  with zero stack cleanup. Recovery Metadata retains all three binary pushes,
  Types/Lowering removes the stale contained `BP+5` byte view and materializes
  the `BP+6` pointer owner, and the generated function passes whole-tail
  validation plus strict recompilation. Three cached and uncached checks produce
  the same generated-C hash. All four Ultra QuickC fixtures pass their generated-
  C contracts and report `validation=passed`

The validation-clean loop/control-flow family is now closed. ReInitBars,
BubbleSort, ExchangeSort, and PercolateUp pass their live function regressions
with `validation=passed`; the four-test live lane passed in 47.44 seconds and
the changed structuring/Condition-IR surface passed 127 tests. Storage identity
remains in Condition IR, status-flag liveness remains in IR, and loop shape
remains in Structuring. CLI changes only preserve proven function names and
persist already accepted retry-lane C artifacts.

The accepted-payload CMP16 defect is closed. Widening copy propagation had
propagated `mask = 0` across conditional `mask |= bit` updates because it did
not invalidate inherited definitions at a branch join. Widening now refuses
that stale continuation state. Structuring return-chain integrity also consumes
the mask-accumulator return fingerprint, so a later pass cannot replace the
proven return before Tail Validation snapshots it. The regressions failed
before the fixes; real `rel_i16` returns `mask`, all six comparisons survive,
and the complete `compare16` compile/decompile/recompile/runtime gate exits
`255`.

A later current-tree CMP16 regression is also closed at Structuring. The final
`JNE` return edge was paired with an exact-tagged `call ? 0 : 1` AST condition;
the return-chain selector understood explicit zero comparisons but not this
equivalent truth-value projection, so it retained inverted polarity. The typed
selector now normalizes explicit zero tests, direct/negated calls, and boolean
call ITEs only when both expressions prove the same CFG branch. Three focused
selection regressions plus the 130-test return-chain surface pass. The real
`main` emits `if (in_window_i16(9, 1, 7)) return 13;`, reports
`validation=passed`, and the CMP16/LOOPS/FPTR optimization suite and complete
`quality-dev` gate pass.

The current focused unit lane passes **1,919 tests** under seven workers. A
fresh `quality-dev` passes direct Ruff `--fix`, MyPy over 266 files, the
39-module mypyc compile/import smoke, complexity, architecture, ownership, the
unit lane, and all three decompilation optimization comparisons. Promoted-file
coverage now includes the new Frontend, IR, Lowering, Structuring, validation,
and CLI modules rather than leaving them outside the real Ruff/MyPy gates.

The mandatory 2026-09-02 default and expanded pipelines are fully green. The
latest 1,919-test unit lane finished in about 65 seconds, and the required
SORTD generated-C, Ultra QuickC, and full MS C tiny lanes returned success. The MS C
lane covers `compare16`, `simple_control`, `loops_jumps`, `storage_classes`,
`function_pointers`, `pointer_memory`, and `scalar_types_io`; every selected
translation unit recompiles and its rebuilt executable exits `255`.

`simple_control/classify` is closed at Types/Lowering: the GP-state projection
preserves instruction provenance, and the final pre-validation orchestrator
replays the existing condition-argument type owner using projected machine-BP
coordinates. The generated signature is `unsigned short classify(short x)`;
the selected fallback validates, recompiles, and the rebuilt executable exits
`255`. Harness reporting now records rejected rebased attempts separately from
the selected validation result, so a clean accepted fallback reports zero final
failures without erasing its attempted-failure history.

`function_pointers/select_and_apply` is closed by authoritative stack identity,
not its stale placeholder name. Types/Lowering publishes verified stack-
prototype materialization even when the C AST was already physically correct;
Rewrite no longer aliases arguments by generated names. Tail Validation now
captures Structuring-materialized condition origin keys and stack coordinates
on both sides of Rewrite, rolls back drift, and records a hard failure. The
150-test changed surface, Ruff/MyPy/type ratchets, `quality-dev`, and the real
four-function gate pass; the emitted guard remains `if (which)` and the returned
call remains `apply_twice(fn, value)`.

A later full-pipeline replay exposed an independent Tail Validation crash in
that same function. Fingerprint simplification reconstructed a temporary
`CBinaryOp` and reran angr type inference over an archless signed word. Tail
Validation now clones the already typed template and substitutes only the
simplified children, preserving its result type, common type, codegen, and
tags. The regression fails on the old constructor path and passes on the typed
projection; the real function validates and returns `apply_twice(fn, value)`.

The Ultra QuickC `args` fixture is also closed at Types/Lowering. Stack-C
canonicalization preserves owned condition tags, exact writable scalar views
lose only equal-width signedness casts, near data pointers use explicit guest-
offset projections, and exact function pointers remain callable values. The
structural fixture contract recognizes equivalent segmented indexed loads from
the parsed C AST instead of demanding one rendered spelling. Tail Validation,
portable compilation, MS C compilation, and rebuilt execution all pass.

The DOS `_dos_loadProgram` wrapper is closed without Rewrite-owned semantic
repair. Types/Lowering recognizes a call result after its typed condition has
been projected from AX into the exact `SS:BP-2` store, and requires the explicit
AX-to-stack binding. Semantics classifies only epilogue instructions that
preserve AX/DX; Structuring follows a bounded jump-only path to the return,
resolves the active error object through the machine-BP coordinate registry,
and materializes `return err;` plus the proven zero continuation return. The
consumed argument PUSH byte carrier is pruned only with exact PUSH provenance.
Both CLI invocation shapes validate and recompile with direct `cs[0]`/`ss[0]`
stores. Focused Ruff/MyPy, `quality-dev` with 1,923 tests, and the mandatory
external pipeline pass.

A later exact-width replay regression in that wrapper is now closed at
Types/Lowering. One logical 16-bit IR write had reached structured C as two
byte-lane lvalues; lowering widened both independently, then interpreted byte
displacement `+1` as C word-pointer element `[1]`. Lowering now materializes the
same-instruction little-endian pair once, converts aligned byte displacements to
typed element indexes, and refuses an unaligned full-width helper without the
complete pair proof. Annotation replay also preserves the canonical
Lowering-owned argument variables instead of replacing them with body-only byte
views. Generic fail-first tests, both live COD CLI shapes, whole-tail validation,
portable-flat recompilation, focused Ruff/MyPy/type ratchets, 435 related tests,
and startup architecture/ownership checks pass.

The larger DOS `loadprog` body is now also closed at its owning layers.
Types/Lowering preserves one binary-proven four-byte `cmdline` stack owner and
projects its exact low/high word views without inventing a fifth logical
argument. Tail Validation consumes the same typed projection facts for call
sources and def-use. Structuring refuses a legacy linear-terminal scan when the
CFG has multiple value predecessors, then recovers only an exact-tagged return
from its own terminal predecessor. The success path is therefore the
binary-proven `return 0`, while the invalid-type and DOS-error paths retain
their distinct `return 1` and `return err`. The generic failing-before
regressions, 261 related tests, direct Ruff/MyPy, live COD validation, portable
recompilation, and `quality-dev` pass. No Rewrite or CLI semantic repair was
added.

The F14 CARR bounds predicates are closed at the Widening/Types and Structuring
boundaries. Required 32-to-16 semantic casts now remain exact low-word
projections, a complete CFG-proven wide predicate persists its stack-pair facts
across later C-AST rebuilds, and the existing atomic wide-return graph owner is
the only total-return materializer. `_InBoxLng` emits four long comparisons,
six logical long arguments, two return leaves, and `validation=passed` in about
8-10 seconds. `_InBox` and the ordinary single-JCC return diamond retain their
correct polarity. The 142-test condition/validation surface, both live CARR
functions, `quality-dev`, and the mandatory 1,922-test plus external executable
pipeline pass.

No test, validation check, or unsupported-input refusal was weakened. The goal
remains incomplete because Tasks 3, 5, 6, 7, and 8 remain open; the required
default, expanded, and changed-surface gates are currently green.

## Execution Ledger And Estimation

Ledger start: `2026-08-29T08:16:21+02:00` (`Europe/Belgrade`). Historical
start, finish, and effort values that were not measured at the time are marked
`pre-ledger` or `unknown`; they are not reconstructed from commit dates. From
this checkpoint onward, each active step records:

- start and finish wall-clock timestamps
- focused engineering time, excluding unattended test time and pauses
- wall span separately, so long tests do not distort implementation estimates
- test/build wait separately from focused engineering time
- acceptance evidence and the next unclosed boundary
- the previous and revised remaining-time range plus the evidence for any change

Start is written at the first task-directed command, not when a failure was
first noticed. Finish is written only after the row's DoD passes. `Spent` is
updated at each checkpoint; pauses and unattended test/build waits are excluded.
Unknown historical values remain unknown instead of being inferred from file or
commit timestamps. These rules make forecast error measurable per root cause.

The fixed weights below define total progress. A task advances only when its
DoD evidence passes; code volume, elapsed calendar time, and plausible-looking
output do not advance the percentage.

Current reporting correction (2026-09-11): the 75% weighted estimate and
80-115h forecast below are historical, not revalidated current progress or an
ETA. The last full audit has 21 failures and 170 skips, global Ruff is red,
and LIFE remains unresolved. Recent evidence repairs do not close a weighted
milestone. Re-audit each task's current DoD and remaining root-cause families
before publishing a replacement percentage or finish date.

| Task | Weight | Complete | Started | Finished | Focused spent | Remaining focused estimate | Evidence / next boundary |
| --- | ---: | ---: | --- | --- | ---: | ---: | --- |
| 1. Whole-binary export | 5% | 100% | pre-ledger | pre-ledger | unknown | 0h | Closed by canonical stdout and strict compilation evidence. |
| 2. Behavior proof | 8% | 100% | pre-ledger | pre-ledger | unknown | 0h | Closed for all source-selftested non-library functions. |
| 3. Interprocedural contracts | 20% | 95% | pre-ledger | - | unknown | 17-27h | Signed stack arguments, exact function-pointer values, indirect calls, typed pointer-memory byte values, atomic argument replay, and terminal local pointer-output carriers are closed; broader multi-output storage remains. |
| 4. Semantic-loss ratchets | 7% | 100% | pre-ledger | pre-ledger | unknown | 0h | Closed by the strict 20/20 executable-only gate and permanent tests. |
| 5. Proof-backed readability | 8% | 0% | restored by user, 2026-09-11; not started | - | 0h | needs recalibration | Execution Step 11 follows Step 9 correctness closure and precedes Step 12. |
| 6. Profiling and performance | 10% | 70% | pre-ledger | - | unknown | 8-12h | Measure aggregate PSS and profile the single-function serial tail. |
| 7. Reko mechanisms | 8% | 0% | not started | - | 0h | 10-16h | Implement only mechanisms supported by owned typed evidence. |
| 8. Ghidra mechanisms | 34% | 85% | pre-ledger | - | unknown | 45-65h | Curated acceptance is green, but the complete 10,091-test audit exposed remaining call/type/CFG and COD recovery families that must close before this task can claim completion. |
| **Total** | **100%** | **75% historical; not revalidated** | - | - | **historical total unavailable** | **Needs re-estimation** | Historical forecast was 80-115h. Current full-audit evidence is 11,750 passed, 21 failed, 170 skipped; global Ruff is red. Focused repairs and curated passes do not establish current whole-plan completion. |

Task-owner estimates above overlap where Tasks 3 and 8 share a mechanism. They
are not summed. The non-overlapping forecast table below retains historical
calibration data, not a current total remaining estimate. Its open rows require
recalibration.

### Active Step Timing

| Step | Started | Finished | Focused spent | Wall span | Status | Remaining focused estimate | Acceptance evidence |
| --- | --- | --- | ---: | ---: | --- | ---: | --- |
| CMP16 coordinate-domain collision isolation and Types/Lowering refusal | `2026-08-29 07:18 +02:00` (first recorded command) | `2026-08-29 09:03 +02:00` | unknown before ledger plus 35-45m after `08:16` | 1h45m | completed | 0h | Two regressions failed before and pass after the fix. Real `rel_i16` emits all six distinct comparisons with `validation=passed`. Initial rollback-leak hypothesis was disproved; the owner was BP/entry-SP coordinate resolution. |
| Changed-surface verification for the CMP16 fix | `2026-08-29 08:49 +02:00` | `2026-08-29 09:03 +02:00` | 8-12m | 14m | completed | 0h | Ruff `--fix`, focused MyPy/type ratchet, architecture checks, 97 related tests, 50 owned tests, and the focused real executable gate pass. |
| Exact logical stack-word ownership | `2026-08-29 09:04 +02:00` | `2026-08-29 09:21 +02:00` | 15-17m | 17m | completed | 0h | Exact Alias logical-read identity now permits one proven two-byte `SS:BP` owner; unproven same-variable recomposition still refuses. Twelve focused tests pass and the live smoke AST now contains `v5 = arg_4` instead of a false byte recomposition. |
| Packed FLAGS preservation validation and production lift context | `2026-08-29 09:21 +02:00` | `2026-08-29 09:31 +02:00` | 9-10m | 10m | completed | 0h | Seventeen focused context/validation tests have 16 passes; the only remaining failure is the end-to-end smoke shape. The previous whole-postprocess `uninitialized eflags` discard is gone, and the live AST exposes the next independent Structuring defect. |
| Collapse pure identical-return guards in Structuring | `2026-08-29 09:34 +02:00` | `2026-08-29 10:10 +02:00` | 26-31m engineering; test waits excluded | 36m | completed | 0h | Structuring owns the typed pure-guard proof and closed evidence counters; Tail Validation consumes its exact delta. Widening now propagates block definitions into returns, and regenerated argument names preserve the Lowering-owned BP/entry-SP projection. Ruff, MyPy for all eight production files, the type/doc ratchet, startup architecture/context/ownership checks, 17 focused tests, and the complete 568-test owned surface pass. |
| Original six focused failures | `2026-08-29 10:10 +02:00` | `2026-08-29 11:06 +02:00` | 40-50m; test waits excluded | 56m | completed | 0h | The final C-declaration smoke now emits `return lhs + rhs;`; Beep and DrawTime remain validation-clean. Twenty-five focused and 188 changed-surface tests pass. Ruff `--fix`, direct MyPy over seven production modules, file type/doc ratchets, and startup architecture/context/ownership checks pass. |
| Current focused-lane failure closure | `2026-08-29 11:14 +02:00` | `2026-08-31 23:54 +02:00` | historical subtotal retained; waits excluded | continued through `2026-08-31` | completed | 0h | Sleep, Swaps, DrawTime, InitMenu, loop/control-flow, call/object/indexed-storage, DrawFrame, and RunMenu families pass their function DoDs. |
| Call/object/indexed-storage materialization family | `2026-08-31 21:43 +02:00` | `2026-08-31 22:22 +02:00` | 24-30m focused; repeated test waits excluded | 39m | completed | 0h | Five live regressions and 161 supporting cases pass. Types/Lowering preserves stronger object expressions, named calls and declarations share one target identity, and rollback cleanup retains validated braces/affine rendering. Ruff, MyPy, type/doc ratchets, and startup architecture checks pass. |
| DrawFrame validation and postprocess-baseline closure | `2026-08-31 22:27 +02:00` | `2026-08-31 22:59 +02:00` | 18-24m focused; repeated test waits excluded | 32m | completed | 0h | Tail Validation consumes the closed pure identical-return proof for the exact two-effect `if/else` surface. Postprocess baseline canonicalization now keys on its typed transaction-completion generation, not an initialized change flag. The live sidecar-free function, 167 related tests, Ruff, MyPy, type/doc ratchets, and startup architecture checks pass. |
| RunMenu packed-FLAGS carrier validation closure | `2026-08-31 23:29 +02:00` | `2026-08-31 23:54 +02:00` | 17-20m focused; repeated live-test waits excluded | 25m | completed | 0h | All postprocess passes were disabled to prove the carrier pre-existed Rewrite. Register-backed AIL virtuals retain their physical storage identity, exact packed-FLAGS evidence is consumed only at matching instruction sites, both live gates pass in 50.04s, 175 related tests pass, and emitted stdout passes `gcc -std=c11 -fsyntax-only`. |
| Frontend/debug and test-profile contract closure | `2026-08-29 11:27 +02:00` (delegated window) | `2026-08-29 11:49 +02:00` | 10-15m agent time, overlapped | 22m | completed | 0h | A truly unsupported `SLDT EAX` fixture preserves the required clear exit, and the inventory replacement selects the current topology regression. Eight focused tests plus Ruff and MyPy pass. |
| Stack-coordinate, argument-identity, and stack-object unit closure | `2026-08-29 11:27 +02:00` (parallel local/delegated window) | `2026-08-29 11:49 +02:00` | 15-22m, overlapped | 22m | completed | 0h | Canonical entry-SP coordinates and exact body-owned argument identity now agree. Thirteen focused tests pass; the fixture-only canonicalization changes preserve production refusal behavior. |
| Wide call-output, loop control-flow, and argument closure for live Sleep | `2026-08-29 11:36 +02:00` | `2026-08-29 12:41 +02:00` | 47-58m engineering; test waits excluded | 1h05m | completed | 0h | Live Tail Validation, the permanent executable-only Sleep test, the combined 151-test Types/Lowering and Structuring surface, direct Ruff/MyPy, and parallel `make linters-files` pass. The function retains two clock calls and one 32-bit argument. |
| Exact inner-break ownership under a typed loop header | `2026-08-29 11:49 +02:00` | `2026-08-29 11:54 +02:00` | 4-5m | 5m | completed | 0h | Regression failed before and all 16 loop-break tests pass after the existing owner checks exact break candidates before refusing a typed header. |
| Final condition-refresh/loop-closure pass order | `2026-08-29 11:54 +02:00` | `2026-08-29 11:58 +02:00` | 3-4m | 4m | completed | 0h | The order regression failed before and 17 related tests pass after final condition refresh precedes final loop-break closure. |
| Typed composite-loop-exit ownership for Sleep | `2026-08-29 11:58 +02:00` | `2026-08-29 12:24 +02:00` (checkpoint) | 17-22m; test waits excluded | 26m | completed | 0h | The regression failed before the fix. Condition chains now precede loop materialization; exact CFG-backed ownership handles both pre- and post-break projections, isolates nested loops, and refuses re-entry targets. The related 122-test surface and live `0x10f38` Tail Validation pass. |
| Positive-BP 32-bit argument plan/interface closure for Sleep | before `2026-08-29 12:24 +02:00`; exact first command was lost at compaction | `2026-08-29 12:35 +02:00` | 10-17m; approximate because the start preceded the retained ledger checkpoint | unknown | completed | 0h | Live instrumentation proved a closed one-argument/four-byte caller census but a wrongly narrowed two-byte body plan. The test failed before the generic storage-width precedence fix; the unit and permanent executable gates now pass with `materialized=1`, `failure=0`. |
| ALU carry/borrow effect-order integrations | `2026-08-29 11:27 +02:00` (delegated) | `2026-08-29 12:07 +02:00` | 25-35m agent time, overlapped; exact timer unavailable | 40m | completed | 0h | Both integrations report one materialized effect and zero failures. Fifty-two focused tests, Ruff `--fix`, MyPy on four production modules, and diff checks pass. |
| Complete focused pytest refresh after Sleep closure | `2026-08-29 12:42:58 +02:00` | `2026-08-29 12:49:42 +02:00` | 0m engineering | 6m44s test wall | completed | 0h | Exact Makefile target: 3,968 passed, 17 failed, 13 warnings. The ten slowest tests are recorded by pytest; the longest was InitMenu at 135.49s. |
| Reproduce and symptom-cluster the 17 focused failures | `2026-08-29 12:49:42 +02:00` | `2026-08-29 12:54:19 +02:00` | 4m37s; test waits excluded | 4m37s plus 2m45s retry test wall | completed | 0h | Exact 17-node retry: 16 failed and one sidecar HeapSort timeout passed. The 16 failures are assigned to six symptom families; earliest-layer owner proof remains part of each implementation row, not this clustering row. |
| Swaps destination identity and validation-blind-spot closure | `2026-08-29 12:54:19 +02:00` | `2026-08-29 13:32 +02:00` | 31-35m; waits excluded | 37m41s | completed | 0h | Two failing-before regressions prove the machine-BP/entry-SP collision and the validation blind spot. Exact coordinate selection preserves all three object-copy effects; duplicate storage identity is refused. The live Swaps regression passes with `validation=passed`, strict C syntax, and the correct three assignments. |
| DrawTime carry-predicate sibling-join closure | `2026-08-29 13:30 +02:00` | `2026-08-29 13:43 +02:00` | 10-13m; waits excluded | 13m | completed | 0h | A failing-before CFG-ownership regression proves the low subtraction may be a sibling of the flags definition. Types/Lowering now performs the existing unique exact arithmetic fallback for a typed missing predicate. The live DrawTime regression and a 72-test carry/Swaps cluster pass with clean Tail Validation and C syntax. |
| InitMenu condition, call-result, and final-brace closure | `2026-08-29 14:23 +02:00` (approximate; first command lost at compaction) | `2026-08-29 15:16 +02:00` | 35-45m; waits excluded | 53m | completed | 0h | Frontend publishes the exact dword-OR zero condition; Types/Lowering removes only typed unobserved AX/EAX results and assigned fixed probes with frame proof; Rewrite only forces braces around already-structured multi-statement bodies. All three live tests, 94 focused tests, Ruff, MyPy, type/doc ratchets, and startup architecture checks pass. |
| Validation-clean loop/control-flow family | `2026-08-29 15:29 +02:00` | `2026-08-29 16:50 +02:00` | exact focused subtotal unavailable after interruption; test waits excluded | 1h21m | completed | 0h | ReInitBars, BubbleSort, ExchangeSort, and PercolateUp pass live Tail Validation; 127 changed-surface tests and the four-test executable lane pass. Generic ambiguity/refusal tests cover storage identity, ordered pretests, duplicate breaks, and pretest condition surfaces. |
| Retry-lane artifact persistence and checkpoint gates | `2026-08-31 10:54 +02:00` | `2026-08-31 13:30 +02:00` | 25-35m engineering; broad external wait excluded | 2h36m including shared-tree integration and external test wall | completed | 0h | Retry-lane C is persisted only after accepted validation. The final late-integration lane passes 18 focused tests with six fixture-dependent loader skips; Ruff, MyPy over 263 files, the 39-module mypyc smoke, architecture/ownership checks, 1,882 pytest cases, and all three pure-Python/mypyc quality comparisons pass. Measured candidate timing was mixed under shared-machine load: CMP16 1.174x and LOOPS 2.616x faster, FPTR 0.254x of baseline, so no universal speedup is claimed. The clean optimization-input rebuild now enforces the fixtures' intentional exit code 255. The broader `test-pipeline` remains red and is recorded below. |
| CMP16 accepted-return closure and pre-validation integrity guard | `2026-09-01 03:28 +02:00` | `2026-09-01 03:55 +02:00` | 15-20m engineering; test waits excluded | 27m | completed | 0h | Failing-before Lowering, Frontend adapter, Widening, and return-integrity regressions isolate the exact stale branch-join definition. Real `rel_i16`, the full `compare16` round trip, 187 related tests, Ruff, MyPy, and the optimization suite pass. |
| Simple-control signed argument and GP-provenance closure | `2026-09-01 03:56 +02:00` | `2026-09-01 04:54 +02:00` | 25-35m engineering; test waits excluded | 58m | completed | 0h | Two failing-before regressions prove the lost GP tags and wrong raw-BP signedness consumer. The real three-function round trip validates the selected outputs, recompiles, and exits `255`; 157 related tests and the default pipeline's 1,906-test lane pass. |
| Architecture promotion and accepted-attempt reporting integrity | `2026-09-01 04:20 +02:00` | `2026-09-01 04:57 +02:00` | 18-25m engineering, overlapping the simple-control gate waits | 37m | completed | 0h | Startup architecture is green, quality-dev passes Ruff/MyPy/mypyc and 1,906 tests, and final versus attempted validation failures are separate typed profile fields. Forty-eight harness tests pass. |
| Function-pointer stack identity and condition-integrity closure | `2026-09-01 05:45 +02:00` (first retained checkpoint) | `2026-09-01 06:20 +02:00` | 30-40m engineering; test waits excluded | 35m | completed | 0h | A failing-before production-shaped regression isolates name-first aliasing of raw stack offset `2` to offset `4`. Alias-owned machine-BP identity is now the only substitution proof, the no-op materialization marker is durable, and Tail Validation rejects any later condition-storage drift. The 150-test surface, file gates, `quality-dev` with 1,906 tests, and the complete four-function runtime gate pass with rebuilt exit `255`. |
| Pointer-memory typed value/storage closure | `2026-09-01 06:20 +02:00` (diagnosis checkpoint) | `2026-09-01 06:41 +02:00` | 15-20m engineering; test waits excluded | 21m | completed | 0h | The stack-coordinate registry now distinguishes an 8-bit semantic value from its 16-bit ABI slot. It refuses the high byte and an adjacent word argument. The 389-test architecture/coordinate surface, Ruff, MyPy, startup guard, and clean three-function compile/decompile/recompile/runtime gate pass with rebuilt exit `255`. |
| Ultra arguments, GP-frame scope, and function-pointer projection closure | `2026-09-01 09:41 +02:00` | `2026-09-01 11:04 +02:00` | 45-60m engineering; test waits excluded | 1h23m | completed | 0h | Condition tags survive stack canonicalization; writable scalar lvalues normalize only with exact physical-width proof; data pointers retain guest-offset semantics; exact function pointers remain callable; canonical `push bp`/`pop bp` is excluded from the GP snapshot consumer and remains owned by frame lowering. Focused regressions fail before and pass after. Ruff, MyPy over 266 files, mypyc smoke, architecture/ownership, 1,913 unit tests, Ultra QuickC, all MS C tiny constructs, and optimization comparisons pass. |
| Tail Validation typed temporary-projection closure | before `2026-09-01 14:11 +02:00`; exact first command lost at compaction | `2026-09-01 14:24 +02:00` | exact focused subtotal unavailable after compaction; final 13m retained; waits excluded | at least 13m retained | completed | 0h | The failing-before archless signed-word regression passes; the real `select_and_apply` emits the required returned call with `validation=passed`; 66 focused tests pass; Ruff, MyPy, the 1,915-test mandatory pipeline, all external round trips, and `quality-dev` pass. |
| CMP16 final return-chain polarity closure | `2026-09-01 19:55 +02:00` (diagnosis checkpoint) | `2026-09-01 20:33 +02:00` | 25-35m engineering; repeated executable and gate waits excluded | 38m | completed | 0h | Production tracing proved `JNE` decoded as `CmpNE` while the exact-tagged AST carried `call ? 0 : 1`. Structuring now selects decoded polarity only with same-branch proof. Three focused selection tests, 130 existing return-chain tests, direct Ruff/MyPy, the real CMP16 function, all three optimization comparisons, and `quality-dev` pass. |
| Architecture ownership promotion and `quality-hard` refresh | `2026-09-01 20:34 +02:00` | `2026-09-01 20:46 +02:00` | 6-10m engineering; gate waits excluded | 12m | completed | 0h | Every newly owned production module has an exact layer header and is enrolled in the Ruff/MyPy and architecture-promotion inventories. `quality-hard` passes Ruff `--fix`, MyPy over 266 files, mypyc smoke over 39 compiled modules, architecture/startup/context checks, and the hard regression lane. |
| angr Clinic semantic-stage compatibility closure | `2026-09-01 20:48 +02:00` | `2026-09-01 21:02 +02:00` | 9-12m engineering; pipeline waits excluded | 14m | completed | 0h | The dependency-updated Clinic now always runs pre-SSA, SSA, post-SSA, and variable-recovery semantics. Cost policy bounds inner peephole work only. The 24-test Clinic/runtime surface, direct Ruff/MyPy, the three previously failing helpers, all 1,915 curated tests, and all seven MS C round trips pass. |
| InitMenu dead packed-FLAGS chain closure | `2026-09-01 21:33 +02:00` | `2026-09-01 22:01 +02:00` | 20-25m engineering; repeated executable waits excluded | 28m | completed | 0h | DCE atomically removes pure empty two-arm conditions and lets Lowering-owned packed-FLAGS live-in protection expire when no consumer remains. Eighty-four focused tests, direct Ruff/MyPy, and the real sidecar-free `0x10060` gate pass; generated C contains neither `inertia_flags` nor the `v48`-`v58` parity chain. |
| DrawBar exact stack-address replay closure | before `2026-09-01 22:34 +02:00`; exact first command lost at compaction | `2026-09-01 22:49 +02:00` | 55-75m engineering; test waits excluded | at least 15m retained | completed | 0h | A failing-before production-shaped regression proves that whole-call quality scoring could preserve a stale scalar low byte over an exact typed `BP_ADDRESS` source. Types/Lowering now resolves the machine-BP coordinate and the compatibility replay consumes that identity before generic score comparison. Five new source/projection tests, 188 related tests, Ruff, MyPy, `quality-dev` with 1,915 tests, the mandatory pipeline with all seven MS C round trips, and live `0x106c8` Tail Validation pass. The sibling `0x101f0` call mismatches are gone; its independent `BP-0x2` carrier failure is the next root cause. |
| DrawFrame regenerated frame-setup carrier closure | `2026-09-01 22:50 +02:00` | `2026-09-01 23:03 +02:00` | 18-25m engineering; gate waits excluded | 13m retained plus gate wall | completed | 0h | A failing-before production-shaped regression proves that the exact `mov bp, sp` carrier survived after earlier cleanup consumed the structured `push bp` carrier. Types/Lowering now accepts the owned BP setup write only with a decoded canonical entry pair. The refusal case, 10 frame tests, 490 related tests, Ruff, MyPy, strict C11 syntax, live `0x101f0` Tail Validation, `quality-dev`, and the mandatory 1,915-test plus seven-round-trip pipeline pass. Required DrawFrame calls and loop semantics match the source oracle. |
| QuickSort short-circuit guard and generated-runtime closure | `2026-09-02 02:10 +02:00` | `2026-09-02 02:49 +02:00` | 25-35m engineering; repeated gate waits excluded | 39m | completed | 0h | Structuring binds each pretest guard to its exact JCC evidence and derives a predecessor only from a uniquely proven short-circuit CFG chain. Both QuickSort scan guards and recursive calls survive, the generated sort core compiles and terminates correctly, and ambiguous/mismatched evidence refuses. Types/Lowering also preserves the signed Sleep comparison through an explicit semantic cast on both operands. Nineteen focused pretest tests, 21 wide-call/Sleep tests, `quality-dev`, and the expanded acceptance pipeline pass. |
| Terminal local pointer-output versus scalar-return closure | `2026-09-02 03:04 +02:00` | `2026-09-02 04:03 +02:00` | 40-55m engineering; gate waits excluded | 59m | completed | 0h | Semantics records a typed all-terminal-path carrier role from decoded operand facts; Types consumes it only with complete unused-caller evidence and a guessed prototype. Sidecar-free Swaps becomes `void`, `_SetDLC` keeps its scalar return, uncertain/direct-global cases refuse demotion, and `quality-dev` plus the required external executable pipeline pass. |
| `_ConfigCrts` indexed-load and live-carrier closure | `2026-09-02 04:28 +02:00` | `2026-09-02 05:05 +02:00` | 24-30m engineering; gate waits excluded | 37m | completed | 0h | Types/Lowering projects exact byte lanes from wider binary load-site evidence, Widening recomposes only a typed virtual word destination, and Rewrite cleanup keeps nested temporaries live at enclosing continuations. The failing-before regressions, real sidecar-free function, 29 focused tests, Ruff, MyPy, mypyc smoke, `quality-dev`, and mandatory plus expanded executable pipelines pass. |
| Quiet native-tool output contract | `2026-09-02 05:05 +02:00` | `2026-09-02 05:18 +02:00` | 10-13m | 13m | completed | 0h | Make recipes suppress duplicate command echo and pass concise native Ruff, MyPy, pytest, and lizard flags. The startup checker has a compact-success mode but preserves full failures. Fifty-seven contract tests, direct Ruff/MyPy, and the focused Make targets pass. |
| COD frontend-fixture and timeout-reporting realignment | `2026-09-02 05:18 +02:00` | `2026-09-02 05:27 +02:00` | 8-9m | 9m | completed | 0h | Five stale block-lift fixture expectations now preserve byte-safe split loads, explicit `NEXT` fallthrough, and dead FLAGS-write elimination. The direct timeout path again reports its recovery phase and larger-timeout hint inside valid C comments. Six block-lift cases plus the process-helper and timeout regressions pass. |
| `_dos_getfree` cleanup-transaction closure | `2026-09-02 05:28 +02:00` | `2026-09-02 05:34 +02:00` | 6m; test waits overlap | 6m | completed | 0h | Rewrite policy now restores and refuses only the optional unused-global declaration cleanup when its validation delta differs. COD/source semantics, the exact `intdos` call, the zero-carry error branch, both return paths, live `validation=passed`, Ruff, MyPy, and nine focused tests pass. |
| F14 regenerated global-read identity closure | `2026-09-02 05:53 +02:00` | `2026-09-02 06:20 +02:00` | 11-14m engineering; broad gate waits excluded | 27m | completed | 0h | Types/Lowering now revisits runtime helper surfaces after regeneration, traverses non-`CStatements` roots, and reconciles the existing explicit COD storage/display alias. Live `_ChangeWeather` emits `if (BadWeather)` with validation clean; three failing suite nodes plus four generic ordering/traversal tests, Ruff, direct MyPy, `quality-dev`, and mandatory plus expanded pipelines pass. |
| Native tool flag and token-output ratchet extension | `2026-09-02 06:20 +02:00` | `2026-09-02 06:23 +02:00` | 3m | 3m | completed | 0h | Ruff quiet/concise, MyPy plain/no-color, Pyright warning-level, pytest short-traceback/no-header, and Lizard warnings-only preserve actionable findings while suppressing success noise. Contract tests, direct invocations, and `quality-dev` pass. |
| `_MousePOS` regenerated physical-register carrier closure | `2026-09-02 06:23 +02:00` | `2026-09-02 06:44 +02:00` | 10-14m engineering; broad gate waits excluded | 21m | completed | 0h | Lowering replays the two exact global stores, then Rewrite folds only an adjacent dead `SimRegisterVariable` carrier with physical-register identity and suffix/live-out proof. A later use refuses. Live `_MousePOS` emits `MouseX = x << 1;`, preserves `MouseY`, `interrupt_int33`, and `return 4`, recompiles, and reports `validation=passed` plus whole-tail clean. Forty-nine focused tests, Ruff, direct MyPy, and `quality-dev` with 1,921 tests pass. |
| F14 `_InBox`/`_InBoxLng` predicate and durable wide-pair closure | `2026-09-02 06:45 +02:00` | `2026-09-02 08:00 +02:00` | 40-50m engineering; repeated corpus and gate waits excluded | 1h15m | completed | 0h | Types/Lowering recognizes only exact 16-bit semantic projections and persists stack pairs only after complete CFG proof. Structuring invokes its existing atomic wide-return owner before competing replay and reuses the recorded proof after AST rebuilds. `_InBoxLng` emits six long arguments and four comparisons with `validation=passed`; `_InBox` and the scalar JLE regression retain correct polarity. The 142-test related surface, two live CLI cases, Ruff, MyPy, `quality-dev`, and the mandatory 1,922-test external pipeline pass. |
| Machine-BP prototype identity and indexed byte-pointer closure | `2026-09-02 08:30 +02:00` | `2026-09-02 09:25 +02:00` | 40-50m engineering; focused waits excluded | 55m | completed | 0h | Types/Lowering now recognizes a sole pointer carrier in either x86 effective-address register and refuses two-carrier ambiguity. Stack prototype materialization joins physical C arguments to logical annotations through the owned machine-BP coordinate instead of raw entry-SP offsets. Failing-before tests cover both defects; 77 related tests, Ruff, MyPy, live `fill_bytes`, and the three-function `pointer_memory` compile/decompile/recompile/runtime construct pass in 16.21s with a `char *dst` byte store. |
| Stored call-return early-exit and DOS wrapper closure | `2026-09-02 09:39 +02:00` | `2026-09-02 10:45 +02:00` | 45-55m engineering; repeated live and gate waits excluded | 1h06m | completed | 0h | Exact PUSH provenance removes the split byte carrier. Lowering joins the projected stack condition to its AX call-result binding; Semantics proves the jump-only epilogue path preserves return registers; Structuring resolves the machine-BP error object and materializes both returns. Failing-before unit tests, both live CLI modes, 83 related checks with only the pre-existing `loadprog` body failure, direct Ruff/MyPy, `quality-dev` with 1,923 tests, and the mandatory external pipeline pass. |
| DOS `loadprog` wide-stack view and path-specific terminal-return closure | `2026-09-02 10:55 +02:00` | `2026-09-02 11:53 +02:00` | 35-45m engineering; repeated live and gate waits excluded | 58m | completed | 0h | Types/Lowering owns one four-byte `cmdline` argument and exact word projections; Tail Validation consumes the same typed projection facts; Structuring refuses cross-path linear substitution and materializes the exact tagged success return from its own CFG predecessor. Generic failing-before tests, 261 related checks, direct Ruff/MyPy, live `validation=passed`, portable recompilation, and `quality-dev` pass. |
| Swaps return-frame, validation-coordinate, and final projection closure | before `2026-09-02 14:02 +02:00`; exact start lost at compaction | `2026-09-02 14:13 +02:00` | exact focused subtotal unavailable after compaction; final diagnosis and gates retained | at least 11m retained | completed | 0h | Lowering consumes the typed CALL return frame before removing the fixed stack probe; Tail Validation translates exact-region C slots to machine-BP ABI offsets; Structuring replays the unique pointer-swap projection after final codegen regeneration and removes only tagged consumed carriers. The live Swaps test passes with one temporary load, both stores, the global increment, `validation=passed`, and strict C syntax. Focused pointer, return-frame, coordinate, and owner tests, Ruff, direct MyPy, `quality-dev` with 1,923 tests, mypyc smoke, and all three quality comparisons pass. |
| Function-wide entry-SP to machine-BP validation-coordinate closure | before `2026-09-02 15:06 +02:00`; exact start lost at compaction | `2026-09-02 15:22 +02:00` | 15-25m focused; complete local gate wall excluded | at least 16m retained | completed | 0h | Types/Lowering now owns one typed C-function coordinate projection. It accepts only the coherent 16-bit near-frame delta from entry-SP `+2` to machine-BP `+4`, applies it consistently to arguments and locals, and refuses already-projected, incomplete, or mixed interfaces. An uncached live DrawBar run and its permanent regression return zero with `validation=passed`; 99 focused tests, Ruff, MyPy, architecture checks, and `quality-dev` with 1,924 tests plus all required external quality comparisons pass. |
| Required project gates after the fix | `2026-08-29 08:51 +02:00` | `2026-09-02 06:40 +02:00` | historical subtotal retained; test time excluded | continued through `2026-09-02` | completed | 0h | Ruff, MyPy over the production surface, the 39-module mypyc smoke, architecture and ownership checks, and 1,921 curated tests pass. All three quality comparisons pass at 1.356x-1.526x. The expanded pipeline remains 5/5: SORTD decompiles 20/20 functions with zero validation failures or timeouts, its generated translation unit compiles with zero warnings, the 19-function sort-core behavior gate passes, and every selected Ultra QuickC and MS C tiny round trip passes. No exclusion or weakened check was added. |
| Complete repository pytest closure | `2026-09-02` | - | latest full audit wall 852.88s; closure work tracked per root family | active | in progress | 20-35h, overlapping task 9 | The exact baseline is 9,944 passed, 23 failed, 170 skipped out of 10,137. The latest exact last-failed rerun is 19 failed and 3 passed in 221.20s. Focused closures project 13 remaining failures; only a complete rerun may replace the exact count, and final DoD remains zero failures. |
| Refresh full-suite census and retire stale stack-coordinate overlap fixture | `2026-09-06 15:14 +02:00` | `2026-09-06 16:15 +02:00` | 61m wall, dominated by the audit, concurrent-source retries, and local gates | completed | 0h | The diagnostic audit reported 9,950 passed, 24 failed, and 170 skipped out of 10,144 in 1,099.15s. Concurrent source mutation and profiler contention make it a triage inventory, not a clean baseline. Final Tail Validation correctly maps entry-SP `+3` to machine BP `+5`; all three entry-range tests pass. One intermediate changed surface reached 182 focused passes, and one completed `quality-dev` run reached 1,925 tests plus external quality comparisons, but later concurrent edits remain outside this slice and require their own fresh gate before integration. |
| DOS logical word-store and canonical annotation-interface closure | before `2026-09-07 04:21 +02:00`; exact start lost at continuation | `2026-09-07 04:31 +02:00` | 25-35m focused engineering; test waits excluded | completed | 0h | Types/Lowering consumes one closed IR word-write fact once across angr's two byte projections, scales aligned byte displacement by the pointee width, and preserves canonical argument identity through annotation replay. The generic regression failed before and passes after; both live COD CLI tests, portable-flat recompilation, whole-tail validation, focused Ruff/MyPy/type checks, 435 related tests, and architecture/ownership gates pass. |

#### Machine-BP prototype identity and indexed byte-pointer closure contract

Reason: 16-bit effective addresses may carry a near pointer in either Capstone
`base` or `index`. The generated C variables may simultaneously use entry-SP
coordinates while annotations use machine-BP coordinates. Missing either fact
widens byte stores or shifts argument types onto the next physical word.

DoD: one decoded argument carrier in either effective-address register yields
an exact pointee-width fact; two argument carriers refuse; prototype replay
joins only by owned machine-BP identity; `fill_bytes` retains a byte pointer;
Tail Validation, Ruff, MyPy, focused tests, and the complete `pointer_memory`
runtime construct pass.

Definition of failure: rendered-assembly or function-name matching; accepting
an address with two argument carriers; joining annotations by list position or
raw `SimStackVariable.offset`; `short *` byte-store widening; validation,
recompile, or generated runtime failure.

#### Stored call-return early-exit and DOS wrapper closure contract

Reason: the call result was stored at `SS:BP-2`, but the typed condition and C
AST could expose different projections of that same storage. The error edge
then carried AX unchanged through a jump-only epilogue while angr retained only
placeholder returns. A byte-executed PUSH carrier also survived as an invalid
casted lvalue.

DoD: Lowering joins only an exact call-return store, typed condition, and
register binding; Semantics proves every instruction on the bounded error path
preserves AX/DX until return; Structuring resolves the active C object by owned
machine-BP identity and fills both placeholder returns; consumed PUSH cleanup
requires exact instruction provenance and argument identity. Both COD CLI
shapes emit `if (err) return err;`, direct output-pointer stores, and `return 0;`
with `validation=passed`; Ruff, MyPy, focused tests, `quality-dev`, and the
mandatory external pipeline pass.

Definition of Failure: rendered-text, procedure-name, or address-specific
recovery; accepting a projected stack condition without its return-register
binding; treating an unknown instruction as return-register preserving;
resolving stack identity by raw offset when a machine-BP projection exists;
deleting a non-PUSH store or a PUSH without exact consumed-argument proof;
missing either return or pointer store; any validation, compile, focused-test,
lint, type, or mandatory-pipeline failure.

#### DOS logical word-store materialization closure contract

Reason: one closed 16-bit logical memory write can be represented by angr as
two structured-C byte projections with the same instruction provenance.
Applying the logical width independently to both lvalues widened the high-byte
address as a word access; the pointer-carrier consumer then confused byte
displacement `+1` with C element index `[1]`. Annotation replay independently
allowed body-only byte declarations to replace the canonical function
interface.

DoD: Types/Lowering joins the low/high stores only when a closed IR word-write,
the same exact instruction address, one typed pointer owner, adjacent byte
offsets, DS identity, and one shared little-endian source all agree. A carrier
setup may not be consumed when another statement in its sequence still uses
it; byte-pair folding may not cross an intervening statement. Aligned helper byte
offsets are divided by pointee width; unaligned full-width helpers without that
complete proof remain explicit; annotation consumes and preserves the canonical
Lowering-owned argument identities. Generic regressions cover the split
projection and wrong element stride. Both `_dos_loadProgram` CLI paths emit one
`cs[0]` and one `ss[0]` store with no `[1]` or residual function-body `SEG_U*`,
report `validation=passed` and clean whole-tail validation, and portable-flat C
recompiles. Focused Ruff `check --fix`, MyPy/type ratchets, related tests, and
architecture/ownership checks pass.

2026-09-07 safety review: three new refusal cases failed before the follow-up
guard: ES stores, SS stores, and a carrier read after the folded store. All
three now preserve their original statements. The existing carrier-as-value
refusal also remains covered. One old positive fixture incorrectly described
a default-DS `mov [bx], ax` using an SS helper; its helper now matches its binary
evidence, with explicit negative segment tests retained in a focused module.
The related 250-test run passes, including the live DOS wrapper's Tail
Validation and generated-C recompilation. The new refusal and annotation
identity modules are enrolled in Ruff, focused ownership, and the normal
pipeline.

The independent venv last-failed refresh completed before this follow-up:
14 failed, 346 passed in 251.47s. This is a selected failure inventory, not a
full-suite count; the pytest cache also contains historical removed nodes.
Failures cover InBoxLng, DrawRadarAlt, dos_free, SetGear, InitBars, ExchangeSort,
DrawFrame, RunMenu, PercolateDown, InsertionSort, TIDShowRange, and main, with
duplicate tests for some functions and timeout-contaminated results. Global
`quality-fast` is still red on MyPy errors outside this store-fold change;
neither Step 9f nor the overall P0 goal is closed by this checkpoint.

#### P0 pointer-store consumption follow-up (2026-09-07)

The [frame-carrier typing checkpoint](reference/p0-frame-carrier-types.md)
preserves exact BP/SP proof decisions while removing a tuple/view binding
collision. Eighteen focused tests pass, including a paired-owner MyPy regression;
`quality-dev` passes with 2,053 pytest cases and its external guards. Global
MyPy diagnostic lines decrease from 149 to 146; full-suite acceptance remains open.

The [access-trait factory checkpoint](reference/p0-access-trait-runtime-factory.md)
repairs a reproduced runtime class/type-alias mismatch in legacy CLI wiring;
the positive collector and existing refusal regressions pass. `quality-dev`
and the mandatory executable pipeline pass (2,047 pytest cases each). Global
MyPy diagnostics decrease from 150 to 149; no full P0 closure is claimed.

The [segment-membership checkpoint](reference/p0-segment-register-membership.md)
aligns Alias's immutable membership contract with IR's ordered register
inventory, preserves constant restore evidence, and strengthens a stale live
DS-state assertion. Global MyPy diagnostics decrease from 155 to 150; full P0
acceptance remains open.

The subsequent [generic-typing checkpoint](reference/p0-generic-typing.md)
removes nine global MyPy diagnostics (164 to 155) while preserving runtime
behavior. Its static decorator-inference regression is enrolled in the routine
pipeline. Global typing and full-suite acceptance remain open.

The subsequent [logical-memory width checkpoint](reference/p0-logical-memory-width.md)
corrects execution-byte promotion to logical-word width in Types/Lowering and
separates proven store projection from setup deletion. Arithmetic tests and the
strict live DOS LoadProgram regression pass without changing byte-safe frontend
execution. The mandatory pipeline and final 2,027-test `quality-dev` gate pass;
the latter now includes the arithmetic suite and live wrapper. Global
`quality-fast` still fails with 164 MyPy error lines. This bounded checkpoint
does not close Step 9f or the full-suite acceptance requirement.

Whole-function carrier consumption now guards pointer-store setup removal at
Types/Lowering. See [the focused evidence record](reference/p0-pointer-store-consumption.md)
for reason, DoD, failure conditions, positive/refusal coverage, and the remaining
full-suite acceptance boundary. This does not close Step 9f or raise the stale
weighted completion estimate.

#### P0 pointer-evidence safety review (2026-09-07)

Reason: the decoded near-pointer collector attributed `BP + scalar_argument`
stack-array accesses to the scalar argument as a pointer, and treated LEA's
memory-shaped operand as a dereference. DrawFrame's `iWidth` consequently
acquired a false pointer contract, causing both binary-only and named output
to fail parameter validation. This is a Types/Lowering evidence-classification
bug; changing the validator or rendered signature would conceal the root.

DoD: BP-indexed scalar accesses and LEA publish no pointer-dereference fact;
an actual direct argument dereference still publishes its exact slot, site,
and width. Frontend resolves the effective memory segment, including explicit
overrides and 32-bit SIB base/index distinctions, before Lowering classifies
global accesses. Both DrawFrame variants must retain four scalar arguments, the
80-byte local array, three memory-fill calls, three output calls, the signed
row-loop condition, clean Tail Validation, and recompilable portable C.
Binary-only regression tests, the related Lowering tests, focused types/docs
and Ruff, `quality-dev`, and the mandatory MS C pipeline must pass.

Definition of Failure: using source names or addresses as proof; suppressing
parameter validation; classifying every address contributor as a pointer;
counting LEA as a load; losing a real dereference, call, loop, or memory effect;
claiming performance improvement without a controlled measurement.

Timing: the first fail-first run started at `2026-09-07 11:04:51 +02:00`.
Two binary-only negative tests failed and the positive dereference test passed.
The generic collector correction makes both DrawFrame variants pass semantic
validation. Live GCC C11 syntax checks pass; the named variant retains the
existing DOS-width `memset` builtin-signature warning. The sidecar-free output
uses an explicit signed `while` condition and still has unrelated rejected
cleanup passes, so no universal speedup or full P0 closure is claimed.
Verification finished at `2026-09-07 11:33:50 +02:00`: 28m59s wall span
from the first fail-first run, including test/build waits; focused engineering
time was not separately measured. Final `quality-dev` reports 1,992 passed,
seven warnings in 81.91s for its pytest phase, a passing external executable
case, and a 39-module mypyc import smoke. The mandatory `test-pipeline` run
reports 1,974 passed, eight warnings in 131.73s and all seven MS C tiny
compile/decompile/recompile/execute cases passing. That pipeline preceded the
last shared diagnostic-routing correction; the final changed-surface gate and
21 focused diagnostics/project-cache/live-DrawFrame tests cover that correction.
Both DrawFrame variants now compile unfiltered stdout and pass Tail Validation.
These are curated gates, not a clean full-suite audit. Global `quality-fast`
remains red on the previously recorded out-of-scope MyPy debt. Step 9f and P0
remain open; no measured end-to-end speedup is claimed for this slice.
The accompanying logical-register-transfer batch reuses one scalar-definition
index per function. Its two focused test modules pass (29 tests in 15.79s),
and scoped Ruff `--fix`, MyPy, and the type ratchet pass. This preserves the
other agent's work without treating index-build reduction as an end-to-end
performance result.

The broader gate exposed a related adapter defect: Capstone's absent segment
override was treated as DS even for BP-based addresses. The new frontend
`capstone_memory_segment.py` owns the effective segment rule; the existing
Lowering memory view consumes it. Four default-segment cases failed before,
while explicit overrides already passed. Six real encoded-memory cases now
cover BP, SI, overrides, and EBP as a SIB base versus index. This also removes
the previous four spurious legacy global sites: the reviewed SORTD inventory
now has 19 exact functions, one divergent function, zero legacy-only keys,
and unchanged authoritative Alias/materialization counts. The updated baseline
preserves the remaining four Alias-only keys and does not weaken the gate.

Cold-run acceptance also exposed stdout contamination. Reason: project and
work-item emitters switched diagnostics to stdout under `PYTEST_CURRENT_TEST`,
and the shared CLI printer bypassed routing in pytest/brief modes. A warm cache
hid this behavior. DoD: diagnostic emitters use stderr in every mode, C remains
on stdout, and both DrawFrame variants compile directly from unfiltered CLI
stdout. Definition of Failure: stripping debug lines in the test, relying only
on a warm result, or treating pytest/brief mode as permission to emit non-C on
stdout. The shared routing matrix adds 18 cases; eight failed before the shared
printer/work-item correction. This is CLI reporting work, not semantic recovery.

Definition of Failure: recovering from function names, addresses, COD/source,
assembly text, or rendered C; treating a byte displacement as a typed element
index; coalescing stores with different instruction provenance, pointer owners,
or source values; silently deleting an unproved lane; replacing the canonical
interface with a body subview; repairing the symptom in Structuring, Rewrite,
postprocess, or CLI; or losing any call, return, memory effect, validation,
recompilation, type, lint, documentation, architecture, or focused-test gate.

#### F14 `_InBox`/`_InBoxLng` predicate closure contract

Reason: the complete 32-bit comparison graph was present in typed ConditionIR,
but mutable C declarations temporarily split each long argument into two words.
The canonical wide-return owner therefore lost its Widening proof after later
AST rebuilds. An experimental total-return helper duplicated Structuring
ownership, and placing chain materialization before legacy JCC replay inverted
an ordinary scalar return diamond.

DoD: Types/Lowering accepts a semantic cast as a low-word projection only when
its destination is exactly 16 bits and its four-byte stack owner covers the
adjacent high slice. Structuring atomically consumes every raw JCC fact, proves
all four 32-bit comparisons and both return leaves, records the synthesized
wide conditions as durable typed evidence, and remains the sole total-return
owner across AST rebuilds. `_InBoxLng` has six logical long parameters, the
four source-equivalent range comparisons, both return values, and
`validation=passed`; `_InBox` and a generic scalar JLE return diamond keep
correct polarity. Focused refusal tests, Ruff, MyPy, `quality-dev`, and the
mandatory external pipeline pass.

Definition of Failure: accepting an 8-bit or untyped cast as a word projection;
widening adjacent stack words without either an external pair proof or a
complete CFG proof anchored by one proven operand; recovering from rendered C,
assembly text, procedure names, or corpus addresses; retaining a second
total-return materializer; allowing legacy replay to overwrite a canonically
owned wide root; losing or inverting any comparison or return leaf; splitting
the final logical long arguments; any Tail Validation failure; or any focused
lint, type, compile, behavior, or mandatory-pipeline failure.

#### `_MousePOS` regenerated physical-register carrier closure contract

Reason: regeneration ran Rewrite cleanup before the final Types/Lowering global
identity replay. That replay correctly materialized `MouseX = cx`, but the
resulting adjacent `cx = x << 1` carrier was too late for cleanup and physical
register names were excluded from the generic dead-copy classifier.

DoD: Types/Lowering remains the only owner of the global-store and interrupt
semantics. Final orchestration reruns AST-only cleanup after all Lowering and
Structuring replays. Rewrite identifies physical registers by typed
`SimRegisterVariable` coordinates, folds only an adjacent movable producer with
one matching consumer and no suffix/live-out use, and refuses a later use. Live
`_MousePOS` preserves both global stores, the interrupt call and its value
arguments, and the explicit AX-derived `return 4`; generated C recompiles,
reports `validation=passed`, and has whole-tail validation clean. Generic
positive/identity/refusal, focused CLI, Ruff, MyPy, and `quality-dev` pass.

Definition of Failure: deriving the fold from rendered C, a function name, COD
text, or an address; moving global or interrupt semantics into Rewrite; folding
a register with any later structured-AST use; keying physical identity on a
Python object id; deleting or changing the interrupt call or either global
store; treating the interrupt helper return as the proven AX result; leaving an
undeclared register in generated C; or any focused compile, validation, lint,
type, or broad development-gate failure.

#### F14 regenerated global-read identity closure contract

Reason: runtime segmented-memory lowering could create a typed `SEG_U16` read
after named-global materialization had already run, while the final regeneration
hook replayed naming only when runtime lowering reported a fresh mutation. The
named-load walker also descended only from `CStatements`, so valid alternative
structured roots stranded a proven read even though exact COD `EQU` storage and
display identities had already been recorded.

DoD: Types/Lowering traverses every supported structured-C root, reruns named
global materialization after runtime helper creation, and reapplies the existing
unambiguous storage/display identity facts after regeneration even when the
helper already exists. Live `_ChangeWeather` preserves both branches and all six
global stores, emits `if (BadWeather)`, reports whole-tail validation clean, and
focused positive/order/refusal, Ruff, and MyPy checks pass. Raw no-label output
may retain a numeric global but must use the current portable runtime segment
identifier.

Definition of Failure: deriving names or control flow from rendered C; merging
ambiguous aliases; replacing generated storage identity instead of projecting
the explicit display alias; limiting traversal to one root class; running
semantic recovery in Rewrite or CLI text processing; losing a branch/store;
retaining the synthetic analysis-image address in labeled CLI C; or any focused
validation, type, lint, or source-call/store survival failure.

#### `_dos_getfree` cleanup-transaction closure contract

Reason: unused generated-global declaration pruning is cleanup-only, but a
non-destructive validation mismatch made its rejection fail the whole function
after the validated baseline had already been restored. The emitted function
was semantically correct and matched the COD source, yet the CLI returned a
validation failure solely because this optional cleanup lacked reject-and-
continue policy.

DoD: Rewrite transaction policy classifies only the declaration-prune pass as
locally rejectable and budgeted, while keeping it outside mandatory semantic
validation. A rejected pass restores the prior validated snapshot. The real COD
function preserves `intdos(&rin, &rout)`, the `cflag == 0` error path, zero and
`rout.x.bx` returns, and reports whole-tail `validation=passed`; focused policy,
COD, Ruff, and MyPy checks pass.

Definition of Failure: accepting a mismatched cleanup result instead of
restoring it; making semantic, call, CFG, alias, type, or structuring passes
optional; changing the source-proven branch polarity; hiding validation state;
matching the function name/address/rendered text as recovery evidence; or any
focused validation, lint, type, call-survival, or return-path failure.

#### COD frontend-fixture and timeout-reporting realignment contract

Reason: five block-lift fixtures encoded obsolete physical VEX shapes from
before independently resolved byte-safe accesses, explicit fallthrough targets,
and dead FLAGS-write suppression. Separately, the terminal direct timeout path
lost the phase and retry guidance required by the CLI contract.

DoD: fixtures assert the current semantic frontend contract without changing
the preserved byte-safe access implementation; fallthrough remains explicit and
dead overwritten flag writes remain absent. Timeout stdout remains valid C
comments and includes both the recovery phase and larger-timeout hint. Focused
block-lift, timeout, and process-helper tests pass.

Definition of Failure: restoring wide unwrapped guest-memory accesses; removing
an explicit control-flow target; requiring a dead FLAGS write; weakening a
semantic assertion merely to fit output; emitting non-C metadata on stdout;
dropping timeout classification or guidance; or changing production semantics
to satisfy a stale fixture.

#### Quiet native-tool output contract

Reason: repeated Make echo plus verbose native tool formatting consumed agent
context without improving diagnostics, especially for broad parallel gates.

DoD: Make exposes overridable concise native flags for Ruff, MyPy, Pyright,
pytest, and Lizard, suppresses duplicate recipe echo, and uses compact startup
output only on success. Ruff uses quiet rather than silent mode, so remaining
diagnostics survive. Full command output is retained in temporary logs for
failures; native exit codes, warnings, test collection, lint/type scope, and
required gates are unchanged. Focused Makefile and startup-check regressions
pass.

Definition of Failure: suppressing a checker, warning family, failure detail,
collection item, or exit status; replacing a native machine-readable/concise
mode with lossy text filtering; hiding required commands; or making local and
Make-invoked tool policy diverge.

#### `_ConfigCrts` indexed-load and live-carrier closure contract

Reason: the byte-safe frontend correctly exposed independently resolved bytes
from one wider binary load, but Types/Lowering rendered each byte as the whole
indexed word. After exact recomposition, late Rewrite cleanup then deleted the
word producer inside a loop because it could not see the return continuation.

DoD: Types/Lowering consumes exact load-site width and segmented-address
evidence to project each byte lane; Widening recomposes only exact low/high
projections into an Alias-proven word or a typed two-byte virtual destination;
Rewrite cleanup carries live-out identities across loops and branches and
refuses unsafe deletion. Failing-before positive and refusal tests pass, the
real sidecar-free function returns and stores the same complete word with
`validation=passed`, and focused, lint, type, mypyc, mandatory, and expanded
executable gates are green.

Definition of Failure: changing the byte-safe frontend access contract;
matching function names, addresses, assembly, or rendered C; treating every
byte as a whole word; recomposing without exact lane and width proof; deleting
a producer live after a nested statement body; moving semantic recovery into
Rewrite; losing the store or return; or any required validation, test, type,
lint, compilation, or runtime gate failure.

#### Terminal local pointer-output versus scalar-return closure contract

Reason: physical AX liveness alone cannot distinguish a scalar function result
from a temporary local value that is reloaded only to complete a terminal
write through a pointer argument. Treating both as returns gave Swaps a false
scalar API; treating every terminal store as output would erase legitimate
direct-global scalar returns such as `_SetDLC`.

DoD: Semantics derives a typed carrier role from decoded operands and requires
the same proof on every terminal path; later reads/writes, direct global stores,
and ambiguous paths refuse. Types may demote only when that proof is complete,
all known callers explicitly ignore the return, and the prototype is guessed.
Focused positive and refusal tests pass, live Swaps is `void`, `_SetDLC` remains
scalar, and Ruff, MyPy, architecture, `quality-dev`, and the external executable
pipeline are green.

Definition of Failure: using function names, addresses, source, assembly text,
or rendered C as proof; making a broad terminal-store rule; demoting an explicit
prototype or a used/unknown caller; accepting mixed terminal paths; implementing
the semantic distinction in Structuring, Rewrite, or CLI; losing a pointer
write or scalar return; or any required type, lint, architecture, validation,
focused-test, compilation, or runtime gate failure.

#### Complete repository pytest closure contract

Reason: the curated pipeline intentionally optimizes development latency and
does not exercise every COD/debug corpus, compatibility contract, or slow live
decompilation. Calling that lane "all tests" hid independent production defects
and made the earlier 79% estimate too optimistic.

DoD: the exact command `pytest -n 7 --dist loadgroup --durations=10` collects the
complete repository suite and exits zero; every currently failing node either
passes after an owning-layer correction or is removed only with written proof
that it is duplicate, superseded, or invalid. Skips remain classified and
intentional. The ten slowest tests and their owner families are recorded, and
the curated quality/executable gates remain green.

Definition of Failure: reporting curated or last-failed results as the complete
suite; adding `xfail`, skip, ignore, timeout inflation, or test deletion to hide
a production defect; fixing rendered C or a corpus address instead of the owner;
running without the required seven-worker profile; omitting slow-test evidence;
or leaving any full-suite failure while claiming the goal or plan complete.

#### QuickSort short-circuit and Sleep comparison closure contract

Reason: a pretest guard without exact branch evidence was borrowing a later
predicate solely because both shared a candidate body target. That inverted
QuickSort's scan exits and made generated execution diverge. Separately, the
wide-call condition owner cast the call result to signed long but left the
other operand dependent on a later mutable declaration, creating a mixed-sign
comparison warning.

DoD: Structuring selects a guard only from exact JCC identity or a unique
short-circuit predecessor whose alternate edge is the same proven exit;
ambiguity and mismatched tags refuse. Both QuickSort scans and recursive calls
survive Tail Validation, generated C compiles, and the behavior harness
terminates with source-equivalent results. Types/Lowering applies the signed
semantic view to both Sleep comparison operands. Focused tests, `quality-dev`,
and all five expanded acceptance lanes pass.

Definition of Failure: selecting evidence by a shared target without exact
branch ownership; deriving through multiple predicates or unequal exits;
repairing polarity or casts in Rewrite/CLI; matching rendered C, assembly text,
function names, or addresses as proof; losing a call or scan; retaining a
compiler warning or runtime timeout; or weakening any validation or test gate.

#### DrawFrame regenerated frame-setup carrier closure contract

Reason: a canonical `push bp; mov bp, sp` entry may lose every structured
`push bp` carrier during earlier semantic cleanup while GP-state lowering keeps
the setup write as a coherent `inertia_ebp` assignment. Requiring only the
vanished push carrier strands exact decoded frame evidence and makes a compiler
frame effect look like an uninitialized user local.

DoD: a failing-before production-shaped test proves the missing-push-carrier
case; a noncanonical decoded entry refuses pruning; the owner consumes only an
exact tagged BP setup write paired with decoded canonical entry evidence; live
DrawFrame retains every source-required call and loop, passes whole-tail
validation and strict C11 syntax, and all changed-surface and mandatory project
gates pass.

Definition of Failure: pruning from a function address, C spelling, variable
name, or rendered text; accepting a noncanonical entry or an unowned write;
moving the repair to Rewrite; losing a DrawFrame call or control-flow effect;
leaving validation changed/uncollected; or weakening/excluding any gate.

#### InitMenu dead packed-FLAGS chain closure contract

Reason: DCE correctly made the obsolete flag-derived branch empty, but Tail
Validation observed that no-op control node and rolled the pass back. After the
empty branch was removed atomically, Lowering's live-in owner inventory still
made every assignment to the packed FLAGS identity permanently protected, so a
semantically dead parity/update chain survived in generated C.

Definition of done: DCE removes only explicit empty `if/else` nodes whose
condition is proven pure; effectful conditions are refused; a packed-FLAGS
initializer remains while an exact consumer exists and expires after the full
consumer chain is dead; evidence counters close; focused Ruff, MyPy, and tests
pass; real sidecar-free `SORTD.EXE` `0x10060` reports `validation=passed` and
emits no raw `inertia_flags`, parity temporaries, or unsupported instruction.

Definition of failure: deleting a single-arm or effectful condition; treating
packed-FLAGS metadata as permission to delete a still-read initializer; keeping
an initializer after all consumers disappear; failing evidence closure, type,
lint, focused tests, C syntax, or Tail Validation; or retaining any raw FLAGS
carrier/parity chain in the accepted `0x10060` C.

#### CMP16 return-chain polarity closure contract

Reason: the machine `JNE` target returns `13`, but Structuring paired that edge
with the equivalent-looking `call ? 0 : 1` truth-value projection and retained
its opposite polarity. Exact branch ownership and decoded JCC meaning must stay
coherent when a return chain is rebuilt.

Definition of done: the selector uses a typed same-branch proof; explicit zero
tests, direct/negated calls, and boolean call ITEs have one normalized polarity;
an unproven branch identity refuses replacement; focused and existing
return-chain tests pass; the real CMP16 `main` preserves all thirteen calls and
returns with `validation=passed`; Ruff, MyPy, optimization comparisons, and
`quality-dev` pass.

Definition of failure: choosing decoded or structured polarity without matching
CFG ownership, accepting `CmpEQ` for the taken `JNE` return edge, matching
rendered C or assembly text, repairing the condition in Rewrite or validation,
losing a call/return, or any required test, lint, type, executable, or quality
gate failure.

#### Architecture hard-gate promotion closure contract

Reason: a production module that owns semantic or structural behavior but is
absent from the global type/lint and architecture inventories can silently
drift outside the layer rules even when its focused tests pass.

Definition of done: every newly introduced owner is enrolled in the project
Ruff/MyPy targets and the architecture promotion set, exact layer headers pass
the ownership checker, and the complete edited-state `quality-hard` target
returns zero without exclusions or weakened checks.

Definition of failure: any owner remains outside those inventories, an exact
layer marker is missing, Ruff/MyPy/mypyc/architecture/context checks fail, or a
new skip, ignore, or reduced check scope is used to obtain a green result.

#### angr Clinic semantic-stage compatibility closure contract

Reason: after the angr/Python dependency refresh, Clinic requires argument and
de-SSA mappings produced by its pre-SSA, SSA, and post-SSA stages before
variable recovery. Inertia's tiny-helper cost policy was incorrectly bypassing
those semantic stages and later produced either an assertion or raw invalid C.

Definition of done: cost guards may bound inner simplification and peephole
work but cannot skip semantic Clinic stages; a focused contract proves stage
execution; `inc_one`, `bump_static`, and `add_sc` produce readable C with clean
Tail Validation; direct Ruff/MyPy pass; and the complete `test-pipeline`
recompiles and executes all seven MS C tiny constructs with exit `255`.

Definition of failure: any semantic Clinic stage is bypassed, empty argument or
de-SSA inputs are invented, a rendered-C repair hides raw addressing, one of
the three focused helpers asserts/falls back/fails validation, or any curated
unit or external round-trip gate fails.

#### Simple-control signed-argument closure contract

Reason: condition-proven signedness belongs to Types/Lowering, while the final
AST orchestrator may only replay that owner after late condition regeneration.
Losing GP assignment tags also made canonical frame pruning unable to identify
the original `mov bp, sp` carrier.

Definition of done: provenance survives GP subregister projection; normalized
ConditionIR facts use authoritative machine-BP coordinates; the selected
`classify`, `sum_to`, and `switch_fold` outputs have clean Tail Validation;
generated C recompiles; the rebuilt executable exits `255`; focused Ruff,
MyPy, architecture, unit, and default-pipeline gates retain the evidence.

Definition of failure: raw positive-BP inference in Rewrite, rendered-C or
assembly matching, an architecture-guard exception that moves semantics late,
loss of an argument/sign/branch, conflating a rejected attempt with the selected
result, rebuilt exit other than `255`, or any required regression/gate failure.

#### Function-pointer stack-identity closure contract

Reason: Structuring had materialized the exact `which` condition at machine
`BP+4`, but Rewrite replaced it through the stale display name `arg_6` with the
next argument at `BP+6`. Tail Validation then canonicalized both surfaces and
missed the storage redirect.

Definition of done: argument substitution consumes only Alias-owned stack
identity; verified stack-prototype materialization is published even when the
AST needs no physical change; Tail Validation compares keyed stack coordinates
across Rewrite and hard-fails drift; `select_and_apply` tests `which`, retains
both function targets, and returns `apply_twice(fn, value)`; the four-function
translation unit recompiles and exits `255`; focused tests, Ruff, MyPy,
type/doc ratchets, `quality-dev`, and optimization comparisons pass.

Definition of failure: argument recovery by display name, rendered C, source,
or assembly text; semantic repair in Rewrite; accepting changed or uncollected
condition storage; loss of either function target or a call argument; rebuilt
exit other than `255`; or any required test, type, documentation, lint,
architecture, validation, or optimization gate failure.

#### Pointer-memory typed value/storage closure contract

Reason: MS C passes an `unsigned char` in a two-byte stack slot, but the load
at machine `BP+6` consumes only its typed low-byte value. Treating the missing
one-byte projection as a raw angr offset redirected it to the following word
argument at `BP+8`.

Definition of done: Types/Lowering records storage width and semantic value
width separately; exact and low-value lookups consume the same Alias-owned
machine-BP identity; high-byte and adjacent-word byte requests refuse; the
generated fill loop assigns `value`, all three functions have clean Tail
Validation, the translation unit recompiles, the rebuilt executable exits
`255`, and focused Ruff, MyPy, architecture, and unit gates pass.

Definition of failure: inferring the argument from a name, rendered C, COD, or
assembly text; implementing value/storage recovery in Rewrite; accepting a
high-byte or adjacent-slot collision; emitting `dst[i] = count`; rebuilt exit
other than `255`; or any required type, lint, architecture, validation, unit,
compile, or runtime gate failure.

#### InitMenu step 5c closure contract

Current revalidation (2026-09-10): the subsequent frame-bookkeeping regression
is closed by [Frontend/IR direction-bit projection](reference/p0-direction-bit-projection.md).
The unchanged behavior acceptance, isolated no-sidecar regression, strict C
compilation, validation and routine gates all pass; no Rewrite recovery was added.

Reason: a block-local dword zero test, unused physical call-result carriers, and
multi-statement C bracing had distinct owners; conflating them would move
semantics into Rewrite and make Tail Validation less trustworthy.

Definition of done: the exact binary-derived condition reaches Structuring,
both branch calls survive, only typed unobserved AX/EAX results are discarded,
the generated sidecar-free and sidecar-assisted C compiles, Tail Validation is
clean, and the permanent live and refusal tests pass.

Definition of failure: any source/name/address/rendered-text recovery, semantic
statement movement in Rewrite, deletion under unknown return-use evidence,
lost call, unsupported/raw flag carrier, validation failure, or C compile error.

#### Loop/control-flow step 5d closure contract

Reason: the failing functions shared validation-clean but noncanonical loop
surfaces whose conditions, exits, and storage identities crossed Condition IR,
status-flag liveness, and Structuring ownership boundaries.

Definition of done: ReInitBars, BubbleSort, ExchangeSort, and PercolateUp pass
live Tail Validation; required calls and stores survive; ordered pretests,
duplicate breaks, and pretest initializers/bodies are materialized only from
unique typed IR/CFG evidence; focused tests and changed-surface gates pass.

Definition of failure: any rendered-text, symbol-name, or address-specific
recovery; semantic repair in Rewrite or CLI; ambiguous condition/loop ownership
accepted instead of refused; lost call/store; validation failure; or focused
test, type, documentation, lint, or compilation failure.

#### Call/object/indexed-storage step 5e closure contract

Reason: exact call arguments, pointer classes, segmented live-ins, object
widths, and indexed global storage cross Alias and Types/Lowering contracts;
late name-based or rendered-C repair can silently change value-versus-pointer
semantics.

Definition of done: all five live materialization regressions pass with
`validation=passed`; required calls, argument classes, indexed stores, and
object widths survive; generated C passes portable syntax checks; the closed
evidence counters have no classified-but-unmaterialized facts; focused tests,
Ruff, MyPy, type/doc ratchets, and architecture ownership checks pass.

Definition of failure: any function/address/source/COD/rendered-text-specific
guess; name-based pointer or helper substitution; semantic repair in Rewrite or
CLI; lost call/store, wrong value-versus-pointer class, ambiguous evidence
accepted instead of refused, Tail Validation failure, C compile error, or any
required focused type, documentation, lint, architecture, or test failure.

#### DrawFrame step 5f closure contract

Reason: Structuring had a closed typed proof that both pure guard arms returned
the same value, while Tail Validation omitted the normal two-effect `if/else`
surface. Independently, postprocess mistook an initialized compatibility flag
for proof that its transaction had completed and compared against a stale
uncanonicalized baseline.

Definition of done: sidecar-free DrawFrame emits all three fill, position, and
buffer-output calls; retains the source-equivalent inclusive loop; compiles as
portable C; reports `validation=passed`; and its focused tests, Ruff, MyPy,
type/doc ratchets, and startup architecture check pass.

Definition of failure: accepting unrelated validation channels or unbounded
control-flow deltas; repairing the guard in Rewrite; parsing rendered C; using
a function/address-specific exception; losing a required call, loop bound, or
argument class; or any required focused gate failure.

#### RunMenu step 5g closure contract

Reason: Tail Validation must distinguish an arbitrary unresolved virtual from
an AIL virtual with exact physical-register provenance. Otherwise typed IR
evidence for packed FLAGS preservation is collected but cannot be consumed,
and valid structured C is rejected at final emission.

Definition of done: sidecar-free RunMenu retains `local_2 = sub_11292();`, all
ten switch cases, and `case 27: return;`; emits `extern long g_0132;`; reports
`validation=passed` and clean whole-tail validation; compiles under strict C11;
and exact-site, wrong-site, focused flag/validation/structuring, lint, type/doc,
and startup architecture gates pass.

Definition of failure: treating every virtual carrier as initialized; accepting
a packed-FLAGS read without exact frontend instruction evidence; adding a
RunMenu/address/rendered-C exception; repairing semantics in Rewrite or CLI;
losing a call, case, return, or signed declaration; or any required focused
gate failure.

### Forecasted Execution Steps

This table is the estimation calibration record for the remaining plan. A row
gets an actual start only when work begins and an actual finish only after its
DoD passes. `Spent` is focused engineering time; unattended builds and test
wall time are recorded in the active-step table or acceptance evidence. The
estimate is revised after every completed row, so later estimates are based on
measured root-cause closure time rather than the number of failing tests.
The final cell in each row is that row's DoD. Missing any listed condition,
weakening a gate, or moving semantics to a later layer is its definition of
failure; the detailed reason and failure clauses remain authoritative in the
numbered task section below.
The rows were designed as non-overlapping historical estimates totaling 80-115h.
That forecast is withdrawn pending current acceptance and root-cause review.
Estimates for the remaining live families are deliberately
separate: a passing test count cannot hide an independent semantic owner or a
validation blind spot.

#### Remaining priority by impact

User stop condition (2026-09-11): finish Step 9 completely, then stop work and
report its acceptance evidence. Do not automatically start Steps 11 or 12.
They remain pending in the full plan and require a new user instruction to
resume. Step 10 work before this checkpoint is limited to measured bottlenecks
needed for Step 9. A green curated lane alone does not trigger this stop:
Step 9's full-suite and quality acceptance below must pass first.

Priority is determined by semantic blast radius and dependency leverage, not
by the easiest percentage gain:

1. **P0 - Step 9, full-suite semantic and interprocedural-contract closure.**
   This is the only remaining step that advances both Task 3 and Task 8, makes
   the complete pytest collection trustworthy again, and removes correctness
   and recompilability defects on which every later quality task depends. The
   earlier `loadprog` storage slice established a binary-proven four-byte
   stack owner, exact Tail Validation subviews and predecessor-specific terminal
   returns. September 19 then exposed missing byte-source bindings and lost
   projection evidence. The latest live run and recompilation now pass after
   generic Alias and cleanup fixes, including an isolated no-source-fallback
   run. The active boundary remains the exact full collection and its refreshed
   failure inventory. Process failures by shared owner:
   multi-output/indexed/indirect storage first, type and object identity second,
   CFG/condition recovery third, and isolated corpus regressions only after
   those shared mechanisms close.
2. **P1 - Step 11, proof-backed readability.** Restored by user on 2026-09-11.
   Begin after Step 9 correctness closure. Prioritize proven stack locals and
   arguments, explicit conditions, and removal of redundant expressions using
   existing evidence. Do not hide unresolved semantics with prettier output.
3. **P2 - Step 12, evidence-supported Reko mechanisms.** Implement after
   the preceding non-performance work, and
   only where the existing IR/Alias/Types contracts can prove the mechanism;
   unsupported proposals must be explicitly closed with evidence rather than
   implemented speculatively.
4. **Conditional - Step 10, measured code or test bottlenecks.** Optimize when
   measurements show material benefit to execution or the development loop;
   a broad campaign remains secondary to P0. Re-profile current HEAD before
   selecting an implementation, preserve accepted/rejected experiment records,
   and retain semantic acceptance and aggregate-worker memory limits. Use
   mypyc only for measured residual Python kernels, not speculative compilation.

Correctness-required mechanisms from Steps 11 or 12 belong to Step 9's active
dependency chain and must not wait for their optional quality phase. Test and
linter closure remain P0, not a final cleanup phase. Performance work may
interrupt this order only when measurements justify its development-time or
execution benefit without weakening correctness gates.

Reason: reduce time to functional and quality closure without optimizing code
that correctness work will replace or repeating rejected experiments.
Scheduling DoD: each optimization has a measured bottleneck, controlled
before/after timings, preserved coverage and semantic gates, and a documented
decision; substantial changes retain the 10% end-to-end acceptance threshold.
Definition of Failure: speculative complexity, weaker coverage or diagnostics,
unrepeatable speed claims, or postponing a live-code preservation fix because
its owner happens to be an optimization pass.

P0 definition of done: every currently failing in-scope repository test is
either corrected by a generic earliest-layer implementation or retired with
documented supersession evidence; the exact complete collection has zero
failures; `quality-hard`, default, and expanded pipelines pass; and all closed
evidence counters remain balanced. P0 definition of failure: accepting a
curated lane as full-suite success, changing tests to bless semantic loss,
repairing calls/types/storage in Rewrite or CLI, introducing corpus-specific
logic, or leaving any unexplained failure hidden by selection, timeout, skip,
or output filtering.

| Order | Step | Start | Finish | Spent | Current estimate | Dependency / completion boundary |
| ---: | --- | --- | --- | ---: | ---: | --- |
| 1 | Reproduce and symptom-cluster the current focused failures | `2026-08-29 12:49:42 +02:00` | `2026-08-29 12:54:19 +02:00` | 4m37s focused; 2m45s test wall separate | complete | Complete lane: 3,968 passed / 17 failed. Exact retry: 16 failed / 1 passed. Six independent symptom families are recorded. |
| 2 | Close frontend/debug and test-profile contract failures | `2026-08-29 11:27 +02:00` | `2026-08-29 11:49 +02:00` | 10-15m agent time, overlapped | complete | Focused failures pass without weakening unsupported-instruction exits or retiring required coverage. |
| 3 | Close stack-coordinate, argument-identity, and stack-object unit failures | `2026-08-29 11:27 +02:00` | `2026-08-29 11:49 +02:00` | 15-22m local/agent time, overlapped | complete | Machine-BP facts resolve through the authoritative coordinate projection; focused unit clusters and refusal cases pass. |
| 4 | Close ALU carry/borrow effect-order integrations | `2026-08-29 11:27 +02:00` (delegated) | `2026-08-29 12:07 +02:00` | 25-35m agent time, overlapped; exact timer unavailable | complete | Generated C preserves one low-half operation and one proven high-half carry/borrow effect; both focused integrations and the 52-test suite pass. |
| 5a | Fix Swaps destination identity and the Tail Validation blind spot | `2026-08-29 12:54:19 +02:00` | `2026-08-29 13:32 +02:00` | 31-35m; test waits excluded | complete | The first incorrect consumer was Types/Lowering's raw entry-SP lookup for machine-BP arguments. Two unit regressions, live C semantics, Tail Validation, strict C syntax, and the changed-surface checks pass. |
| 5b | Close DrawTime carry-predicate sibling ownership | `2026-08-29 13:30 +02:00` | `2026-08-29 13:43 +02:00` | 10-13m; test waits excluded | complete | A typed missing predicate searches the complete function only through the existing unique exact arithmetic/CFG ownership proof. Ambiguous and mismatched evidence still refuse; the focused and live regressions pass. |
| 5c | Close the three InitMenu validation/condition failures | `2026-08-29 14:23 +02:00` (approximate) | `2026-08-29 15:16 +02:00` | 35-45m focused; 63.22s final live-test wall separate | complete | Exact binary-backed conditions and the pause guard validate; both calls survive; sidecar-free and sidecar-assisted C compile; Rewrite adds braces only and does not recover semantics. |
| 5d | Close the five validation-clean loop/control-flow shape failures | `2026-08-29 15:29 +02:00` | `2026-08-29 16:50 +02:00` | exact focused subtotal unavailable after interruption | complete | ReInitBars, BubbleSort, ExchangeSort, and PercolateUp use IR/CFG-owned condition and loop structure, pass live Tail Validation, and retain required calls and stores. |
| 5e | Close the five call/object/indexed-storage materialization failures | `2026-08-31 21:43 +02:00` | `2026-08-31 22:22 +02:00` | 24-30m focused; final 54.31s test wall separate | complete | Five live regressions plus supporting unit contracts pass; exact typed target identity removes stale numeric declarations and lower-level IR replay cannot overwrite stronger object lowering. |
| 5f | Close the DrawFrame validation failure | `2026-08-31 22:27 +02:00` | `2026-08-31 22:59 +02:00` | 18-24m focused; final 10.86s related-suite wall separate | complete | DrawFrame passes Tail Validation with no semantic repair in Structuring cleanup or Rewrite; the source-equivalent loop and every required call survive. |
| 5g | Close the RunMenu portable-C declaration failure | `2026-08-31 23:29 +02:00` | `2026-08-31 23:54 +02:00` | 17-20m focused; final two-test live wall 50.04s | complete | RunMenu validates, compiles as portable C, retains the Escape path and call result, and consumes packed-FLAGS evidence only through exact physical-register identity. |
| 6 | Rerun the complete focused pytest lane and classify any newly exposed failures | `2026-09-01` (exact start not retained) | `2026-09-01 03:55 +02:00` | test wall recorded separately | complete | The complete unit lane passes 1,906 tests; each external MS C failure has a concrete function-level symptom. |
| 6a | Close CMP16 stale accepted-return propagation and its validation blind spot | `2026-09-01 03:28 +02:00` | `2026-09-01 03:55 +02:00` | 15-20m focused; test waits excluded | complete | Widening invalidates branch-joined definitions, Structuring guards the proven return fingerprint, and the full `compare16` round trip exits `255`. |
| 7a | Close `simple_control` GP provenance and signed argument projection | `2026-09-01 03:56 +02:00` | `2026-09-01 04:54 +02:00` | 25-35m focused; test waits excluded | complete | The existing Types/Lowering owner consumes projected machine-BP coordinates; all three selected functions validate and the rebuilt executable exits `255`. |
| 7b | Close function-pointer stack identity and condition integrity | `2026-09-01 05:45 +02:00` (first retained checkpoint) | `2026-09-01 06:20 +02:00` | 30-40m focused; test waits excluded | complete | Alias-owned storage identity survives Rewrite; the generic validation guard rejects argument redirects; the full `function_pointers` gate exits `255`. |
| 7c | Close `pointer_memory` typed byte-value storage | `2026-09-01 06:20 +02:00` | `2026-09-01 06:41 +02:00` | 15-20m focused; test waits excluded | complete | Types/Lowering owns the typed low-byte projection inside the word ABI slot; the full gate exits `255`. |
| 7d | Fix and rerun the remaining `scalar_types_io` gate | diagnosis refreshed `2026-09-01 06:20 +02:00` | `2026-09-01 11:04 +02:00` | included in the measured Ultra arguments closure; waits excluded | complete | All ten selected functions validate; the translation unit recompiles and the rebuilt executable exits `255`. |
| 7e | Close CMP16 final return-chain branch polarity | `2026-09-01 19:55 +02:00` | `2026-09-01 20:33 +02:00` | 25-35m focused; test waits excluded | complete | Structuring reconciles exact-tagged call truth projections with the decoded JCC only under same-branch proof; real CMP16 validation and `quality-dev` pass. |
| 7f | Close DrawBar's machine-BP/entry-SP call-address collision | before `2026-09-01 22:34 +02:00`; exact first command lost at compaction | `2026-09-01 22:49 +02:00` | 55-75m focused; waits excluded | complete | Exact typed address-source identity overrides stale whole-call quality scoring; live `0x106c8` validates and the default pipeline remains green. The then-independent DrawFrame frame-carrier failure is tracked by 7g. |
| 7g | Close DrawFrame's regenerated canonical frame-setup carrier | `2026-09-01 22:50 +02:00` | `2026-09-01 23:03 +02:00` | 18-25m focused; waits excluded | complete | An owned BP setup write plus decoded canonical entry evidence survives earlier PUSH cleanup; live `0x101f0` validates, compiles, and retains every required call and loop. |
| 8 | Run `quality-hard`, `test-pipeline`, and required expanded acceptance gates | started `2026-09-01` | `2026-09-02 02:49 +02:00` | historical gate work plus 25-35m final closure engineering; test walls separate | complete | `quality-hard`, `quality-dev`, 1,919 curated tests, and the expanded 5/5 acceptance pipeline are green without exclusions or weakened checks. |
| 8a | Audit the complete pytest collection and classify every failure family | `2026-09-02` | `2026-09-02 03:04 +02:00` | test wall recorded separately | complete | Exact `pytest -n 7 --dist loadgroup --durations=10` audit: 10,091 collected, 9,865 passed, 56 failed, 170 skipped in 724.28s. Failures are grouped into COD/F14/DOSFUNC recovery, SORTD/source-sidecar behavior, three fast unit-contract families, and the slow TIDShowRange/debug corpus. |
| 9a | Close terminal local pointer-output carrier versus scalar-return identity | `2026-09-02 03:04 +02:00` | `2026-09-02 04:03 +02:00` | 40-55m focused; quality and pipeline waits separate | complete | Semantics owns a typed all-terminal-path proof; Types consumes it only with complete unused-caller evidence and a guessed prototype. Swaps becomes `void`, direct-global `_SetDLC` remains scalar, uncertain paths refuse demotion, `quality-dev` and the required executable pipeline pass. |
| 9b | Close `_ConfigCrts` byte-lane projection and cross-structure temporary liveness | `2026-09-02 04:28 +02:00` | `2026-09-02 05:05 +02:00` | 24-30m focused; gate waits excluded | complete | Types/Lowering preserves exact byte subviews, Widening proves exact word recomposition, and Rewrite cleanup refuses deletion across a live enclosing continuation. Real Tail Validation, 29 focused tests, `quality-dev`, and mandatory plus expanded pipelines pass. |
| 9c | Preserve validated callee pointer evidence across exact-function project views | `2026-09-02 12:43 +02:00` | `2026-09-02 13:01 +02:00` | about 18m focused; test waits included | complete | The existing ABI seeding service rebases immutable pointer evidence, detects conflicts, and makes HeapSort's two `Swaps` arguments typed pointers. Focused source-assisted and sidecar-free validation, strict C11 syntax, Ruff, MyPy, architecture checks, and `quality-dev` pass. |
| 9d | Keep Swaps call-frame and pointer-swap projections coherent through final regeneration | before `2026-09-02 14:02 +02:00`; exact start lost at compaction | `2026-09-02 14:13 +02:00` | exact subtotal unavailable after compaction | complete | Typed return-frame ownership, machine-BP validation coordinates, and the unique exact swap projection now survive their downstream consumers. Live Swaps has exactly three object-copy assignments, the counter effect, clean Tail Validation, and strict C syntax; focused Ruff, MyPy, `quality-dev`, and regression gates pass. |
| 9e | Keep typed C-function stack coordinates coherent across final validation | before `2026-09-02 15:06 +02:00`; exact start lost at compaction | `2026-09-02 16:08 +02:00` | 45-60m focused after the first checkpoint; broad gate wall separate | complete | The Types/Lowering owner accepts only the canonical near-frame entry-SP-to-BP delta and may project unregistered negative locals, while positive slots remain under Alias/type ownership. Live uncached DrawBar passes; 101 focused tests, `quality-dev` with 1,924 tests, and the mandatory pipeline are green. `scalar_types_io`, including `add_long`, recompiles and exits `255`. |
| 9f | Refresh the complete failure inventory and remove superseded fixtures | `2026-09-06 15:14 +02:00` | - | 41m first census/checkpoint plus current focused closures; failed-set and pipeline waits separate | in progress | The complete 10,208-test run reached 10,016 passed / 22 failed / 170 skipped in 1,233.30s, but remains non-authoritative because source changed. A later source-stable retained-failure run reached 14 failed / 48 passed / 1 skipped in 386.32s; this is a focused checkpoint, not a replacement full-suite count. Steps 9m-9p close QuickSort's typed-view, combined Structuring-validation and final stack-coordinate failures, plus OVERLAY's far-pointer constant and wide-return failures. The named and sidecar-free QuickSort regressions and the focused OVERLAY regression now pass. Step 9f still requires a source-stable complete collection and zero failures. |
| 9g | Close sidecar-free CMP32 wide argument owner materialization | before `2026-09-06 16:33 +02:00`; first retained diagnostic checkpoint | `2026-09-06 16:50 +02:00` | 25-35m focused; repeated executable waits excluded | complete | Types/Lowering now consumes body-proven four-byte argument starts while building the positive-BP interface, before stable stack projection. Already-correct wide types also enlarge their physical stack owner. The storage-width regression failed before the fix; 130 changed-surface tests, the 1,926-test `quality-dev` lane, the mandatory seven-program MS C pipeline, and all four sidecar-free CMP32 Tail Validation regressions pass. |
| 9h | Close RunMenu JCC-owned dword access provenance | before `2026-09-06 18:10 +02:00`; exact first diagnostic lost at compaction | `2026-09-06 18:26 +02:00` | exact subtotal unavailable after compaction; final 20m retained; 6m29s changed-file test wall separate | complete | Types/Lowering first uses exact instruction tags, then consults an exact tagged VEX block only when the segment contract identifies one unique matching access instruction. Ambiguous or incomplete facts still refuse. Both RunMenu variants validate, strict portable-flat C compilation succeeds, and scalar `clPause` high/low projections replace invalid subscripting. The focused 15 policy tests, three dword regressions, Ruff `--fix`, MyPy, and the type/doc ratchet pass. The broader ownership-selected run was 228 passed and 14 failed in concurrently modified non-RunMenu SORTD families; Step 9f therefore remains open. |
| 9i | Keep indexed-condition addresses independent from compared-value width | `2026-09-06 18:35 +02:00` | `2026-09-06 19:05 +02:00` | 9m focused implementation plus 1m27s initial and 1m05s final live-test wall | complete | Structuring's compatibility consumer retains the exact condition producer binding for register-index resolution but no longer applies an 8-bit comparison view to a proven 16-bit address index. The fail-first unit and 402-test initial surface pass. After 9j removed the independent duplicate-call failure, sidecar-free BubbleSort, ExchangeSort, and PercolateDown all emit full-word indexes, pass Tail Validation, preserve required calls exactly once, and compile under strict portable-flat C. |
| 9j | Count exact attached callsite identities before recovering missing calls | diagnosis began before `2026-09-06 19:01 +02:00`; exact continuation start not retained | `2026-09-06 19:13 +02:00` | 25-35m focused across continuation; gate waits separate | complete | Types/Lowering owns exact live-callsite presence; Structuring attaches and splits those identities before missing-target recovery and reattaches only after a genuine insertion. Rewrite retains compatibility fallback only. Live and stale-node regressions pass; 305 focused tests, the final 503-test changed-file gate, all three affected SORTD functions, and strict C syntax are green. The two independent shared-tree pipeline blockers exposed here are closed by the corrected void-return ownership assertion and Step 9k; the mandatory pipeline is green again. |
| 9k | Inventory unresolved indirect calls before callsite summarization | diagnosis began before `2026-09-06 19:16 +02:00`; exact start lost at compaction | `2026-09-06 19:44 +02:00` | 25-35m focused; two pipeline waits recorded separately | complete | Frontend owns one deterministic decoded function-instruction inventory and exposes every exact near/far call address, including unresolved indirect calls omitted by angr's resolved callsite set. The existing Recovery Metadata summarizer records `target_source=("bp", 4)` and Types/Lowering materializes the function-pointer parameter. Generic inventory, bridge, and direct-recovery-refusal tests are enrolled in the curated lane; live `apply_twice` validates and emits a callable typed parameter; all four `function_pointers` functions recompile and execute with exit `255`; the mandatory 3/3 pipeline passes with 1,940 pytest tests and all seven MS C construct groups. |
| 9l | Preserve signed semantic views and own shared-tail returned-call clones | after `2026-09-06 20:44 +02:00`; exact start not retained | `2026-09-06 21:56 +02:00` | 45-60m focused; gate waits separate | complete | Types/Lowering preserves `CSemanticCast8616` through stack canonicalization and canonicalizes exact call targets from typed KB identity; Tail Validation fingerprints semantic source/destination width and signedness; Structuring removes a returned-call clone only from the same exact callsite, physical return register, argument ASTs, and proven shared CFG tail. Named and sidecar-free Sleep regressions, divergent-argument refusal, 181 related tests, focused Ruff/MyPy, startup architecture and ownership checks, the 1,944-test curated lane, and all seven configured MS C round trips pass. The prior 17-failed / 5-passed checkpoint predates this slice and must not be reused as a current count. |
| 9m | Validate exact semantic casts as typed comparison views | `2026-09-06 22:06 +02:00` | `2026-09-06 22:24 +02:00` | 18m focused; 1m35s executable wait separate | complete | Validation projects an explicit `CSemanticCast8616` to its storage fingerprint only when source width, destination width, and ConditionIR-required signedness match exactly. Wrong signedness, widening, unknown width, and untyped casts refuse. QuickSort's two `branch-condition:predicate-mismatch` failures disappear with byte-identical generated C; its independent structuring-snapshot and def-use failures remain visible. Ruff `--fix`, strict MyPy, 131 adjacent tests, and startup architecture/context/ownership gates pass. |
| 9n | Compose identical-return and JCC Structuring validation proofs | `2026-09-06 22:36 +02:00` | `2026-09-06 23:12 +02:00` | about 28m focused plus 8m current-tree revalidation; executable waits separate | complete | Tail Validation consumes only the exact condition/control-flow observations owned by one closed identical-return collapse and leaves a balanced residual for the existing JCC validator. Seven focused tests, strict MyPy, Ruff `--fix`, and architecture checks pass; sidecar-free QuickSort passes and source-assisted QuickSort reaches `structuring=stable`, exposing only the independent final stack-coordinate defect closed by 9o. |
| 9o | Resolve final C argument coordinates through the complete function interface | `2026-09-06 23:12 +02:00` | `2026-09-06 23:24 +02:00` | 12m focused; live-test waits separate | complete | Validation consumes the existing Types/Lowering whole-function coordinate projection before ambiguous per-variable fallback. Entry-SP `+4` no longer collides with the first argument's machine-BP `+4`; both QuickSort arguments initialize `BP+4..+7`, parameter width facts resolve at `BP+4/+6`, 53 focused unit tests pass, and named plus sidecar-free QuickSort validate and recompile. The source-comparison fixture now accepts only the explicit 16-bit semantic view while retaining exact call, pointer-index, and recursion-bound checks. |
| 9p | Preserve wide far-pointer returns and materialize exact stack-offset constants | before `2026-09-07 00:30 +02:00`; exact first diagnostic not retained | `2026-09-07 01:05 +02:00` | exact subtotal unavailable across continuation; final implementation and verification about 25m; test waits separate | complete | Types/Lowering now recognizes only an exact byte-pair word-load shape, so materialization cannot consume its enclosing DX:AX return. Decoded same-block constant flow retains `36` only through exact register and BP-stack identities; overlapping or unresolved writes invalidate it. The focused OVERLAY body emits both words and `36 + (funcNumber << 1)`, passes clean whole-tail validation, avoids asm fallback, and recompiles as portable-flat C. Eight focused tests, the 190-test segmented-load surface, and the 52-test changed-file gate pass with Ruff `--fix`, MyPy, type/doc ratchet, startup architecture, context, and ownership checks green. |
| 9q | Preserve caller-clean arguments and current typed stack-owner widths | before `2026-09-07 02:27 +02:00`; exact first diagnostic not retained | `2026-09-07 02:46 +02:00` | exact subtotal unavailable across continuation; final root fix and verification about 12m; executable waits separate | complete | Recovery Metadata no longer interprets a returning callee's zero terminal cleanup as zero arguments. ARGS retains its three physical CRT pushes, folds the stale `BP+5` byte view into the current word owner, materializes the `BP+6` pointer, passes strict recompilation and clean whole-tail validation, and is byte-deterministic across three generated-C checks. The 131-test argument surface, the 137-test callsite/fixture surface, focused Ruff/MyPy/type gates, and all four Ultra QuickC fixtures pass. The fixture AST parser is independent of host libc headers. |
| 9 | Finish remaining general interprocedural contracts, full-suite failure families, and open Ghidra mechanisms | `2026-09-02 02:10 +02:00` | - | prior closures plus completed 9c/9d/9e slices; waits excluded where recorded | Unestimated: historical 55-76h is stale; recalibrate against current complete-suite failures and open contracts | Tasks 3 and 8 meet their per-step DoD for general indexed, indirect, stack, multi-output, type, CFG, COD, and full-suite contracts; the exact complete collection reaches zero failures without hiding coverage. |
| 10 | Profile and optimize the remaining serial decompiler tail | prior accepted work; see DECOMPILER_PERFORMANCE_PLAN.md | - | recorded per experiment; no reliable aggregate | needs current-HEAD profiling | Accepted optimizations already exist. Re-profile before extending or closing this step; retain aggregate-memory and semantic gates. Do not repeat rejected experiments. |
| 11 | Audit accepted proof-backed readability | resumed 2026-09-19 23:11 +02:00 | - | first slice approximately 35m, including gates | bounded audit pending | Signed-conversion slice accepted; new SP-proof machinery deferred by approved remaining-plan-acceptance.md. |
| 12 | Audit existing mechanisms and named-function correctness | audit started 2026-09-19 | - | not yet aggregated | bounded audit in progress | 168 storage-contract tests pass; seven-function acceptance and final gates remain. Broad mechanism implementation deferred. |

#### Step 9c acceptance contract

Reason: pointer-argument classification was already correct in the full-binary
project, but its per-project registry disappeared when CLI created an exact
function project. The downstream call lowering therefore received no pointer
identity and rendered numeric values even though the callee evidence existed.

Definition of done:

- the existing Types/Lowering ABI service transfers only already-validated,
  immutable pointer evidence and rebases only the source and target addresses
- conflicting target evidence refuses replacement, incomplete prototypes do
  not discard independent pointer evidence, and no new pointer classification
  occurs at the project boundary
- source-assisted and sidecar-free HeapSort preserve both `Swaps` pointer
  argument classes, report `validation=passed`, and compile as strict C11
- focused tests, Ruff `--fix`, MyPy, architecture import checks, and
  `quality-dev` pass

Definition of failure:

- CLI, Structuring, or Rewrite infers pointer semantics from names, addresses,
  rendered C, or call shape
- evidence is silently overwritten, transported without validation, or lost
  merely because a complete prototype cannot yet be formed
- output becomes prettier while a call, argument class, memory effect, CFG
  edge, Tail Validation result, compile gate, type, documentation, or lint gate
  regresses

#### Step 9d acceptance contract

Reason: Swaps exposed three projection-coherence defects. Fixed stack-probe
removal could leave its CALL return-frame artifacts behind; exact-function C
arguments used entry-SP-like slots while validation compared machine-BP ABI
slots; and final shared-call regeneration could restore a raw temporary load
already consumed by the lowering-owned pointer-swap projection.

Definition of done:

- fixed stack-probe removal consumes its typed CALL return frame first and does
  not emit the return IP as a local/object write
- Tail Validation maps the active exact C argument list to deterministic
  machine-BP ABI offsets and refuses incomplete or ambiguous layouts
- one unique exact pointer-swap sequence survives final Structuring
  regeneration; only an extra temporary load tagged inside the already-proven
  instruction region is removed
- live Swaps retains the global increment, one temporary load, both pointer
  stores, `validation=passed`, and strict generated-C compilation
- focused return-frame, pointer-swap, validation-coordinate, and owner tests,
  Ruff `--fix`, MyPy, and index coverage pass

Definition of failure:

- generic DCE is taught to discard arbitrary pointer reads, or Rewrite/CLI
  reconstructs the swap
- an untagged, ambiguous, unrelated, call-bearing, memory-writing, or
  control-flow statement is removed
- argument names, source labels, function addresses, rendered C, or corpus
  shape become semantic evidence
- the global increment, either pointer store, call/frame effect, validation
  verdict, compile gate, type, documentation, lint, or deterministic output
  regresses

#### Step 9e acceptance contract

Reason: Tail Validation had begun canonicalizing final C arguments onto
machine-BP ABI offsets, but unregistered locals still used angr entry-SP
offsets. DrawBar therefore compared the same storage as `BP-0x2c` versus
`BP-0x2e`, and some final arguments as `BP+0x4` versus `BP+0x2`. Keeping the
argument-only translation in Tail Validation created two competing coordinate
truths.

Definition of done:

- Types/Lowering owns a typed function-wide coordinate projection and Tail
  Validation consumes that owner instead of duplicating ABI arithmetic; final
  argument storage may prove the coordinate relation while a transient
  function type is unavailable, but it does not prove parameter types
- only the coherent 16-bit near-frame relation from entry-SP `+2` to
  machine-BP `+4` is accepted; mixed, incomplete, already-projected, and
  noncanonical interfaces refuse
- the function-wide fallback projects only negative local slots; unregistered
  positive slots keep their original coordinate so wide-argument
  materialization remains the authoritative owner
- argument and local dependencies use the same proven delta, so DrawBar loses
  all `+2/+4` and `-0x2e/-0x2c` false mismatches
- an uncached live DrawBar run and its permanent regression report
  `validation=passed`, retain generated C, and return zero
- focused coordinate, call-argument, fingerprint, and DrawBar tests, Ruff
  `--fix`, MyPy, architecture ownership, mypyc smoke, `quality-dev`, and the
  mandatory external pipeline pass; `scalar_types_io` recompiles and its
  rebuilt executable exits `255`

Definition of failure:

- Tail Validation, Rewrite, or CLI guesses a universal `+2` correction without
  a coherent final argument-storage interface
- a machine-BP, mixed, one-off `+6`, ambiguous, or incomplete interface is
  shifted; unrelated segmented runtime lowering changes as a side effect
- an unregistered positive slot is shifted before Alias/type materialization,
  or a split-word intermediate surface blocks a proven wide argument
- arguments and locals are canonicalized by separate owners or source/COD,
  names, addresses, assembly, rendered C, or corpus shape become evidence
- DrawBar loses a call, argument dependency, memory effect, return, CFG edge,
  validation verdict, recompilation result, type, documentation, lint, or
  deterministic output

#### Step 9f acceptance contract

Reason: curated and ownership-selected gates can stay green while the complete
pytest collection retains stale fixtures or exposes independent COD, F14, and
SORTD semantic regressions. Concurrent source edits also make raw pass/fail
counts untrustworthy unless the source fingerprint is unchanged for the whole
run.

Definition of done:

- one complete `pytest -n 7` collection starts and ends with the same source
  fingerprint and records exact pass, fail, skip, duration, and slow-test data
- every reproduced failure is classified by its earliest authoritative owner;
  semantic defects receive fail-first focused coverage before implementation
- a fixture is removed or relaxed only when its old assertion is superseded by
  a typed ownership contract and current output remains validation-clean,
  recompilable, behaviorally equivalent, and at least as strict about calls,
  argument classes, memory effects, returns, and CFG
- the complete stable collection has zero failures, while the mandatory MS C
  compile/decompile/recompile/execute pipeline and changed-file Ruff, MyPy,
  type, documentation, architecture, and ownership gates pass
- slow-test evidence and remaining independent root families are retained in
  this plan so the next checkpoint can be reproduced without stale estimates

Definition of failure:

- accept a run whose source fingerprint changed, infer a complete-suite result
  from a subset, or hide missing, duplicate, crashed, or timed-out nodes
- delete or weaken a test merely because it is slow or red, or replace a
  semantic assertion with cosmetic output matching
- repair Alias, type, condition, memory, call, or CFG semantics in Rewrite,
  postprocess, CLI, a corpus-specific address/name rule, or rendered-text logic
- claim completion while any reproduced full-suite failure, Tail Validation
  delta, strict recompilation error, behavior mismatch, type/doc/lint error, or
  non-deterministic output remains

#### Step 9h acceptance contract

Reason: JCC-owned C nodes carried the branch instruction in `ins_addr` while
the compared dword access remained attached to the exact CMP VEX block. The
segment policy therefore refused otherwise proven entry-DS bytes, and the
downstream scalar subword projection emitted invalid `clPause[...]` syntax.
Resolving dynamic codegen ownership against the existing typed segment
contract belongs in Types/Lowering, not Structuring, Rewrite, or CLI.

Definition of done:

- direct and typed-switch RunMenu decompilation both report
  `validation=passed`, and strict portable-flat C recompilation returns zero
- output contains scalar `clPause >> 16` and `clPause & 0xffff` projections and
  no `clPause[` subscript
- the policy's unique and ambiguous block-local cases are covered
- Ruff `check --fix`, MyPy, and the type/doc ratchet pass for touched production
  code

Definition of failure:

- infer an access from block proximity without one unique machine instruction
  and complete matching segment facts, or accept competing matching instructions
- emit scalar subscripting, lose RunMenu's Escape path or call effects, or fail
  Tail Validation or strict C recompilation
- repair the symptom in Structuring, Rewrite, or CLI

#### Step 9i acceptance contract

Reason: an indexed byte load has two independent widths: the loaded value is
eight bits, while its x86 effective-address index remains the proven 16-bit
value. Passing the comparison width into nested address materialization changed
values 128 through 65535 into negative or truncated C subscripts. The frontend
already preserves both widths in typed IR; the compatibility Structuring
consumer must keep the producer binding without conflating those roles.

Definition of done:

- a fail-first typed-condition regression proves that an eight-bit comparison
  retains its two-byte stack index while still resolving register indices at
  the exact condition producer
- BubbleSort, ExchangeSort, and PercolateDown emit full-word array indices with
  no signed-byte cast or `-Wchar-subscripts` failure
- all three functions report `validation=passed`, preserve each required call
  exactly once, and compile under strict portable-flat C
- Ruff `check --fix`, MyPy, type/doc, architecture, ownership, and the focused
  changed-surface tests pass

Definition of failure:

- the load width or JCC signedness narrows, signs, or truncates its address index
- producer binding is discarded, guessed from rendered C, or recovered from a
  corpus-specific address/name pattern
- the symptom is hidden with a warning suppression, cast-only cleanup, Rewrite,
  CLI, or changed test expectation
- any call, argument class, memory effect, branch, validation verdict, strict C
  gate, type, documentation, or lint check regresses

#### Step 9j acceptance contract

Reason: exact-function decompilation can render a callee with a rebased numeric
name while the frontend inventory retains its original callsite and target
addresses. Name-based presence accounting then treated an already represented
binary call as absent and inserted a duplicate after the structured condition.

Definition of done:

- live structured nodes bound to an exact typed summary satisfy that callsite's
  inventory entry regardless of their rendered callee name
- stale node-to-summary bindings cannot hide a genuinely missing inventory entry
- Structuring attaches and splits exact identities before recovery and reattaches
  summaries after a genuine insertion; Rewrite performs no normal-path recovery
- BubbleSort, ExchangeSort, and PercolateDown each retain the required call pair
  exactly once, report `validation=passed`, and compile as strict portable-flat C
- Ruff `check --fix`, MyPy, type/doc, architecture, ownership, and the focused
  changed-surface tests pass

Definition of failure:

- presence is inferred from rendered callee text, source order, or a corpus name
  instead of exact typed callsite identity
- a detached summary suppresses recovery, or an attached rebased call is inserted
  a second time
- semantic call recovery is moved into Rewrite, postprocess cleanup, or CLI
- any required call, argument class, memory effect, branch, validation verdict,
  strict C gate, type, documentation, or lint check regresses

#### Step 9k acceptance contract

Reason: angr's recovered `get_call_sites()` set retained the resolved stack-probe
call in `apply_twice` but omitted both unresolved `call [bp+4]` instructions.
The existing Recovery Metadata summarizer could classify that exact indirect
target source, but it was never invoked for either instruction. Types/Lowering
therefore received zero function-pointer facts and rendered `fn` as a scalar.

Definition of done:

- Frontend exposes one deterministic, address-ordered decoded instruction
  inventory for a recovered function and derives all exact near/far callsite
  addresses from it, including unresolved indirect calls
- callsite summary combines decoded call addresses with resolved CFG calls and
  external tail calls without inventing an indirect target
- unresolved indirect summaries bypass the legacy missing-direct-call recovery
  shim and reach the existing typed function-pointer parameter owner
- live `apply_twice` emits a callable typed parameter, calls it twice with the
  proven argument, reports `validation=passed`, and has a clean whole tail
- the complete `function_pointers` construct recompiles and executes with exit
  `255`; Ruff `check --fix`, MyPy, type/doc, architecture, ownership, focused
  tests, and the mandatory pipeline pass

Definition of failure:

- an unresolved indirect call is omitted, assigned a guessed direct target, or
  recovered from rendered C, source order, names, or corpus-specific addresses
- Frontend, Recovery Metadata, and Types/Lowering keep competing instruction or
  callsite inventories instead of consuming one authoritative decoded owner
- Rewrite, postprocess cleanup, or CLI invents function-pointer semantics
- any call count, argument class, memory effect, CFG edge, validation verdict,
  strict C gate, runtime exit, type, documentation, or lint check regresses

#### Step 9l acceptance contract

Reason: stack C-variable canonicalization stripped every cast before it could
distinguish an owned signed semantic view from a cosmetic code-generation cast.
This changed Sleep's signed comparison while the old Tail Validation
fingerprint erased the same distinction. Independently, a structured condition
and its trailing return carrier could contain clones of one exact callsite with
different display names, so rendered target equality blocked the existing
shared-tail ownership proof. These concerns belong to Types/Lowering, Tail
Validation, and Structuring respectively; Rewrite and CLI must not repair them.

Definition of done:

- stack canonicalization preserves `CSemanticCast8616`, including its exact
  source and destination types, while ordinary cosmetic casts remain removable
- Tail Validation produces distinct fingerprints for signed, unsigned, and
  absent semantic views but retains existing cosmetic-cast normalization
- shared-tail ownership requires one exact machine callsite, matching argument
  ASTs, the exact physical return-register destination, and proven structured
  ancestry plus CFG topology; divergent arguments and ambiguous ownership refuse
- exact typed call targets converge on the authoritative project function and
  metadata name even when an AST clone starts with a stale numeric display name
- named and sidecar-free Sleep pass Tail Validation with one required call;
  focused Ruff `check --fix`, MyPy, type/doc, architecture, ownership, related
  tests, and the mandatory MS C pipeline pass

Definition of failure:

- signedness or width is erased as cosmetic in lowering or in validation, or a
  semantic cast is reconstructed as an untyped ordinary cast
- a call is removed using rendered callee names, source/COD text, address/name
  allowlists, argument count alone, or without exact physical-register and CFG
  ancestry evidence
- divergent arguments, ambiguous callsites, or an unknown return carrier are
  accepted instead of refusing to change the tree
- semantic recovery moves into Rewrite, postprocess cleanup, or CLI, or any
  required call, argument class, memory effect, branch, return, validation
  verdict, strict recompilation result, type, documentation, or lint check
  regresses

#### Step 9m acceptance contract

Reason: Step 9l correctly made semantic casts visible to Tail Validation, but
the final C can express the same typed value either as a signed declaration or
as an explicit same-width signed view over identical storage. The storage-domain
ConditionIR fingerprint represented the first form, so QuickSort's correct
explicit views were rejected. This equivalence belongs to Validation; changing
the structured loop or deleting casts would erase proven semantics.

Definition of done:

- Validation projects only `CSemanticCast8616` operands whose source and
  destination widths equal the corresponding ConditionIR operand width
- signed and unsigned relational casts agree with the exact ConditionIR
  comparison family; equality casts remain value-preserving only at equal width
- wrong-signedness, width-changing, unknown-width, and non-semantic casts remain
  distinct and are rejected when their full fingerprints do not match
- the real QuickSort run no longer reports either typed semantic-view
  `branch-condition:predicate-mismatch`, and its generated C hash is unchanged
- focused Ruff `check --fix`, strict MyPy, adjacent validation tests, and startup
  architecture, context, and ownership gates pass

Definition of failure:

- Validation strips semantic casts globally, accepts a cast from spelling alone,
  or ignores ConditionIR width or signedness
- Structuring, Rewrite, postprocess, or CLI changes the correct loop merely to
  satisfy a fingerprint comparison
- the two predicate mismatches remain, generated C changes without stronger
  semantics, a refusal case passes, or a focused quality gate regresses
- the remaining structuring-snapshot or def-use failures are hidden or reported
  as fixed instead of retained as the next independent blockers

#### Step 9n acceptance contract

Reason: one Structuring pass can make several independently proved semantic
transformations. QuickSort simultaneously replaced two decoded JCC predicates
with typed loop guards and removed one opaque guard whose true and false arms
returned the same expression. The identical-return validator treated the whole
combined delta as its own, so its proof could not compose with the existing JCC
proof even though both transformations were independently closed.

Definition of done:

- Validation consumes exactly one removed condition with its exact `if:`
  control-flow observation only when Structuring recorded one closed,
  fully-accounted identical-return materialization
- an `else` observation is consumed only for the proved else-return shape;
  fallthrough-return materializations do not claim it
- a residual delta is retained only when added and removed condition and
  control-flow channels remain balanced and nonempty for the next validator
- ambiguous matching conditions, semantic failures, malformed deltas, and any
  write, call, or return-channel change refuse without mutating the delta
- the current-tree focused unit tests, strict MyPy, Ruff `check --fix`, and
  architecture checks pass, and live QuickSort no longer fails at the original
  aggregate Structuring snapshot

Definition of failure:

- Validation accepts a condition by partial text matching, consumes an
  unproved observation, or hides an unbalanced residual
- the identical-return proof claims a write, call, return, or semantic-failure
  channel, or mutates a refused delta
- Structuring, Rewrite, postprocess, or CLI reconstructs or deletes semantics
  merely to make validation pass
- the original aggregate mismatch remains, any required loop guard/call/return
  regresses, or any focused type, documentation, lint, architecture, or test
  gate fails

#### Step 9o acceptance contract

Reason: final C arguments use angr's entry-SP coordinates while binary and
validation facts use machine-BP coordinates. In a two-word interface, the
second argument's entry-SP `+4` numerically equals the first argument's
machine-BP `+4`. Resolving each variable independently therefore made the
second argument ambiguous even though the complete ordered function interface
proved both slots.

Definition of done:

- final entry-defined ranges and function-parameter validation first consume
  the existing Types/Lowering whole-function coordinate projection
- each projected slot must match the same argument index, entry-SP offset, and
  storage width; an absent or incoherent projection falls back to the existing
  conservative per-variable resolver
- tests cover the two-word `+2/+4` entry-SP to `+4/+6` machine-BP collision and
  retain refusal for incomplete or contradictory interfaces
- named and sidecar-free QuickSort preserve all calls, pointer argument
  classes, loop guards, recursive bounds, and returns; Tail Validation passes
  and portable-flat C recompiles
- focused Ruff `check --fix`, strict MyPy, unit tests, architecture checks, and
  the changed-surface quality gate pass

Definition of failure:

- Validation guesses from argument names, source/COD text, rendered C, or raw
  positive offsets instead of consuming the typed function projection
- an argument is initialized without exact index, offset, and width agreement,
  or an incoherent interface is accepted instead of falling back/refusing
- a test removes explicit 16-bit semantic views merely to match source spelling
  or permits a wrong pointer index or recursion boundary
- any call, argument class, memory effect, branch, return, validation verdict,
  strict recompilation result, type, documentation, lint, architecture, or
  focused regression gate fails

#### Step 9p acceptance contract

Reason: the far-pointer word-load materializer accepted any two dereferences
inside an `Or`, so it consumed the complete DX:AX return instead of only the
low-word byte pair. Once that overmatch was removed, the C AST still exposed a
stack temporary for the binary-proven constant `36`. Exact constant provenance
belongs beside decoded far-pointer evidence in Types/Lowering, not in Rewrite,
postprocess, CLI, or rendered-C cleanup.

Definition of done:

- the materializer accepts only one direct byte dereference combined with one
  direct byte dereference shifted by eight, through scalar casts only, and
  preserves every enclosing expression
- decoded same-basic-block evidence tracks exact register constants and exact
  BP-relative stores; overlapping or unresolved memory writes and unknown
  register writes invalidate the affected proof
- a proved offset constant becomes the helper's typed offset expression, while
  missing or invalidated evidence retains the existing stack-variable path
- tests cover the former wide-return overmatch, exact constant retention,
  exact-overlap and unresolved-write invalidation, and non-constant fallback
- `_overlay_functionAddress` retains both high and low return words, emits
  `36 + (funcNumber << 1)`, reports clean whole-tail validation, uses no asm
  fallback, and recompiles under the strict portable-flat target
- focused Ruff `check --fix`, MyPy, type/documentation ratchet, startup
  architecture, context, ownership, segmented-load, and changed-file gates pass

Definition of failure:

- infer a constant from source, COD, assembly or rendered C text, a procedure
  name, a binary address, or an unproved cross-block value
- allow an overlapping or unresolved write to leave a stale constant alive, or
  replace the conservative stack-variable path when no exact constant exists
- consume the enclosing wide return, lose either return word, change an index,
  segment, displacement, memory effect, call, CFG edge, or validation channel
- repair the symptom in Structuring, Rewrite, postprocess, or CLI, weaken Tail
  Validation or recompilation, or leave any focused type, documentation, lint,
  architecture, ownership, or regression gate failing

#### Step 9q acceptance contract

Reason: one stack-coordinate projection froze the value width while its owned C
variable could still be upgraded from a byte view to a word. After that owner
was corrected, Recovery Metadata still reported a complete zero-argument caller
census because it treated `RET` cleanup zero as proof that a returning callee
takes no arguments. Zero cleanup instead identifies a caller-clean convention;
it says nothing about how many preceding pushes belong to the call. The fixture
gate also parsed host libc implementation headers rather than only generated C,
making its structural verdict depend on the host toolchain.

Definition of done:

- a stack-coordinate projection derives its current semantic value width from
  the owned typed C variable while retaining the separately proven storage size
- a returning callee with zero terminal stack cleanup does not erase physical
  push evidence or manufacture a zero-argument census
- tests cover a byte-to-word owner upgrade and a caller-clean call with three
  physical word arguments; ambiguity continues to retain evidence rather than
  delete it
- sidecar-free ARGS has no stale `BP+5` argument, materializes the `BP+6`
  pointer owner, uses distinct argument/local identities, emits no invalid
  pointer assignment or shift, passes strict recompilation, and reports clean
  whole-tail validation
- repeated ARGS runs produce byte-identical C, and all four Ultra QuickC
  fixtures pass their generated-C contracts with `validation=passed`
- the generated-C fixture parser excludes host include expansion and an
  ARGS-preamble regression proves that its AST verdict is host-header independent
- focused Ruff `check --fix`, MyPy, type/documentation ratchet, and parallel
  argument/callsite/fixture regressions pass

Definition of failure:

- infer arity from `RET` cleanup zero, callee returning status, source/COD names,
  rendered C, or a fixture-specific address
- discard caller-clean pushes, bypass conflicting evidence in Types/Lowering,
  or repair argument identity in Structuring, Rewrite, postprocess, or CLI
- retain the stale contained byte owner, merge unrelated local and argument
  identities, emit invalid pointer operations, or weaken Tail Validation or
  strict recompilation
- let host libc syntax determine fixture-contract success, or leave any focused
  type, documentation, lint, ownership, deterministic-output, or regression gate
  failing

### Estimate History

| Checkpoint | Remaining focused estimate | Change | Evidence |
| --- | ---: | ---: | --- |
| `2026-08-29 11:49 +02:00` | 91-139h | baseline | Five focused failures closed; 2 ALU and 16 live SORTD checks reproduced. |
| `2026-08-29 12:05 +02:00` | 90-138h | -1h / -1h | Sleep moved from an unclassified rendering symptom to one Structuring ownership boundary; two generic regressions pass. |
| `2026-08-29 12:07 +02:00` | 89-133h | -1h / -5h | Both delegated ALU integrations pass their DoD, removing that whole forecast row. |
| `2026-08-29 12:24 +02:00` | 89-132h | 0h / -1h after rounding | Sleep's composite loop-exit ownership now passes 122 related tests and live Tail Validation. The remaining Sleep failure is isolated to one Types/Lowering positive-BP plan/interface decision. |
| `2026-08-29 12:41 +02:00` | 88-131h | -1h / -1h | Sleep's permanent sidecar-free test, combined 151-test surface, and parallel per-file linter/type ratchets pass; its remaining prototype boundary was a generic contained-view width precedence defect. |
| `2026-08-29 12:59 +02:00` | 95-145h | +7h / +14h | The exact retry reduced 17 failures to 16 reproducible failures but exposed six independent owner families. Swaps also reveals a Tail Validation blind spot, so the previous single-bucket 2.25-9.5h estimate was not defensible. |
| `2026-08-29 13:16 +02:00` | 94-144h | -1h / -1h after rounding | Live pass-by-pass identity tracing isolates Swaps to one Types/Lowering coordinate-consumer defect. The step remains open because its failing-before test, production correction, and Tail Validation rejection case have not all passed. |
| `2026-08-29 13:43 +02:00` | 93-141h | -1h / -3h after rounding | Swaps passes its complete function-fix DoD. DrawTime's independently exposed carry-predicate failure also has a failing-before generic regression, an earliest-layer fix, live `validation=passed`, strict C syntax, and a 72-test related cluster. |
| `2026-08-29 15:16 +02:00` | 92-137h | -1h / -4h after rounding | InitMenu's three live failures close in 35-45 focused minutes across their distinct Frontend, Types/Lowering, and cleanup owners. The permanent three-test live gate and 94 focused tests pass. |
| `2026-08-31 11:10 +02:00` | 90-132h | -2h / -5h | The loop/control-flow family and its retry-artifact reporting contract pass their focused DoD. The fresh full MS C lane exposes five explicit later-task failures instead of being reported as green. |
| `2026-08-31 22:22 +02:00` | 87-124h | -3h / -8h | Step 5e closed faster than forecast after three shared root causes were isolated: lowering precedence, validated rollback cleanup completeness, and typed call/declaration target coherence. Five live regressions, 161 supporting cases, file gates, and startup architecture checks pass. |
| `2026-08-31 22:59 +02:00` | 86-121h | -1h / -3h | Step 5f closed through two generic validation contracts: exact identical-return delta cardinality and typed postprocess transaction completion. DrawFrame passes sidecar-free with source-equivalent control flow; 167 related tests and all changed-surface gates pass. |
| `2026-08-31 23:54 +02:00` | 85-120h | -1h / -1h | Step 5g closed faster than forecast after pass isolation proved the defect pre-existed postprocess. Register-backed AIL virtuals now retain exact physical-register identity in validation; wrong-site packed-FLAGS reads still fail. Both live RunMenu gates, 175 related tests, changed-file gates, startup architecture checks, and strict C syntax pass. |
| `2026-09-01 03:55 +02:00` | 82-116h | -3h / -4h | CMP16's accepted-return defect closed at Widening, with a Structuring integrity guard that prevents Tail Validation from blessing the same loss later. The current unit lane and three of seven MS C constructs pass; four constructs remain independently red. |
| `2026-09-01 04:57 +02:00` | 80-113h | -2h / -3h | `simple_control` closes in 25-35 focused minutes at GP projection and condition-argument Types/Lowering. Quality-dev is fully green, the unit lane remains 1,906/1,906, four of seven MS C constructs pass, and selected-versus-attempted validation reporting is explicit. |
| `2026-09-01 06:20 +02:00` | 75-105h | -5h / -8h | `function_pointers` closes after pass tracing isolates a name-first Rewrite alias. The correction consumes machine-BP identity only, and a typed Tail Validation surface now rejects future stack-coordinate redirects. The 150-test surface, quality-dev, optimization suite, and complete runtime gate pass. |
| `2026-09-01 06:41 +02:00` | 74-103h | -1h / -2h | `pointer_memory` closes after separating a byte value from its word ABI storage slot in Types/Lowering. Exact refusal tests, 389 related tests, architecture startup, and the clean three-function runtime gate pass. |
| `2026-09-01 14:24 +02:00` | 70-99h | -4h / -4h | Atomic argument replay, byte stack projection, and validation-only typed expression projection close the two replayed MS C failures. The mandatory 1,915-test pipeline, all external round trips, and `quality-dev` pass. |
| `2026-09-01 20:33 +02:00` | 70-99h | unchanged | An unplanned current-tree CMP16 regression consumed 25-35 focused minutes but did not close a remaining weighted task. Its same-branch Structuring fix now passes the real executable, 133 focused tests, all optimization comparisons, and `quality-dev`; `quality-hard` and the broad gates remain open. |
| `2026-09-01 20:46 +02:00` | 70-99h | unchanged | The edited-state `quality-hard` gate now passes after all new owners were promoted into the global lint/type and architecture inventories. Step 8 remains open until the fresh default, expanded, and broad full-suite gates pass. |
| `2026-09-01 21:02 +02:00` | 70-99h | unchanged | The dependency-updated angr Clinic exposed an invalid semantic-stage shortcut. The generic runtime-policy correction closes the three newly failing MS C helpers and restores the full default pipeline; Step 8 remains open for expanded and broad gates. |
| `2026-09-01 22:49 +02:00` | 70-99h | unchanged | DrawBar's typed exact-address replay now validates and the mandatory pipeline remains green. This closes an unplanned regression inside the still-partial shared interprocedural/Ghidra task, so no weighted milestone or forecast row closes yet. DrawFrame's independent `BP-0x2` frame carrier is next. |
| `2026-09-01 23:03 +02:00` | 70-99h | unchanged | DrawFrame's regenerated canonical setup carrier now validates and the mandatory pipeline remains green. This closes the sibling regression but not a weighted top-level DoD; Step 8 still requires expanded and broad gates, and Step 9 remains the next semantic family. |
| `2026-09-02 02:49 +02:00` | 68-96h | -2h / -3h | Exact JCC ownership and conservative short-circuit predecessor recovery close QuickSort's two scan guards and generated-runtime timeout. A signed semantic-view correction closes the final Sleep warning. `quality-dev` and the complete expanded 5/5 pipeline pass with 1,919 curated tests, SORTD 20/20, zero validation failures/timeouts/compiler warnings, and a passing generated sort-core behavior gate. The weighted total remains 79% after rounding because the broader call/type/CFG task is still open. |
| `2026-09-02 04:03 +02:00` | 80-115h | +12h / +19h | The first exact 10,091-test repository audit proves that curated green did not mean full-suite green: 9,865 passed, 56 failed, and 170 skipped. Four failures have since been corrected or independently verified, leaving about 52 projected pending an exact rerun. The Swaps terminal pointer-output carrier now closes at Semantics and Types with `quality-dev` and the executable pipeline green, but the newly explicit full-suite root families increase the honest forecast and reduce weighted completion to 75%. |
| `2026-09-02 05:18 +02:00` | 80-115h | unchanged | The exact last-failed rerun is now 47 failures and 25 passes in 287.46s. `_ConfigCrts` closes with failing-before regressions, live `validation=passed`, and green quality, mandatory, and expanded pipelines; its separate COD block-lift fixture remains independently red and is the next investigation. The weighted total remains 75% after rounding. |
| `2026-09-02 06:44 +02:00` | 80-115h | unchanged | The exact last-failed rerun is 34 failures and 25 passes in 237.00s. F14 regenerated global reads and `_MousePOS`'s dead physical-register carrier close with live validation, compile, liveness-refusal, and `quality-dev` evidence. These improve the still-open shared Ghidra/full-suite task but do not complete a weighted milestone, so total progress remains 75%. |
| `2026-09-02 08:04 +02:00` | 80-115h | unchanged | The CARR scalar/wide predicate family closes at the existing Types/Lowering and Structuring owners with validation, focused tests, `quality-dev`, and the mandatory external pipeline green. The exact last-failed rerun improves from 34 to 32 failures while retaining 25 passes and finishes in 237.88s. The remaining failures still span independent call/type, segmented-memory width, CFG, and SORTD regeneration families, so the weighted total and forecast remain 75% and 80-115h. |
| `2026-09-02 08:30 +02:00` | 80-115h | unchanged | Four stale assertions are corrected only where current output is source-equivalent, recompilable, and reports `validation=passed`: Ready5's word store, F14 LookUp's hexadecimal literal, ReInitBars' explicit cast/control shape, and portable `main`'s hexadecimal mode constant. BubbleSort's direct calls likewise accept explicit ABI casts. The exact last-failed lane is now 27 failures and 26 passes in 167.42s; DOS pointer typing, overlay uninitialized storage, SetGear flag provenance, and the remaining semantic families stay red. |
| `2026-09-02 09:25 +02:00` | 80-115h | unchanged | The `pointer_memory` timeout is closed at Types/Lowering: indexed x86 addresses recognize one unambiguous argument carrier, and prototype replay joins entry-SP C variables to annotations by machine-BP identity. Failing-before tests, 77 related tests, direct Ruff/MyPy, live `fill_bytes`, and the complete three-function construct pass; generated runtime finishes instead of timing out. The weighted total remains 75% because the complete-suite and remaining SORTD semantic families are still open. |
| `2026-09-02 09:39 +02:00` | 80-115h | unchanged | The mandatory pipeline is green with 1,923 tests and every required MS C runtime construct. The exact last-failed lane is 26 failures and 25 passes in 224.10s. DOS `loadProgram` now retains its two pointer outputs, but its invalid casted low-byte lvalue and missing return flow remain the next independent root. |
| `2026-09-02 10:45 +02:00` | 80-115h | unchanged | DOS `_dos_loadProgram` is closed across both CLI shapes. Exact PUSH provenance removes the invalid split carrier; typed AX-to-stack binding, machine-BP object identity, and a bounded return-register-preserving epilogue proof materialize both returns at their owning layers. Focused Ruff/MyPy, 83 related checks with only the already-known larger `loadprog` body failure, `quality-dev` with 1,923 tests, and the mandatory external pipeline pass. The weighted total remains 75% pending the refreshed full-suite lane and remaining COD/SORTD families. |
| `2026-09-02 11:53 +02:00` | 80-115h | unchanged pending exact audit | The larger DOS `loadprog` body closes in 35-45 focused minutes. A typed four-byte stack owner now supplies exact validation subviews, and Structuring refuses a multi-predecessor linear return scan before recovering each exact-tagged terminal value from its own CFG predecessor. Generic failing-before tests, 261 related checks, direct Ruff/MyPy, live COD validation, portable recompilation, and `quality-dev` pass. The weighted total and forecast remain unchanged until the exact full collection refreshes the remaining independent failure families. |
| `2026-09-02 13:01 +02:00` | 80-115h | unchanged pending exact audit | The refreshed exact collection establishes a 10,132 collected / 9,931 passed / 31 failed / 170 skipped baseline in 1,314.23s. Three infrastructure defects and four stale semantic-shape assertions are closed. HeapSort's remaining pointer-argument defect is then closed generically by transporting validated callee evidence across project views; focused validation, strict C11 syntax, Ruff, MyPy, architecture checks, and `quality-dev` pass. About 23 failures are projected, not confirmed, until the next exact audit. |
| `2026-09-02 16:08 +02:00` | 80-115h | unchanged pending exact audit | The exact full audit remains 10,137 collected / 9,944 passed / 23 failed / 170 skipped in 852.88s; the exact last-failed rerun remains 19 failed / 3 passed in 221.20s. Architecture enrollment, one stale fixture, four cosmetic assertions, and DrawBar's function-wide coordinate drift are closed. The final local-only coordinate rule passes an uncached DrawBar gate, 101 focused tests, `quality-dev` with 1,924 tests, and the mandatory pipeline; `scalar_types_io` recompiles and exits `255`. About 13 failures are projected, not confirmed, until the next exact audit. |
| `2026-09-06 18:26 +02:00` | 80-115h | unchanged pending stable exact audit | RunMenu's JCC-owned dword-access provenance closes at Types/Lowering with strict recompilation, Tail Validation, refusal coverage, Ruff, MyPy, and type/doc checks green. The shared-tree ownership-selected run passed both RunMenu variants but found 14 failures in other concurrently modified SORTD families, so Step 9f and the weighted estimate remain open. |
| `2026-09-06 18:44 +02:00` | 80-115h | unchanged pending stable exact audit | Indexed byte-condition materialization now preserves its proven 16-bit address index and the changed-surface gate passes 402 tests. Three real SORTD bodies lose the invalid signed-byte subscripts, but their acceptance remains blocked by the separately exposed duplicate-final-callsite Tail Validation family; no weighted milestone closes. |
| `2026-09-06 19:13 +02:00` | 80-115h | unchanged pending stable exact audit | Exact attached callsite identities now prevent rebased callee names from creating duplicate recovered calls. BubbleSort, ExchangeSort, and PercolateDown pass Tail Validation and strict C syntax; 305 focused tests and the 458-test changed-file gate pass. The shared-tree pipeline remains red on an independent function-pointer argument type loss and a concurrent void-return registry/test mismatch, so Step 9f and the weighted estimate stay open. |
| `2026-09-06 19:44 +02:00` | 80-115h | unchanged pending stable exact audit | Frontend decoded-call inventory now includes unresolved indirect calls, allowing the existing typed summary and function-pointer lowering to recover `apply_twice` without a Rewrite or CLI repair. The generic regression is enrolled in the curated lane; the corrected void-return ownership assertion and this fix restore the mandatory pipeline with 1,940 pytest tests and all seven compile/decompile/recompile/execute constructs passing. Step 9f still requires a stable complete 10k-test audit, so weighted progress and forecast do not change. |
| `2026-09-06 20:44 +02:00` | 80-115h | unchanged pending stable complete audit | A source-stable rerun confirms all 22 provisional failures. Five shared-contract nodes close at Semantics, analysis, Types/Lowering, and architecture ownership; the stable failed-node checkpoint improves to 17 failed / 5 passed in 204.09s. The 124-test focused surface, changed-file Ruff/MyPy/type ratchet, architecture check, 1,940-test curated lane, and all seven MS C round trips pass. Global `quality-fast` remains blocked by pre-existing shared-tree MyPy errors outside this checkpoint, and Step 9f remains open until a source-stable complete collection reaches zero failures. |
| `2026-09-06 21:56 +02:00` | 80-115h | unchanged pending stable complete audit | Step 9l closes Sleep's signed semantic-view loss and duplicate returned-call clone at their owning layers. The 181-test related surface, focused Ruff/MyPy, architecture and ownership gates, 1,944 curated tests, and all seven configured MS C round trips pass. The global quality aggregate still reports shared-tree MyPy debt outside this slice; the prior 17/5 checkpoint is stale, and Step 9f remains open for a source-stable complete collection. |
| `2026-09-07 01:05 +02:00` | 80-115h | unchanged pending stable complete audit | Step 9p closes OVERLAY's far-pointer word-load overmatch and exact offset-constant loss at Types/Lowering. The live body retains its complete DX:AX return, emits `36 + (funcNumber << 1)`, passes Tail Validation and portable-flat recompilation, and avoids asm fallback. Eight focused tests, 190 segmented-load tests, and the 52-test changed-file gate pass. Step 9f remains open for a source-stable complete collection, so the weighted estimate does not change. |

Current expected finish for the complete plan is **80-115 focused engineering
hours**, approximately **2.0-3.8 working weeks** at 30-40 focused hours per
week, or roughly **2026-09-16 through 2026-09-29** if work continues at that
rate. The midpoint forecast is about **98 focused hours / 2026-09-22**.
This is a range, not a calendar promise: newly exposed semantic failures can
increase it. The next recalibration occurs after the complete focused-lane
DoD for each subsequent family, using measured focused time per independent
root cause rather than the raw count of failing tests.

## Historical Measured Baseline

Fresh command on 2026-08-06:

```text
./decompile.py SORTD.EXE --ignore-local-sidecar-hints --no-alternate-source-c -q
```

- selected/decompiled: 20/20 non-library functions
- validation: 20/20 passed; whole-tail validation clean
- assembly/details fallback: 0
- empty functions, timeouts, tracebacks: 0
- default function execution: 7 clean processes, one function per process
- elapsed: 4:36.36; CPU utilization: 478%; peak RSS: 305,748 KiB
- stdout separation: only generated C; diagnostics remain on stderr
- direct stdout recompilation: passed strict GCC syntax checking with all 20
  generated function bodies in one canonical translation unit
- default regression pipeline: 3/3 lanes passed; 1,788 focused tests, four
  Ultra QuickC fixtures, and all seven MS C tiny constructs passed their
  compile/decompile/recompile/exit-code contracts

The previous direct-output defect concatenated independently valid payloads and
produced conflicting declarations. Whole-binary stdout now uses the same owned,
structured export contract as generated artifacts. Conflicts are typed failures
reported on stderr with a nonzero exit status.

Latest required-gate verification on 2026-08-28 passes all three default lanes
with zero failures, skips, or timeouts. The focused lane passes 1,841 tests in
66.77 seconds; all four Ultra QuickC fixtures pass in 55.39 seconds; and all
seven MS C tiny constructs pass their compile, original-run, decompile,
recompile, and decompiled-run contracts in 55.89 seconds. The focused lane
remains over its historical 30-second soft budget and is retained as
performance debt, not hidden as a correctness pass. The hard gate also passes
Ruff `--fix`, strict MyPy over 224 source files, the 38-module mypyc
compile/import smoke, architecture and ownership checks, and 1,841 tests. The
generated-C quality comparisons pass without semantic-quality regression.

This rerun caught a real `scalar_types_io/byteops_unsigned` validation
regression after the byte-safe frontend work: word-aligned frame bindings were
incorrectly replacing the proven one-byte access width of direct stack
variables. Tail Validation now keeps direct access width distinct from frame
allocation width. The focused construct decompiles all ten functions, validates
cleanly, recompiles, and returns the expected 255; the full default pipeline
keeps that behavior as a permanent external gate.

## Address Coverage

Ghidra entries before NOP padding are mapped to Inertia's canonical body entry.

| Inertia body | Source label | Ghidra entry | Leading NOPs | Status |
| --- | --- | --- | ---: | --- |
| `0x10010` | main | `0x10010` | 0 | matched |
| `0x10060` | InitMenu | `0x1005d` | 3 | matched |
| `0x101f0` | DrawFrame | `0x101db` | 21 | matched |
| `0x102e0` | RunMenu | `0x102cc` | 20 | matched |
| `0x10498` | DrawTime | `0x10491` | 7 | matched |
| `0x10560` | InitBars | `0x10554` | 12 | matched |
| `0x10678` | ReInitBars | `0x10672` | 6 | matched |
| `0x106c8` | DrawBar | `0x106c8` | 0 | matched |
| `0x10768` | SwapBars | `0x1075b` | 13 | matched |
| `0x107b8` | Swaps | `0x10794` | 36 | matched |
| `0x10808` | InsertionSort | missing | - | Ghidra discovery loss |
| `0x108d0` | BubbleSort | missing | - | Ghidra discovery loss |
| `0x10970` | HeapSort | missing | - | Ghidra discovery loss |
| `0x109e8` | PercolateUp | `0x109e8` | 0 | matched |
| `0x10a88` | PercolateDown | missing | - | Ghidra discovery loss |
| `0x10b50` | ExchangeSort | missing | - | Ghidra discovery loss |
| `0x10c18` | ShellSort | missing | - | Ghidra discovery loss |
| `0x10ce0` | QuickSort | missing | - | Ghidra discovery loss |
| `0x10e70` | Beep | `0x10e5d` | 19 | matched |
| `0x10f38` | Sleep | `0x10f18` | 32 | matched |

For all 13 address-matched bodies, the sets of direct calls to the 20
application functions agree. The seven missing Ghidra bodies are a Ghidra
function-discovery defect: Inertia discovers them from the binary and validates
their generated C.

## Whole-File Findings

### Closed P0: Recompilable normal output

Inertia previously repeated `g_08F0_entry` and emitted stale/conflicting callee
declarations such as `int` versus `short` return types. Batch stdout now
canonicalizes those declarations and passes `gcc -std=c11 -Wall -Wextra
-Werror -fsyntax-only` without changing or losing any of the 20 bodies.

Owner: CLI/export assembly in `inertia_decompiler/`. Function postprocess must
not reconcile interprocedural declarations.

### Closed P0: Semantic completeness

The current edited tree passes the strict executable-only 20/20 gate with zero
validation failures or unsupported-instruction output. RunMenu `0x102e0` keeps
its Escape return, and DrawTime/QuickSort consume byte-executed stack slices
through complete Alias range evidence rather than Rewrite or CLI repair.

The generated behavior gate now compiles and executes unchanged output for all
19 non-library functions covered by `SORTDEMO.C` function self-tests. `main`
has no source function-selftest contract; it remains compile- and
validation-covered. This does not yet claim whole-program replacement
equivalence.

### P1: Ghidra semantic errors

The matched Ghidra output is useful for control-flow comparison but is not a
better correctness oracle:

- InitMenu assigns its loop variable `0x4d00` instead of preserving the binary
  increment, changing termination and menu traversal.
- InitBars indexes by `% 0x60b` and stores an uninitialized stack value where
  the binary/source behavior selects a bounded random entry and swaps values.
- PercolateUp passes a computed object address as a row index to the redraw
  call; the call argument class is wrong.
- Beep loses an argument on an output-port call and exposes register fragments.
- ReInitBars does not express the complete widened clock store cleanly.
- DrawFrame, DrawTime, and InitMenu leave stack-call setup variables in forms
  that are not directly recompilable C.
- DrawBar recovers a 34-byte buffer although the binary-proven Inertia object is
  44 bytes (the source declaration has 43 elements).

Where these differ, Inertia's binary evidence plus passing validation wins.

### P1: Inertia type and readability debt

Cross-function return and parameter contracts still disagree before export
canonicalization. Several source-void procedures render as scalar-returning
functions, even when callers ignore the result. This should be solved from
binary caller/return-use summaries in Types/Lowering, not by source names and
not by Rewrite.

Raw `SEG_U*` accesses remain appropriate when DS object identity is unproven.
They are readability debt, not permission to guess a global. Numeric names are
not a defect under the no-debug-information requirement.

### P2: Performance

Default N-1 clean-process execution is working with seven workers on this
eight-CPU host. The current cold run is 278.41 seconds and an unchanged-tree
replay is 95.90 seconds. Accepted results are cached; failed results are always
revalidated. The remaining serial tail requires pass-level optimization inside
complex functions, not more worker fan-out or mutable shared-project rebuilds.

## Ordered Plan With Per-Step DoD

### 1. Canonicalize whole-binary stdout at CLI/export

Status: complete.

Reason: Independently valid function payloads can still form an invalid or
semantically inconsistent translation unit when declarations are concatenated.
The CLI/export owner must assemble one canonical whole-binary result without
repairing function semantics.

Definition of done:

- normal whole-binary stdout is assembled from accepted typed function
  payloads through one structured declaration table
- `./decompile.py SORTD.EXE > out.c` followed by strict GCC syntax checking has
  zero declaration/type conflicts
- every one of the 20 generated function bodies remains present and unchanged
- assembly conflicts stop the CLI with a clear stderr error and nonzero status
- direct single-function output and `--output-c-dir` artifacts remain stable
- focused export/CLI tests, Ruff `--fix`, types/docs, and architecture checks pass

Definition of failure:

- stdout contains duplicate or conflicting declarations, drops or changes a
  function body, or requires postprocess semantic repair
- an assembly conflict is hidden, emitted only as metadata, or exits successfully
- any focused CLI/export, compilation, typing, documentation, or architecture
  gate fails

Measured maintenance on 2026-08-21:

- the real strict 20-function payload exposed three compatible return-contract
  variants: K&R `unsigned short` versus `unsigned long`, and exact-parameter
  `void` versus return-capable `int` declarations. These are now joined by one
  typed export-contract owner; incompatible parameter or return classes remain
  hard assembly conflicts
- declaration joining moved into the 177-line
  `generated_external_function_contracts.py` module, reducing
  `generated_translation_unit_assembly.py` from 370 to 235 lines without
  changing function bodies
- direct binary candidate inventory and the selected function queue are again
  reported as distinct counts; the strict gate now reports 20 queued and 20
  materialized functions instead of relabeling 254 raw candidates as queued

### 2. Expand behavior proof beyond the sort core

Status: complete for every source-selftested non-library function.

Reason: Compilation and tail validation do not alone prove application-visible
behavior. Executing generated bodies against independently derived outcomes
catches lost calls, wrong argument classes, memory-effect drift, and incorrect
control flow.

Definition of done:

- every source-selftested application function has a generated-C harness
- required calls and value-versus-pointer argument classes are checked
- generated execution matches the source oracle's return values, memory
  effects, and expected exit code
- the default or expanded pipeline fails on missing functions, sanitizer
  failures, behavioral differences, assembly fallback, or validation failure
- no source text or name is used to recover semantics

Definition of failure:

- any source-selftested function lacks an unchanged generated-C harness or an
  expected call, return, memory effect, or exit code differs
- sanitizer, fallback, validation, or generated-function-presence failures do
  not fail the default or expanded pipeline
- source names, source text, or peer output participate in semantic recovery

Measured closure: 19/19 generated function bodies compile and execute unchanged
under ASan/UBSan against source-derived outcomes. The cases include RunMenu
Escape/dispatch behavior, DrawTime timing/sound arguments, Beep output-port
arguments, full-width ReInitBars copies, and InitMenu pointer-table traversal.
The final expanded pipeline passes 5/5 lanes. Its status parser associates
deferred canonical definitions and their declaration preludes with the exact
function record, so batch stdout cannot create false "generated C missing"
results or bypass leakage/call-contract checks.

Fresh verification on 2026-08-22 passes all five expanded lanes with zero
failures, skips, or timeouts: the focused Python lane completes in 45.196
seconds, Ultra QuickC passes 4/4 fixtures and validation, and all seven MS C
tiny constructs pass compile/run/decompile/recompile/decompiled-run checks.
Sidecar-free SORTD decompiles 20/20 functions with zero validation failures,
timeouts, or tracebacks; its canonical translation unit compiles and the 19
source-selftested bodies pass the generated behavior gate. The independent
status/source-contract scoreboard passes 20/20. `quality-hard` also passes
Ruff `--fix`, strict MyPy for 121 source files, the mypyc build/import smoke,
architecture/context/ownership checks, and generated-C comparisons.

### 3. Unify interprocedural function contracts at Types/Lowering

Status: in progress; argument storage, return-use caller-census refusal, and
typed register-return condition forms are enforced.

Reason: Definition/callsite signature disagreement is evidence that the project
has competing interprocedural truths. One binary-evidenced contract must own
parameter, return, stack-delta, signedness, and pointer/value decisions before
rendering or export.

Definition of done:

- each internal function has one binary-evidenced return/parameter contract
  shared by its definition and every callsite before export
- ignored returns become `void` only when the caller census is complete and no
  return use exists; unknown evidence refuses conversion
- signedness and pointer/value classes survive clean-worker transport
- closed evidence counters report every classified and materialized contract
- focused negative tests prove refusal on conflicting or incomplete callers

Definition of failure:

- a contract is inferred from an incomplete caller census, guessed storage, a
  function/source name, or rendered C
- definitions and callsites receive different contracts, or CLI/postprocess
  reconciles them after Lowering
- evidence counters do not close, conflict/unknown cases are silently accepted,
  or focused validation and behavior gates regress

Measured progress on 2026-08-17:

- `CalleeArgumentCountEvidence8616.closes_census` now requires every discovered
  caller to be normalized, classified, and materialized with zero failures.
- one classifiable caller plus any unclassified caller now yields `UNKNOWN`,
  and Types/Lowering refuses interface unification instead of accepting a
  transient local header; a function with no discovered callers may still use
  body-local argument evidence.
- argument-width evidence and positive-BP interface lowering consume the same
  closed-census contract rather than reconstructing a weaker verdict.
- return-use recovery now inventories every proven label/prologue alias in one
  evidence record; the CLI no longer scans aliases independently and selects a
  partial result that happens to classify as unused.
- a recursive read-modify-write consumer of `AX` now proves a used return and
  blocks `void` demotion. Only a recursive terminal `call; ret` pass-through
  cycle may be excluded, and that cycle cannot independently prove `void`.
- Capstone register-access facts distinguish a return-carrier read-modify-write
  from a pure clobber before Types/Lowering consumes the caller census.
- Semantics now owns a typed per-terminal-path return-storage state. Wide
  `DX:AX` promotion requires every entry-reachable terminal path to prove the
  pair with closed counters; one word-only path, an incomplete CFG successor,
  a stale `DX`, or an intervening non-epilogue instruction refuses promotion.
- the compatibility AX-lane projection is empty when terminal-path collection
  is incomplete, so legacy type consumers cannot infer from a successful
  subset while the typed evidence still exposes the failed census.
- negative tests cover incomplete collection, malformed cached evidence,
  incomplete `UNKNOWN` evidence, the no-caller boundary, recursive value use,
  recursive pass-through exclusion, and calls split across entry aliases.
- the exact Ultra QuickC `args` regression retains both required calls, and the
  default pipeline passes 3/3 lanes: 1,469 focused tests, 4/4 Ultra QuickC
  fixtures, and all seven MS C tiny compile/decompile/recompile/runtime cases.
- the return-use focused surface passes 103 tests; the complete changed-file
  gate passes Ruff, MyPy for seven source modules, type ratchet, architecture,
  MCP/Understand-Anything state, ownership, and 175 related tests.
- the return-storage focused surface passes 38 tests and its changed-file gate
  passes Ruff, MyPy, type ratchet, architecture, context, ownership, and 159
  related tests. A repeated default pipeline remains 3/3 green; its longest MS
  C fixture stayed within normal variance rather than adding fallback work.
- Semantics now owns complete terminal stack-cleanup evidence. Callee cleanup
  is accepted only when every entry-reachable return is classified, all five
  evidence counters close, and every return agrees on one even immediate.
- callsite summarization no longer decodes a guessed 256-byte window and trusts
  its first `ret`. Conflicting return immediates, an incomplete CFG successor,
  an indirect/bodyless branch, or malformed cleanup evidence now refuses the
  cleanup contract; a bodyless direct terminal return remains supported.
- the terminal-cleanup and downstream call-contract surface passes 155 focused
  tests. Ruff `--fix`, MyPy, type ratchet, architecture ownership, MCP/context,
  and ownership-manifest gates pass for the complete changed surface, and the
  repeated default pipeline passes all focused, Ultra QuickC, and seven MS C
  tiny compile/decompile/recompile/runtime contracts.
- Types/Lowering now owns one closed source-order argument-storage contract.
  Every proven argument carries an exact stable `SS:BP+offset` identity and
  width; physical right-to-left push order is normalized once and consumed by
  both definitions and callsite declarations. An incomplete width census
  refuses materialization instead of falling back to one local call summary.
- Mixed-width tests prove that physical `(word, dword)` pushes become source
  `(dword, word)` storage at `BP+4` and `BP+8`; zero-argument and incomplete-
  census cases close or refuse explicitly. The focused argument-contract
  surface passes 126 tests and the changed-file gate passes Ruff `--fix`,
  MyPy, type ratchet, architecture/context, ownership, and 361 selected tests.
- The repeated default pipeline passes 3/3 lanes after this contract change:
  1,469 focused tests, 4/4 Ultra QuickC fixtures, and all seven MS C tiny
  compile/decompile/recompile/runtime cases. The promoted QuickC `args`
  fixture also passed three concurrent deterministic stress runs.
- Semantics now publishes one exact terminal return-storage class only after
  every reachable path agrees. `AL`, `AH`, `AX`, and `DX:AX` remain distinct;
  mixed or incomplete paths have no scalar projection. Calling-convention and
  all active return-type/value consumers use this exact contract, so a wide
  `DX:AX` result can no longer be silently narrowed to `AX` through the legacy
  lane-set compatibility view.
- Exact-storage negatives cover mixed paths, incomplete collection, and both
  direct and terminal-call attempts to type `DX:AX` as a word. The focused
  surface passes 56 tests; its changed-file gate passes Ruff `--fix`, MyPy for
  eight source modules, type/docs ratchets, architecture/context, ownership,
  and 230 selected tests. The default pipeline remains 3/3 green.
- VEX import now resolves callable pyvex result types through the block type
  environment and converts their bit widths to exact byte widths. Byte
  interrupt stores therefore remain byte stores through IR, Lowering, and
  final validation instead of being silently promoted to words.
- IR owns two lossless normalizations: exact same-instruction little-endian
  byte micro-operations coalesce into one machine access, and an exact
  JCC-only transport load is rebound to the immediately preceding CMP value.
  Frontend VEX topology remains unchanged because altering it regressed the
  Ultra QuickC `args` control flow and duplicated one distinct call argument.
- The fresh sidecar-free SORTD indexed-address census closes at 42 raw facts,
  36 normalized facts, six coalesced facts, 36 classified facts, 35 Alias
  materializations, and one explicit refusal. Collector parity reports 31
  matches, four Alias-only pointer accesses in `0x107b8`, eight legacy-only
  BP/SS false positives, and zero identity conflicts.
- The complete checkpoint passes the 499-test changed-file gate, a broader
  112-pass/65-skip semantic selection, all 1,673 default-pipeline tests, all
  four Ultra QuickC fixtures, and all seven MS C tiny compile/decompile/
  recompile/runtime cases. The hard gate also passes Ruff `--fix`, strict
  MyPy, architecture/context/ownership checks, mypyc compile/import smoke for
  38 modules, and all three generated-C quality comparisons.
- Callsite summaries now retain the exact decoded return-store instruction
  address instead of dropping it after classifying destination and width.
  Structuring uses that typed address, the exact call instruction tag, and one
  unique adjacent sequential ownership witness to bind call results across
  unrelated angr dirty carriers; dirty IDs and rendered names are not proof.
- The uncached sidecar-free `_TIDShowRange` regression now emits
  `mseg = MapInEMSSprite(2, 0); if (mseg)` and preserves all arguments. Its
  uninitialized AX condition is closed, reducing the final def-use failures
  from 39 to 31. The 116-test callsite/Structuring surface, Ruff `--fix`,
  strict MyPy, and architecture checks pass.
- Structuring shared-tail replay exposed one projection disagreement at the
  `_RectCopy` callsite `0x1085`: two statements referenced the same structured
  call node, but the callsite summary classified its return as used. The exact
  machine witness is `lcall 0x11e, 6; add sp, 0x10; sub ax, ax`; the final
  instruction clobbers the return value rather than consuming it.
- Semantics now owns exact `sub reg, reg` and `xor reg, reg` zero-idiom facts.
  Both bounded and linear caller return-use classifiers consume that single
  fact and classify the witness as `CLOBBERED`; Structuring can therefore
  coalesce the duplicate statement occurrence without postprocess repair.
  Focused Ruff `--fix`, strict MyPy for the four touched source modules, and 16
  return-use/shared-tail tests pass.
- Two uncached real `_TIDShowRange` runs retain exactly two body-level
  `_RectCopy` calls and report zero duplicate-callsite or multiplicity
  diagnostics. The previous segmented-write mismatch is absent from the
  current final verdict.
- Alias now consumes the generic decoded register reaching-source proof at
  exact condition-producer boundaries. The `_TIDShowRange` roots close at two
  raw self-test candidates, two classified storage identities, two materialized
  bindings, and zero failures: `mseg` is `SS:BP-0xc`, while the switch selector
  is `DS:0x7002`. The existing Alias carrier owner then propagates the selector
  through the exact `DEC AX` chain and materializes comparisons against `1..4`.
  Explicit ES absolute loads refuse DS identity, and competing owned bindings
  hard-fail. The prior 88 unresolved SSA register-carrier reads are absent.
- The focused source-binding/carrier/reaching-source surface passes 25 tests;
  the changed-file gate passes Ruff `--fix`, strict MyPy for six non-test
  modules, type/docs ratchets, architecture/context/ownership checks, and 64
  selected tests.
- Structuring now owns regenerated aliases of one exact stored call result.
  It requires one unique typed `SS:BP+offset` destination and same-sequence C
  AST dominance with no intervening destination write, unrelated call, or
  control transfer; ambiguous or nested occurrences refuse without mutation.
  Machine source order is deliberately not used because every regenerated
  occurrence carries the same original VEX position.
- The uncached real `_TIDShowRange` run closes at one raw, normalized,
  classified, and materialized ownership fact with zero failures and two
  rewritten aliases. Final C contains exactly one body-level
  `mseg = MapInEMSSprite(2, 0);`, preserves `if (mseg)`, reports
  `validation=passed`, and passes whole-tail validation.
- Eight focused ownership tests, the 60-test shared-call/Structuring surface,
  Ruff `--fix`, strict MyPy, and architecture checks pass. The prior CLI smoke
  test no longer accepts timeout as success; its fresh seven-worker real run
  passes in 219.27 seconds and enforces exact call counts and validation.
- Types/Lowering now publishes every condition-derived and binary-proven
  pointer interface to the authoritative prototype registry before later
  stack/segment replays. A stale same-precedence CCA snapshot can no longer
  restore unsigned arguments over signed `ConditionIR` or restore scalar
  arguments over a proven pointer class; stronger signature/user snapshots
  still win.
- Parameter validation now distinguishes logical C width from ABI stack-slot
  width. A byte scalar in a two-byte MS C slot may match either projection,
  while a logical type wider than its storage or a width matching neither
  projection refuses validation.
- The terminal-call Types/Lowering owner now replaces an inferred `void`
  prototype only when closed caller-use evidence, a typed callee return, and an
  exact AX-preserving terminal path agree. It publishes that contract before
  Structuring materializes `return callee(...)`; explicit signature/user
  prototypes remain immutable.
- The real `compare16`, `simple_control`, `function_pointers`,
  `pointer_memory`, and `scalar_types_io` fixtures compile, decompile,
  recompile, validate, and return `255`. `select_and_apply` retains the required
  returned `apply_twice` call, and `fill_bytes` retains its byte-pointer
  interface. The focused condition/terminal-return/validation surfaces pass
  216 tests, and the full required pipeline passes 3/3 lanes.

Remaining task-3 work: materializing indexed, indirect, stack, and broader
multi-output live-out storage plus stack effects beyond closed terminal `ret`
cleanup. Exact stable direct DS/ES must-write outputs and
their caller-side condition uses now enter the same storage contract only when
every target-reaching caller path preserves the call output; mixed-path and
partial-overwrite cases refuse. Input trials, exact reaching-definition binding,
scalar/pointer register outputs, all strict/non-strict/equality `DX:AX`
condition forms, recursive return pass-through propagation, SCC-wide
production publication, and one transaction that updates definitions and
callsites are implemented.

### 4. Keep discovery and semantic-loss ratchets permanent

Status: complete; the current strict whole gate is 20/20 with zero discovery,
materialization, fallback, validation, timeout, or traceback failures.

Reason: The known-good 20-function corpus is a durable completeness boundary.
Permanent discovery, materialization, fallback, and tiny-example ratchets stop
later cleanup or performance work from silently dropping code or effects.

Structuring now distinguishes machine facts from facts joined to one exact AST
placement site. Exact instruction provenance plus exact stack destination
tracks a Lowering-typed function designator without reinterpreting its value;
tagless replay still requires strict source identity. A classified placement
with no materialized assignment is a hard pipeline error, while an unjoined
fact is retained as `UNKNOWN_REFUSE`.

Definition of done:

- the sidecar-free pipeline continues to require exactly these 20 application
  addresses, 20/20 validation, zero empty/fallback/timeout/traceback results
- comparison diagnostics remain restricted to Inertia's 20 functions and
  account for NOP-padded entry aliases deterministically
- regressions cover Beep's minimum-duration guard and call arguments,
  DrawFrame's pre-test initializer, Sleep's widened condition, and RunMenu's
  Escape return
- any classified semantic fact with zero materialization fails the pipeline
- all seven MS C tiny constructs compile, run, decompile without asm fallback,
  recompile, and match the required DOS exit code

Definition of failure:

- any expected application function disappears, aliases nondeterministically,
  falls back to assembly/details, times out, or fails validation
- a classified fact is not materialized and the pipeline still succeeds
- any Beep, DrawFrame, Sleep, RunMenu, or MS C tiny regression escapes the
  enforced pipeline

### 5. Improve readability only from proof

Status: in progress. The first exact signed-conversion projection is accepted
with whole-file validation, recompilation, behavior and default pipeline gates.
See [the slice report](reference/step11-signed-casts.md); remaining work is
tracked in [the execution ledger](reference/remaining-plan-execution.md).

Reason: Stack locals, aggregates, signed conditions, and object names are useful
only when they are projections of accepted Alias, Widening, Types, and
Structuring facts. Readability must expose proof, not manufacture semantics.

Definition of done:

- proven stack slots render as locals/arguments and proven aggregate layouts
  render as arrays/structs without conflicting declarations
- explicit signed conditions survive rendering and recompilation
- unresolved segment/global identity stays explicit rather than guessed
- numeric function names remain valid when no symbol evidence exists
- every readability change keeps validation and behavior gates green

Definition of failure:

- output becomes prettier by guessing a local, type, object, condition, name,
  call argument, or control-flow shape
- unresolved segmented identity is hidden or distinct address spaces are merged
- recompilation, validation, call preservation, or behavior is worse than the
  recorded baseline

### 6. Profile before further parallelization

Status: in progress; primary N-1 execution, accepted-result caching, and
complexity-prioritized clean-worker submission are complete, while aggregate
PSS verification and per-function hot-path work remain.

Reason: The validated primary path already uses available CPUs, while mutable
fallback rebuilds may share project state and multiply memory. Profiling and
isolation evidence are required before concurrency can safely reduce wall time.

Definition of done:

- deterministic function order and output hashes are unchanged across repeats
- aggregate worker RSS stays below 2 GiB with a documented worker cap
- pass-level profiles identify CPU-bound owners before adding concurrency
- mutable fallback rebuilds remain serial until isolated-state and OOM tests
  prove bounded parallel execution

Definition of failure:

- concurrency is added without pass-level timing, isolated-state tests, and
  aggregate memory measurements
- output order or hashes become nondeterministic, worker RSS exceeds the 2 GiB
  budget, or a worker failure is lost
- measured wall time does not improve materially or semantic gates regress

Measured maintenance on 2026-08-21: the frontend `Memory` wrapper no longer
defines a custom destructor merely to delete its owned bytearray. A SIGALRM
timeout could interrupt that destructor with the `BaseException`-derived
`AnalysisTimeout`, producing an unraisable traceback after successful
decompilation. Normal Python ownership now releases the bytearray, and a
structural regression prevents the unnecessary destructor from returning.

Fixed-budget decompiler measurements must also wait for codebase-memory indexing
to become idle. One automatic graph refresh consumed about 6.6 CPUs and 8 GiB
RSS, causing the unchanged 50-second startup catalog to close at 17/20 and then
19/20 entries. The same edited tree closed at 20/20 once indexing finished; do
not weaken discovery or validation timeouts to hide external host contention.

Measured maintenance on 2026-08-27:

- pure-binary clean-process failures no longer trigger an evidence-identical
  in-process retry; sidecar-backed retries remain when evidence can differ
- the remaining replay cost belongs to uncached failed functions; caching their
  failure payloads is forbidden because failure details vary under contention

Measured maintenance on 2026-08-28:

- clean workers now use deterministic longest-processing-time-first submission
  from the already available block/byte complexity estimate; result collection
  and C emission retain original stable indexes
- on the same edited tree, workers, environment, and binary, wall time fell from
  259.25s to 211.86s (47.39s, 18.3%) while user CPU stayed effectively flat at
  1161.45s versus 1153.79s. The generated C files are byte-identical, all 20
  functions decompile, asm/detail fallback remains zero, and whole-tail
  validation is clean
- the earlier 440.56s longest-first experiment is superseded: it did not use
  this bounded clean-worker submission contract and was not a valid predictor
  for the current queue. Remaining speed work must profile internal passes,
  especially the 42-block QuickSort worker that still closes the final wave

### 7. Borrow Reko's proven quality mechanisms without its unsafe fallbacks

Status: pending. The comparison artifact is
`comparisons/reko/SORTD/reko-0.12.4/NON_LIBRARY_COMPARISON.md`.

Reason: Reko demonstrates useful placement and iteration strategies for wide
values, call storage, and aggregate typing, but its invalid placeholders and
known SORTD losses violate Inertia's evidence contract. Borrowing must be
mechanism-specific and independently implemented at Inertia's owning layers.

Definition of done:

- tasks 7.1 through 7.4 satisfy their individual DoD and refusal cases
- independently implemented mechanisms improve the named SORTD functions while
  preserving validation, calls, behavior, recompilation, and layer ownership
- licensing review confirms that no incompatible Reko implementation was copied

Definition of failure:

- Reko output, source names, addresses, rendered text, or invalid placeholders
  become semantic evidence or recovery fallbacks
- an implementation copies incompatible code, bypasses Inertia's typed
  contracts, or introduces semantic recovery in Rewrite/CLI/export
- any closed gate in task 7.4 fails or a peer-looking result is accepted over
  binary validation

This step is about decompilation quality only. Reko 0.12.4 is not a better
whole-function oracle: 14/20 corresponding application bodies contain
`<invalid>` or `<unknown>`, and QuickSort explicitly loses eight recursive call
arguments. Its useful mechanisms are narrower:

- Beep preserves the minimum-duration guard, word-to-byte timer writes, Sleep
  argument, and final speaker-control restore;
- Sleep keeps the split-word clock value as one 32-bit calculation and
  comparison;
- InitBars retains both initialization loops and the random-selection dataflow;
- Swaps keeps the two-byte object exchange as one object operation.

Use `borrow/reko/` as design evidence, not as semantic truth and not as code to
copy blindly. Reko is GPL-licensed and has a different IR/type model; any
implementation must be independently expressed in Inertia's owned typed
contracts and reviewed against this project's licensing requirements.

#### 7.1 Re-run wide-value recovery at evidence-producing boundaries

Reason: Split-word values become recoverable at several points after Alias,
propagation, and call summaries. Re-running only affected Widening candidates
can recover complete arithmetic and conditions without a late AST heuristic.

Reko runs its `LongAddRewriter` immediately after register SSA, repeats it after
value propagation, then eliminates condition codes and runs
`LongComparisonFuser`; it fuses sliced stores afterward. See:

- `borrow/reko/src/Decompiler/Analysis/SccWorker.cs:170-232`
- `borrow/reko/src/Decompiler/Analysis/LongAddRewriter.cs:37-94`
- `borrow/reko/src/Decompiler/Analysis/LongComparisonFuser.cs:40-106`

Implement the equivalent idea in Inertia's existing Widening ownership rather
than adding a rewrite pass:

1. Normalize proven low/high carriers (`DX:AX`, adjacent 16-bit stack/global
   halves, and carry/borrow-linked pairs) after Alias establishes storage
   identity.
2. Re-run only the widening candidates whose inputs changed after typed value
   propagation or call-summary materialization; do not repeatedly scan the
   whole AST.
3. Materialize 32-bit add/subtract, divide, slice, store, and comparison facts
   before Structuring. Preserve signedness and exact low/high provenance.
4. Fuse multi-block high-word/low-word comparisons only when CFG targets,
   condition polarity, and both carrier identities prove one comparison.
5. Unknown or conflicting halves remain separate; they are never joined by
   adjacency or shape alone.

Acceptance cases:

- Sleep remains `goal = wait + clock()` followed by one correct 32-bit clock
  comparison, with `validation=passed`.
- ReInitBars keeps one 32-bit `clStart` store rather than unrelated 16-bit
  writes.
- Beep keeps the 32-bit dividend/divisor relationship and the exact low-byte
  and high-byte slices passed to the two timer-port writes.
- Negative tests reject cross-block joins with mismatched carry provenance,
  segment space, alias object, or branch target.

Definition of done:

- all listed Sleep, ReInitBars, and Beep acceptance cases pass with closed
  Widening evidence counters and `validation=passed`
- affected-candidate scheduling is deterministic and avoids whole-AST rescans
- mismatched carrier, carry/borrow, segment, alias, definition, or CFG evidence
  produces an explicit refusal and preserves the lower representation

Definition of failure:

- low/high halves are joined by adjacency, register shape, or rendered syntax
  without exact identity and carry/borrow provenance
- widening is introduced in Structuring, Rewrite, CLI, or export
- any call argument, memory effect, comparison, validation verdict, or negative
  refusal case regresses

#### 7.2 Build one interprocedural storage contract, then bind calls exactly

Reason: The largest remaining semantic risk is disagreement between function
definitions and individual callsites. A whole-program storage contract makes
every emitted argument and return traceable to its exact reaching definition.

Reko first derives each procedure signature from program dataflow and only then
rewrites calls and returns. Inputs include sequence registers, individual
registers, and sorted stack slots; outputs come from live-out storage. See:

- `borrow/reko/src/Decompiler/Analysis/CallRewriter.cs:85-155`
- `borrow/reko/src/Decompiler/Analysis/CallRewriter.cs:158-220`
- `borrow/reko/src/Decompiler/Analysis/ProcedureFlow.cs`

Its `CallApplicationBuilder` binds sequence and stack storage from reaching SSA
definitions, but falls back to synthesized invalid arguments when binding
fails. See `borrow/reko/src/Decompiler/Analysis/CallApplicationBuilder.cs:183-264`.
Borrow the former and explicitly forbid the latter.

Extend plan step 3 in Types/Lowering as follows:

1. Compute a whole-program, SCC-aware contract for every internal function:
   exact stack offsets and widths read, register/sequence inputs, preserved and
   clobbered storage, return/live-out storage, stack delta, and signed/value/
   pointer class.
2. Bind every call argument from the reaching definition of that exact storage
   at that callsite. A split value carries its sequence identity and slice
   provenance; a stack argument carries its BP/SP-relative source identity.
3. Iterate contracts only to a deterministic fixed point. A caller and callee
   disagreement is a typed conflict, not permission to pick one signature.
4. Never synthesize an argument, read an arbitrary current-SP slot, or emit an
   invalid placeholder. Missing proof is `UNKNOWN_REFUSE`, retains the lower
   representation, and fails materialization if the call was classified.
5. Feed the accepted contract into definitions and all callsites before C
   emission; export must not reconcile signatures afterward.

Acceptance cases:

- Beep's two `outp(0x42, ...)` calls bind the low and high byte of the same
  proven quotient, and `Sleep(duration)` binds the full duration value.
- SwapBars binds both row values to DrawBar and the first row value to DrawTime.
- QuickSort binds both arguments on every recursive edge, including the two
  opposite call orders; a Reko-like missing recursive argument is a hard gate
  failure.
- A negative fixture with incomplete caller coverage refuses a unified
  signature and emits no guessed argument.

Definition of done:

- every internal function has one deterministic SCC-aware contract consumed by
  its definition and all callsites before C emission
- all Beep, SwapBars, QuickSort, and incomplete-census acceptance cases pass,
  including exact value-versus-pointer classes and recursive argument order
- contract evidence counters close and transport preserves typed storage
  identities across clean workers

Definition of failure:

- an argument or return is synthesized, selected from an arbitrary stack slot,
  repaired in export, or accepted without reaching-definition proof
- recursive or conflicting caller evidence is ignored, resolved by order, or
  converges nondeterministically
- any required call/argument is lost or an unknown/conflict does not refuse

#### 7.3 Infer arrays and small structures from alias-equivalent accesses

Reason: Proven aggregate identities can replace noisy segmented accesses and
whole-object byte traffic with readable arrays and fields. The transformation
is valid only after Alias, Widening, and bounded range evidence agree.

Reko's type pipeline normalizes expressions, builds equivalence classes,
collects constraints, builds aggregate types, replaces type variables, and only
then rewrites memory expressions. See:

- `borrow/reko/src/Decompiler/Typing/TypeAnalyzer.cs:33-111`
- `borrow/reko/src/Decompiler/Typing/EquivalenceClassBuilder.cs`
- `borrow/reko/src/Decompiler/Typing/TypeCollector.cs`
- `borrow/reko/src/Decompiler/Typing/DataTypeBuilder.cs`
- `borrow/reko/src/Decompiler/Typing/TypedExpressionRewriter.cs:208-315`

Adopt a bounded version after Alias and Widening, owned by Types/Lowering:

1. Group accesses only by proven `Address(space, base, offset)` alias identity,
   not textual similarity or numeric proximity across objects.
2. Collect typed constraints from load/store width, constant field offset,
   proven induction stride, call argument class, copy width, and widening
   identity.
3. Materialize an array only when one base, one element width, and consistent
   indexed accesses are proven. Materialize a structure only when non-overlap
   or an explicit union relation accounts for every observed field.
4. Keep conflicting constraints as separate typed alternatives and leave raw
   segmented accesses in C. Do not reproduce Reko's giant `Eq_*` unions or
   member-pointer expressions.
5. Rewrite memory expressions to object/field/index access only after the
   aggregate contract is accepted; this final rewrite introduces no new
   semantics.

Acceptance cases:

- InitBars proves the 43-word stack array from its initialization loop,
  bounded random index, and same-object replacement store.
- `abarPerm` and `abarWork` prove independent arrays of two-byte elements;
  each element proves byte `len` and byte `clr` fields from consistent offsets.
- Swaps materializes one two-byte temporary and three whole-object copy effects,
  while pointer/value argument classes remain unchanged.
- ReInitBars proves whole-element copies between the two arrays without merging
  their base identities.
- Negative tests reject a structure/array when accesses cross DS/SS, use
  inconsistent stride, overlap without union evidence, or have an unbounded
  index.

Definition of done:

- InitBars, `abarPerm`, `abarWork`, Swaps, and ReInitBars satisfy all listed
  array/field/copy acceptance cases with every observed byte accounted for
- the accepted aggregate contract is owned by Types/Lowering and its final
  rendering introduces no new semantic fact
- all cross-segment, inconsistent-stride, overlap, and unbounded-index fixtures
  refuse materialization and retain explicit accesses

Definition of failure:

- arrays or structures are inferred from proximity, source shape, peer output,
  default element counts, or accesses from different alias objects/spaces
- overlapping or unbounded accesses are hidden by a guessed aggregate
- pointer/value classes, copy widths, validation, or behavior regress

#### 7.4 Closed evidence and gates

Reason: Mechanism-specific improvements are not durable unless every fact is
accounted for and the complete binary, compile, behavior, tiny-example, and
architecture gates enforce the same contract.

Each of the three mechanisms must report
`raw_fact_count`, `normalized_fact_count`, `classified_fact_count`,
`materialized_count`, and `failure_count`. If `classified > 0` and
`materialized == 0`, the owning pipeline stage fails.

Definition of done:

- focused before/after regressions cover Beep, Sleep, InitBars, ReInitBars,
  Swaps, SwapBars, and QuickSort;
- all affected functions have `validation=passed`, no semantic call loss, and
  generated output no farther from `SORTDEMO.C` than the current baseline;
- the sidecar-free 20-function gate, strict GCC translation-unit check, 19
  generated behavior harnesses, and all seven MS C tiny constructs pass;
- `make test-pipeline PYTHON=./.venv/bin/python` passes before claiming the
  mechanism improved decompilation;
- no source name, source text, Reko output text, address allowlist, or rendered-C
  pattern participates in recovery;
- no semantic work is added to postprocess, CLI, or export assembly.

Definition of failure:

- evidence counters are missing/inconsistent, or classified facts can reach
  zero materialization without failing their owning stage
- any focused function, 20-function corpus, GCC, behavior-harness, MS C tiny,
  architecture, typing, documentation, or test-pipeline gate fails
- recovery depends on source/peer text, names, address allowlists, rendered C,
  or a late semantic repair layer

### 8. Borrow Ghidra's strongest mechanisms at their owning layers

Status: implementation in progress from the IR/Alias vertical milestone.

Reason: Ghidra's strongest results come from memory SSA, storage trials, typed
range propagation, split-value normalization, conservative CFG collapse, and
bounded iteration. Inertia needs equivalent capabilities while retaining its
stricter segmented-memory and validation contracts.

Definition of done:

- tasks 8.1 through 8.11 meet their individual DoD in pipeline order
- each mechanism has one authoritative typed owner and replaces, rather than
  duplicates, any superseded late semantic producer
- the full task 8.7 closed gate passes and known Ghidra SORTD errors remain
  explicit negative fixtures

Definition of failure:

- Ghidra output is treated as truth, known Ghidra guesses are reproduced, or
  semantic work lands later than its owning layer
- two active passes own the same fact, or migration removes durable behavior
  before its typed replacement and tests exist
- licensing review is skipped for copied/adapted code or any closed gate fails

The useful Ghidra evidence is in its native decompiler core under
`/home/xor/ghidra/Ghidra/Features/Decompiler/src/decompile/cpp/`. These are
implementation signposts, not proof that every Ghidra result is correct. In
particular, the mechanisms below explain quality seen in `main`, DrawFrame,
RunMenu, SwapBars, Swaps, Beep, and Sleep, but must be tightened so Inertia
does not reproduce Ghidra's known SORTD errors.

Ghidra is Apache-2.0 licensed, but this plan borrows algorithms and separation
of responsibilities rather than copying source. Any copied or closely adapted
implementation still requires an explicit license and notice review.

#### 8.1 Keep stack locations in SSA until locals can be proven

Status: complete; exact `SS:BP+offset` ranges partition into canonical byte
cells with versioned definitions and joins through IR and Alias. Widening now
accepts a composed byte-view component only when every range is nested under
one unique Alias-equivalent owner, and Lowering materializes that owner. General
non-laminar contained views are now covered. Exact call-bearing direct scalar
writes are covered when typed call effects prove that the unique owner survives;
the project-wide multi-function semantic-artifact handoff is complete. The
overlap, escape, one-branch SP-change, and DS/SS-collision negative-fixture DoD
is complete. Sidecar-free DrawFrame and DrawTime retain clean Lowering-owned
locals without setup temporaries, and InitMenu no longer conflates its `BP-2`
loop local with an unreferenced `BP+2` control-slot declaration.

Reason: Early conversion of stack storage into loosely related C temporaries
loses definition, join, width, escape, and call-clobber evidence. Exact SS range
SSA is required before a stack range can safely become one local or argument.

Ghidra does not recover locals from rendered stack syntax. Its `Heritage`
engine constructs SSA for disjoint memory locations, delays stack-memory SSA
until locations are discovered, inserts phi nodes, renames definitions, and
guards memory across LOAD, STORE, and calls. `ActionStackPtrFlow` separately
solves stack-pointer changes and repairs stack-relative loads. See:

- `heritage.hh:190-315` (`Heritage`, memory SSA, guards, phi placement, rename)
- `heritage.cc:986-1065` (`discoverIndexedStackPointers`)
- `heritage.cc:1443-1605` (call, STORE, and LOAD guards)
- `heritage.cc:2479-2705` (SSA rename, phi placement, and heritage pass)
- `coreaction.cc:113-206` (`StackSolver::solve`, `StackSolver::build`)
- `coreaction.cc:262-512` (`ActionStackPtrFlow`)
- `varmap.cc:1120-1320` (`MapState::gatherVarnodes`,
  `ScopeLocal::restructureVarnode`, `ScopeLocal::restructure`)

Implement the equivalent in Inertia's IR, Alias, Widening, and Lowering layers:

1. Give each stack read/write an `Address(space=SS, base=entry_sp_or_bp,
   offset, width)` identity before naming any local or argument.
2. Build memory definitions and joins per exact stack range; split or merge
   overlapping ranges only with byte-accurate evidence.
3. Model call stack delta and clobbers as typed effects. Unknown delta prevents
   local materialization instead of silently rebasing later accesses.
4. Lower an SS range to one local only after all definitions, uses, widths,
   joins, and escapes agree. Keep unresolved accesses explicit.

Measured progress on 2026-08-21:

- `IRCallStackEffect8616` now applies stack deltas to the coordinate they
  actually move. A complete, known callee-cleanup delta may preserve an
  explicitly preserved `SS:BP+offset` or entry-SP range, while a nonzero delta
  still refuses a current-`SP` range and an unknown delta refuses every range.
- the Semantics callsite-summary producer is covered end to end through
  function memory SSA for a value argument cleaned by the callee. Positive BP,
  nonzero-SP, and unknown-delta cases prevent either blanket refusal or unsafe
  preservation.
- 33 focused IR/Semantics/Alias/Lowering tests pass. Sidecar-free DrawFrame,
  DrawTime, and InitMenu compile/validation regressions pass unchanged.
  `quality-dev` passes Ruff `--fix`, MyPy, mypyc smoke, architecture/context/
  ownership checks, 1,523 tests, and all three quality comparisons. The
  required pipeline passes its focused, Ultra QuickC, and seven MS C tiny
  compile/run/decompile/recompile/runtime lanes.
- IR now partitions every accepted exact BP access by all observed byte
  boundaries. Stores define each canonical cell, loads retain ordered reaching
  slices, and joins create one phi per changed cell while the original access
  remains the accounting unit. Exact one-cell accesses retain the compatible
  versioned-address path.
- Call effects are checked against each original access range. If one escaped
  or unpreserved view is refused, its entire connected overlap component is
  refused, preventing a partially accepted neighbor from consuming an ignored
  store.
- Alias projects complete multi-cell accesses as typed composed views, rechecks
  that every slice is contained by the original storage identity, and keeps
  exact one-cell accesses on the existing fact path. Malformed views and
  inconsistent overlap relations have typed refusals.
- Widening owns composed stack-object proof. It accepts only a connected overlap
  component whose ranges are all contained by one unique owner with consistent
  Alias storage, and carries every source access, fact, version, and byte phi
  into the accepted artifact. Partial sibling overlap is accepted only when
  that owner contains every range; ownerless partial overlap, missing or
  ambiguous ownership, inconsistent storage, and orphan views refuse the whole
  component.
- Lowering consumes that exact Widening artifact instead of rediscovering
  storage. Missing, stale, or incomplete Widening fails the pipeline; a refused
  component suppresses every covered exact fragment so no partial local can
  escape. Existing exact-range materialization remains unchanged.
- Structured-C word recomposition now treats AST variables only as a
  materialization target. It consumes the current complete Widening artifact,
  requires exact function, `SS:BP`, owner, low-byte, and high-byte ranges, and
  refuses missing, stale, ambiguous, cross-region, wrong-offset, or wrong-scale
  evidence. The declared projection pass runs after its artifact producer; the
  previous independent `SimStackVariable` ownership reconstruction is removed.
- A typed Widening resolver now classifies each structured stack view as
  `NOT_CANDIDATE`, `ACCEPTED`, or `REFUSED` against the current object artifact.
  Proven low/high byte reads project from the unique word owner, and pure byte
  assignments become tag-preserving read/modify/write assignments to that
  owner. A call-bearing RHS is accepted only when every tagged C callsite maps
  one-to-one to an exact IR call effect that proves the complete owner range is
  preserved. Untagged, mismatched, duplicate, incomplete, and clobbering call
  evidence refuses; other side effects remain unchanged. Stale, refused,
  ambiguous, cross-function, and unmaterialized owners cannot bypass the typed
  decision.
- Scalar-view expression construction is isolated from proof resolution and
  supports exact byte or word subranges of proven 2-byte and 4-byte owners.
  Reads use unsigned owner-width shifts and masks; pure writes preserve every
  non-view bit with a tag-preserving read/modify/write assignment. Unsupported
  three-byte views refuse, and the older two-byte recomposition fold remains
  word-only so a dword owner cannot replace a partial value. Nested pure RHS
  reads are projected before the containing-owner write is finalized.
- The immediate object Widening, Lowering, and artifact-backed projection
  lifecycle passes 46 focused cases. Sidecar-free ExchangeSort, DrawFrame,
  DrawTime, and InitMenu compilation/validation regressions pass. Ruff `--fix`,
  strict MyPy, mypyc smoke, architecture/context/ownership gates, and all three
  quality comparisons pass. The mandatory seven-worker pipeline is 3/3 green:
  1,548 focused tests, four validated Ultra QuickC fixtures, and all seven MS C
  tiny compile/run/decompile/recompile/decompiled-run constructs; no lane
  failed, skipped, or timed out.
- Project-wide exact-function SSA now has one IR-owned readiness registry. Raw
  `IR` artifacts may upgrade once to canonical `SEMANTIC` artifacts; they cannot
  downgrade, and divergent same-stage publication refuses without replacing
  accepted evidence. The main Semantics path publishes its call-effect-enriched
  artifact, while lazy exact-function lookup performs the same enrichment for
  interprocedural consumers.
- Types/Lowering storage-trial, return, and live-out consumers now require the
  Semantics-ready registry artifact instead of rebuilding an independent raw
  SSA view. Two-function tests prove independent address caching, replay object
  identity, typed missing-function refusal, one-way upgrade, and conflict
  refusal. The broader interprocedural surface passes 120 tests, and six real
  sidecar-free SORTD regressions pass with compilation and validation intact.
- The closed checkpoint passes Ruff `--fix`, project-wide MyPy, mypyc import
  smoke, architecture/context/ownership checks, and all three quality
  comparisons. The mandatory seven-worker pipeline is 3/3 green: 1,582 focused
  tests, four validated Ultra QuickC fixtures, and all seven MS C tiny
  compile/run/decompile/recompile/decompiled-run constructs; no lane failed,
  skipped, or timed out.
- The explicit branch-dependent `SS:SP` join fixture now proves the
  correctness-first refusal path end to end: IR reports
  `unproven_stack_range`, Alias retains the typed upstream refusal, and
  Lowering creates no candidate or C local. The equal-offset explicit DS/SS
  fixture proves that DS remains a distinct typed address outside stack SSA and
  only the SS owner can materialize. No production semantic workaround was
  required; the existing IR -> Alias -> Lowering ownership boundary was
  already conservative. Both fixtures are enforced by the Makefile and focused
  pipeline. The checkpoint passes 31 focused tests, six real SORTD regressions,
  `quality-dev`, and all three mandatory pipeline lanes: 1,584 focused tests,
  four validated Ultra QuickC fixtures, and all seven MS C tiny constructs.
- Types/Lowering now owns declaration-map cleanup separately from argument
  inference. It classifies exact Alias stack identities below the first ABI
  argument, removes only declarations absent from both the function body and
  header, and refuses unknown-width, ABI-crossing, body-owned, header-owned,
  and overlapping views. Typed evidence reports raw, normalized, classified,
  materialized, failed, and refused facts; classified facts cannot silently
  produce zero materializations.
- The sidecar-free InitMenu regression now rejects any surviving `BP+2`
  declaration owner while preserving its calls, strict portable-flat compile,
  `validation=passed`, and clean whole-tail result. Fresh DrawFrame and DrawTime
  captures retain their clean local shapes. The first cold isolated InitMenu
  run reached clean validation but hit the unchanged 180-second watchdog; the
  warm acceptance passed in 72.2 seconds, so no timeout was relaxed and the
  cold-path variance remains performance debt under task 6.
- Seven declaration-identity cases and the existing eight argument-identity
  cases pass. Ruff `--fix`, strict MyPy, mypyc import smoke, architecture,
  context, ownership, and `quality-dev` gates pass. The mandatory seven-worker
  pipeline is 3/3 green with 1,589 focused tests, four validated Ultra QuickC
  fixtures, and all seven MS C tiny compile/run/decompile/recompile/decompiled-
  run constructs.

This should remove Ghidra-like stack setup temporaries from DrawFrame,
DrawTime, and InitMenu without moving stack recovery into Rewrite. Negative
tests must cover overlapping locals, SP changes on one branch, escaped stack
addresses, and DS/SS offset collisions.

Definition of done:

- exact SS ranges have versioned definitions, phi joins, byte-accurate overlap
  handling, and typed call delta/clobber effects in IR/Alias
- every accepted composed view has one unique Alias-equivalent Widening owner;
  every unresolved component refuses atomically before Lowering
- DrawFrame, DrawTime, and InitMenu improve through Lowering-owned locals while
  every listed overlap/SP/escape/segment fixture refuses unsafe materialization
- evidence counters close and validation, behavior, and recompilation remain
  green

Definition of failure:

- stack identity is reconstructed from rendered C, variable names, or raw
  numeric proximity, or DS and SS storage are conflated
- an unknown stack delta, overlap, escape, or clobber is silently ignored
- Lowering bypasses, recreates, or accepts a stale/incomplete Widening decision
- locals are discovered in Structuring/Rewrite or any required effect regresses

#### 8.2 Recover call and return contracts from storage trials

Status: in progress. Exact input storage-trial collection, `DX:AX`
direct-global return materialization, replay-safe call accounting, exact
final-callsite multiplicity validation, regenerated stored-result alias
ownership, deterministic return/live-out trial
collection, signed/unsigned strict and non-strict `DX:AX` ordering use typing,
sign-insensitive equality/inequality use typing, recursive pass-through
propagation, production SCC publication, and atomic callee plus callsite type
application are complete. Exact terminal call-result passthrough now also
updates inferred caller return types before Structuring while preserving
explicit signature/user interfaces. Exact direct DS/ES must-write live-outs with condition
uses preserved on every target-reaching caller CFG path are implemented,
including a deterministic union when different callers consume disjoint proven
outputs. Nested overlapping direct views now materialize only through a unique
maximal Alias owner. Widening projects exact and contained direct caller views
from that owner, retaining the proven byte offset and exact access width before
Types/Lowering creates a trial. Every project-wide trial, return, and live-out
consumer now reads the canonical Semantics-ready exact-function SSA artifact.
RunMenu call-result-to-stack materialization is complete. The first terminal
pointer-parameter output slice reaches a logical callee-parameter registry;
exact caller-target projection from expression reaching definitions and typed
callsite effect/object materialization are complete. Proof-driven pointee/object
typing, indexed effects, and broader object-type materialization remain.

Reason: Calls and returns cross function boundaries where local inference is
insufficient. Typed storage trials allow a complete caller census to prove
inputs, outputs, stack delta, and split returns without guessed signatures.

Ghidra treats a call signature as an evolving dataflow contract. It checks
candidate input storage against alias information over multiple passes, then
resolves a calling-convention model and builds call inputs. Outputs are
recovered from live uses; split return registers are joined with a `PIECE`
operation. See:

- `coreaction.cc:1754-1820` (`ActionActiveParam`, `ActionActiveReturn`)
- `coreaction.cc:1858-1983` (`ActionReturnRecovery`)
- `fspec.hh:1628-1727` (`FuncCallSpecs`, active inputs/outputs and stack delta)
- `fspec.cc:5585-5805` (trial-use checks and input/output construction)
- `coreaction.cc:4680-4740` (`ActionPrototypeTypes` and input extension)

Use this to refine plan steps 3 and 7.2 in Types/Lowering:

1. Represent each candidate parameter/return as a typed storage trial with
   width, exact stack/register identity, reaching definition, use evidence,
   signedness, and value-versus-pointer class.
2. Resolve a function contract only after the complete caller census agrees;
   join split returns only when both pieces have the same return provenance.
3. Apply the accepted contract to the callee and every callsite in one
   transaction. Conflicts remain typed failures, never export repairs.
4. Require every emitted argument to retain its reaching-definition proof.

The hard negative boundary comes from Ghidra itself: PercolateUp converted an
object address into a row value, and Beep lost an output-port argument. Those
outputs become rejection fixtures for argument-class changes and incomplete
trials. QuickSort's two recursive edges remain the fixed-point stress test.

Measured progress on 2026-08-20:

- direct-global `DX:AX` stores now consume or reuse one exact typed call across
  same-group, cross-group, and replayed C-AST projections; cleanup refuses to
  remove a standalone call unless the matching canonical assignment is active
- synthesized value calls retain their instruction identity, allowing the
  existing callsite declaration owner to infer the proven return class
- callee arity no longer aliases unrelated linear code targets by low 16 bits;
  explicit project aliases remain the only rebasing authority
- an incomplete whole-program arity census emits an honest unprototyped
  declaration with the proven return type instead of guessing parameters
- isolated sidecar-free ReInitBars and DrawTime regressions pass strict GCC,
  `validation=passed`, whole-tail validation, and exact one-call assertions
- Tail Validation now owns a typed callsite-multiplicity report with closed
  evidence counters. It counts only final C calls carrying an exact required
  machine instruction identity; target names, rendered C, and untagged calls
  are not treated as multiplicity proof
- an assignment-RHS call plus a standalone call with the same `ins_addr` now
  fails the absolute final semantic guard and persists as a
  `callsite_multiplicity` snapshot failure, while two distinct machine
  callsites targeting the same callee pass
- the validation cache contract was versioned, and the new module/test are in
  the promoted Makefile, architecture, and ownership inventories. Ruff
  `--fix`, MyPy, types/docs, architecture/context/ownership, 490 selected
  changed-surface tests, and both isolated sidecar-free SORTD regressions pass
- typed IR analysis now proves the machine-BP to angr entry-SP coordinate
  before stack-memory SSA Lowering. Unknown coordinates refuse local
  materialization, positive BP ranges remain typed storage-trial refusals, and
  exact materialization retires only the obsolete entry-SP declaration
  projection. Width-to-type Lowering now maps proven one-, two-, and four-byte
  scalar ranges exactly instead of ignoring width
- the three stack-annotation regressions now emit one `BP-2` `unsigned short`
  local with the requested name and no stale byte, dword, or split-argument
  declaration. Their strengthened smoke tests pass; 152 related tests and the
  512-test changed-surface gate pass with Ruff `--fix`, MyPy, types/docs,
  architecture/context, and ownership checks
- the `whsum` declaration failure no longer reproduces: the existing
  Types/Lowering owner consumes the complete caller-width census and emits
  `void sub_105e6(unsigned short a0, unsigned short a1);`; the CLI only replays
  that typed contract before rendering. Tail validation passes and C11 syntax
  checking with implicit declarations promoted to errors succeeds
- the fixture now requires that source-backed prototype in its generated-C
  contract, so the default pipeline cannot pass if the declaration disappears
- the required seven-worker default `make test-pipeline` passes all three
  lanes: 1,486 focused tests, four validated QuickC fixtures, and all seven MS
  C tiny compile/decompile/recompile/runtime constructs. The measured lane
  times on the final edited-state run were 79.702s, 101.846s, and 174.758s
  respectively; only the focused lane exceeded its 30s advisory budget
- typed Types/Lowering contracts now retain exact stack/register identity,
  width, SSA reaching definition and use, signedness, pointer/value class,
  split-return provenance, stack delta, and the mandatory five evidence
  counters. A deterministic SCC solver closes only complete callsite censuses
  and retains typed refusal reasons for every unresolved or conflicting set
- focused QuickSort and mutual-recursion fixtures converge independently of
  input order; Beep-like incomplete censuses and PercolateUp-like
  pointer-to-value changes refuse, and split `DX:AX` outputs require one shared
  provenance before joining
- one atomic transaction contract now represents an accepted callee contract
  with every proof-bearing callsite binding. Focused tests prove that omitted
  callsites cannot be consumed, but the main Types/Lowering path does not yet
  publish the SCC result to production declaration and prototype consumers
- the direct-caller census now retains one typed origin record per callsite:
  evidence project, exact caller function address, machine callsite address,
  and typed summary. Argument-count and width evidence derive from that same
  census, so the production trial collector no longer has to guess which
  function or rebased project owns a summary. The extraction also reduced the
  oversized argument-count module from 392 to 177 lines; Ruff `--fix`, MyPy,
  architecture/context/ownership gates, and 453 selected tests pass
- a Types/Lowering reaching-definition resolver now verifies the exact typed
  CALL use and binds immediate, `SS:BP` value, stable `DS`/`ES` value, and
  `SS:BP` address arguments to program-owned SSA definitions. Split global
  loads retain byte-accurate memory pieces; a claimed BP address must trace
  through local SSA aliases to the matching BP origin, while missing,
  conflicting, and call-output facts refuse with typed reasons and closed
  evidence counters. All four production modules remain below 350 lines; seven
  real-lifter regressions and the 508-test ownership-expanded changed-surface
  gate pass with Ruff `--fix`, MyPy, types/docs, architecture/context, and
  ownership checks. `quality-dev` passes, and the default seven-worker pipeline
  passes 1,502 focused tests, four validated QuickC fixtures, and all seven MS
  C tiny compile/decompile/recompile/runtime constructs; lane times were
  37.270s, 63.146s, and 108.145s
- Ruff `--fix`, MyPy, ownership/header guards, architecture/context checks,
  115 related tests, and the 655-test changed-surface gate pass. The default
  seven-worker pipeline also passes 1,495 focused tests, four QuickC fixtures,
  and all seven MS C tiny compile/decompile/recompile/runtime constructs; lane
  times were 36.554s, 69.144s, and 107.550s
- the IR layer now owns a lazy, exact-function SSA registry so every retained
  caller origin resolves against one program-owned dataflow artifact; missing
  function bounds, IR refusal, and SSA refusal are typed failures, and only
  proven artifacts are cached
- the production Types/Lowering input collector joins the closed caller census,
  exact source-order `SS:BP+offset` callee storage, SSA reaching definitions,
  condition signedness, and binary pointer-use evidence. It materializes
  immediate, stack value/address, and split `DS`/`ES` global trials with exact
  source and destination pieces; pointer signedness is explicitly not
  applicable rather than guessed
- duplicate machine callsites, unknown stack delta, missing caller SSA,
  reaching-definition conflicts, piece mismatches, and unknown or conflicting
  signedness/value classes refuse with typed reasons and closed five-field
  counters. Seven real-lifter tests cover positive and refusal behavior, and
  the focused interprocedural surface passes 20 tests
- the changed-surface gate passes Ruff `--fix`, MyPy for ten source files,
  types/docs and dot-access ratchets, architecture/context/ownership checks,
  and 540 selected tests. `quality-dev` passes, including the 38-module mypyc
  import smoke and three no-regression quality comparisons. The required
  seven-worker `make test-pipeline` passes 1,509 focused tests and all six
  selected tiny MS C compile/run/decompile/recompile/decompiled-run programs
- the caller return-use census now retains one typed fact per direct machine
  call: exact caller function, callsite, witness instruction, use kind, verdict,
  and recursive-pass-through exclusion. Transitive wrapper observations update
  only the verdict and preserve the local return witness; unknown paths remain
  visible failures. The owner was extracted from the oversized callsite summary
  into a 96-line recovery-metadata contract while preserving public re-exports
- five focused exact-fact tests, all 14 caller-use regressions, 145 broader
  caller-evidence consumer tests, and the 456-test changed-file gate pass with
  Ruff `--fix`, MyPy, types/docs, architecture/context, and ownership checks
- return definitions now distinguish ordinary SSA/constant values from typed
  `CALL_OUTPUT` producers. An observed return use binds only to the unique typed
  CALL at the exact machine callsite and an exact accepted target address; it
  never fabricates an SSA version or aliases targets by their low 16 bits
- AX and split DX:AX definitions retain exact register storage and one shared,
  deterministic call provenance. Unknown/unobserved uses, missing callsites,
  target mismatches, invalid storage, and duplicate pieces are typed atomic
  refusals. Return trials now require `CALL_OUTPUT` at their own callsite
- seven real-lifter producer tests and six updated SCC/solver tests pass. The
  463-test changed-file gate also passes Ruff `--fix`, MyPy, types/docs,
  architecture/context/ownership, and confirms Understand-Anything automatic
  updates remain disabled
- a dedicated Types/Lowering classifier now joins one exact caller return-use
  witness, Alias-owned AX/AL/AH storage identity, and canonical `ConditionIR`.
  Signed ordering proves a signed scalar return; unsigned ordering retains its
  proven unsigned interpretation but refuses the still-ambiguous pointer/value
  class, while equality, missing witnesses, split carriers, contradictory
  identities, and duplicate semantic projections remain typed atomic refusals
- the classifier retains its exact condition and all five evidence counters.
  Ten focused classification tests include real lifted signed/unsigned/equality
  branches and the complete refusal matrix. Ruff `--fix`, MyPy, types/docs,
  architecture/context/ownership, and the 473-test changed-file gate pass;
  Understand-Anything automatic updates remain disabled
- the Alias layer now owns exact full-word SP/BP/SI/DI domains and angr register
  offsets in addition to AX/BX/CX/DX. This lets Types/Lowering identify legal
  8086 address carriers without creating a competing register map
- a dedicated Types/Lowering classifier now starts at one exact, versionless AX
  `CALL_OUTPUT`, follows only versioned equal-width semantic MOVs in the exact
  witness block, and proves pointer class only when that lineage reaches one
  stable, segment-proven, single-base DS/ES/SS LOAD or STORE. Pointer
  signedness is explicitly `NOT_APPLICABLE`
- mixed address bases, provisional addresses, carrier clobbers, absent
  dereferences, duplicate witnesses, versioned or mismatched call outputs, and
  caller identity mismatches remain typed refusals. The shared result/evidence
  contract was extracted so the scalar classifier is 254 lines, the contract
  is 147 lines, and the pointer classifier is 342 lines
- eleven focused pointer tests cover real-lifter positive and refusal paths;
  the ownership-expanded changed-file gate passes Ruff `--fix`, MyPy for six
  selected source files, types/docs, architecture/context/ownership checks,
  and 509 selected tests. Understand-Anything automatic updates remain
  disabled. The required full pipeline was not rerun for this bounded
  same-block prerequisite
- the first cross-block probe exposed an earlier IR defect: real pyvex
  `Exit.dst` values are direct constants, while VEX import accepted only
  wrapped constant expressions. Conditional blocks therefore retained only
  one of their taken/fallthrough successors, making later SSA blocks appear
  disconnected. VEX import now normalizes both boundary forms before building
  `IRBlock.successor_addrs`; it does not synthesize edges in Types/Lowering
- a dedicated real-lifter CFG regression proves that both successors survive
  and that function SSA records the complete predecessor join. Thirty-five
  focused IR/SSA tests and the 91-test ownership-expanded changed-file gate
  pass Ruff `--fix`, MyPy, types/docs, architecture/context/ownership checks,
  and the disabled Understand-Anything auto-update guard
- returned-pointer lineage now crosses only authoritative function-SSA CFG
  edges. At a join, every predecessor must retain the same Alias-owned
  full-word carrier domain and any register phi must contain the exact sorted
  `(source_block, value)` inputs produced by those predecessors
- direct edges and compatible all-predecessor phi joins retain complete typed
  edge and phi evidence through the final stable DS/ES/SS dereference. A
  clobbered predecessor, incomplete CFG, corrupted phi, ambiguous/provisional
  address, or reachable cycle refuses with a stable typed reason; cycles are
  not guessed through an implicit fixed point
- block-local transfer and CFG/phi convergence have separate Types/Lowering
  owners. The pointer classifier was reduced from 342 to 145 lines; its 244-line
  block-transfer and 298-line flow modules remain below the 350-line ratchet
- six new real-lifter CFG tests cover direct transfer, compatible phi input,
  clobbered joins, corrupted phi evidence, incomplete CFG, and cycle refusal.
  All 18 focused pointer/CFG tests pass, and the ownership-expanded changed-file
  gate passes Ruff `--fix`, MyPy for nine production files, types/docs,
  architecture/context/ownership checks, and 527 selected tests in 52.38s.
  Understand-Anything automatic updates remain disabled. The required full
  pipeline was not rerun for this bounded pointer-flow increment
- deterministic return/live-out collection now joins the complete input
  callsite census with Semantics-owned terminal carrier proof, exact caller
  return-use facts, program-owned SSA, versionless `CALL_OUTPUT` definitions,
  and the existing scalar-condition or segmented-pointer classifiers. Proven
  `AX` scalar and pointer uses become solver-ready return trials; closed unused
  returns preserve their callsites with no invented output
- machine instruction addresses are not assumed to identify one SSA
  instruction. Scalar trials require one direct Alias-matching register read,
  while pointer trials consume the exact alias step already retained by the
  pointer-flow proof. Corrupt censuses, exact function/target mismatches,
  unknown terminal storage, unsupported use kinds, and unproven `DX:AX` use
  remain typed refusals
- the collector, per-callsite materializer, and typed result contracts are
  separate Types/Lowering owners at 291, 339, and 90 lines. The SCC solver now
  refuses an empty incomplete callsite set instead of raising `IndexError`.
  Six real-lifter collection tests, all 53 focused return/SCC tests, and the
  68-test ownership-expanded changed-surface gate pass with Ruff `--fix`,
  MyPy, types/docs, architecture/context, and ownership checks. Understand-
  Anything automatic updates remain disabled
- a dedicated 323-line condition/CFG selector and 256-line split classifier
  now prove non-strict signed or unsigned lexicographic `DX:AX` comparisons.
  The proof retains the three canonical conditions, exact SSA CFG edges,
  control-only trampoline blocks, both Alias-owned storage pieces, and distinct
  AX/DX use instructions before creating one shared-provenance output trial
- incomplete AX-only evidence, semantically active trampolines, non-adjacent
  comparison pieces, competing chains, and broken CFG paths remain typed
  refusals. One real-lifter integration regression and three direct selector
  tests cover the acceptance and dangerous refusal boundaries
- all 57 focused return/SCC tests pass. The ownership-expanded changed-file
  gate passes Ruff `--fix`, MyPy for ten production modules, types/docs,
  architecture/context/ownership checks, and 500 selected tests. Understand-
  Anything automatic updates remain disabled; the required full semantic
  pipeline was not rerun for this bounded split-return increment
- Semantics now retains an exact direct target, terminal return instruction,
  and CFG block path for each caller-selected call-result pass-through. The
  closed evidence census refuses active post-call effects, indirect calls,
  ambiguous CFGs, duplicate candidates, and missing identities; four focused
  pass-through tests and the existing terminal-call tests cover these bounds
- Types/Lowering now lowers each proven recursive pass-through into a deferred
  trial retaining the exact SSA `CALL`, target, terminal machine return, and
  CFG path without inventing storage, signedness, or a pointer/value class. A
  recursion-only trial remains complete collection evidence, but the solver
  refuses it as `PASSTHROUGH_OUTPUT_UNRESOLVED` instead of accepting an empty
  output contract. Three real-lifter tests cover the positive identity join,
  witness mismatch, and mandatory no-seed refusal
- the SCC solver now advances a non-empty, otherwise valid direct output seed
  through deferred recursive pass-throughs as an explicit fixed-point state.
  It never treats an empty/void shape as a seed, and recursion-only evidence
  still refuses as `PASSTHROUGH_OUTPUT_UNRESOLVED`
- accepted callsite bindings retain the exact deferred `CALL`, target,
  terminal return, and CFG-path proof beside the shared function output slots;
  no synthetic RET SSA read or export-time signature repair is introduced. A
  callsite carrying both direct-return and pass-through evidence is a typed
  `CALLSITE_SET_CONFLICT`
- the single-function join was extracted into a 340-line Types/Lowering owner,
  reducing the SCC solver from 350 to 196 lines. All 18 focused return/SCC
  tests pass, and the ownership-expanded changed-file gate passes Ruff
  `--fix`, MyPy for five production files, types/docs,
  architecture/context/ownership checks, and 505 selected tests. Understand-
  Anything automatic updates remain disabled
- a 330-line production Types/Lowering lifecycle owner now collects the current
  function's closed input and return trials, replaces that function in the
  immutable sorted program trial payload, resolves every retained SCC, and
  publishes the complete result in one project assignment before prototype and
  declaration consumers run. The atomic payload now retains both source trials
  and their accepted/refused resolutions
- incomplete input or return collection leaves the preceding atomic payload
  unchanged. A complete solver conflict is published as a typed refusal, and
  both definition-width and callsite-declaration consumers refuse to fall
  through that known conflict to older heuristic evidence
- production publication/replay, incomplete-collection preservation, typed
  conflict publication, and refusal-aware declaration tests pass. The focused
  interprocedural surface passes 32 tests; the ownership-expanded gate passes
  Ruff `--fix`, MyPy for eight production files, types/docs,
  architecture/context/ownership checks, and 663 selected tests. Understand-
  Anything automatic updates remain disabled
- one shared Types/Lowering adapter now projects accepted scalar storage widths
  and signedness to exact angr `SimType` objects and preserves proven 16-bit
  near-pointer pointee types. Empty output sets remain unproven rather than
  being guessed as `void`; multiple logical outputs and unsupported widths are
  typed refusals
- prototype preflight verifies exact source-order `SS:BP` storage, C argument
  identity and width, pointer pointee coherence, and the accepted output shape
  before any mutation. The application transaction then updates C arguments,
  the callee prototype, function metadata, and the callsite return declaration
  together; a published typed refusal blocks older width reconciliation
- focused tests prove scalar width/signedness projection, `DX:AX` long return
  projection, near-pointer preservation, no partial mutation on refusal,
  lifecycle ordering, and one identical return type at the callee and callsite.
  The 73-test integrated surface, Ruff `--fix`, MyPy, architecture/context and
  ownership guards, and `quality-dev` including the 38-module mypyc smoke pass
- one typed decision-graph owner now proves signed and unsigned strict and
  non-strict ordering plus equality and inequality from exact Alias-owned
  `DX:AX` pieces, canonical `ConditionIR`, authoritative function-SSA edges,
  common sinks, and refusal-free control-only trampolines. The prior condition
  module is a 23-line compatibility facade; the authoritative owner remains
  below the 350-line ratchet
- equality/inequality trials retain `SIGN_INSENSITIVE` rather than claiming
  source signedness. The shared SimType adapter uses a canonical unsigned C
  projection that preserves all proven bits while the typed trial remains the
  authoritative sign interpretation
- real-lifter tests cover signed and unsigned strict comparisons and equality/
  inequality, while malformed sink topology and active trampoline paths refuse
  explicitly. The integrated return/type surface passes 83 tests
- the complete edited-state `quality-dev` gate passes Ruff `--fix`, MyPy for 65
  source files, the 38-module mypyc compile/import smoke, architecture/context/
  ownership checks, 1,523 fast-pipeline tests, and all three decompilation
  quality comparisons
- the required seven-worker default pipeline passes 3/3 lanes: 1,523 focused
  tests, 4/4 validated Ultra QuickC fixtures, and all seven MS C tiny build/run/
  decompile/recompile/decompiled-run constructs. Lane times were 37.728s,
  63.614s, and 107.548s; only the focused lane exceeded its advisory budget
- VEX STORE import now derives the direct-memory width from the resolved value,
  preserving byte stores carried through temporaries instead of defaulting the
  address and store to a word
- Semantics now classifies exact stable direct DS/ES stores as must-write only
  when every entry-reachable machine-return path writes the same byte range.
  Conditional writes, incomplete/non-return terminals, indirect aliases,
  overlapping direct ranges, and DS/ES identity conflicts refuse atomically
  with closed evidence counters
- Types/Lowering now binds one such output to the exact caller `CALL_OUTPUT`,
  follows every authoritative SSA CFG path that can reach the candidate use,
  and activates a live-out trial only for the direct load named by canonical
  `ConditionIR`.
  VEX JCC replay loads do not become duplicate machine uses; absent uses remain
  inactive rather than being invented
- signed/unsigned ordering, equality, and zero-use evidence retain exact
  storage, callsite, definition, condition, and signedness. A full exact write
  on every target-reaching path becomes `NOT_REACHED`; a clean/write join or a
  partial overlapping write is `INTERVENING_WRITE`. Indirect aliases, calls,
  cycles, incomplete CFG, target mismatch, conditional callee writes, and
  conflicting signedness remain typed refusals
- accepted memory outputs use the distinct `LIVE_OUT` role in the existing SCC
  contract. The C return-type adapter consumes only `RETURN`, so a memory-only
  function is not incorrectly emitted with a scalar return type
- the semantic and lowering modules have explicit architecture and test owners
  and are registered in the Makefile typed, Ruff, and focused-test ratchets.
  Ruff `--fix`, focused MyPy for the complete production surface, architecture/
  ownership checks, and 73 focused tests pass
- the edited-state `quality-dev` gate passes Ruff `--fix`, MyPy, the 38-module
  mypyc compile/import smoke, architecture/context/ownership checks, 1,523
  focused tests, and all three decompilation-quality comparisons
- the required seven-worker pipeline passes 3/3 lanes: 1,523 focused tests,
  4/4 validated Ultra QuickC fixtures, and all seven MS C tiny build/run/
  decompile/recompile/decompiled-run constructs. Lane times were 44.760s,
  72.383s, and 137.923s
- one dedicated Types/Lowering join owner now forms the deterministic union of
  exact `LIVE_OUT` storage across a complete caller census. Different callers
  may consume disjoint proven outputs from one callee without forcing every
  callsite to have an identical live-out subset. Input and scalar-return roles
  retain their identical-shape agreement requirement
- the join refuses same-storage type conflicts, duplicate storage within one
  callsite, malformed trial roles, and incomplete caller censuses. A primitive-
  field total-order key keeps mixed DS/ES storage deterministic without
  comparing raw enums. Seven focused tests cover disjoint, multiple-output, and
  mixed DS/ES acceptance plus each refusal. The owner is 252 lines, and
  extracting it reduced the function solver from 350 to 262 lines
- the edited-state `quality-dev` gate passes Ruff `--fix`, MyPy, the 38-module
  mypyc compile/import smoke, architecture/context/ownership checks, 1,598
  tests, and all three decompilation-quality comparisons. The required pipeline
  passes 3/3 lanes with the same 1,598 tests, 4/4 validated Ultra QuickC
  fixtures, and all seven MS C tiny build/run/decompile/recompile/decompiled-run
  constructs
- RunMenu's exact `call 0x11292; mov [bp-2], al` evidence was already collected
  correctly, but the Types/Lowering classifier required the impossible
  production state `stack_cleanup == 0`; callsite collection represents the
  absence of a positive caller cleanup as `None`. The classifier now accepts
  `None` or legacy `0` only when argument count and widths are exactly empty,
  while contradictory positive cleanup remains a typed refusal
- the strict sidecar-free RunMenu regression now materializes
  `local_2 = sub_11292();`, retains the subsequent value argument and Escape
  exit, passes strict portable-flat compilation, `validation=passed`, and clean
  whole-tail validation. The permanent regression requires both the assignment
  and Escape case; the focused callsite/Lowering surface passes 100 tests
- the closed checkpoint passes Ruff `--fix`, MyPy, the 38-module mypyc compile/
  import smoke, architecture/context/ownership checks, 1,598 focused tests, and
  all three quality comparisons. The mandatory seven-worker pipeline passes all
  three lanes with 4/4 Ultra QuickC fixtures and all seven MS C tiny build/run/
  decompile/recompile/decompiled-run constructs; no lane failed, skipped, or
  timed out
- the frontend now classifies `cmp r8, imm8` and transfers an exact low-byte
  direct `DS`/`ES` provenance through an equal-width register copy. High-byte
  and transformed carriers explicitly refuse transfer. VEX import retains the
  parent 16-bit register storage identity while recording the one-byte effect
  width
- real producer and interprocedural regressions prove that
  `mov al, [mem]; mov bl, al; cmp bl, 0` reaches the canonical exact-function
  SSA artifact and materializes the required `LIVE_OUT` trial
- the strict sidecar-free gate passes 20/20 attempted, classified, decompiled,
  materialized, normalized, queued, raw, and selected functions with zero
  timeout, traceback, discovery, empty-output, validation, or policy failures
- the final edited-state `quality-dev` gate passes Ruff `--fix`, MyPy, the
  38-module mypyc compile/import smoke, architecture/context/ownership checks,
  1,604 focused tests, and all three generated-C quality comparisons
- the mandatory seven-worker pipeline passes 3/3 lanes: the same 1,604 focused
  tests, 4/4 validated Ultra QuickC fixtures, and all seven MS C tiny build/run/
  decompile/recompile/decompiled-run constructs with matching exit code 255;
  no lane failed, skipped, or timed out
- the prior caller path proof used `any(...)`, so one clean successor could
  short-circuit traversal and hide a sibling write, unknown alias, or call before
  both paths merged at the same condition load. A dedicated 292-line
  Types/Lowering owner now computes reverse target reachability and joins every
  target-reaching path as `CLEAN`, `OVERWRITTEN`, `NOT_REACHED`, or
  `UNKNOWN_REFUSE`; disconnected branches and exits remain irrelevant
- fifteen focused regressions cover mixed clean/write, clean/alias, clean/call,
  partial overlap, full overwrite, disconnected load, and a blocked branch that
  cannot reach the load. The materializer shrank from 340 to 242 lines, and the
  new owner is registered in the Ruff, MyPy, architecture, and test-ownership
  inventories
- the strict sidecar-free edited-state gate passes 20/20 with zero fallback,
  timeout, traceback, discovery, empty-output, validation, or policy failures.
  All 12 bodies emitted by the timeout-limited pre-change run are byte-identical;
  the edited run additionally emitted the eight pre-change timeout functions
- the final `quality-dev` gate passes Ruff `--fix`, MyPy, the 38-module mypyc
  compile/import smoke, architecture/context/ownership checks, 1,610 focused
  tests, and all three quality comparisons. The mandatory seven-worker pipeline
  passes the same 1,610 tests, 4/4 Ultra QuickC fixtures, and all seven MS C tiny
  build/run/decompile/recompile/decompiled-run contracts with exit code 255
- closed `UNUSED` caller-return evidence now permits the existing Types/Lowering
  owner to demote an exact synthetic terminal zero to `void`, even when the
  terminal machine state still carries `AX`. Nonzero constants, variable
  returns, effectful call returns, and incomplete caller censuses remain scalar
  or refuse demotion
- the sidecar-free SORTD artifact changes only four source-void functions:
  InitMenu, RunMenu, Swaps, and QuickSort. Their signatures become `void` and
  synthetic `return 0;` statements become bare returns; all calls and other C
  statements are byte-identical to the preceding artifact. The strict gate now
  requires RunMenu's binary-proven `case 27: return;`, and rejects either a
  scalar RunMenu signature or an Escape `break`
- the edited-state strict gate passes 20/20 functions with zero fallback,
  timeout, traceback, discovery, empty-output, validation, or policy failures.
  Focused positive and refusal regressions pass; `quality-dev` passes Ruff,
  MyPy, mypyc smoke imports, architecture/context/ownership checks, 1,612 tests,
  and all three quality comparisons. The mandatory seven-worker pipeline passes
  the same 1,612 tests, 4/4 Ultra QuickC fixtures, and all seven MS C tiny
  build/run/decompile/recompile/decompiled-run contracts
- Semantics now retains the exact terminal-path partition for stable direct
  `DS`/`ES` outputs: store sites, all entry-reachable return terminals, and the
  subset definitely written before return. `MUST_WRITE` and `CONDITIONAL`
  dispositions are valid only when that typed path evidence is internally
  complete and coherent
- Types/Lowering projects a conditional output as an explicit `MAY_WRITE`
  memory effect through caller collection and the accepted atomic function
  contract. It never invents an unconditional `CALL_OUTPUT` definition or value
  trial. Conversely, a must-write effect without its exact value trial and a
  conditional effect with such a trial both refuse the whole contract
- positive and refusal coverage passes across 129 Semantics and
  interprocedural-storage tests. Ruff `--fix`, focused MyPy, types/docs ratchets,
  mypyc smoke imports, and explicit graph-available architecture/context/
  ownership checks pass. The strict sidecar-free gate remains 20/20 with zero
  fallback, timeout, traceback, discovery, empty-output, validation, or policy
  failures
- the edited-state `quality-dev` gate passes 1,617 tests and all three generated-C
  quality comparisons. The mandatory seven-worker pipeline passes the same
  1,617 tests, 4/4 Ultra QuickC fixtures, and all seven MS C tiny build/run/
  decompile/recompile/decompiled-run contracts; no selected lane failed,
  skipped, or timed out
- the sidecar-free ReInitBars baseline already emits exactly one
  `g_0BA6 = sub_1137e();` assignment with `unsigned long` callee and global
  declarations, strict GCC acceptance, `validation=passed`, and clean whole-
  tail validation. Its regression now guards the full 32-bit declaration
  contract instead of prompting a false implementation fix
- Semantics now publishes each exact overlapping direct `DS`/`ES` range with
  terminal-path evidence and does not decide storage ownership. Alias binds
  every range to a segment-preserving identity, records all nested subviews,
  and selects one unique maximal owner. Crossing overlaps, duplicate storage,
  missing Alias facts, and unproven segment origins refuse atomically with all
  five evidence counters
- Alias now owns the typed segmented range relation used by downstream layers:
  exact, contained, contains, crossing, disjoint, unproven, and unknown. DS and
  ES equal numeric offsets remain distinct storage spaces, and incomplete
  overlap evidence cannot be promoted by Widening or Lowering
- Widening now groups direct caller loads under the unique maximal Alias owner
  and publishes exact whole or contained views with the exact byte offset,
  width, instruction sites, and source accesses. Crossing overlap, unproven
  range identity, conflicting widths, and conflicting storage refuse the whole
  view collection with closed evidence counters
- Types/Lowering consumes the Widening view instead of rediscovering overlap.
  It creates the `CALL_OUTPUT` definition and storage trial at the projected
  view's exact range; caller-path analysis uses the Alias-owned relation to
  distinguish a disjoint write from a full or partial overwrite
- positive and refusal coverage passes across the Semantics, Alias, live-out,
  and storage-slot surfaces. The changed-file gate passes 668 tests with Ruff
  `--fix`, MyPy, types/docs, architecture/context, and ownership checks. The
  strict executable-only SORTD gate remains 20/20 with zero timeout, traceback,
  discovery, empty-output, validation, or policy failure
- the edited-state `quality-dev` gate passes 1,622 tests, the 38-module mypyc
  compile/import smoke, and all three generated-C quality comparisons. The
  mandatory seven-worker pipeline passes 3/3 lanes: the same 1,622 tests, 4/4
  validated Ultra QuickC fixtures, and all seven MS C tiny build/run/decompile/
  recompile/decompiled-run contracts; no lane failed, skipped, or timed out
- contained high-byte production integration, duplicate-load grouping,
  segment separation, disjoint-write preservation, whole-owner overwrite, and
  crossing/unproven/conflicting refusal fixtures pass. The changed-file gate
  passes 672 tests with Ruff `--fix`, MyPy, types/docs, architecture/context,
  and ownership checks. The strict executable-only SORTD gate remains 20/20
  with zero timeout, traceback, discovery, empty-output, validation, or policy
  failure
- the edited-state `quality-dev` gate passes the 38-module mypyc compile/import
  smoke and all three generated-C quality comparisons, with measured candidate
  speedups of 7.484x, 4.817x, and 4.304x and no quality regression. The
  mandatory seven-worker pipeline passes 3/3 lanes: 1,633 focused tests, 4/4
  validated Ultra QuickC fixtures, and all seven MS C tiny build/run/decompile/
  recompile/decompiled-run contracts
- Types/Lowering now joins every exact whole or contained caller projection
  under one canonical Alias-owned memory-output object. Register and sequence
  returns remain scalar function outputs, while exact callsite views retain
  their Widening provenance. DS and ES remain distinct ownership spaces
- conflicting owners, crossing ranges, missing, extra, or duplicate trials,
  and signedness or value-class conflicts refuse the object transaction with
  closed evidence counters. Seven focused object tests cover whole/high-byte,
  disjoint-caller, segment, conflict, missing, duplicate, and orphan cases
- the focused object/storage surface passes 23 tests. The changed-file gate
  passes Ruff `--fix`, MyPy, types/docs, architecture/context, ownership, and
  628 selected tests; strict executable-only SORTD remains 20/20, and
  `quality-dev` passes its mypyc and generated-C comparison gates. The
  mandatory seven-worker pipeline passes 3/3 lanes: 1,640 focused tests, 4/4
  validated Ultra QuickC fixtures, and all seven MS C tiny build/run/decompile/
  recompile/decompiled-run contracts; lane times are 29.266s, 55.004s, and
  82.097s with zero failure, skip, or timeout
- atomic publication now revalidates each accepted Alias-owned memory object
  against the exact effects and optional `LIVE_OUT` trials retained by the same
  caller/callsite binding. Missing callsites or effects, duplicate owners or
  views, trial mismatches, and orphan effects or trials refuse before the
  project contract surface is mutated
- the transaction proof has typed verdicts, failure reasons, and all five
  evidence counters. Its focused publication/storage surface passes 25 tests,
  including valid replay and four post-solver corruption cases; the diagnostic
  `PipelineHardError` names the typed failure while retaining structured detail
- the `mul_us` scalar fixture exposed two distinct terminal-value defects. The
  Semantics fact for implicit `mul` output now names `AX` as its destination,
  and Structuring consumes the resulting typed AX lineage before a plausible
  but stale `return a;` can bypass it. No semantic repair was added to Rewrite
  or CLI; the startup architecture guard rejected that wrong-layer dependency
- the Structuring owner accepts one fully proven terminal block and one return,
  closes all five evidence counters, and replaces an existing value only when
  the candidate is equivalent or extends its left-hand AX read/modify/write
  lineage. Ambiguous CFGs, multiple returns, unsupported widths, missing proof,
  and unrelated reshaping are typed refusals that preserve the existing body
- tail validation caught the first over-broad implementation widening a byte
  local in `byteops_unsigned`; the non-extension refusal now keeps its exact
  byte storage while allowing `mul_us` to become `return a * b;`. The focused
  171-test surface, Ruff `--fix`, strict focused MyPy, architecture checks, and
  all ten scalar compile/run/decompile/recompile/decompiled-run functions pass
- after the Python/angr dependency upgrade, `fill_bytes` exposed an owned
  Types/Lowering API mismatch rather than a condition-recovery defect. Angr now
  passes a shared recursive-type `memo` into `SimType._with_arch`; the fixed
  16-bit near-pointer implementation used the old signature, so codegen text
  regeneration raised before Structuring or Postprocess validation could be
  collected. Its implementation now preserves and forwards that memo through
  the public architecture-binding contract
- a function-prototype regression exercises the exact recursive binding path.
  Ruff `--fix`, strict focused MyPy, and all 11 focused SimType tests pass; the
  full three-function `pointer_memory` compile/run/decompile/recompile/
  decompiled-run gate is green with clean tail validation and exit code 255
- caller storage trials now build SSA from the Frontend-owned exact function
  boundary rather than a synthetic entry-only block. The old one-block census
  stopped at an early stack-probe call, silently missed later application
  callsites, and refused otherwise proven pointer inputs and returns as
  `CALLSITE_NOT_FOUND`
- the focused multi-block census regression proves every exact block reaches IR
  import. The real `scalar_types_io` `pick_ptr` contract is now accepted as two
  pointer inputs, one scalar selector, and one pointer return; its unchanged
  generated C recompiles and the rebuilt DOS executable returns 255
- next implementation boundary: publish pointer-parameter memory outputs before
  attempting general indexed or indirect effects. In SORTD `Swaps` (`0x107b8`),
  exact IR stores through `BX` at `0x107d7` and `0x107df` retain distinct SSA
  versions; the Alias reaching-source owner proves those versions come from
  callee inputs `SS:BP+4` and `SS:BP+6`, respectively
- the vertical slice must preserve the pointer-relative segment, offset, width,
  store sites, terminal-path disposition, and parameter storage through
  Semantics, Alias, Widening, and Types/Lowering. Caller targets may be projected
  only from each exact reaching argument definition. Ambiguous bases, competing
  parameter sources, partial path coverage, and caller target conflicts must
  remain typed refusals
- conditional, exact whole-owner, contained, overlapping-caller-view, and
  object-owned direct stable `DS`/`ES` effects are complete for their current
  scope and must not be reconstructed from rendered C
- the first pointer-parameter output vertical slice is implemented at its
  owning layers. Semantics retains all four terminal byte stores in sidecar-free
  Swaps `0x107b8`; Alias proves the two distinct BX versions originate at
  `SS:BP+4` and `SS:BP+6`; Widening forms two exact two-byte parameter-relative
  views; Types/Lowering publishes logical output parameters 0 and 1 in one
  project-local typed registry with closed evidence counters
- exact caller memory targets are now projected at the separate Lowering join.
  IR owns exact
  16-bit modular affine traces with constants, stack-derived terms,
  coefficients, logical-word reconstruction, and SSA definition paths;
  Types/Lowering requires that projection to agree with the typed callsite
  source and retains the exact outgoing byte definitions. Carry-dependent,
  malformed, width-conflicting, unsupported, missing, and contradictory
  expressions refuse with distinct typed reasons
- the sidecar-free Swaps census proves and atomically publishes all 18 targets
  across nine callers: 17 exact affine expression arguments, including the
  two-source form at `0x10c8e`, plus the direct `DS:0x0b4c` offset. Each target
  joins the callee-proven `DS` segment and two-byte width without guessing a
  pointee type or converting dynamic storage into a direct global identity.
  The storage lifecycle now publishes this registry immediately after callee
  output views and before input trials
- typed caller effect/object materialization is complete at the function
  contract boundary. The live-out collector partitions all 18 targets by exact
  caller/callsite, the object join groups them into two callee-owned pointer
  outputs with nine views each, and atomic publication revalidates every view
  against the original callsite effect. Dynamic targets never become direct
  `StorageIdentity8616.MEMORY` owners or fabricated scalar `LIVE_OUT` trials;
  duplicate, mismatched, missing, and orphaned facts refuse atomically. The
  next boundary is proof-driven pointee/object typing and code-generation
  consumption, not another effect-recovery pass
- the production integration exposed and removed a cross-layer Semantics veto:
  one same-segment indirect STORE previously erased every independently proven
  direct terminal STORE as a possible alias conflict. Semantics now retains the
  direct fact without claiming disjointness; Alias and interprocedural Lowering
  remain the only owners of the relationship. The real Swaps pipeline test
  carries both effects through the accepted function contract
- Ruff `--fix`, strict MyPy, type/doc/dot-access ratchets, startup architecture,
  context and ownership checks, and the 725-test ownership-expanded
  changed-file gate pass. The mandatory full pipeline passes 1,841 curated
  tests plus all seven MS C tiny compile/decompile/recompile/exit-behavior
  examples; its external semantic summary is three passed, zero failed, zero
  skipped, and zero timed out
- the pointer slice and its adjacent return/declaration ownership fixes pass the
  focused semantic tests, strict MyPy, Ruff `--fix`, and the full sidecar-free
  gate: 20 attempted, normalized, classified, decompiled, and materialized;
  zero timeout, traceback, discovery, empty-output, validation, or policy
  failures. DrawTime and DrawBar declarations consume exact Frontend range
  boundaries when direct-call stubs are empty, and Beep keeps its two-argument
  interface without read-only return probes materializing phantom arguments
- the fresh post-fix sidecar-free SORTD run decompiles 20/20 functions with
  `validation=passed`, clean whole-tail validation, no unsupported instruction
  or assembly fallback output, and strict GCC acceptance. Its 723-line C is
  byte-identical to the pre-fix output; the loaded run took 283.15 seconds at
  451% CPU with 328,380 KiB parent maximum RSS
- direct-stack replay now distinguishes a changed structured statement root
  from newly published typed evidence. Evidence-only publication remains a
  stable C result, duplicate stores remain suppressed, and a failed
  `SemanticLaneState` is never cached as stable, so a repaired materializer is
  retried instead of skipped. Nine focused replay/materialization regressions
  pass with Ruff `--fix` and strict MyPy
- the edited-state `quality-hard` gate passes Ruff `--fix`, strict MyPy across
  224 production files, the 38-module mypyc import smoke, complexity,
  architecture/startup/context/ownership checks, and 1,841/1,841 fast-pipeline
  tests in 84.32s. CMP16, LOOPS, and FPTR generated-C quality comparisons all
  pass; measured candidate speed ratios were 2.641x, 2.176x, and 0.884x
- caller-observed byte-return recovery now has one complete-census join in
  Types/Lowering. It aggregates exact post-call extension evidence, refuses
  empty/provisional/conflicting observations without caching them, and applies
  the accepted signedness to both the function prototype and the final
  regenerated C surface. Focused acceptance, refusal, conflict, and projection
  tests pass, and the uncached real `mix_uc` function renders as
  `unsigned char` with `validation=passed`
- the scalar fixture and both generated runtime harness projections now require
  `mix_uc(64, 0) == 128`; this high-bit assertion closes the signedness hole
  that low-bit arithmetic alone could not detect. Its ten-function full DOS
  pipeline passes compile, original execution, decompilation, validation,
  recompilation, and decompiled execution with expected exit code 255
- the current milestone passes Ruff `--fix`, strict MyPy across 254 source
  files, the 39-module mypyc smoke, 139 callsite/interface tests, 236 segmented
  runtime lowering tests, and 1,871 fast-pipeline tests. The idle-host
  optimization suite and mandatory full `test-pipeline` remain pending because
  a concurrent seven-worker decompilation caused the CMP16 baseline to hit the
  unchanged 180-second timeout before quality comparison

Definition of done:

- candidate inputs/outputs retain exact storage, width, reaching-definition,
  use, signedness, and pointer/value evidence through deterministic trials
- one accepted contract is transactionally applied to the callee and every
  callsite after complete-census agreement
- PercolateUp and Beep reject the known bad transformations, while both
  QuickSort recursive edges converge with all arguments preserved

Definition of failure:

- incomplete or conflicting trials produce a guessed argument, return, stack
  delta, or export-time signature repair
- split returns are joined without shared provenance or a pointer is converted
  to a scalar value class without proof
- fixed-point order changes the contract or any required call is lost

#### 8.3 Propagate types through IR, aliases, and bounded object ranges

Status: in progress; the IR-to-Alias prerequisite and first project-wide
Widening consumer migration are complete. Indexed DS/ES addresses retain exact
versioned terms and Alias storage/index ownership; Widening now owns two-byte
global layout, exact copy-family joins, and the first exact static bounded-range
publication. Types/Lowering consumes that range for exact existing declaration
extents. General type propagation and replacement of the remaining per-function
legacy rendering collectors remain.

Reason: Type information must follow value and alias provenance across the
pipeline before memory expressions can become pointers, indexes, fields, or
aggregates. Bounded range evidence prevents useful typing from becoming shape
guessing.

Ghidra initializes a temporary type from each operation, propagates only a
more-specific type across p-code edges, propagates pointer target types to
known aliases, reconciles return types, and writes accepted types back. Its
local map then combines fixed and open range hints; an indexed LOAD/STORE is
considered array evidence only when it has a nonzero proven step. See:

- `coreaction.cc:5095-5500` (`ActionInferTypes`)
- `varmap.cc:170-355` (`RangeHint::attemptJoin`, `RangeHint::merge`)
- `varmap.cc:896-1081` (`MapState::addRange`, `addFixedType`,
  `reconcileDatatypes`, `addGuard`)
- `ruleaction.cc:6671-6835` (`RulePtrArith`, `RuleStructOffset0`)
- `ruleaction.cc:7597-7775` (`RulePieceStructure`)
- `ruleaction.cc:9618-9775` (`RulePtrFlow`)

Adopt this after Alias and Widening, with stricter Inertia evidence:

1. Propagate types through owned IR operations using a deterministic
   specificity order; block propagation at conflicting aliases or segment
   spaces.
2. Convert integer arithmetic to pointer/index/field operations only when the
   base `Address`, element width, stride, and bounds are proven.
3. Reconcile overlapping range hints only when one byte-accurate array,
   structure, or explicit union accounts for every access.
4. Preserve raw segmented accesses when evidence conflicts.

Measured progress on 2026-08-21:

- `IRAddress.base_values` preserves each dynamic address term as an `IRValue`,
  and block-local SSA assigns the exact register version used by the memory
  access instead of leaving only an unversioned register-name tuple
- the new IR owner classifies every indexed DS/ES load or store and traces the
  supported same-block `MOV`/`SHL` chain to a stable `SS:BP` source; multiple
  terms, missing/conflicting definitions, unsupported expressions, unproven
  addresses, and unsupported shifts remain typed refusals
- all five evidence counters close, direct segmented accesses stay outside the
  indexed census, and the producer does not infer Alias identity, bounds,
  arrays, structures, C types, or rendered expressions
- `X86_16/ir/indexed_address_pipeline.py` publishes the closed IR artifact in
  the main execution path, and `X86_16/alias/indexed_address_projection.py`
  refuses to run when that earlier owner is missing or has the wrong contract
- Alias preserves DS versus ES, displacement, access width, exact index SSA
  value, shift, definition path, and canonical `SS:BP+offset` source range;
  the direct Alias API now refuses symbolic DS/ES addresses instead of
  collapsing them to the constant displacement
- the canonical segmented Alias range builder now accepts negative BP-relative
  stack offsets while retaining nonnegative DS/ES offsets
- `X86_16/lowering/indexed_address_collector_parity.py` publishes a typed,
  non-semantic migration census with matched, Alias-only, legacy-only, and
  duplicate keys; real lifted load and store fixtures have exact parity, while
  divergent and duplicate fixtures remain visible
- nineteen indexed real-lifter, Alias, refusal, and parity regressions pass;
  every inventory mismatch class has a direct regression, repeated same-site
  typed refusals remain visible, and the ownership-expanded focused selection
  passes 75 tests
- `quality-dev` and `quality-hard` pass Ruff `--fix`, strict MyPy, the 38-module
  mypyc compile/import smoke, 1,673 focused tests, and all three generated-C
  comparisons. The required default pipeline passes its focused suite and all
  seven MS C tiny compile/run/decompile/recompile/decompiled-run constructs
- the sidecar-free SORTD indexed-aggregate regression passes recompilation and
  validation in 23.34s after the main-path IR/Alias artifacts were enabled
- `scripts/indexed_address_parity_inventory.py SORTD.EXE` now runs the canonical
  sidecar-free, non-library function catalog and writes deterministic JSON to
  stdout (or `--report-out PATH`); the durable measured report and work order
  are recorded in this section, while the JSON is reproducible and is not kept
  as a temporary repository artifact
- the 20-function SORTD inventory now closes from 42 raw frontend memory
  micro-operations to 36 normalized machine accesses: 6 exact
  same-instruction little-endian pairs are coalesced, 35 facts reach Alias,
  and 1 remains a typed refusal
- collector parity now has 31 matched keys, 4 Alias-only keys, 8 legacy-only
  keys, no duplicates, and no identity conflicts; 17 function reports are
  exact and 3 remain divergent
- machine-instruction review proves that the 8 legacy-only keys are late
  collector false positives: each uses BP-based addressing and therefore SS,
  while the legacy global collector incorrectly reports DS
- the former width/provenance conflicts are closed at their authoritative
  boundaries: VEX result widths are resolved against the IRSB type environment,
  IR coalesces only exact same-instruction contiguous micro-operations without
  changing the frontend byte-access ABI, and IR import rebinds only an exact
  JCC transport load to the identical immediately preceding CMP value; the
  established frontend VEX shape remains unchanged for angr structuring
- the 4 remaining Alias-only accesses are the two pointer-argument loads and
  two pointer-argument stores in function `0x107b8` (`Swaps` in the reviewed
  source); they are valid Alias evidence but are not bounded global aggregate
  evidence
- Alias now classifies only exact direct unscaled dereferences as
  pointer-relative and exact scaled nonzero-base accesses as globally indexed
  candidates. The closed sidecar-free census reports 4 pointer-relative facts,
  31 globally indexed candidates, and 1 retained upstream refusal; mixed forms
  remain typed refusals, and no Alias role claims aggregate bounds
- the role classifier is attached atomically by the existing Alias main-path
  publisher. Real lifted pointer/global fixtures, ambiguous and upstream
  refusal fixtures, ownership checks, and the whole-SORTD census are permanent
  regressions
- normalized indexed STORE facts retain every exact VEX byte-lane member. IR
  traces each member backward through supported same-block SSA operations and
  materializes a copy only when all lanes converge on one unchanged indexed LOAD
- Alias resolves both copy endpoints to canonical facts and accepts the relation
  only when both are globally indexed with the same exact stack index storage and
  shift. Pointer-relative, transformed, width-conflicting, and different-index
  cases remain typed refusals
- the sidecar-free SORTD copy census closes all 8 indexed STORE candidates: 3
  are exact IR copies and 5 are IR refusals; Alias retains 2 globally indexed
  copies and 6 refusals. The accepted sites are `0x106a9 -> 0x106b2`
  (`DS:0x08f0` to `DS:0x0b4c`) and `0x10871 -> 0x1087a`
  (`DS:0x0b4a` to `DS:0x0b4c`)
- Alias now publishes one immutable 20-function program census from the
  complete binary-discovery catalog and reuses the canonical IR SSA registry;
  exact supplied boundaries are validated before cached artifacts can replay.
  A missing or conflicting function remains a typed program refusal
- Widening consumes every Alias access/copy fact or refusal exactly once. A
  partial program suppresses all layout inference; transformed copies and
  different index identities retain separate families or refuse layouts
- the current sidecar-free Widening census closes 44 inputs as 27 consumed and
  17 explicit refusals. It proves only `DS:0x08f0` and `DS:0x0b4c` as two-byte
  layouts and joins their family only through the exact `0x08f0 -> 0x0b4c`
  copy; the `0x0b4a -> 0x0b4c` copy has no proven source layout and cannot join
- `project_global_object_layout.py` no longer manufactures indexed storage
  views from instruction-backed collectors. CLI discovery transports the
  complete catalog without semantic classification, Alias owns the census,
  Widening owns layout/family proof, and Lowering hard-fails an open artifact
- real-lifter positives and refusals, registry/cache replay, and the isolated
  sidecar-free SORTD aggregate regression pass. The latter keeps strict GCC,
  `validation=passed`, whole-tail cleanliness, `g_08F0_entry`, and the exact
  `g_0B4C` copy behavior; its measured wall time was 39.60 seconds
- implementation order is now: (1) [done] fix machine width and owning
  instruction provenance, (2) [done] close the whole-SORTD identity-conflict
  census, (3) [done] classify Alias facts as pointer-relative versus global
  indexed candidates, (4) [done] prove whole-element load-to-store value paths
  in IR and project both endpoints through Alias, (5) [done] migrate project
  layout recovery to Alias-fed Widening, (6) [done for exact static loop bounds]
  publish bounded object ranges and consume them in Types/Lowering, and now
  (7) generalize range/type propagation to dynamic, indexed, indirect, stack,
  and field-bearing objects. Widening must not consume the parity inventory or
  any rendered representation
- Widening now reduces the complete Alias program census into one closed final
  project-range artifact. Static exact loop bounds may produce a range;
  dynamic bounds, incomplete function evidence, uncovered accesses, layout
  mismatches, and segment conflicts remain typed refusals with closed counters
- the range artifact has one typed deterministic codec and is transported with
  its exact layout dependency through project caches and clean-worker JSON.
  Missing, malformed, open, or cross-layout records refuse instead of being
  reconstructed independently inside a worker
- Types/Lowering consumes only that transported Widening artifact, binds it to
  one exact existing segmented global declaration, and strengthens only the
  proven array extent. Ambiguous or missing names hard-fail when a classified
  range cannot materialize; upstream dynamic-range refusals leave declarations
  unchanged
- focused positive, refusal, cache, worker-transport, and declaration tests
  pass. The complete edited-state `quality-hard` gate passes Ruff `--fix`,
  strict MyPy for 211 source files, mypyc import smoke for 38 modules,
  architecture/context/ownership checks, 1,808 tests, and all three generated-C
  comparisons
- the required default pipeline passes the same 1,808 tests and every selected
  MS C compile/run/decompile/recompile/decompiled-run contract. All ten
  `scalar_types_io` functions validate, recompile, and produce rebuilt exit 255;
  no pipeline lane fails, skips, or times out

Do not borrow Ghidra's fallback assumption that an unlocked indexed range has
at least four elements (`varmap.cc:1215-1219`). InitBars' wrong `% 0x60b`,
uninitialized store, and DrawBar's wrong 34-byte object are mandatory negative
fixtures. Array bounds must come from CFG/range evidence, not a default size.

Definition of done:

- deterministic specificity propagation is implemented across owned IR,
  aliases, calls/returns, and exact object ranges
- pointer/index/field and aggregate materialization requires proven base,
  element width, stride, bounds, segment space, and complete access coverage
- InitBars and DrawBar reject Ghidra's bad modulus, uninitialized value, default
  count, and undersized-object outcomes while positive bounded cases improve

Definition of failure:

- a default element count, numeric proximity, unlocked range, or rendered
  expression creates a pointer, array, structure, or field
- conflicting aliases, address spaces, bounds, or overlaps are merged rather
  than preserved explicitly
- accepted types diverge between IR, contracts, diagnostics, rendering, or tests

#### 8.4 Normalize split values and carry before type and structure recovery

Status: complete for the bounded split-value and carry/borrow scope exercised by
SORTD. Semantics -> Alias -> Widening retains exact ADC/SBB values, and typed
pre-join CFG instruction ownership now prevents the former instruction-address-
only placement contract from claiming ambiguous branch joins.

Structuring now publishes typed pre-join Clinic CFG instruction ownership with
exact block/instruction sites and typed missing, ambiguous, unreachable, and
order-conflict outcomes. Carry Lowering retains both low/high block addresses,
requires that artifact on the main execution path, and refuses another
reaching definition of the same FLAGS identity. Explicit C predicate projection
is Lowering-only and consumes the already typed ADD_WITH_CARRY or
SUB_WITH_BORROW relation; it does not infer semantics from rendered C.

Reason: Split carriers and carry/borrow expressions obscure the single values
needed by type propagation and explicit conditions. Widening must normalize
them while exact Alias and definition provenance is still available.

Ghidra has dedicated p-code rules for converting PIECE/extension forms,
eliminating redundant carry expressions, combining low/high add-subtract
pieces, and preserving pointer flow through segmented casts. See:

- `ruleaction.cc:213-260` (`RulePiece2Zext`, `RulePiece2Sext`)
- `ruleaction.cc:4002-4055` (`RuleCarryElim`)
- `ruleaction.cc:5288-5355` (`RulePieceAddSub`)
- `ruleaction.cc:11583-11980` (`RulePieceCarryAdd`)
- `ruleaction.cc:9264-9305` (`RuleSegmentCastPtrArith`)

Implement these ideas only in Inertia's Widening layer, after Alias proves
carrier identity. A wide `Value` must retain low/high slice provenance, carry
or borrow provenance, signedness, and its segmented address space. Sleep,
ReInitBars, DrawTime, and Beep are positive fixtures. Ghidra's remaining
`CARRY2`/register fragments are evidence that shape-only fusion is insufficient;
mismatched branch, carrier, segment, or definition must produce
`UNKNOWN_REFUSE`.

Definition of done:

- Widening produces typed wide values with exact low/high slice, carry/borrow,
  signedness, definition, and segment provenance before Types/Structuring
- Sleep, ReInitBars, DrawTime, and Beep pass focused positive regressions and
  closed evidence counters
- every mismatched branch/carrier/segment/definition fixture produces
  `UNKNOWN_REFUSE` and preserves the original lower representation

Definition of failure:

- split values are fused by shape, adjacency, register convention, or AST text
- semantic normalization occurs in Structuring, Rewrite, CLI, or export
- a slice, carry, memory effect, condition, or call argument changes incorrectly

Measured closure on 2026-08-28:

- 22 focused carry/CFG ownership tests pass, including two mutually exclusive
  SUB/borrow chains sharing one FLAGS SSA identity, another reaching machine
  definition, duplicate owners, missing owners, and same-block order conflict
- the fresh strict sidecar-free SORTD gate generates and validates all 20
  application functions with zero fallback, timeout, traceback, discovery, or
  policy failure. DrawTime emits `sub_10e70(arg_4 * 60, 75)`, both exact Sleep
  argument shapes, no raw `ss << 4`, and `validation=passed`
- the same edited source state passes `quality-hard`, the default test pipeline,
  strict MyPy, Ruff `--fix`, architecture/context/ownership checks, all three
  generated-C comparisons, and every selected MS C end-to-end contract

#### 8.5 Collapse CFG regions only after conditions are explicit

Status: in progress. The exact switch-case edge to a proven enclosing
loop-tail exit is complete for RunMenu; general sequence/condition/loop/switch
region collapse remains open.

Reason: Structured loops and branches are trustworthy only when their CFG
boundaries and `Condition` provenance are already explicit. Conservative region
collapse improves readability without inventing branch meaning.

Ghidra first identifies loop backedges and nesting, then repeatedly collapses
well-constrained graph regions into sequence, AND/OR, if, if/else, while,
do/while, and switch nodes. Only afterward does it order blocks and mark the
remaining unstructured edges as gotos. See:

- `blockaction.cc:1124-1184` (`CollapseStructure::labelLoops`,
  `orderLoopBodies`)
- `blockaction.cc:1284-1573` (sequence, condition, if, and loop rules)
- `blockaction.cc:1649-1715` (switch collapse)
- `blockaction.cc:1877-1895` (`CollapseStructure::collapseAll`)
- `blockaction.cc:2169-2196` (`ActionBlockStructure`, `ActionFinalStructure`)

Use the same conservative region-collapse order in Structuring, but consume
only Inertia `Condition` objects whose flag/value provenance is already
explicit. Every collapse must preserve exact entry, exit, backedge, and branch
polarity. RunMenu and DrawFrame are positive fixtures; InitMenu's corrupted
loop update is the negative fixture proving that a pretty loop is not enough.
When a region cannot be proven, retain a deterministic goto instead of
inventing a loop or condition.

Definition of done:

- Structuring collapses regions in deterministic sequence/condition/loop/switch
  order using only typed `Condition` objects and exact CFG topology
- RunMenu and DrawFrame improve while preserving entry, exits, backedges,
  polarity, calls, and validation
- InitMenu's bad loop-update shape is rejected and every unproven region retains
  a deterministic goto

Definition of failure:

- assembly or rendered-C shape supplies condition or loop semantics
- a prettier region changes entry/exit/backedge/polarity or hides an unresolved
  edge
- unproven control flow is guessed instead of retained explicitly

Measured progress on 2026-08-21:

- Structuring now owns an exact typed-AST transformation from switch-case
  gotos to the enclosing loop-tail label into `break`; Rewrite and CLI do not
  infer or repair this control flow
- the owner requires one unambiguous target, no executable suffix, no nested
  breakable scope, no external incoming target, complete codegen publication,
  and exact materialization evidence; every ambiguity refuses and preserves the
  original goto
- tail validation consumes only the matching typed `goto:<address>` delta and
  leaves unrelated deltas for their authoritative validators
- the sidecar-free RunMenu output converts nine proven exits, removes
  `LABEL_10488`, retains the Escape path, and passes whole-tail validation;
  focused tests cover the positive topology, idempotence, evidence counters,
  exact validation composition, and all refusal cases
- discovery-cache replay now re-emits the exact restored source-region evidence
  diagnostic, so strict cold and replay runs enforce the same 20/20 discovery
  contract instead of treating a correct cache hit as missing evidence
- the strict cold current-source and cached-replay checks both report
  20 raw, normalized, classified, and materialized functions, zero discovery
  failures, zero timeouts, zero tracebacks, and zero validation failures
- `quality-dev` passes Ruff `--fix`, MyPy, the 38-module mypyc import smoke,
  architecture/context/ownership checks, 1,613 tests, and all three
  decompilation-quality comparisons; the required test pipeline also passes
  its three selected lanes, including Ultra QuickC and all seven MS C tiny
  compile/run/decompile/recompile/decompiled-run constructs
- concurrent code-graph indexing can consume most host CPUs and cause false
  function-deadline failures. Acceptance runs therefore use bounded resource
  isolation; semantic timeouts were not increased to hide host contention
- exact-function relifting now owns `ConditionIR` for real projects. The old
  lifter compatibility cache is keyed only by rebased block address and cannot
  prove ownership across extracted functions; a two-project regression rejects
  complete sibling evidence at the same address
- the real five-function `compare16` batch now passes tail validation, C
  recompilation, and DOS behavior with exit `255` instead of the contaminated
  exit `12`; the permanent MS C tiny pipeline retains this end-to-end ratchet
- the MS C `switch_fold` regression was a Structuring projection-lifetime
  defect: a proven selector-return condition did not remain authoritative after
  later condition/lowering regeneration, so rendered C could retain an
  uninitialized carrier. Structuring now fingerprints the exact selector and
  return projection, checks it against the live AST, replays it at every owned
  lifecycle boundary, and hard-fails any active but stale projection
- Ultra QuickC `args` exposed a separate Structuring identity defect. The
  semantic call condition was intentionally preserved, but the C expression
  still carried tags from the preceding call and its exact binary-arm
  orientation had not been published. Call-return materialization now selects
  the unique typed `ConditionIR` from structured callsite identity plus the
  callsite summary return block, then restamps the C condition with that exact
  identity. Rendered names and stale tags are fallback evidence only
- binary-arm classification infers an empty arm only as the complement of an
  independently CFG-proven opposite arm. A nonempty unknown arm, ambiguous
  reachability, or non-unique callsite/return identity refuses materialization
  and preserves the existing structure
- the repaired real `args` fixture retains both required calls and places
  `local_4 = 1` only under the proven `v` branch; it has
  `validation=passed`, recompiles, and passes its runtime/source contract. The
  focused Structuring/import surface passes 92 tests, and the required gate
  passes 1,709 focused tests, 4/4 validated QuickC fixtures, and all seven MS C
  tiny constructs. Ruff `--fix`, strict focused MyPy, `linters-dev`, and the
  architecture/context/ownership checks are green

#### 8.6 Explicitly do not borrow Ghidra's function-start patterns

Reason: Ghidra's pattern-driven discovery missed seven application functions
that Inertia discovers and validates. Compiler patterns cannot replace binary
CFG/call-target evidence or weaken the permanent completeness ratchet.

Ghidra's pattern-driven discovery lives in
`Ghidra/Features/BytePatterns/src/main/java/ghidra/app/analyzers/FunctionStartAnalyzer.java`.
It is not a SORTD strength: the analyzed image missed InsertionSort,
BubbleSort, HeapSort, PercolateDown, ExchangeSort, ShellSort, and QuickSort.
Inertia's existing binary CFG/call-target discovery and permanent 20-function
ratchet are stronger for this corpus. Compiler byte patterns may be optional
evidence, but never a required or primary discovery mechanism.

Definition of done:

- binary CFG/call-target discovery remains authoritative and the sidecar-free
  20-function address ratchet passes deterministically
- any compiler pattern support is optional typed evidence with explicit
  provenance, conflicts, and refusal behavior
- fixtures prove that missing/wrong patterns cannot remove, rename, resize, or
  create a required function

Definition of failure:

- a corpus/address allowlist or compiler byte pattern becomes the primary or
  required function-discovery mechanism
- any of the seven Ghidra-missed functions disappears or needs sidecar/pattern
  evidence to survive
- pattern disagreement is silently preferred over binary CFG evidence

#### 8.7 Implementation order and closed gate

Reason: The shortest reliable path follows ownership dependencies. Earlier
storage and value facts must exist before contracts, types, and CFG structure
can consume them, and every stage needs a closed regression boundary before the
next stage expands the blast radius.

Implement in pipeline order, not in order of visible C prettiness:

1. IR/Alias stack memory SSA and call effects.
2. Widening PIECE/carry normalization.
3. Types/Lowering call contracts and aggregate ranges.
4. Structuring region collapse from explicit conditions.

Each owner reports the standard closed evidence counters. Before accepting a
mechanism, compare its focused functions before and after, require
`validation=passed`, no call loss, correct argument classes, and no output
farther from `SORTDEMO.C`. Then run the sidecar-free 20-function gate, strict
GCC translation-unit check, all 19 behavior harnesses, the seven MS C tiny
constructs, and `make test-pipeline PYTHON=./.venv/bin/python`.

Definition of done:

- tasks execute in the stated IR/Alias, Widening, Types/Lowering, Structuring
  order and each stage closes its evidence counters and focused tests first
- before/after artifacts prove no call loss, correct argument classes,
  `validation=passed`, and no result farther from the source oracle
- the 20-function, GCC, 19-harness, seven-tiny-example, and test-pipeline gates
  all pass from one recorded source state

Definition of failure:

- work advances past a failed/unknown earlier owner or introduces a downstream
  repair for a missing upstream fact
- before/after evidence is absent, stale, or taken from different source states
- any required focused or full gate fails, is skipped, or is weakened

#### 8.8 Concrete Inertia integration and migration map

Reason: Existing proof surfaces must be extended instead of creating another
parallel decompiler pipeline. A concrete producer/consumer migration map keeps
one authoritative owner per fact and makes technical-debt removal enforceable.

The source references above are sufficient to study Ghidra, but implementation
must extend Inertia's existing proof surfaces rather than create duplicate
passes. Use this map as the handoff:

| Mechanism | Reuse or extend | Migrate or retire | First focused tests |
| --- | --- | --- | --- |
| function memory SSA | `ir/ssa_function.py`, `ir/effects.py`, `ir/address_ir.py` | extend SSA keys from scalar `IRValue` identity to exact `Address` ranges; do not add AST-local SSA | `test_x86_16_ir_ssa.py`, `test_x86_16_segment_stack_restore.py` |
| stack identity and call clobbers | `alias/state.py`, `alias/transfer.py`, `alias/callsite_stack_merge.py` | replace any later inference of stack identity from C variables | `test_x86_16_alias_state_transfer.py`, `test_x86_16_segmented_stack_alias.py` |
| split-value/carry widening | `widening/stack_widening.py`, `widening/register_widening.py`, `widening/word_projection_recomposition.py` | move semantic work out of instruction-to-C recovery in `structuring/compare32_recovery.py`; Structuring may consume the resulting wide `Condition` only | `test_x86_16_alias_api_and_widening_proof.py`, `test_x86_16_compare32_recovery.py` |
| function contracts | `lowering/stack_prototype_materialization.py`, `lowering/callee_argument_interface.py`, `lowering/return_type_evidence.py` | remove prototype discovery/reconciliation from `decompiler_postprocess.py` and `decompiler_postprocess_stage.py` as equivalent typed consumers become available earlier | `test_x86_16_stack_prototype_promotion.py`, `test_x86_16_return_type_evidence.py`, `test_x86_16_validation_call_argument_sources.py` |
| aggregate ranges | `lowering/stack_aggregate_objects.py`, `lowering/object_lowering.py`, `type_equivalence_classes.py`, `type_array_matching.py` | replace Capstone-derived aggregate facts with IR/Alias range facts; postprocess may replay an accepted type but may not discover it | `test_x86_16_stack_aggregate_objects.py`, `test_x86_16_sortd_indexed_aggregate_regression.py` |
| region structuring | `structuring/loop_recovery.py`, `structuring/control_flow.py`, `structuring/condition_lowering.py`, `structuring/typed_switch_seqnode.py` | retire direct assembly-shape semantic recovery as typed CFG regions cover each case | `test_x86_16_loop_recovery.py`, `test_x86_16_structuring_switch.py`, `test_x86_16_typed_switch_seqnode.py` |

The migration rule is strict: first make the earlier typed producer pass the
existing positive and refusal tests, then switch one downstream consumer to
that contract, and only then remove the superseded late producer. Do not keep
two semantic authorities active for the same fact.

Definition of done:

- every table row has an earlier typed producer, an explicitly migrated
  consumer, focused positive/refusal tests, and removal of the superseded late
  producer
- imports and architecture checks enforce the documented owner boundaries
- IR, typed contracts, consumers, diagnostics, documentation, and tests expose
  one coherent representation of each migrated concept

Definition of failure:

- old and new producers remain simultaneously authoritative or disagree
- semantic recovery is added to root compatibility, postprocess, CLI, export,
  or another layer outside the map
- a late producer is removed before its behavior survives in contracts, tests,
  and documentation

#### 8.9 The key Ghidra lesson is iteration, not one pass

Reason: Alias, widening, contracts, types, conditions, and CFG structure depend
on each other's accepted facts. A bounded typed worklist reaches the necessary
fixed point without repeatedly rebuilding the whole decompiler or losing
determinism.

Ghidra's quality comes partly from repeatedly running mutually dependent
analyses to a fixed point. Its main action order is visible in
`coreaction.cc:5560-5770`: Heritage runs before active parameter/return
recovery; local ranges and types are rebuilt; simplification and stack-pointer
flow run; then block structure and pointer rules run. This is why listing the
individual rules without their scheduling would be incomplete.

Inertia should use a bounded typed worklist instead of blindly repeating the
whole decompiler:

1. IR or Alias changes enqueue only affected storage ranges and callsites.
2. Accepted alias changes enqueue dependent widening candidates.
3. Accepted widening changes enqueue dependent type, contract, and condition
   facts.
4. Accepted contract/type changes enqueue affected callers, callees, and CFG
   regions.
5. Stop at a deterministic fixed point. A configured iteration limit produces
   an explicit failure with the still-changing fact identities.

The cache key for each fact must include function address, exact storage or CFG
identity, input fact versions, and analysis version. Sorted worklists and typed
status values preserve determinism across worker processes.

Definition of done:

- typed dependencies enqueue only affected facts and converge to the same
  sorted fixed point across repeated and multi-process runs
- cache keys include function, exact storage/CFG identity, input versions, and
  analysis version
- iteration exhaustion reports an explicit typed failure listing still-changing
  fact identities; it never emits a partial success

Definition of failure:

- the implementation blindly repeats whole-program/AST passes or has an
  unbounded worklist
- worker count, scheduling, or cache warmth changes accepted facts or output
- iteration limits, stale cache entries, or dependency cycles silently produce
  incomplete materialization

#### 8.10 Smallest high-impact implementation milestone

Status: complete for the first exact word range, including the closed pipeline
gates. Generalization continues under 8.1 and 8.2.

Reason: One exact SS range exercised through IR, Alias, Widening, Lowering, and
validation proves the cross-layer contracts before generalizing expensive
memory SSA and interprocedural changes across the entire binary.

Do not start by cloning all of Ghidra's Heritage or type system. The first
vertical milestone should be one exact SS memory range flowing through the
entire owned pipeline:

1. Extend function SSA so one `SS:BP+offset` range has versioned definitions
   and phi inputs across branches.
2. Preserve that range through a call only when the typed call effect proves
   it is not clobbered or escaped.
3. Join a proven adjacent low/high pair into one wide `Value` when applicable.
4. Materialize the resulting local/argument through the existing Lowering
   consumer, with no semantic discovery in postprocess.
5. Validate its register, memory, return, and control-flow effects before and
   after rendering.

Use DrawFrame's initialized loop local as the positive SORTD case. Use an
overlapping-width stack fixture and a branch with unknown SP delta as refusal
cases. Once this vertical slice passes, generalize the same contracts to Beep
call arguments, Sleep's wide clock value, and InitBars aggregate ranges.

Measured progress on 2026-08-17:

- function SSA now versions exact stable `SS:BP+offset:size` LOAD/STORE ranges
  independently from scalar SSA and creates deterministic memory phi inputs at
  branch joins; serialized `IRAddress` projections retain the version
- store and phi versions are globally deterministic within the function, and
  a bounded fixed-point solver carries reaching versions through CFG edges
- overlapping byte ranges and provisional SP-relative ranges are explicit
  refusals; they remain unversioned and are counted in the five-field evidence
  loop rather than being materialized as locals
- `IRCallStackEffect8616` records net stack delta, preserved ranges, escaped
  ranges, and completeness. Unknown calls refuse range propagation; only a
  complete zero-net-delta effect that explicitly preserves and does not escape
  the exact range may carry its version through the call
- the Alias layer now projects every versioned stack LOAD, STORE, and memory
  phi through the canonical storage-identity model, preserves the exact SSA
  version and phi inputs, and carries every upstream refusal into a typed Alias
  refusal; mixed-storage phi inputs refuse instead of joining by shape
- the Alias projection runs immediately after VEX function SSA in both owned
  structuring execution paths and hard-fails if upstream evidence accounting is
  open. Fixed-point exhaustion also returns only unversioned blocks plus one
  refusal per access, never a partial SSA artifact
- the Types/Lowering adapter deduplicates exact Alias SSA versions into storage
  candidates and invokes the existing Alias-fact stack lowering consumer.
  Frame-control words, overlaps, provisional SP ranges, unknown calls, and any
  candidate that fails materialization remain typed refusals or hard failures;
  accepted ranges become real `SimStackVariable`/`CVariable` objects
- action 3 is not applicable to DrawFrame's single 16-bit loop range; no
  adjacent low/high pair is present to widen. Its refusal boundary remains
  covered by the existing exact-carrier Widening tests rather than shape fusion
- block-local IR SSA now preserves every `IRValue` provenance field while
  assigning versions, recursively versions `IRBinaryValue` operands and
  indexed-address expressions, and retains `IRCondition.width_bits`; it no
  longer drops `source_tmp`, memory-access, or index evidence needed by
  Widening
- a real sidecar-free `add ax,bx; adc dx,cx` lift proves that the exact VEX
  temporary chain from the prior flags value through the carry mask and high
  add survives SSA (`t71 -> t72 -> t73 -> t75 -> t77 -> DX`)
- every imported `WrTmp` definition now retains its numeric `source_tmp`, so
  Semantics resolves definitions without parsing `tNN` display names
- typed Semantics evidence now closes the exact low-result, final flags version,
  carry/borrow extraction, high base operation, high final operation, and all
  operand definitions for real `add/adc` and `sub/sbb` lifts. Widening consumes
  those links with canonical Alias register domains and retains both slices,
  signedness `unknown`, definitions, and carry/borrow provenance in one 32-bit
  fact; it does not inspect mnemonics, assembly, C, or AST shape
- real-lifter positive tests and mask, cross-block, result-carrier, segment, and
  source-definition refusal tests close all five evidence counters. Ruff
  `--fix`, MyPy, architecture/context/ownership gates, and 162 seven-worker
  changed-surface tests pass; all new production modules remain below 350 lines
- final acceptance passes `quality-dev` with the 38-module mypyc smoke, 1,523
  focused tests, and all three quality comparisons. The required default test
  pipeline is 3/3 green: 1,523 tests, Ultra QuickC fixtures, and all seven MS C
  tiny compile/run/decompile/recompile/decompiled-run cases; there are no
  failures or timeouts
- after this provenance repair, `quality-dev` passes Ruff `--fix`, MyPy, the
  38-module mypyc compile/import smoke, architecture/context/ownership checks,
  1,523 focused tests, and all three decompilation-quality comparisons. The
  required seven-worker pipeline passes 3/3 lanes: 1,523 focused tests, 4/4
  validated Ultra QuickC fixtures, and all seven MS C tiny build/run/decompile/
  recompile/decompiled-run constructs; lane times were 30.383s, 65.414s, and
  101.599s
- final return-type regeneration now consumes the complete caller-use census
  and exact terminal register-storage contract in Types/Lowering. `NONE` plus
  `UNUSED` removes only side-effect-free synthetic returns; AX storage is
  preserved and call/dirty return expressions hard-fail
- DrawFrame passes both source-backed and isolated sidecar-free focused checks.
  The no-sidecar result has `validation=passed`, a `void` four-argument
  signature, `char local_52[80]`, the exact loop local, all nine required calls,
  a pre-test loop, and no scalar return; whole-tail validation is clean
- immutable IR and Alias contracts are split from their 292-line and 248-line
  solvers, keeping all four new modules below 350 lines. Ruff `--fix`, MyPy,
  types/docs, architecture/context, ownership, and 506 changed-surface tests
  pass. The required pipeline is 3/3 green: 1,469 unit-focused tests, Ultra
  Quick C, and all seven MS C tiny compile/decompile/recompile/runtime cases.

Remaining milestone work: generalize the accepted wide-value and exact source-
carrier contracts to the prioritized SORTD functions. The required full
pipeline must be rerun after that function-level increment; no pair may be
fused from mnemonic or AST shape alone.

Definition of done:

- all five vertical-slice actions are implemented with one exact stack-range
  identity and no semantic discovery in postprocess
- DrawFrame's initialized loop local passes as the positive case, while
  overlapping-width and unknown-SP-delta fixtures refuse materialization
- focused before/after validation, call/memory/control-flow checks, strict GCC,
  and the required pipeline gates pass before generalization begins

Definition of failure:

- the range loses identity or provenance between layers, or a call clobber,
  overlap, phi input, or unknown SP delta is ignored
- postprocess/CLI reconstructs the local or wide value from rendered output
- generalization starts before the positive and refusal vertical-slice gates pass

#### 8.11 Eliminate dead status-flag definitions before C expressions exist

Status: complete for the bounded SORTD status-flag and unsupported-instruction
closure. Typed per-bit same-block and function-CFG proofs, direct-callee
summaries, and lazy frontend emission are implemented for `ADD`, `SUB`, `INC`,
`DEC`, `SHL`, `SHR`, and `SAR`. On the exact `sub_109e8` CLI path all 11
classified CFG candidates materialize and packed flag equations fall from 4 to
0. The strict sidecar-free corpus now closes 20/20, and the required default
project pipeline passes.

Reason: Eagerly materialized packed-status updates retain large parity and
carry equations even when later instructions overwrite every affected flag.
This obscures otherwise simple C and increases simplifier and codegen work.
The proof must track each flag independently because instructions such as
`INC` preserve carry while `ADC` and `SBB` consume it.

Definition of done:

- Semantics owns a typed per-bit read/overwrite contract for decoded x86
  instructions; the frontend only projects Capstone evidence into it
- same-basic-block writes are omitted only after all written bits are proven
  overwritten before any read, and absent lookahead keeps complete flags
- the exact `sub_109e8` `SUB -> SAR 1 -> MOV -> INC` sequence is covered, while
  `INC -> ADC`, conditional reads, zero/unknown shift counts, and unknown
  instructions retain the prior flags
- a later IR/CFG liveness pass handles cross-block deadness with successor,
  loop, and call-effect evidence; the frontend does not guess beyond its block
- the five evidence counters close for every suppression decision, and a
  classified dead write cannot reach zero materialization
- `sub_109e8` loses the dead flag equations without losing either call, changing
  branch polarity, or worsening tail validation; focused gates, the SORTD
  corpus, strict recompilation, MS C tiny examples, types/docs, and Ruff pass

Current evidence on 2026-08-27:

- 24 focused status-liveness tests cover same-block, successor, loop, call,
  live-condition, unknown-edge, cache-relift, and zero-materialization cases
- partial-live `SHL`, `SHR`, and `SAR` regressions prove that a ZF-only
  successor does not construct parity equations; unknown/live paths keep flags
- 188 status-liveness and 80386 edge tests pass, including instruction execution
  semantics beyond the decompiler-only projection
- all 11 exact `sub_109e8` candidates close with `failure_count=0`; the prior
  uninitialized `reg+0x24` carriers were FLAGS, and those failures disappear
  when the CFG artifact is consumed
- Structuring now resolves direct-stack assignments through the Lowering-owned
  machine-BP to entry-SP registry, closing the independent `0x10a4f` ownership
  failure without weakening classified/materialized evidence checks
- Types/Lowering persists the proven complete aggregate typedef through codegen
  rollback, so final rendering no longer emits an incomplete `g_08F0_entry`
- the exact sidecar-free function has `validation=passed`, whole-tail validation
  clean, GCC acceptance, both calls intact, and no unsupported instructions;
  no call/body repair occurs in Rewrite or CLI
- the current whole-file C output has zero unsupported/unknown-instruction and
  zero packed flag-equation markers; the strict run validates all 20 selected
  non-library functions with no fallback, empty body, timeout, or traceback
- Beep's exact gate preserves the one-argument `inp(0x61)` call node, binds its
  typed machine `[BP-2]` return store to the projected `local_2`, emits both
  required uses, and passes tail validation without call reconstruction
- changed-source Ruff `--fix`, MyPy, mypyc, types/docs, architecture, and
  ownership checks pass; the default pipeline passes 1,763 Python tests and all
  three selected MS C tiny-example build/run/decompile/recompile lanes with no
  failures, skips, or timeouts

Definition of failure:

- flags are deleted as one packed value instead of per bit, or carry is dropped
  across `INC/DEC` before `ADC/SBB`
- calls, indirect control flow, unknown instructions, or uncertain successors
  are treated as overwrites without typed evidence
- flag semantics are repaired from assembly/rendered C or in Structuring,
  postprocess, CLI, or export code
- output is merely prettier while call, control-flow, validation, compilation,
  behavior, evidence-accounting, typing, documentation, or lint gates regress

### 9. Bounded SORTD acceptance and comparison index

Status: complete under the user-approved bounded scope on September 19, 2026.
Evidence and limitations: [closure ledger](reference/step9-closure.md). Follow the
[acceptance contract](reference/step9-acceptance-contract.md) for the complete
DoD and failure criteria; the index-specific obligations below remain required.

Reason: Address-aligned, function-specific artifacts make quality changes
reviewable and prevent subjective claims based on whichever peer output looks
best. The index also records Ghidra discovery losses explicitly.

Definition of done:

- all 20 Inertia functions have current Inertia and available peer links mapped
  by binary address, with missing peer functions labeled explicitly
- each focused change records calls/argument classes, memory effects, control
  flow/types, remaining debt, and validation verdict before and after
- regenerated artifacts update line anchors in the same change and peers remain
  diagnostic inputs rather than semantic truth

Definition of failure:

- links or addresses are stale, missing, or point to a different binary/source
  state without disclosure
- a comparison omits semantic calls, memory effects, argument classes, or
  validation and reports only cosmetic similarity
- Ghidra, Reko, or `SORTDEMO.C` output is used directly as recovery evidence

Use these links immediately before and after each implementation change. They
point to the September 19 final Inertia translation-unit export, historical
Ghidra C output, and historical Reko 0.12.4 C output. Artifact identity,
compilation context, current semantic review, and remaining debt are recorded in
[the current comparison](reference/step9-current-comparison.md). The peer
outputs are diagnostics, not truth: an Inertia change is an
improvement only when validation and behavior gates still pass and the result
is semantically clearer or more complete than both peers.

| Function | Inertia baseline | Ghidra result | Reko result |
| --- | --- | --- | --- |
| main | [`SORTD.default-check.dec:114`](SORTD.default-check.dec#L114) | [`FUN_1000_0010...c:4`](SORTD_decomp/FUN_1000_0010_1000_0010.c#L4) | [`SORTD_0800.c:8`](comparisons/reko/SORTD/reko-0.12.4/SORTD.reko/SORTD_0800.c#L8) |
| InitMenu | [`:137`](SORTD.default-check.dec#L137) | [`FUN_1000_005d...c:4`](SORTD_decomp/FUN_1000_005d_1000_005d.c#L4) | [`:38`](comparisons/reko/SORTD/reko-0.12.4/SORTD.reko/SORTD_0800.c#L38) |
| DrawFrame | [`:183`](SORTD.default-check.dec#L183) | [`FUN_1000_01db...c:2`](SORTD_decomp/FUN_1000_01db_1000_01db.c#L2) | [`:120`](comparisons/reko/SORTD/reko-0.12.4/SORTD.reko/SORTD_0800.c#L120) |
| RunMenu | [`:224`](SORTD.default-check.dec#L224) | [`FUN_1000_02cc...c:4`](SORTD_decomp/FUN_1000_02cc_1000_02cc.c#L4) | [`:159`](comparisons/reko/SORTD/reko-0.12.4/SORTD.reko/SORTD_0800.c#L159) |
| DrawTime | [`:359`](SORTD.default-check.dec#L359) | [`FUN_1000_0491...c:4`](SORTD_decomp/FUN_1000_0491_1000_0491.c#L4) | [`:336`](comparisons/reko/SORTD/reko-0.12.4/SORTD.reko/SORTD_0800.c#L336) |
| InitBars | [`:389`](SORTD.default-check.dec#L389) | [`FUN_1000_0554...c:4`](SORTD_decomp/FUN_1000_0554_1000_0554.c#L4) | [`:399`](comparisons/reko/SORTD/reko-0.12.4/SORTD.reko/SORTD_0800.c#L399) |
| ReInitBars | [`:445`](SORTD.default-check.dec#L445) | [`FUN_1000_0672...c:4`](SORTD_decomp/FUN_1000_0672_1000_0672.c#L4) | [`:454`](comparisons/reko/SORTD/reko-0.12.4/SORTD.reko/SORTD_0800.c#L454) |
| DrawBar | [`:468`](SORTD.default-check.dec#L468) | [`FUN_1000_06c8...c:4`](SORTD_decomp/FUN_1000_06c8_1000_06c8.c#L4) | [`:482`](comparisons/reko/SORTD/reko-0.12.4/SORTD.reko/SORTD_0800.c#L482) |
| SwapBars | [`:492`](SORTD.default-check.dec#L492) | [`FUN_1000_075b...c:2`](SORTD_decomp/FUN_1000_075b_1000_075b.c#L2) | [`:510`](comparisons/reko/SORTD/reko-0.12.4/SORTD.reko/SORTD_0800.c#L510) |
| Swaps | [`:510`](SORTD.default-check.dec#L510) | [`FUN_1000_0794...c:4`](SORTD_decomp/FUN_1000_0794_1000_0794.c#L4) | [`:540`](comparisons/reko/SORTD/reko-0.12.4/SORTD.reko/SORTD_0800.c#L540) |
| InsertionSort | [`:526`](SORTD.default-check.dec#L526) | missing (discovery loss) | [`:564`](comparisons/reko/SORTD/reko-0.12.4/SORTD.reko/SORTD_0800.c#L564) |
| BubbleSort | [`:569`](SORTD.default-check.dec#L569) | missing (discovery loss) | [`:619`](comparisons/reko/SORTD/reko-0.12.4/SORTD.reko/SORTD_0800.c#L619) |
| HeapSort | [`:606`](SORTD.default-check.dec#L606) | missing (discovery loss) | [`:668`](comparisons/reko/SORTD/reko-0.12.4/SORTD.reko/SORTD_0800.c#L668) |
| PercolateUp | [`:634`](SORTD.default-check.dec#L634) | [`FUN_1000_09e8...c:4`](SORTD_decomp/FUN_1000_09e8_1000_09e8.c#L4) | [`:717`](comparisons/reko/SORTD/reko-0.12.4/SORTD.reko/SORTD_0800.c#L717) |
| PercolateDown | [`:664`](SORTD.default-check.dec#L664) | missing (discovery loss) | [`:759`](comparisons/reko/SORTD/reko-0.12.4/SORTD.reko/SORTD_0800.c#L759) |
| ExchangeSort | [`:703`](SORTD.default-check.dec#L703) | missing (discovery loss) | [`:809`](comparisons/reko/SORTD/reko-0.12.4/SORTD.reko/SORTD_0800.c#L809) |
| ShellSort | [`:742`](SORTD.default-check.dec#L742) | missing (discovery loss) | [`:866`](comparisons/reko/SORTD/reko-0.12.4/SORTD.reko/SORTD_0800.c#L866) |
| QuickSort | [`:786`](SORTD.default-check.dec#L786) | missing (discovery loss) | [`:920`](comparisons/reko/SORTD/reko-0.12.4/SORTD.reko/SORTD_0800.c#L920) |
| Beep | [`:864`](SORTD.default-check.dec#L864) | [`FUN_1000_0e5d...c:2`](SORTD_decomp/FUN_1000_0e5d_1000_0e5d.c#L2) | [`:1060`](comparisons/reko/SORTD/reko-0.12.4/SORTD.reko/SORTD_0800.c#L1060) |
| Sleep | [`:894`](SORTD.default-check.dec#L894) | [`FUN_1000_0f18...c:2`](SORTD_decomp/FUN_1000_0f18_1000_0f18.c#L2) | [`:1092`](comparisons/reko/SORTD/reko-0.12.4/SORTD.reko/SORTD_0800.c#L1092) |

The compact peer assessment and known defects are linked at
[`NON_LIBRARY_COMPARISON.md:43`](comparisons/reko/SORTD/reko-0.12.4/NON_LIBRARY_COMPARISON.md#L43).
When a result file is regenerated, update this table in the same change because
line anchors may move.

For every focused implementation, save the new Inertia output separately and
compare the exact function against all available columns. Record in the change
notes: preserved calls and argument classes, preserved memory effects, improved
expressions/control flow/types, remaining ugliness, and validation verdict. A
peer-looking result without passing validation is a regression, not a win.
