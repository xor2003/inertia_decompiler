# Step 9 Current Semantic Review

## Artifact And Scope

Latest acceptance (September 19): all 20 functions pass validation, strict
compilation has zero errors and zero warnings, and the 19-function generated
behavior harness passes. RunMenu's dead `v12`/`v29` disappear while its live
decrement chain survives. The other 19 function bodies are unchanged from the
preceding saved baseline. See [the root-cause report](step9-runmenu-dce.md).

Final focused checks: 229 passed in 16.94s. Scoped lint/type/doc checks,
project-wide MyPy, architecture and ownership gates pass. Both `quality-fast`
and `quality-hard` exit 2 at existing Ruff debt, not typing errors; neither is
a green quality gate. The final default pipeline passed all three lanes:
5,861 routine tests in 352.04s, four QuickC fixtures, and seven MS C tiny round
trips. Bounded Step 9 is complete; see [the closure ledger](step9-closure.md).
The user permits reviewed
compiler warnings as debt or justified narrow suppressions; none are needed
for this zero-warning artifact. Semantic validation was not relaxed.

Refreshed September 19, 2026 from `.cache/step9-final-sortd.txt` and its
saved function exports. Earlier timings below describe historical runs only.
This is the dirty worktree based on `37fc06c52925a335dac3597c6b5c5edb9e945a58`,
not an assertion that the base commit alone produces these results.
The 1,051-file `DECOMPILATION_CACHE_SOURCE_FILES` manifest digest after this
change is `0e6d25693be5c59bbf8d65eedf920e6405b4723ce9162fb2b9aa3ab17840368c`,
computed by the existing `_cache_source_digest` utility. This identifies the
production cache manifest, not all repository files or a committed revision.

`SORTD.default-check.dec` is now the final combined C export, without the old
mixed diagnostic transcript. Its SHA256 is
`9c82793b3e08d400ccfef813f15faf8019c80b4d75717a7d94e97583a2b8a897`.
The translation-unit gate assembles the 20 exports with runtime declarations.
Explicit GCC C compilation (`-x c -std=c11 -Wall -Wextra -fsyntax-only`) returns
zero with zero errors and zero warnings. The strict zero-warning gate passes;
see [its report](step9-sortd-compilation.json). InsertionSort's unused field,
InitBars' unused array read and RunMenu's unused carriers are removed with
existing storage/value evidence and liveness proof, not warning suppression.
The earlier apparent zero-warning result was invalid: without `-x c`, GCC did
not parse the `.dec` file as C. The gate now sets the language explicitly;
regressions cover `.c`, `.dec`, and extensionless invalid C inputs.
Compilation is not proof of a linked DOS executable or every input path.

The refreshed gate isolates the 26,432-byte declared MZ image of `SORTD.EXE`,
without sidecars. Image SHA256:
`09e3ce9746b96ebc2fdefd73f34cdf63c1be6acf6c2736c8fc89db595f2ce798`.
The [saved acceptance report](step9-sortd-acceptance.json) records all 20
accepted addresses and zero violations. Additional evidence:
`.cache/step9-final-sortd.{txt,json,log}` and function exports in
`.cache/step9-final-sortd-functions/`. Temporary evidence may not survive cleanup;
the saved C and this checkpoint retain the result and its limitations.

The [20-function index](../SORTD_GHIDRA_PLAN.md#9-bounded-sortd-acceptance-and-comparison-index)
provides current Inertia anchors and historical peer links. Ghidra/Reko were
not rerun. Ghidra discovery losses remain explicitly labeled; numerical names
are acceptable. Peer procedure entries can precede Inertia body entries through
NOP padding. Neither peer nor original C was used as recovery input.

## Current Bodies

All entries below have `validation=passed` in the fresh whole-file run.
These are source inspections of the generated bodies, not new exhaustive
behavioral tests of all 20 functions. Calls use scalar values unless a pointer
class is stated. Shared debt: SI/DI preservation and some register updates
remain explicit; target `short`/`long` widths still require the intended runtime
contract. Do not remove those effects merely for presentation.

| Function / body address | Calls and memory effects present | Control flow, types, remaining debt |
| --- | --- | --- |
| main / `10010` | Screen setup, bar/menu initialization, menu execution, final return call; bar-count store | Application sequence retained; numeric runtime calls and saved registers remain |
| InitMenu / `10060` | Frame, cursor, string-copy, formatting, output; local buffer pointers and DS/SS arguments distinguished | Menu loop and sound/delay guards present; split wide equality and buffer transport remain verbose |
| DrawFrame / `101f0` | Fill/output with local buffer pointer, scalar cursor arguments; edge and terminator writes | Four parameters and frame loop present; repeated SI assignments remain |
| RunMenu / `102e0` | All six sort dispatches, reinitialization, timing/menu calls; counters, selected algorithm, delay and sound stores | ESC exit and live decrement chain preserved; no raw FLAGS cycle or unused locals; scalar key arithmetic, nested branches and label remain |
| DrawTime / `10498` | Clock, signed division, format/output buffer pointer, Beep and Sleep; clock store | Sound branch and scaled scalar tone argument retained; mixed named/segmented global access remains |
| InitBars / `10560` | Seed/time/random, screen-info output pointer, final redraw; 43-word temporary array and two-byte bar writes | Initialization and randomized-removal loops present; unused byte-projected load removed; register transport remains |
| ReInitBars / `10678` | Clock and per-bar DrawBar; whole bar copy and clock store | Copy/redraw loop present; saved-register transport remains |
| DrawBar / `106c8` | Fill/output buffer pointer, color and cursor scalars; 44-byte buffer fills and terminator | Two fill spans and signedness-sensitive lengths retained; SS output argument remains explicit |
| SwapBars / `10768` | Two scalar DrawBar calls and scalar DrawTime call | Wrapper effects retained; explicit ABI preservation remains |
| Swaps / `107b8` | Two bar-pointer arguments; whole-object swap and swap-count increment | Typed two-byte temporary retained; saved registers remain |
| InsertionSort / `10808` | DrawBar/DrawTime scalar indices; bar shifts, final insertion, comparison/swap counts | Signed-byte ordering now preserved; redundant local byte stores and expanded sign extension remain |
| BubbleSort / `108d0` | Swaps takes two bar pointers, SwapBars takes two indices; comparison count | Last-swap outer exit and adjacent-element ordering preserved; SI updates remain |
| HeapSort / `10970` | PercolateUp/Down scalar bounds, Swaps pointers, SwapBars indices | Heap-building and draining phases retained; saved registers remain |
| PercolateUp / `109e8` | Swaps pointers and SwapBars indices; comparison count | Signed parent division and early ordering break retained; SI transport remains |
| PercolateDown / `10a88` | Swaps pointers and SwapBars indices; comparison count | Child-bound exit, child choice, ordering break retained; signed bound casts remain |
| ExchangeSort / `10b50` | Timing index and swap pointer/index calls; comparison count | Minimum-selection nested loops and conditional swap retained; register plumbing remains |
| ShellSort / `10c18` | Swaps pointers and SwapBars indices; comparison count | Gap reduction and last-swap loops retained with signed bounds; casts remain |
| QuickSort / `10ce0` | Both recursive argument pairs and swap pointer/index calls; comparison count | Partition scans, two-element case, recursive order retained; pivot byte-store duplication and sign-extension expressions remain |
| Beep / `10e70` | Port reads/writes, timer division, scalar Sleep call; speaker state save/restore | Minimum-duration guard and restore branch retained; binary divisor overwrite remains explicit |
| Sleep / `10f38` | Initial clock and one clock call per poll; local deadline store | Signed wide deadline comparison now explicit; poll temporary declared; saved registers remain |

## Focused Before/After Evidence

Before means the preceding September 18/19 failed checkpoint, not the older
July comparison snapshot. The validation verdict is not inferred from peers.

| Surface | Before | Now / owning layer |
| --- | --- | --- |
| Sleep | Failed terminal-wide branch validation / lost declaration | Passed; Structuring consumes complete terminal proof, Lowering preserves wide capture, Validation checks precision; compiled deadline/ABI oracle recorded in [Sleep evidence](p0-terminal-wide-validation.md) |
| InsertionSort | Signed-extension precision failure | Passed; IR preserves byte width and signed extension, Lowering projects proven object bytes; 65,581 compiled cases in [evidence](p0-condition-sign-extension.md) |
| BubbleSort, PercolateDown, ShellSort | Existing-loop condition ownership / precision failures | All passed; existing-loop owners and typed condition-delta validation retain the binary branches and swap pointer/value classes |
| RunMenu | Validation passed but raw flag artifact gate failed | Passed without flag cycles; IR publishes binary callee summaries, Lowering proves dead components, Validation normalizes equivalent durable precision evidence; 2,560 execution cases plus corruption controls |
| Whole file | 20 emitted/validated but final artifact checks failed | 20 emitted/validated and zero gate violations; DrawTime equivalent-cast check and exact final-body RunMenu execution evidence fixed in test tooling |

RunMenu's latest focused surface: 166 passed in 38.14 seconds, including live
execution and corrupted controls. Missing/indirect/conflicting callees,
flags-reading calls, live return/argument carriers, and malformed persisted
summaries retain code. Calls and memory operations are never classified as
removable merely because they have no implicit status inputs.

## Historical Acceptance Checkpoints

The notes below record earlier states, not remaining blockers in the refreshed
artifact above. Current scope and closure are governed by the bounded contract.

The [bounded contract](step9-acceptance-contract.md) is authoritative. Whole-file
acceptance passes for all 20 addresses with closed counters and no violations.
The 19-function generated sort-core harness passes compilation and behavior;
it excludes main and is not a whole-program DOS equivalence claim.

The default pipeline completed with 268 prerequisite tests, 5,808 routine tests
in 334.64 seconds, and all three lanes passing (zero failed/skipped/timed out).
Evidence: `.cache/step9-bounded-pipeline.log`. It started before removal of a
duplicate test enrollment; it is not the final unchanged-source closure run.
After that removal, architecture and ownership checks, scoped pipeline Ruff,
and 50 pipeline tests pass. A separate focused owner/gate run passed 116 tests.

Open: resolve the two compiler warnings without weakening evidence-based DCE,
refresh required final gates after the last source change, and complete the
final comparison/acceptance audit. Pre-existing global Ruff and unrelated
COD/test debt remain in [the backlog](post-step9-backlog.md), not silently passed.

Warning investigation, before the projection fix: a direct sidecar-free `0x10808` run with
`INERTIA_DEBUG_OPTIMIZATION=1` exits zero with `validation=passed`.
The live DCE trace repeatedly retains `ir_8` with `reason=keep_unknown`,
`outside_reads=0`, and `live=False`; memory-read refusal counters increase.
Evidence: `.cache/step9-insertion-dce.{c,log}`. This proves conservative refusal
despite no recorded value use, not that the memory evaluation is disposable.
Source inspection of `postprocess/optimization/dce.py` shows local field and
local-address memory-read shapes are not generally classified as discardable.
Do not broaden their purity classification merely to silence GCC. Any deletion
needs authoritative storage/effect evidence, positive and refusal tests, and
fresh semantic/behavioral acceptance. The other three warnings have not yet
been traced to exact live refusal reasons. No decompiler behavior was changed
during that diagnostic run.

The subsequent narrow cleanup change classifies a direct field projection of
an already-typed local `SimStruct` value as a local read. It does not infer
storage, layout or call semantics and still refuses pointer projections and
nonaggregate bases. Existing liveness must separately prove the destination
unread. The regression failed before the fix; 89 DCE tests pass afterward,
including live-result, pointer and nonaggregate refusal cases. The test file
is enrolled in Make, the routine pipeline and the ownership manifest.
Scoped MyPy passes when the declaration-pruning dependency is included.
Ruff on the touched legacy DCE module reports the same 21 diagnostic families
as HEAD (10 complexity, 11 magic-value findings); this is not a clean lint run.
Test and enrollment-file Ruff passes. Architecture and ownership checks pass.
The fresh whole-file gate again accepts all 20 functions; the sort-core harness
again passes compilation and behavior for 19 functions. Compilation warnings
fall from four to three. The refreshed default pipeline has passed its 268
prerequisite tests and 5,819 routine tests in 377.64 seconds; both external lanes
also pass. All three lanes pass, with zero failed/skipped/timed out lanes.
`quality-hard` exits 2 at global Ruff, so it does not prove that
its subsequent checks ran. Evidence: `.cache/step9-projection-pipeline.log`
and `.cache/step9-projection-quality-hard.log`.

RunMenu has a different blocker: DCE removes its unused carriers, but the
postprocess validator rejects and restores that pass. The exact delta contains
conditions and their call-control contexts, not calls, writes or returns:
`ds_global:0x134` changes to `stack_slot:SS:BP-0x2:size1` in four fingerprints.
Evidence: `.cache/step9-runmenu-dce-validation.{c,log}`. Investigate contextual
condition replay and register provenance; do not accept the delta merely
because the destination variables are unused. InitBars was subsequently resolved
by the local-array purity proof recorded above.

Further RunMenu investigation (same source digest): exact JCCs `10452`,
`1046b`, `1047a`, and `10480` alternate between high-word global provenance
and the keyboard stack byte. The legacy `_stateful_register_expr_before_insn_8616`
uses address-ordered instructions, not CFG reaching definitions. It accumulates
arithmetic from mutually exclusive dispatcher arms (for example `-138` before
the decrement at `1046a`, although that arm subtracts `0x48`). This replay is
not adequate evidence for changing a materialized condition.

An in-process probe with `PYTHONHASHSEED=0` confirms that the `10452` condition
already carries typed/Structuring materialization tags. Its explicit value
chain fingerprints as raw AX because the assignment alias resolver refuses
the captured return of the uppercase call. The owned-condition gate then
refuses register-backed values and falls back to the legacy replay.
The first probe omitted `PYTHONHASHSEED=0`; CLI restart discarded its hook,
so its empty observation log is not evidence about condition coverage.

Rejected experiment: resolve uniquely assigned register captures through bound
call summaries and retain fully proven materialized capture chains. Six focused
cases showed one failure before the change; 29 focused tests passed afterward.
However, live RunMenu exited 4: captured-call and raw-register fingerprints
were not coherent across validation snapshots/passes, and restored output
failed final def-use/control-flow checks. All experimental production/test
changes were removed. Do not repeat this partial integration: capture identity
must survive cloning/restoration and every condition-validation projection must
use the same authoritative value proof, with no address-order fallback as truth.
Evidence: `.cache/step9-runmenu-capture-after.{c,log}` and
`.cache/step9-capture-condition-{before,after,related}.log`.

The broader switch-decision-tree test failure is independently pre-existing:
after removal, the identical production digest still gives 316 passes and that
one failure in 7.08s. This is not a full-suite result or an accepted semantic
regression. Evidence: `.cache/step9-capture-reverted-tests.log`.
The restored live RunMenu run exits zero with `validation=passed` and clean
whole-tail validation. Its C is byte-identical to the accepted pre-experiment
RunMenu artifact (`cmp -s` exits zero). Evidence:
`.cache/step9-runmenu-capture-reverted.{c,log}`.

## Historical Acceptance Ledger

The following entries retain earlier observations and superseded blockers.
They are not current gate verdicts; use the bounded status above.

The whole-file and compilation gates are green. Global quality is not:
`quality-fast` exits 2 at repository-wide Ruff (6,235 findings: 4,176 magic-value,
1,863 complexity, 194 Boolean-complexity, two dictionary-iteration findings).
This includes legacy findings in some changed large files; it is not only
unrelated-file debt. The focused flags/precision modules passed scoped Ruff,
MyPy and types/docs. The default pipeline passed all three lanes: 5,536 routine
tests in 281.30 seconds, four QuickC fixtures, and seven MS C tiny full round
trips. Its prerequisite contract set passed 268 tests in 10.54 seconds. The
routine lane remains above its 30-second advisory budget. External lane times:
41.808 seconds for QuickC, 88.855 seconds for MS C tiny.

After that run, ownership headers, future annotations, and dynamic-boundary
documentation were completed; a duplicate DrawTime Makefile entry was removed,
leaving its other enrollment intact. The resulting 399-test architecture and
Structuring regression set passed in 29.56 seconds. Scoped Ruff and types/docs,
configured global MyPy, full architecture, agent context, and ownership passed.
Understand-Anything automatic updates remain disabled.

Named/rebased Sleep remains open. Two subsequent Lowering repairs preserve
binary call identity after naming and reconcile original/rebased target
coordinates without relaxing callsite or return-shape equality. Their focused
regressions passed (31 tests, 6.49s), as did scoped Ruff, MyPy and types/docs.
The missing-callsite warning is gone, but uninitialized AX/DX and uncovered
branches still prevent live validation. These changes postdate the whole-file
and default-pipeline results above; those results are not current-source closure.

A fresh isolated-cache probe on 2026-09-19 located the remaining branch-origin
loss inside `_rewrite_decoded_jcc_conditions_8616`, invoked by Structuring's
condition materialization before terminal-loop proof collection. Both rebased
routes reproduce it: branch/block pair `(0x1020, 0x101d)` disappears (or
`(0x1040, 0x103d)` in the alternate slice), while the other two pairs survive.
AIL-to-symbolic conversion, symbolic-to-AIL conversion, stable-stack lowering,
and the preceding typed-condition subpass retain all three pairs. Thus the
earlier suspicion of angr's expression conversion is disproven.
Evidence: `/tmp/step9-sleep-subpass.log`; the probe exits 4, not success.

The legacy `_build_rewrite_8616` defect is now reproduced and repaired: it
constructed branch tags but attached them to `decoded.expr` only when that
expression had no dictionary of tags. Existing empty/producer-tag dictionaries
lost the branch identity. The existing provenance regression now covers both
cases (two failures before the fix); all 100 tests in its module pass afterward
in 6.79s. Replacement metadata now retains expression metadata and applies the
branch provenance, without adding condition recovery or relaxing validation.

The isolated-cache live probe at 14:11:13-14:11:20 +02 confirmed all three
origins reach terminal-loop proof collection on both rebased routes. Structuring
is now stable, but Postprocess validation still rejects the result with
`branch-condition:wide-proof-mismatch:actual=capture-mismatch`. Evidence:
`/tmp/step9-sleep-origin-fixed.log`. The subsequent capture probe showed one
correctly placed clock writer retaining the original target tag, while its
reported identity changed to a rebased address or `None`. Lowering now consumes
that tag through the existing checked target-coordinate matcher. Conflicting
numeric targets still refuse; three fail-first identity cases now pass.
The related terminal-wide set passes 42 tests in 7.15s, with clean scoped
Ruff/MyPy/type-ratchet checks for the binding owner and its test module.

Both named Sleep routes now pass validation. The behavioral harness needed
the explicit register globals already supplied by the sidecar-free harness;
these are shared, not removed from generated code. Added deliberate SI/DI
corruptions are rejected. The complete focused Sleep set passes 16 tests in
15.67s, including unchanged generated-C compilation and clock/ABI execution.
Evidence: `/tmp/step9-sleep-full-after.log`. Scoped Ruff was run with `--fix`;
the legacy JCC modules still report 73 findings and the wider Sleep surface
reports 33 existing magic-value findings. No quality gate was weakened.
Whole-file refresh started at 14:17:03 +02 and completed successfully: 20/20
functions emitted and validated, zero violations/timeouts/tracebacks. All 20
individual exports and the combined translation unit pass the project C
recompilation checker. The combined export is byte-identical to the saved
then-saved snapshot, so the comparison anchors were current at that checkpoint.
Evidence: `/tmp/step9-sortd-current.json`, `/tmp/step9-sortd-current.txt`,
and `/tmp/step9-sortd-current-functions/`. The refreshed default pipeline now
passes 5,544 routine tests and both compiler lanes. A historical-failure retry
passes 25 cases and fails 22; full-suite acceptance remains open. See
[the current failure inventory](step9-failure-refresh-20260919.md).
Full-suite closure and global Ruff remain open; neither is implied by the green
default pipeline or refreshed comparison index.
