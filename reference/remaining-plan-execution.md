# Remaining Plan Execution

User resumed the remaining steps on September 19, 2026 after bounded Step 9
closed. That historical closure remains valid; this work is a new checkpoint.

At 23:58 +02:00 the user approved the
[bounded Steps 10-12 acceptance contract](remaining-plan-acceptance.md).
That contract supersedes the broad implementation obligations below. The user
then clarified that new mechanisms should still be added for demonstrated
SORTD improvements. Saved-register SP recovery remains an evidence-directed
candidate; speculative generalization is deferred. Each admitted mechanism
must meet the bounded contract before final gates can close the milestone.
The subsequent explicit parity clarification restores Task 5 and Tasks 7.1-7.4
feature acceptance within the selected inventory. Audits identify implementation
gaps; they do not replace required new features. See the corrected contract.

Step 12 initial contract-test audit: 168 passed, seven third-party warnings,
16.80s with pytest -n 7. `.cache/step12-storage-audit.log` covers the existing
interprocedural-storage test family. This is mechanism evidence only, not proof
of complete live caller coverage or completion of the seven-function audit.

## Order

1. Step 11: proof-backed readability (Task 5), starting with exact signed-value
   conversions already present in IR. Then inspect remaining proven stack,
   aggregate and expression projections; do not rename from source guesses.
2. Step 12: evidence-supported Reko mechanisms (Task 7). Reassess existing
   implementations before adding work; implement only independently supported
   wide-value, call-contract and aggregate mechanisms at their owning layers.
3. Step 10: measured performance (Task 6), only for material bottlenecks.
   Re-profile current code and honor the recorded rejected experiments.

The broader Tasks 3/8 and unrelated full-suite/lint debt are not silently closed
by this sequence. Numeric function names and explicit unknowns remain valid.

## First Readability Slice

Started September 19, 23:11 +02:00; accepted at 23:45:44 +02:00. Approximately
35 minutes elapsed, including investigation and test waits. This slice is done;
the broader Step 11 remains in progress.
Reason: InsertionSort/QuickSort conditions print sign-extension arithmetic even
though IR already owns exact conversion widths and operations.
DoD: consume exact IR proof as explicit signed casts; keep original load width,
single evaluation and unknown-case refusal; regressions demonstrate failure
before and pass after; fresh function and whole-file validation, compilation,
behavior and default pipeline stay green. Record global quality debt honestly.
Failure: recognizing rendered text, guessing signedness, widening a memory load,
duplicating evaluation, accepting near-matches, or hiding semantic deltas.

Baseline InsertionSort regression: 1 passed in 37.06s (30.42s test call),
`.cache/step11-insertion-before.log`. The baseline artifact retained expanded
`((byte & 255) ^ 128) - 128` expressions; the new output uses proven signed casts.

The first implementation passes whole-file validation (20/20), zero-warning
compilation and generated behavior (19 functions). Final default pipeline passes
all three lanes, including 5,885 routine tests. See
[the signed-conversion report](step11-signed-casts.md) for exact
ownership, tests, before/after evidence and current limitations.

## Next Investigation, Not A New Solver

The next Step 11 candidate is saved-register byte-pair readability. Start from
the existing `widening/stack_memory_objects.py` owner, which consumes composed
Alias overlap evidence. Do not join adjacent bytes by appearance and do not
delete SI/DI/upper-register preservation. First determine whether a proven
word object is missing upstream or merely not consumed by Lowering.

Reason: byte-by-byte saved-register plumbing is repeated across the current
output and obscures application logic without being dead code.
DoD: one representative function has an exact Alias/Widening word-object proof,
unchanged reads/writes/calls and entry/exit register effects, positive and
conflicting-definition/overlap/escape refusal tests, closed counters and fresh
validation/compilation/behavior gates. Only then generalize to the corpus.
Failure: adjacency-only joining, segment merging, changed access width or
partial-write behavior, or dropping an ABI effect because it looks redundant.
This is an investigation candidate, not an assertion that the proof exists.

### Saved-Register Investigation Checkpoint

September 19, 23:56 +02:00: no production transformation added in this slice.
An isolated-cache live SwapBars probe observed both stage invocations. Alias
accepted six raw BP argument byte facts but refused 26 accesses, including the
SP-relative save/restore sites. Logical projection reported 13 missing exact raw
memory-SSA sites; Widening proved only the two argument words and Lowering had
no saved-register candidate. Evidence: `.cache/step11-saved-register-probe.log`.
Repeated SP offsets refer to different source temporaries, not one proven slot.

This first probe inspected only the memory-SSA object path. The September 20
GP-restore probe below supersedes the inference that a new SP proof is necessary
for saved-register readability. The current block-local stack-extent analysis
does refuse calls/branches, but another Alias owner already proves this case.
Do not relax those guards or invent a duplicate frame solver.

The baseline SwapBars regression failed on `local_4` despite legitimate saved
SI storage. Replaced incidental local-name/count assertions with an unchanged-C
compiled oracle: 405 argument/register cases, ordered calls, saved low words,
and current upper halves. Adversarial stubs test the explicit restore effects,
not a claim that the real callees clobber those registers. Seven deliberately
corrupted implementations are rejected. Live CLI regression plus oracle controls:
9 passed in 6.85s (`.cache/step11-swapbars-oracle.log`); this run may use warm
accepted-function caches and is not a new fresh semantic acceptance claim.
Enrolled controls and the sidecar-free regression in Make and routine pipeline.

Scoped Ruff and ownership-manifest validation pass. Pipeline/ownership unit
checks: 111 passed, one failure in the existing tail-validation-family exact-list
expectation (additional alias-cycle tests), unrelated to the new SwapBars owner.
See `.cache/step11-swapbars-enrollment.log`; do not call this a green full suite.
Graph indexing and coverage remain unavailable (transport closed); findings use
direct source reads and the live probe, not an exhaustive graph audit.

### Corrected GP Restore Diagnosis And Refreshed Baseline

Newest user priority: coherent word-only GP-state projection for proven 16-bit
binaries, without printed upper-half preservation. See the Step 11 contract.
Current `lowering/gp_register_state.py` always creates four-byte runtime lanes
and emits partial writes with a preserved parent mask. Change the authoritative
lane/projection contract and every consumer together, not the rendered C or
the real-mode lifter. The byte-pair-local feature remains pending behind this.

Width-proof groundwork now exists in `semantics/register_lane_width.py`:
decoded effects classify each architectural GP lane as word-only observed,
wide access or unknown/refused, retaining exact inventory indices and closed
classification counters. This does NOT grant whole-program narrowing permission
and is not yet wired into runtime declarations or output. It consumes the
existing register-bit-effect owner rather than another register inventory.
Thirteen focused tests pass (7.45s), including explicit operand/address overrides,
byte lanes, unknown/empty inventories and wide writes. Ruff, scoped MyPy and
ownership checks pass. The tests are enrolled in the routine pipeline.

Capstone reports implicit word PUSH/POP as ESP effects. The next slice refines
this through the real-mode stack rule: implicit SP remains word-sized even for
a dword operand, but explicit ESP and [ESP] operands remain wide. Three positive
tests failed before this refinement; all 20 cases passed afterward, including
operand/address overrides and a 32-bit decoder negative control. Other implicit
stack instructions remain conservative until independently modeled. Next
establish closed CFG/call-boundary coverage before binding
one coherent runtime width across functions, validation and worker transport.
Generated C has not changed from this groundwork; the user-requested word-only
presentation and parity steps remain incomplete.

September 20, approximately 00:04 +02:00: isolated-cache live diagnostic
`.cache/parity-gp-probe.log` proves that
`alias/segment_stack_restore.py` produces two PROVEN cross-block SwapBars
save/restore facts, zero failures, exact saved SI/DI instruction identities and
entry-SP byte offsets. Complete call-stack effects retain the saved bytes.
`lowering/gp_stack_restore.py` reports both facts materialized but zero new
snapshots: its `has_materialized_gp_stack_bytes_8616` branch accepts the existing
byte representation and skips word snapshot projection. Thus memory-SSA's SP
refusal is not the actual readability blocker for this case.

Next admitted feature: a focused Types/Lowering word projection consuming these
existing Alias facts and exact C storage/use evidence. Preserve single snapshot
evaluation, all reads, call order, restore low words and current upper halves.
Refuse extra writers, escaped storage, unrelated readers, conflicting source
identity and non-dominating saves. Keep byte fallback valid when proof is
insufficient. Do not move recovery into Rewrite or remove byte effects merely
because the output looks cleaner. DoD includes readable word locals in SwapBars,
the compiled corruption oracle, focused refusal tests, fresh tail validation,
whole SORTD compilation/behavior and routine pipeline acceptance.

Refreshed whole-file baseline: 20/20 decompiled, zero failures/timeouts/validation
failures, no violations (`.cache/bounded-sortd.{json,txt,log}`). Compilation:
20 functions, zero errors and warnings (`.cache/bounded-compilation.json`).
Generated behavior: 19 functions pass (`.cache/bounded-behavior.log`). All exported
files are byte-identical to the accepted Step 11 output. Against Step 9 only
InsertionSort and QuickSort bodies differ, plus their combined translation unit.
These are baseline gates, not completion of the requested parity features.

### Beep Parity Oracle

The current generated behavior harness checked timer-port order but omitted the
actual low/high quotient bytes. Added one shared runtime-observation predicate
used by the full harness and compiled oracle controls. For frequency 120 it
requires divisor 120, quotient bytes 215 and 38 in order, the mode write, speaker
enable and original speaker-control restoration, with exactly five writes.
The controls reject zeroed/swapped quotient bytes, wrong divisor, missing write
and failed restoration. Fifteen gate tests pass in 6.20s; the updated complete
19-function generated behavior harness also passes. Logs:
`.cache/parity-timer-tests.log`, `.cache/parity-timer-behavior.log`.
Existing routine pipeline and ownership entries already cover these files.
This improves the named Beep acceptance evidence; it is not a new decompiler
mechanism or closure of all wide-value/call-contract obligations.

Source scout for Task 7.2 found existing owners in Types/Lowering:
`interprocedural_storage_solver.py::resolve_program_storage_trials_8616`
already resolves deterministic SCCs, refuses duplicate function trials and
closes aggregate counters. Its bounded output/pass-through iteration fails
explicitly if convergence is not reached.
`interprocedural_storage_pipeline.py::_publish_trials_8616` republishes the
retained trial set through that solver before applying the resulting contracts.

Do not recreate those mechanisms from the old plan's wording. Next investigate
collection completeness and all definition/callsite consumers, including worker
transport, against Task 7.2's exact acceptance cases. These source observations
are not proof that every function/callsite is covered or that Task 7.2 is done.
Graph access and coverage checks were unavailable (transport closed); the
identified function bodies were inspected directly.

### Word Register Output: Incomplete

User acceptance: word-only binaries should expose word register operations,
such as `inertia_si = value`, without repeated upper-half ESI merge expressions.
The decoded register-lane width classifier is a foundation, not an integrated
output feature or a whole-program proof. Preserve 16-bit truncation and wrapping;
unknown calls, undecoded paths and explicit wide operands must not authorize
discarding observable upper bits. Coherent subregister views can preserve shared
storage internally without printing the preservation expression at every write.
Implement the contract in Types/Lowering and its runtime/storage consumers,
not as rendered-C replacement. Acceptance requires mixed-width negative controls,
tail validation, generated-C compilation and behavior gates.

The separate saved-register word-local projection experiment was rejected and
removed from production: SwapBars passed, but the whole-file gate produced only
19/20 functions. In main (0x10010), the DI restore referenced an uninitialized
local. Raw-offset equality and fresh variable identity did not resolve it;
the exact later rebinding cause remains unproven. Evidence remains in
`.cache/gp-word-sortd.*` and `.cache/gp-word-main2.*`. Do not repeat those failed
approaches as established fixes. Preserve the existing byte-save representation
until coherent storage projection is proven. The shared-byte-reader regression
remains in the existing binding test matrix.

The register-width work now has a separate typed program-closure reducer in
`semantics/register_lane_closure.py`. It requires an exact expected inventory,
complete per-function coverage, resolved transfer targets, classified width
effects and a closed execution boundary. A wide callee keeps its word-only
callers in the full shared storage ABI; recursion does not create evidence.
Missing callees, external observers, undecoded paths and unknown transfers
refuse narrowing. Duplicate producers and mixed lane identities fail early.
Results are deterministic immutable records with worker-serialization tests
and a closed proof-obligation census. This is not runtime/output integration:
the production collector still must establish these facts, and Lowering,
runtime declarations and validation must consume one coherent decision.
Do not mark COMPLETE merely because CFG discovery returned successfully.

### Coherent Word Runtime Provider

`lowering/gp_word_runtime.py` now provides a C89 shared-storage ABI with one
32-bit union per GP register. `inertia_si` and `inertia_esi` are lvalue views of
the same object, not independently synchronized globals. Word writes preserve
the upper word internally; byte updates preserve the other byte and word
arithmetic wraps through unsigned-short assignment. Explicit integer-width,
layout and target-byte-order checks fail compilation for unsupported hosts.
This alternative avoids deleting upper state merely for presentation, including
when full-program narrowing cannot be proven.

Five focused tests pass in 5.85s. Separate runtime/client translation units
compile as C89 with warnings-as-errors and strict aliasing at O0 and O2. All
eight GP lanes are exercised. Corrupt split-storage and swapped-word providers
compile but fail the behavior oracle, without producing abort/core files.
Ruff and scoped MyPy pass. This is GCC evidence, not yet an MS C execution gate.

Production still uses the legacy scalar ABI. Integration must atomically change
the typed projections, declaration publication/worker transport and all runtime
providers. Do not publish union macros alongside legacy scalar definitions or
relax tail validation. Word/full view identity must remain coherent in every
validation projection. Preserve evaluation ordering for effectful sources;
do not replace a parent read around a call merely because the final masks match.
Next: wire the authoritative view contract into Lowering and validation, then
adopt the provider in generated compilation/behavior harnesses and MS C tests.
The requested output improvement remains incomplete until live SORTD output
and the final acceptance gates verify it.

The runtime ABI is now selectable through the existing runtime-header renderer
and MS C compiler/linker transaction using `GPRegisterRuntimeABI8616`, not
source-text detection. The real MS C gate compiles the client and generated
INERTIA.C as separate objects, links them, and executes the shared full/word
checks in DOS. The new ABI and legacy scalar path both pass the focused builder
regressions: 64 tests, 7 dependency warnings, 6.98s. Startup architecture and
ownership checks pass. Defaults remain scalar until typed Lowering/validation
and declaration publication are switched together; SORTD output is unchanged.

Scoped MyPy passes when the source package roots are supplied explicitly
(`MYPYPATH=./angr_platforms:.`, `--explicit-package-bases`). The initial combined
invocation failed on duplicate scripts module naming, not a runtime defect.
Ruff passes for the new provider, header owner and runtime-support changes;
the existing builder file retains 12 complexity/Boolean findings outside the
two updated compiler wrappers. These findings are not suppressed or reported
as a clean global lint gate. Logs: `.cache/gp-word-integration-*`.

### Live Word-Assignment Projection

The GP write owner now invokes a Types/Lowering projection when codegen has an
explicit coherent ABI selection. `CGPWordAssignment8616` retains the canonical
full-register assignment as its only semantic AST. The statement renderer uses
the runtime word lvalue only while exact parent/mask identity and a pure value
still hold. Mutation, effectful values, assignment-expression use and scalar
ABI selection retain the explicit full assignment. Reads are not blindly
shortened: changing their C promotion width can change surrounding arithmetic.

The declaration exporter consumes the selected ABI's metadata. Its new CLI
dependency is permitted solely for declaration rendering; width inference and
partial-write recovery remain forbidden in CLI. A live probe exposed a legacy
missing-global bug: it emitted `extern unsigned short inertia_si` after the
runtime macro. A compiled regression reproduced that failure. The formatter
now excludes Lowering's reserved word-lvalue symbols from synthetic globals;
it does not infer a register from the rendered C.

An isolated, in-process sidecar-free SwapBars probe on September 20 around
01:02 +02:00 emits word assignments for SI/DI, passes tail validation and the
portable compilation check. The exact emitted artifact passes the existing
405-case call/argument/register behavior oracle, including adversarial callee
upper-word changes. Artifacts: `.cache/gp-word-live.{c,log}` and
`.cache/gp-word-live-behavior.log`. Focused projection, GP, traversal and oracle
tests: 80 passed, 7 dependency warnings, 7.64s. The declaration regression family
also passes (27 tests). This is a successful opt-in probe, not default rollout
or whole-plan completion. The source and normal CLI still default to scalar ABI.

Next required integration: stable ABI selection and propagation across codegen
replacement and workers, matching runtime providers throughout whole-file/DOS
gates, default activation, then all 20 SORTD functions and the final pipeline.
Do not claim the direct diagnostic hook is a production selection mechanism.

The first broad checkpoint passed all three pipeline lanes, with 5,924 pytest
tests in 295.49s plus QuickC and all seven MS C round trips. However, the newly
added GP projection/runtime tests were only in Make's focused lists, not the
curated pipeline list. Enrollment is now corrected and protected by a test;
the pipeline must be rerun before claiming those tests were included.

Removed the unconnected `register_lane_width`/`register_lane_closure` experiment
and its private tests. Source inspection found no production consumers. That
work addressed physical upper-bit deletion, which the chosen coherent views do
not perform. Existing instruction semantics are unchanged; the runtime keeps
the full register and exposes its word view. The earlier census/closure notes
above are historical, not active mechanisms or remaining integration tasks.
Required boundary behavior is checked through shared-storage, mutation-refusal,
mixed-width, wrapping, compiled-C and actual DOS execution tests instead.
The DOS-specific test explicitly skips without its external toolchain; fast
ownership selects the host tests, and `test-pipeline --require-external` still
blocks when the DOS toolchain is unavailable. No skip applied in the local run.

The enrolled pipeline rerun finished with three passing lanes, zero failures,
skips or timeouts; its pytest lane passed 5,926 tests in 287.76s. Evidence:
`.cache/gp-word-test-pipeline-enrolled.log` and the pipeline summary JSON.
This remains the scalar-default checkpoint, not coherent-default acceptance.

A subsequent mutation regression demonstrated that narrowing the preserved
parent with a cast incorrectly retained word projection. Lowering now requires
direct register variables for both the destination and preserved parent; the
register-view classifier's cast stripping is insufficient preservation proof.
The new regression failed before that guard and passed afterward. Projection,
runtime and SwapBars tests: 32 passed, 7 dependency warnings, 8.19s. Scoped Ruff
with `--fix` and MyPy with `--follow-imports=skip` passed for the projection
module. Artifacts: `.cache/gp-word-narrow-before.log` and
`.cache/gp-word-guard-after.log`. The broad pipeline predates this narrow guard.
Production ABI activation and whole-file acceptance remain open as above.

### Whole-File Runtime Gate Migration

The SORTD behavior gate now accepts `--gp-runtime-abi coherent_word_views`.
Its focused tooling owner uses Lowering's header and single storage definitions
for all translation units; scalar artifacts remain supported by the explicit
scalar selection (still the default). No ABI is inferred from rendered C.
A new coherent-ABI compilation test first failed on the fixture's old scalar
definitions. The fixture now omits those definitions when the authoritative
coherent header is supplied. Both ABI variants link and reset all GP lanes;
invalid untyped ABI selections fail before writing files.

Verification: 40 focused tests passed in 7.12s with 7 dependency warnings;
Ruff `--fix`, scoped MyPy, touched tooling type/doc checks, startup architecture
and ownership checks passed. The actual scalar baseline artifacts still pass
all 19 compiled behavior cases in `.cache/sortd-runtime-scalar-check`.
Logs: `.cache/sortd-gp-runtime-before.log` (expected compilation failure),
`.cache/sortd-gp-runtime-focused.log` (accepted focused run).
These tests are enrolled in the existing default SORTD gate test module.
This migrates the acceptance harness, not production default ABI selection.
Next: initialize the coherent ABI at the Lowering lifecycle boundary, keep MS C
runtime providers consistent, and verify normal workers and cached output.
The final decompilation cache already hashes production Python source recursively;
verify the new owner remains included before relying on invalidation.

### Normal CLI ABI Activation

Production GP Lowering now initializes each fresh/rebuilt codegen with the
coherent ABI. Explicit legacy selections survive replay, and malformed selections
fail before processing the AST. The MS C runtime writer and SORTD/RunMenu gates
consume the same typed default. The final-result cache includes both new Lowering
owners in its recursive source hash; a regression protects that inclusion.

The first normal-worker run accepted only 9/20 functions. Integration exposed
three declaration bugs, reproduced before fixing:
- preprocessor replacement expressions were mistaken for function headers,
  allowing local-declaration cleanup to erase a following aggregate's fields;
- old scalar externs survived replacement by the typed coherent ABI, and macro
  lvalues were not consistently treated as declared names;
- runtime header insertion moved globals ahead of already-existing typedefs.
These fixes are declaration/lexical handling, not semantic recovery in CLI.
Runtime gates no longer allocate independent scalar SI/DI storage for coherent
artifacts. The intermediate 18/20 run is retained as failure evidence.

The final normal-worker run accepted 20/20 functions with no validation failures,
timeouts or violations. Whole-file compilation: 20 functions, zero errors and
warnings. The unchanged-body sort-core gate passed all 19 cases, with the coherent
ABI selected by default. RunMenu passed its 2,560 cases; normal-CLI SwapBars passed
405 cases. Artifacts: `.cache/gp-default-final.{json,txt,log}`,
`.cache/gp-default-final-functions`, `.cache/gp-default-compilation.json`,
`.cache/gp-default-sort-core`, `.cache/gp-default-runmenu-behavior` and
`.cache/gp-default-swapbars-behavior`.

Focused activation checks passed 102 tests; the final declaration regression
family passed 116 tests in 7.88s. Scoped MyPy and touched type/doc checks pass.
Architecture and ownership checks pass. Global `quality-fast` exits at existing
Ruff debt; it is not green and later gates were not reached. The separately
started default pipeline is pending in `.cache/gp-default-test-pipeline.log`.
Graph indexing/coverage remains unavailable (transport closed); source inspection
was used, with no exhaustive graph claims.

Remaining word-rendering obligation: InitBars still has one explicit masked SI
write whose value is `tmp_0`. The shared return-expression purity predicate
refuses `SimTemporaryVariable`; do not weaken return recovery to fix rendering.
Prove direct typed scalar-temporary reads at the word-assignment owner, retain
effectful/unknown refusal controls, and rerun function/whole-file acceptance.
This checkpoint activates normal CLI output but does not close Step 11 or 10-12.

### Word-View Slice Accepted

The remaining InitBars temporary case is resolved at the word-assignment owner:
a direct typed integer temporary is read once without substituting its defining
expression. The stricter return-recovery predicate is unchanged. Floating and
pointer temporaries, narrowing parent casts, effectful values and assignment
expressions retain their explicit canonical form. Compiled C tests include a
wide temporary whose low word is stored while the destination's upper word
survives. Focused GP tests: 39 passed, 7 dependency warnings, 6.72s.

The first activated default pipeline exposed 12 harness failures and one QuickC
checker failure. Shared execution harnesses now consume the authoritative GP
runtime instead of allocating scalar copies or omitting word-view declarations.
Their behavior/corruption tests remain intact; REP tests additionally check the
preserved upper DI word. The QuickC structural parser now obtains `<limits.h>`
constants from its actual preprocessor rather than stripping the include and
failing the runtime width assertions. Positive and deliberately incorrect
indexed-argument contracts exercise that header path. No gate was weakened.

Final accepted source evidence:
- 20/20 sidecar-free functions, no validation failures, timeouts or violations:
  `.cache/gp-word-complete.{json,txt,log}` and
  `.cache/gp-word-complete-functions`.
- 20-function translation unit: zero errors/warnings:
  `.cache/gp-word-complete-compilation.json`.
- All 19 unchanged-body behavior cases pass:
  `.cache/gp-word-complete-sort-core`.
- Explicit GP upper-preservation assignment count: baseline 55, accepted 0.
  InitBars now renders `inertia_si = tmp_0;`.
- Default pipeline: all 3 lanes passed, no skips/timeouts; 5,950 pytest cases
  passed in 296.99s, four QuickC fixtures validated, seven MS C tiny round trips
  passed. `.cache/gp-word-complete-test-pipeline.log` and the pipeline summary.
- Previously failing harness family: 36 focused passes; additional shared
  harness positive/corruption controls: 48 passes. Scoped MyPy, touched type/doc,
  architecture and ownership checks pass. New kernel Ruff checks pass. Existing
  global lint debt remains visible, including two pre-existing complex-condition
  warnings in `scripts/generated_c_contracts.py`; global quality is not green.

Observed activation/verification window: September 20, 01:37:44 to 02:20:24
+02:00, 42m40s wall time including edits and waits. Boundaries are the first
failing lifecycle-test log creation and final pipeline log completion; earlier
scaffolding work is not included, and active coding time was not separately
metered. The full Steps 10-12 goal remains active: finish the bounded Task 5/7
  parity obligations, then the agreed reproducibility/resource measurements.

### Step 12 Contract Refresh Guard And Parity Audit

September 20, 02:29:12 to 02:41:56 +02:00: 12m44s observed implementation and
verification window, including waits. Active coding and waiting were not
separately metered. See [the bounded parity audit](step12-parity-audit.md) for
current positive cases, reviewed proof owners and remaining requirements.

Reproduced stale accepted storage contracts after refused collection refreshes:
three pre-fix failures, covering inputs, unavailable return evidence and refused
return collection. Types/Lowering now fails before downstream consumers with
the function address, layer and typed publication result. Six regression cases
cover direct publication and the production prototype-consumer path. The old
atomic payload is not partially mutated, and no argument/signature is guessed.
Moved the existing trial replacement operation into its transaction owner;
the lifecycle module shrank from 353 to 350 lines. No new solver was introduced.

Acceptance on the changed source:
- `make check-files`: exit 0; scoped Ruff/MyPy/type/doc, startup architecture,
  ownership and 198 tests pass (26.35s). The test module is already enrolled.
- SORTD: 20/20, zero validation failures/timeouts/violations. All individual
  exports and the translation unit are byte-identical to the accepted word-view
  output. `.cache/storage-refresh.{json,txt}` and `storage-refresh-functions`.
- GCC: zero errors/warnings; all 19 behavior harnesses pass.
  `.cache/storage-refresh-compilation.json` and `storage-refresh-sort-core`.
- Default pipeline: all 3 lanes pass, no failures/skips/timeouts; 5,956 pytest
  cases pass in 293.32s, QuickC passes and all seven MS C round trips pass.
  `.cache/storage-refresh-test-pipeline.log` and the pipeline `summary.json`.
  The unit lane still exceeds its advisory 30-second budget; this is not a
  performance milestone or a claim that the entire pipeline takes 293 seconds.
- `quality-fast`: exit 2 at existing global Ruff debt; later sequential gates
  are not claimed run. `.cache/storage-refresh-quality-fast.log`.

Source checkpoint: dirty shared worktree based on
`37fc06c52925a335dac3597c6b5c5edb9e945a58`. Relevant owner SHA-256 values:
`interprocedural_storage_pipeline.py`:
`043ab295f7b2e04b1f1ba4e3afe420b5d82ad610bc82a0b18b171254d4f7bed6`;
`interprocedural_storage_transaction.py`:
`3daa827397047bbbf7050b254a5746b9e2b147440b52794bbc660463705c45e0`.

Also inspected every one of the 20 body diffs against Step 9: only the accepted
word-view assignments and three signed conversions differ. Remaining byte-local
and segmented-access readability debt stays visible. The audit records why
worker transport of raw caller evidence does not yet prove shared accepted
storage contracts. Next capture live contracts/censuses across workers before
adding any missing transport or publication mechanism. Steps 10-12 remain open.

### Step 12 Caller-Owned Memory Evidence

Observed probe/fix/verification window: September 20, approximately 02:44:00 to
03:05:50 +02:00, 21m50s including waits. The start is the first live-probe log's
creation time (02:43:59.979); active coding and waiting were not separately
metered. No performance improvement is claimed.

Live Swaps and QuickSort probes found closed input censuses (nine and five
callsites respectively), but memory live-outs looked up callers in the isolated
callee project and refused with `function_not_found`. Lowering now uses the
existing census-owned caller project and exact function boundary for both SSA
and conditions. Duplicate contexts refuse explicitly; condition caches separate
equal addresses in different projects. Refusal construction and per-callsite
collection were factored into their existing contract/flow owners. Touched
production modules are 96, 292, 249 and 309 lines and pass scoped Ruff/MyPy/docs.

Focused isolated-owner/conflict regressions failed before the fix and pass
afterward. `make check-files` passes, including 200 tests in 28.32s. The final
focused live-out/context set, including an additional cross-project cache
control, passes 23 tests in 8.81s. The caller-context module is now explicitly
enrolled in the default pipeline; no slow duplicate binary test was added.

Final acceptance artifacts:
- `.cache/storage-caller.{json,txt}` and `storage-caller-functions`: 20/20,
  no validation failures, timeouts or violations. All exports and the combined
  translation unit are byte-identical to `storage-refresh-functions`.
- `.cache/storage-caller-compilation.json`: zero errors and warnings;
  `storage-caller-sort-core`: all 19 behavior cases pass.
- `.cache/storage-caller-test-pipeline.log`: all three lanes pass, no failures,
  skips or timeouts; 5,963 pytest cases in 298.33s, four QuickC fixtures and all
  seven MS C tiny round trips. The external lanes additionally took 36.59s and
  85.34s; 298.33s is not the total pipeline time.
- `.cache/storage-caller-quality-fast.log`: still exits 2 at unrelated global
  Ruff debt. Later sequential gates are not claimed run. Scoped checks pass.

The live after-probes still refuse unified contracts for a newly exposed,
specific reason: return-use facts identify NOP-padding range starts, while the
input census identifies recovered function entries. Swaps' 18 pointer effects
now survive memory collection; eight caller identities still disagree.
QuickSort's five input callsites remain proven, including four recursive calls,
but all five return-use identities disagree. Both generated functions still
pass tail validation. Do not report either unified contract complete.

The [parity audit](step12-parity-audit.md) records exact producer paths, verified
NOP bytes, and the next Frontend canonical-entry mechanism's reason, DoD and
failure definition. In particular, do not reuse 0x00/0xcc discovery padding
heuristics as execution-equivalence proof. This is the next blocking feature
work before accepted-contract worker transport. Steps 10-12 remain active.

### Step 12 Binary-Proven Caller Identities

First explicitly observed edit/test timestamp: September 20, 03:15:42 +02:00.
Final verification observed complete at 03:37:37 +02:00: a 21m55s window,
including waits. Active engineering and waiting were not separately metered.

The Frontend now owns a compact, typed NOP-entry equivalence witness consumed
by both callsite inventories. Exact decoding bounds and call instructions stay
unchanged. Lookup, recursive-cycle classification and transitive return-use
queries consume the same identity. Only contiguous 0x90 bytes establish aliases;
traps, zero bytes, prefixed instructions, malformed/conflicting witnesses,
truncated reads and wrapping entry windows have explicit negative coverage.

The new incomplete-range control exposed a separate absence-of-evidence bug:
return-use analysis could classify all results UNUSED after one caller read
failed. The Frontend range-census property now prevents that claim. Closed
accounting with failures does not mean a complete caller census. This guard
checks range availability, not a new proof of complete instruction decoding.

Live `storage-entry-{swaps,quicksort}.log` probes used an independent result-cache
namespace. Swaps now publishes and replays an accepted unified contract: nine
input callsites and 27 return/memory facts, all counters closed. QuickSort's five
caller identities now agree, including recursion, but the solver still refuses
`passthrough_output_unresolved`. The parity audit documents the required typed
discarded-return evidence and its DoD/failure controls; do not turn empty output
tuples into seeds without that proof.

Verification on the final source state:
- `.cache/caller-entry-scoped-check-files.log`: 335 tests pass in 26.60s;
  scoped Ruff/MyPy/type-doc, startup architecture and ownership checks pass.
- `callsite_summary.py`: separate MyPy and type/doc ratchets pass. Its existing
  whole-file complexity debt blocks the larger `check-files` selection; no
  suppression or threshold changes were made.
- Before-fix regressions: three inventory failures, two recursive-alias
  failures and one incomplete-range failure, retained in
  `.cache/caller-entry-{before,recursive-before,incomplete-before}.log`.
- `.cache/storage-entry-final.{json,txt}` and `storage-entry-final-functions`:
  20/20 validate, no timeouts, tracebacks or violations. All 20 exports remain
  byte-identical to the accepted `storage-caller-functions` checkpoint.
- `.cache/storage-entry-final-compilation.json`: zero errors and warnings.
  `storage-entry-final-behavior.log`: all 19 compiled behavior cases pass.
- `.cache/caller-entry-quality-fast.log`: exit 2 at existing global Ruff debt.
  The later sequential fast-test gate is not claimed run by this command.
- `.cache/storage-entry-test-pipeline.log`: all three default lanes pass, with
  zero failed, skipped or timed-out lanes. Pytest: 5,979 passes in 301.62s;
  four QuickC fixtures in 40.475s; seven MS C tiny round trips in 86.29s.
  The pytest command's wall time was 302.127s; total lane time was about 429s,
  plus the Make prerequisite checks (268 tests in 8.75s), not 301.62s total.
  Warnings examined: seven UEFI dependency deprecations and one existing
  multithreaded `fork()` deprecation in the Swaps pointer-output test. No warning
  was suppressed. These are separate from the zero-warning C compilation.

Updated one stale ownership-test expectation to retain two already-enrolled
tail-validation regression suites. The new entry-identity tests are enrolled in
both changed-file ownership and the default pipeline. The new production owner
is in the global typed/Ruff Make inventories and both recovery/decompilation
cache source manifests.

This accepts the caller-identity and incomplete-range safety slice, not the
full original canonical-caller acceptance item: QuickSort still needs a proven
empty-output seed, and accepted-contract worker reconstruction remains open.
The goal and all remaining Step 10-12 requirements remain active.

Source checkpoint remains the dirty shared worktree based on
`37fc06c52925a335dac3597c6b5c5edb9e945a58`. Owner SHA-256 values:
- `frontend_caller_entry_identity.py`:
  `d95fe1f7ebfd1160bf9c11d1d0e13b654cc5c60f047e417d8c271fafff5b1da4`
- `frontend_direct_callsite_index.py`:
  `8851ed1890f3fa4de774021a09bd8e63c41f4aee7bcc5e25cf33e5a22608f7de`
- `frontend_caller_return_use_program.py`:
  `87cfe52735006e267d67369c714c653fa5ecd45bb9f5a8109885fb28050bccc3`
- `lowering/callee_range_callsite_facts.py`:
  `6c880bf7e2eb0ac6cd894f98fde1b7e0985df32291be982b71078926ea0c5499`
- `callsite_summary.py`:
  `7cd45eb6b30feaf7276f7735619fea6c61f9cdef0b1725cd4182abe87eaa68ce`

## Explicit Discarded-Return Proof (September 20)

Observed execution window: 03:38:46-04:06:07 +02:00, 27m21s including gate
waiting; active coding and waiting were not separately metered.

Types/Lowering retains classified discarded-return observations through
collection, SCC solving and atomic publication. Empty recursive output requires
a complete exact caller census and a proven external discarded result. Unknown,
contradictory, mismatched and internal-only evidence refuses. Corrupt publication
fails before replacing an accepted payload.

The isolated QuickSort probe publishes an accepted contract with five input and
five return facts, clean validation and a passing compiled-C behavior harness.
Normal-worker observation still shows Swaps and QuickSort refusing: the codec
reconstructs caller facts with `caller_function=None`, and isolated projects
cannot resolve external caller SSA. Frontend-owned boundary transport is next;
the parity audit owns its reason, DoD and failure criteria.

Verified artifacts:
- `.cache/discard-return-check-files.log`: 218 tests in 24.91s, scoped Ruff,
  MyPy, type/doc, architecture and ownership pass. Separate solver/collector
  MyPy and type/doc checks pass; existing complexity debt remains unsuppressed.
- `.cache/storage-discard.json`: 20/20 validate; exports byte-identical to
  `storage-entry-final-functions`. Compilation: zero errors/warnings. All 19
  generated behavior cases pass.
- `.cache/storage-discard-test-pipeline.log`: 5,996 pytest passes in 288.38s.
  Summary confirms all three lanes passed: unit wall 288.948s, four QuickC
  fixtures in 32.929s, seven MS C round trips in 86.273s. Lane wall total
  408.15s excludes Make prerequisites; zero failed/skipped/timed-out lanes.
- `quality-fast` remains blocked by existing global Ruff debt. Its later
  sequential test command is not claimed executed. Dependency warnings remain
  visible and are not generated-C warnings.

This accepts the discard-proof slice, not Task 7.2 or Steps 10-12.

## Caller Boundaries In Normal Workers (September 20)

Observed start/end: 04:16:58-04:43:03 +02:00, elapsed 26m05s including gates.
Active coding and gate waiting were not separately metered.

Frontend block witnesses now preserve caller entry, actual executable extents
and byte identity across JSON. Destination restoration verifies mapped bytes,
closed reachability and absence of unwitnessed executable gaps. The callsite
codec binds only matching caller/callsite identities; missing proof remains
unknown. Worker schema is 8; program-callsite cache schema is 3. Existing source
manifests already include the new owner, verified by a cache-identity regression.

Semantics consumes restored successor edges through a focused adapter to the
existing terminal-path proof. The solver, return effects and instruction
interpretation are unchanged. Unknown inputs and post-call AX changes still
refuse. New non-test owners have explicit types/docs and default-gate enrollment.

Actual normal-worker observations, with fresh result-cache namespace and
`worker_evidence=true`, now prove accepted and unchanged accepted publication:
- QuickSort: five input and five return facts; no failures.
- Swaps: nine input and 27 return/memory facts; no failures.
Artifacts: `.cache/storage-boundary-final-probe/*.jsonl`,
`.cache/storage-boundary-final.{c,log}`. All 20 functions validate in that run.

The first trial was stopped after detecting an invalid producer witness for
unreachable catalog callsites. Producer membership validation fixes this while
retaining strict decoder rejection. The second trial exposed the graph-only
terminal-path adapter. Positive and AX-clobber refusal regressions precede its
fix. Before-fix logs: `boundary-codec-before.log`, `boundary-return-before.log`.
The initial standalone witness test also failed before its module existed.

Current verification:
- `.cache/boundary-final-check-files.log`: 100 tests in 20.40s; scoped Ruff,
  MyPy, type/doc, architecture, ownership pass. The boundary suite itself passes
  24 cases including fresh-project SSA and terminal semantics.
- Standalone MyPy/type-doc checks pass for touched legacy semantic/schema owners.
  Existing global Ruff debt still blocks `quality-fast`; the old terminal-path
  functions retain pre-existing complexity 12/25. No suppression was introduced.
- `.cache/storage-boundary.json`: 20/20 validate, zero timeouts/tracebacks.
- `.cache/storage-boundary-compilation.json`: zero errors and warnings.
- `.cache/storage-boundary-behavior.log`: 19 compiled behavior cases pass.
- Only QuickSort differs from `storage-discard-functions`: redundant signed
  casts removed and unsigned index casts placed explicitly; no calls or CFG
  operations change. The other 19 function exports are byte-identical.

An optional raw-transcript harness invocation failed on duplicate runtime union
declarations: normalized stdout already defines these types, and the harness
forcibly includes another runtime header. Subsequent source inspection corrected
the initial incomplete diagnosis that extraction alone removed a header guard.
This is separate tooling debt, not a passed check; acceptance above uses the
established per-function export path. The parity audit records the exact owner.

Final default pipeline (`storage-boundary-test-pipeline.log`): exit zero, all
three lanes pass, zero failed/skipped/timed-out lanes. Pytest: 6,020 passes in
305.26s (lane wall 305.762s); QuickC: four fixtures in 41.831s; MS C: all seven
compile/decompile/recompile/behavior round trips in 86.934s. Lane wall total
434.527s excludes Make prerequisite checks (268 tests in 9.98s). Eight unit
warnings were examined: seven UEFI dependency warnings and one existing
multithreaded-fork deprecation, none suppressed. This is the default curated
pipeline, not a claim about every pytest in the repository.

`quality-fast`, `quality-hard` and `quality-dev` were attempted and remain
blocked by existing global lint debt. Their later sequential test prerequisites
are not claimed run. Changed-surface check-files and separate legacy-owner
typing/docs passed as recorded above. Frozen owner hashes were rechecked after
the gates and did not change.

The isolated acceptance image exactly matches SORTD's MZ executable bytes;
the checked-in SORTD.EXE additionally contains one trailing newline. Thus the
normal-worker and isolated-export runs cover the same executable code.

Remaining: fallback caller-range summed-size audit and all other original
Steps 10-12 obligations. Source graph MCP was unavailable; bounded direct reads
and executable evidence were used instead. No full-step completion is claimed.

Owner SHA-256 at the frozen acceptance checkpoint:
- `frontend_boundary_transport.py`:
  `ef78a894796a5f10d421b3b32c87b759df460589d737058ebf757bdc316b2153`
- `semantics/terminal_boundary_paths.py`:
  `dd344ba01959844afc877309d0b3f6b47e61d0ffba13bb87c82decc0143ca7f3`
- `lowering/callee_callsite_codec.py`:
  `6debb20e2636980c86cc4c98830b7181b8023cab44d39ec621937c496abc337b`
- `semantics/terminal_call_paths.py`:
  `c0cf4c3581f9e6bb5492fee35d2c670136f58c75bba58dc2c9d4e05eeb807ff6`

## Proven Caller-Range Fallback (September 20)

Observed start/end: 04:43:58-04:56:37 +02:00, elapsed 12m39s including gates.
Active work and gate waiting were not separately metered.

Reason: the fallback catalog scan treated angr's sum of block byte counts as a
contiguous extent. Discontiguous functions could be truncated, while metadata
without any blocks could invent a range. The collector now consumes the shared
Frontend boundary witness introduced above. Explicit caller ranges are retained;
unavailable fallback proof does not remove existing catalog call facts.

DoD: discontiguous extents come from actual closed binary reachability, unknown
boundaries remain unavailable, explicit ranges survive unchanged, typed/doc/lint
and routine ownership checks pass, and the bounded SORTD/default gates regress
neither behavior nor output. Failure: guessed `addr + size` ranges, lost existing
call facts, or a semantic/compilation/behavior regression.

Before-fix evidence: `.cache/caller-range-before.log` has two expected failures
and 25 passes. After-fix `.cache/caller-range-check-files.log` has 103 passes in
19.50s, plus scoped Ruff/MyPy/type-doc/architecture/ownership gates. The changed
collector is smaller and its protocol no longer exposes the misleading size.

Whole-binary evidence: `.cache/caller-range.json` reports 20/20 validation with
zero timeouts, tracebacks or violations. Every export is byte-identical to
`storage-boundary-functions`. Compilation has zero errors/warnings, and all
19 compiled behavior cases pass. Reports/logs share the `caller-range` prefix.
`quality-fast` was attempted and remains blocked by existing global lint debt.

Frozen collector SHA-256:
`3ee98f11f9d0d13c597f66d6fb43f45861dd2ef7a904d931fc58a31bda9462ee`.
This hash was rechecked after compilation and during the frozen pipeline run.

Final default pipeline (`caller-range-test-pipeline.log`): exit zero; all three
lanes pass, with zero failed/skipped/timed-out lanes. Pytest: 6,023 passes in
303.92s (lane wall 304.415s); four QuickC fixtures in 32.962s; all seven MS C
round trips in 86.933s. Lane wall total is 424.310s, excluding the 268 Make
prerequisite tests in 12.79s. The seven unit warnings are existing UEFI dependency
deprecations, examined and not suppressed. This is the curated default pipeline,
not the entire repository pytest inventory.

This closes a boundary-discovery defect, not the remaining Task 5/7 or Step 10
obligations. The next bounded widening probe is specified in the parity audit.
