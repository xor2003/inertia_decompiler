# Focused DOS Compiler Coverage

Status: implementation required, not complete. Priority: stability, correctness,
then remaining Ghidra/Reko parity (low priority, retained in the previous plan).
Deliver a working framework, not another inventory-only report.

## Objective And Limits

Stable, correct decompilation of non-library application functions in unpacked
16-bit real-mode DOS games compiled from C, without requiring source/debug hints.
Signature-matched library bodies and unpacking are excluded; library-call ABI,
arguments, results and effects remain required. Do not silently exclude unmatched
functions. C long arithmetic compiled into 16-bit sequences is in scope.

Defer primary handwritten-assembly workloads, comprehensive mixed/32-bit real-mode
support and 387 FPU. Preserve existing support. Protected-mode/DPMI and Windows
need a separate scope decision. No exhaustive-all-C or entire-game-porting claim.

### Bounded Memory Models

Required models for this plan: **small and large only**. Establish the first
four-case slice in small; add a targeted large-model subset within the same
32-64-case budget, not a duplicate of every small-model test. Small covers near
code/data defaults; large covers far code/data defaults. Large witnesses must
exercise far calls, far data access, pointer arguments/results and segment
preservation through the complete round trip.

Tiny, medium, compact and huge are deferred. Do not claim mixed-default model
coverage or huge-pointer normalization from small/large results. C long arithmetic
remains required and is unrelated to the choice of memory model.

## Shortest Execution Path

Finish the current small repair at a recorded checkpoint, then implement one
vertical slice using existing infrastructure. Do not make fixing every known
corpus failure a prerequisite for building the framework that will expose them.
Keep those failures tracked; never replace a failing admitted case with an easier
one. One active implementation slice; no parallel framework rewrite.

Operate as an automated batch/fix loop: the framework selects and runs bounded
batches, preserves full artifacts and emits concise failures and uncovered
obligations. The agent investigates failures, fixes their owning layers and
reruns affected cases before the next batch. Do not manually inspect every
passing case or repeatedly re-plan the pipeline. Feature-witness admission still
requires evidence; a passing round trip alone cannot silently grant coverage.

The existing tiny MS C examples remain the foundation. Extend their fixtures and
shared runner rather than create a competing corpus or run identical round trips
twice in the routine pipeline. Removing unfocused old tests is low priority and
requires evidence of supersession, duplication or an obsolete requirement.

### 1. Reuse One Existing Round Trip

Reason: establish useful execution before spending time on schema or generators.
Inspect `scripts/build_msc6_examples.py`, `scripts/test_pipeline.py`, `examples/`
and their tests once. Reuse existing MS C/kvikdos build/run/decompile/recompile
owners and result contracts. Start with installed MS C 6 and one verified model.

DoD: one existing linked-EXE fixture runs through the adapter; original and
recompiled behavior match, tail validation passes, and timings/artifacts remain
available. Document reused entrypoints and missing capabilities in this file.
Failure: a second orchestration stack, source-assisted semantic recovery, or
counting compilation alone as correctness. COD objects are diagnostic inputs,
not substitutes for linked executable acceptance.

### 2. Freeze A Minimal Manifest And Oracle

Reason: make failures reproducible and coverage honest with minimal new code.
Use a typed/versioned manifest and structured stage results, extending existing
contracts where possible. First admit four existing or tiny cases: arithmetic
boundaries, array/alias writes, branch/loop behavior, and nested call arguments.
Freeze exact compiler settings and obligation IDs; new cases must fill a gap.

DoD: compare returns/exit codes, defined memory and relevant output/effects.
Normalize pointer observations; ignore uninitialized bytes and padding. Original
binary behavior is the decompiler oracle; source expectations separately check
compiler/harness behavior. Mutated return, memory-write and branch controls fail.
Tests cover invalid manifests, stage failure, timeout and deterministic replay.
Record versions/options/model, source/input hashes, observations and timings.
Failure: undefined/unspecified behavior masquerading as a decompiler bug, host
integer semantics substituted for DOS semantics, or unknown/timeouts marked pass.

### 3. Deliver The Routine Make Target Early

Reason: get daily regression value before broad combinations or random search.
Wire the four-case slice into Make and the existing pipeline. Allow selection by
case/obligation and rerunning failed cases. Keep raw logs/artifacts on disk and
one structured summary; no new dashboard, database or reporting service.

DoD: selected/all-admitted commands work; failures return nonzero; reports separate
not-attempted, excluded, compiler/harness failure, crash/timeout, validation,
generated-C compilation and behavior failures. Passing witnesses alone count
toward coverage. Measure incremental routine runtime; target <=60 seconds on the
recorded configuration. All four admitted cases and negative controls pass.
Failure: hiding failures with skips, weakening deadlines/oracles for speed, or
calling this four-case slice full compiler/decompiler coverage.

### 4. Expand By Missing Interactions, Not File Count

Reason: gain coverage per execution rather than multiply every option blindly.
Map existing fixtures first. Add small parameterized C templates only for gaps:

| Groups | Required inventory |
| --- | --- |
| Values | Arithmetic, comparisons, conversions, multiword C long |
| Storage | Arrays, pointer aliasing, structures, admitted bitfields/unions |
| Calls | Direct, indirect, near/far pointer arguments/results, nested/variadic |
| Flow/state | Branches, loops, switches, globals, values live across calls |
| Boundaries | Matched library calls, pointer/model/ABI and alias/loop interactions |

The explicit variation inventory lives in `examples/compiler_coverage/pilot.json`.
Enums distinguish numbering, representation and use sites; pointers distinguish
address spaces, indirection, qualifiers, aliasing, arithmetic and lifetime;
arrays distinguish element shape, dimensions, storage and access; structures
distinguish layout, nesting, copies and ABI transport; unions distinguish valid
member use from target-specific reinterpretation; bitfields distinguish widths,
allocation, signedness and neighbor-preserving updates. Target-specific or
extension cases require a compiler probe before admission. Do not generate
undefined behavior such as out-of-bounds access, dangling dereferences or
cross-object pointer subtraction as ordinary correctness cases.

These listed variations are inventory, not a promise that the first four cases
cover them. Freeze named interactions per group before admitting new witnesses;
do not take the full Cartesian product of every variation and compiler setting.

Reuse `deep/` as an existing compiler-option variation corpus: the user retained
listings that differed for its input sources. It is not a complete C syntax or
semantic-feature corpus. Options producing identical code for one source may
produce different code for another; do not infer global option equivalence or
discard configurations on that basis. Preserve option order and distinguish
listing-only differences from actual code-generation differences.

Track language-feature coverage separately from compiler-configuration coverage.
Map existing sources to explicit obligations, then add small fixtures for missing
constructs and their defined behavior. Exercise representative configurations per
feature, adding targeted combinations for ABI, layout and optimization risks.
Syntax present in source is only a candidate: an optimized-away construct is not
a binary witness. COD/object listings help select and diagnose cases; linked-EXE
round trips remain the acceptance test. Neither all syntax nor all combinations
are claimed covered by the bounded pilot.

Use 1-3 functions under test, small arrays and bounded loops. Reuse one binary
for multiple deterministic boundary inputs. Do not make everything volatile.
Use an existing constrained covering-array tool only once actual factors exist;
no solver implementation. Cover valid pairs within declared factor groups and
named risky triples; do not claim global pair coverage from local groups.

DoD: freeze a 32-64-case pilot budget and exact obligations before expansion.
Each obligation has a passing witness; inspect typed IR/CFG/effect evidence that
the compiler emitted the mechanism, rather than optimized it away. Report gaps
and exclusions. If obligations do not fit, explicitly revise scope/budget; do
not silently drop them. Near/far extensions and target-defined behavior are
documented separately from C89. Keep routine and release-lane coverage distinct.
Failure: duplicate examples without new obligations, text matching as semantic
proof, unsupported compiler flags, or expanding the acceptance set mid-repair.

### 5. Plug In Csmith, Keep Exploration Bounded

Reason: find unexpected interactions after the runner/oracle already work.
Use the user's [MS-DOS branch](https://github.com/xor2003/csmith/tree/ms-c-dos),
not upstream/default-branch Csmith or a new port. Initial pinned revision:
`35e702de01e158bc948a2024d0e187c1803d1ebb` (verified remote branch tip).
First integrate one fixed seed through the same adapter, then at most
16 candidate seeds per ten-minute exploration run with bounded program sizes.
Add a separate Make target; generated cases do not automatically enter pytest.

DoD: pin generator revision/build/options; retain integer seed, generated C and
hash, compiler configuration, inputs and failures. Repeating the same environment
reproduces the source and result. A seed alone is not durable across upgrades.
Capture generator stdout with identical options: `--output` embeds its path in
the generated comment and changes raw source hashes across artifact directories.
Initial local seed-1 stdout replay was byte-identical; its function has no
observable global effects, so it is not an adequate behavioral coverage witness.
The original local executable reported an older embedded Git version than the
checkout. A fresh isolated build now reports `35e702d`; see the ledger below.
Minimize failures manually first into owner-layer regressions, preserving defined
behavior and failure class; retain unreduced failures explicitly. Integrate an
existing automatic reducer only if repeated reduction becomes a measured cost.
Failure: an endless mandatory seed campaign, discarded flaky failures, budget
expiry counted as success, or minimized tests that no longer exercise the defect.

## Time And Token Discipline

- Optimize total completion/debugging tokens, not code size alone. Expand shared
  tooling when it replaces repeated inspection or manual work; avoid speculative
  abstractions. Compact failure evidence and exact reruns are useful investments.
- Reuse graph/source findings and existing test helpers; do not repeatedly audit
  the entire repo. Keep a short entrypoint/result ledger here, not new reports.
- Default to one agent. Delegate only an independent bounded task with clear
  ownership and expected time savings; never duplicate the active investigation.
- Run focused tests first; broad required gates at semantic checkpoints, not
  after every edit. Reuse evidence only when its source/configuration is unchanged.
- Use `PYTHON_JIT=1`, pytest `-n 3 --tb=short --durations=10`, and scoped
  `ruff check --fix`; mandatory types/docs and project acceptance rules still apply.
- Do not overlap broad gates. Bound workers by observed memory/CPU use; three
  pytest workers do not authorize three independent full decompiler pools.
- Cache immutable build inputs/results by complete source/tool/configuration
  identity using existing caches. Do not add a new cache before measuring need.
- Report counts, failure IDs, changed coverage and timing. Read only the relevant
  failed-stage excerpt; retain full logs without flooding the conversation.
- On failure, reduce/reproduce one defect family, fix at its earliest correct
  layer, then rerun its case and neighboring obligations. No speculative cleanup.

## Completion Boundary

Steps 1-3 deliver the first usable framework; they do not close this plan.
The pilot is complete only when Steps 1-5 and the frozen coverage obligations
pass, including negative controls and existing required project gates. Further
MS C 5, other models/flags or game-corpus expansions are separate milestones. Existing
unresolved issues and deferred parity remain visible, not silently declared done.

## Implementation Ledger

- Runtime near-input representation checkpoint (2026-09-30): compiled
  portable controls reproduced4 failures/2passes7.85s: a runtime offset0 or
  65536 became DS:0 rather than near null. Lowering now emits owned
  `NEAR_ARG_PTR`, with one evaluation and uint16 narrowing of each argument.
  The runtime header owns native DOS versus portable guest-view representation;
  neither conversion proves pointer classification or selector equality.
  A retained enum-tagged conversion is not wrapped again; a matching name alone
  does not suppress conversion. Portable/header cohort45pass11.56s, scoped
  gate51pass20.67s, final focused callers/value cohort21pass11.27s; configured
  Pyright0errors. MS C6/KVM native offset/null/wrap/evaluation control1pass7.18s.
  The required default pipeline's main lane ended8694pass/20fail754.54s;
  remaining lanes are still running. The TIDShowRange oracle family cannot
  initialize ASan under the launcher's4GiB virtual-address cap (shadow mapping
  needs approximately15TiB). The exact Unicorn word-conditional control also
  crashed a worker in the capped launch; xdist then deadlocked with controller
  waiting for events and all3 survivors waiting for scheduling input, confirmed
  by live py-spy stacks. The owned controller was interrupted via verified
  pidfd, preserving166pass/1worker-crash and incomplete status. Normal Codex
  confinement with unlimited RLIMIT_AS reran the10 ASan controls and exact
  Unicorn case:11pass13.34s, without weakening either oracle or the Devin
  launcher boundary. Do not use the Devin-specific4GiB launcher for ASan gates.
  Other failures still
  require focused baseline classification. No broad-gate or pointer-function
  acceptance is inferred from these focused results. Atomic callee/body/caller
  publication and admitted-case rebuilt behavior remain open.

- Accepted-slot/word bridge (2026-09-30): new nonpublishing
  `storage_word_input_binding` checks the exact ordered two-byte input envelope
  and consumes `ModularArgumentTypeFacts8616` for the callee's own proven word
  address. It never relabels census pieces or grants pointer representation.
  Gap, reversal, overlap, cross-segment, wrong-role/width, missing SSA and stale
  receipt controls are enrolled in the routine pipeline. An isolated unchecked
  envelope oracle produces7fail/1pass11.39s with3workers, without shared-source
  edits. Scoped gate25pass
  18.33s and configured Pyright0errors cover this bridge and body preflight.
  The body census now traverses exact owned `CGPWordAssignment8616` and
  `CSemanticCast8616` canonical fields; plugin subclasses still refuse. Before
  that change, the two owned-node controls failed and the subclass control
  passed. Fresh-cache KVM diagnostics independently bound both real POINT
  input words and return congruence; the scalar function retained clean tail
  validation. Native representation, complete caller join and atomic
  publication remain required. Dummy selectors in body diagnostics test AST
  closure only and provide no segment evidence.

- Near-call stack-input/result-selector checkpoint (2026-09-30): new
  nonpublishing lowering receipts bind the exact caller dereference selector
  to callee-entry DS, and join SSA-proven SS:BP address-of pushes to that same
  DS value. They replay registered caller SSA, exact CALL/push coordinates,
  contiguous source-byte slices, complete preservation and retained invocation
  context; no global small-model DS==SS assumption. Result-use cohort10pass,
  stack-input cohort8pass plus scoped gates/Pyright0errors. Combined result-use,
  stack-input and routine-pipeline enrollment checks74pass9.81s. A deliberately
  unchecked selector assumption fails the unequal-segment binary control
  (1fail/6pass15.43s). Real POINT both select_word calls bind the same SS:BP-20
  source address and complete result uses (SS and DS), independently of source
  and optional catalogs. This is selector/offset evidence, not native C-pointer
  representation, atomic prototype/body publication or DOS round-trip success.
  Parent review now accepted detached AST construction, split into owned
  near_return_expression/near_return_selector with construction/replay tests.
  Original5, further3 and literal-rendering1 corruption controls reproduced red
  before correction; final57 focused tests and scoped gates pass. Combined
  candidate/selector/input/pipeline-enrollment cohort131pass28.59s. This does
  not authorize body/prototype publication or complete this admitted case.

- Direct-call segment proof guard (2026-09-29): the nonpublishing DS=SS CALL
  candidate now requires closed counters, exact SS-save/DS-restore roles and
  ordered in-block addresses before its retained result reports `complete`.
  The producer checks that invariant before returning PROVEN and diagnostics
  expose the same verdict. A new focused regression failed before the change;
  the final three-worker direct-call cohort passes 42 tests and `make
  check-files` passes. The guard does not prove callee entry state, intervening
  CALL preservation, input pointer segment/pointee, or `select_word` output.
  `/dev/kvm` is absent in this session, so no new DOS round trip is claimed.
  `quality-dev` first stopped on an unwritable host `/tmp`; with workspace
  `TMPDIR`, static checks and 296 contract tests passed but the fast pipeline
  ended red (8,157 passed, 31 failed, one skipped). Failures include missing
  KVM, a source-drift guard and unresolved semantic cases; no broad acceptance
  follows from the focused proof gate.
- Source-free COD oracle checkpoint (2026-09-29): the routine gate expected
  `_dos_setProcessId(unsigned short pid)` from COD source annotation although
  its machine body never reads BP+4 and the fixture has no observed caller.
  The focused regression reproduced that unsupported expectation; it now
  requires the empty signature and keeps the raw-stack-parameter/empty-body
  checks. Two focused cases pass with three pytest workers; no generated-C,
  pointer-witness, or full-gate acceptance follows from this test correction.
- Current gate and pointer replay (2026-09-29): the prior three-worker
  `quality-dev` ended red with 8,174 passes and nine failures. One failure was
  the default binary lane's outdated exact test inventory; the newly added
  two-call continuation test remains admitted, and its inventory control now
  passes. Another failure was an ASan host-loader conflict: `/etc/ld.so.preload`
  injects AppProtection ahead of ASan, making all nine corruption controls
  spuriously pass. The test oracle now runs its sanitized executable with that
  host preload hidden inside a read-only Bubblewrap mount and requires its own
  `Tscale=` diagnostic for each corruption. The two corrected test files and
  related pipeline tests pass 66 focused checks with three workers; no broad
  gate rerun or other seven-failure resolution is inferred.
  A source-stable, KVM-backed fresh `array_pointer_writes` run remains
  `validation_failed` after 62.36 seconds. All five selected source-free
  function jobs returned zero and `select_word` passed tail validation, but
  the emitted `unsigned short * sub_100f1(void* arg_4, unsigned short arg_6)`
  returns `(arg_6 << 1) + arg_4`. MS C 5.1 rejects arithmetic on the unsized
  `void*` at C2147. Exact binary code is AX=[BP+4]+([BP+6]<<1), with two caller
  dereferences; result pointee width alone has not proven the input's segment,
  pointee type, or safe C pointer arithmetic. Current source has no production
  consumer of either `collect_near_scaled_return_candidate_8616` or
  `bind_near_return_offset_c_ast_8616`; they remain nonpublishing probes. Next
  semantic slice must bind
  the existing near scaled-return IR and C-operand congruence to that exact
  caller result-use proof, then publish coherent input/body/return/caller
  types atomically or refuse. No cast or harness repair is accepted.
  Evidence: `.cache/compiler-coverage/pointer-current-20260929-1651/`.
- Caller BP transport checkpoint (2026-09-29): reviewed IR reaching-definition
  transport and full Analysis predecessor census are integrated after the
  neighboring gate ends red (8008pass/23fail/1skip). Exact CALL preservation,
  widths, register overlap, entry origin and consumed sites remain mandatory;
  no pointer or ABI recovery moves to Rewrite. Reviewed bytes match live owners.
  Normal shared-tree cohort62passes/7warnings59.83s; scoped Ruff, strict MyPy
  including the actual scalar contract, configured Pyright and startup/context/
  ownership pass. Devin's15line registration delta is parent-reviewed; one
  scalar-consumer ownership line is added, preserving concurrent registrations.
  Ordinary quality-dev starts11:14:27UTC with KVM API12/unlimited parent VAS;
  static/startup and296 preliminary contracts pass. User reduces pytest to
  three workers; parent orderly interrupts its seven-worker controller, leaving
  partial156passes/7warnings and terminal2 at11:47:29UTC (1983.44s wall).
  Source also changed; this interrupted run is not acceptance. Preserve its
  artifacts and restart with three workers under new output names.
  The real caller still lacks proven BP-preserving CALL effects. Restoring BP
  from a saved word is not alone whole-callee proof, especially across unknown
  writes or SS changes. No function fix, linked witness or plan admission.
  Artifacts: .cache/devin-reports/frame-register-livein-20260929/.
- SS-selector restore safety (2026-09-29): parent reviews the bounded test-only
  Devin timeout and integrates Alias invalidation for explicit SS-register
  writes, also with unknown instruction addresses. Captured values and fresh
  same-selector saves remain valid; old storage cannot cross a selector change.
  Final normal-source red4fail/5pass and green175pass/3warnings28.79s use the
  user-selected three pytest workers. Scoped static/ownership checks pass and
  the regression is routine-enrolled. Make/pipeline/partition test defaults
  now use three independently of compiler/linter pools. Broad gates, actual
  CALL BP preservation, linked witnesses and Steps1-5 remain unaccepted.
- Next ordinary quality-dev uses new shared-quality-dev-three artifacts; the
  interrupted seven-worker logs/results are preserved. No partial run or
  changed-source result may close plan acceptance.
  It starts11:59:25UTC, three pytest workers, char10:232/API12 and unlimited
  parent VAS; the final source-stable result is terminal2 at13:13:17UTC:
  9failed/8109passed/63warnings2071.36s in the main unit lane, after296
  preliminary passes40.72s. Total4433.35s includes waiting for the pipeline
  lock. Default/external lanes were not reached. The unchanged implementation
  fingerprint is abe93ba81f69af41c6e73bd8cdb9f309528d73ef1071d979bea0e6a96fac317a.
  Failures cover DOS signature/argument recovery, three SORTD obligations,
  a stale SS-copy control, incidental InBox argument names and two CLI timeouts.
  This is not a green broad gate. A fresh storage_classes retry is
  build_failed with unchanged implementation/environment because its DOS child
  cannot find `/dev/kvm`; a scoped launcher retry fails at device stat. Fresh
  native exit7 probes succeeded in other launch boundaries but are not a
  compiler roundtrip or plan admission.
- Native launch and diagnostic checkpoint (2026-09-29): paired probes show
  `/dev/kvm` present for direct commands but absent with shell log redirection.
  Logs opened inside the runner retain the exact verified rootRO/repoRW,
  private-device, char10:232/API12 and4GiB boundary; no sandbox is relaxed.
  Direct storage_classes builds and runs (original exit255), then fails the
  source-prefix guard after26.97s. PREFIX_UNSUPPORTED is retained: source global
  declarations cannot seed binary-only recovery. Direct simple_control builds
  and runs but reaches its600s outer deadline (601.58s); all three initial
  function jobs time out and tail validation stays uncollected. Neither case
  is admitted or replaced. One classify diagnostic retains the original60s
  analysis deadline and unchanged source/binary identity: in-process hooks
  observe actual analysis, CLI exits0, tail validation passes and decompilation
  takes44.84s (97.89s whole diagnostic). Force-thread diagnostics are not the
  default fork lane, a controlled speedup baseline or a linked roundtrip.
  Artifacts: .cache/compiler-coverage/{storage-classes-three-kvm-direct-20260929-1212,
  simple-control-three-kvm-direct-20260929-1221,
  classify-timeout-profile-20260929}/.
- Nonpublishing leaf-BP provenance checkpoint (2026-09-29): an independently
  corrupted retained restore fact incorrectly passed the prototype's complete
  predicate. Fresh Alias recomputation rejects it while retaining the valid
  control; scoped Ruff/strict MyPy/Pyright pass. All19 snapshot controls now
  pass/3warnings10.40s with three pytest workers. An initial harness import
  failed because the outer live-package shim took precedence; the corrected
  clean child retains all seven snapshot-origin assertions. Source and test
  bytes remain unchanged across the successful run. No production owner or
  CALL flag changes.
  Parent reviews Devin60502's SS-local-store proposal, but does not accept its
  sufficiency claim: address wrapping, actual write widths and per-site must
  coordinates still need proof. Five real callees remain refused; all function,
  default-lane, linked, pilot and required gate obligations remain open.
- SS control correction and diagnostic review (2026-09-29): the broad test's
  PUSH SS / MOV SS / POP DS sequence cannot keep an Alias copy across the
  selector change. Parent retains the production refusal and strengthens the
  stale control to three actual binary sequences: post-change POP, an unproven
  GPR bridge, and a pre-change captured POP. Typed ALIAS_SOURCE_MISSING and
  SS_WRITE_AFTER_SAVE remain explicit. Focused red1fail precedes3passes; the
  final live SS/provenance family passes50tests/3warnings17.38s, three workers,
  source/test identity unchanged. This does not clear the other eight failures.
  A default-fork classify diagnostic exits0/tail-passed19.49s decompilation/
  50.18s whole; generated C matches the earlier thread diagnostic exactly.
  Sequential timing/cache/contention differences do not establish a speedup.
  Parent-reviewed worker instrumentation observes121scalar-index builds
  (1.506s inclusive) and9stack-word transfer builders(0.597s inclusive) during
  25.52s decompilation. Nested times must not be added; local index reuse is
  not the dominant timeout bottleneck and no optimization patch is accepted.
  The retained whole simple_control case remains timed_out, not replaced by
  the successful single-function diagnostics. Artifact families:
  .cache/compiler-coverage/{pytest-checkpoints,classify-default-lane-20260929,
  classify-index-parent-20260929}/ and the reviewed measurement handoff under
  .cache/devin-reports/classify-index-measurement-20260929/.
- Fresh normal native checkpoint (2026-09-29): the unchanged simple_control
  case now passes the full adapter in27.43s, original/recompiled exit255,
  three source-free numeric jobs and clean tail reports. Source/environment
  fingerprints remain unchanged and SIMPLE.EXE is byte-identical to the earlier
  timed-out fixture. This is a warm run: classify and sum_to use validated
  request/function caches, while switch_fold analyzes live. All original value
  call sites survive in the rebuilt harness. It is not cold timing, controlled
  speedup, automatic obligation admission or a green four-case/global suite.
  Artifact: .cache/compiler-coverage/simple-control-native-final-20260929-1501/.
- Three-worker follow-up: compiler-coverage-contracts had one missed literal-n7.
  Parent adds the target to the existing concurrency regression, reproduces
  the direct test-helper failure against Make's dry-run, then switches the recipe
  to the shared PYTEST_WORKERS setting. Six direct Make controls pass; they do
  not create pytest pools. Serialized focused pytest now passes36tests/3warnings
  in19.86s with3workers and unchanged source/tests; the saved InBox baseline
  reproduces its incidental-name failure after tail/compiled checks pass.
  Test-only InBox Devin1281 expires124/360.54s without completed green/report.
  Parent independently reviews its positional C-AST oracle, retains all compiled
  behavior/tail checks, and adds4positive/11negative durable controls because the
  exploratory worker script's prints did not make failures affect its exit code.
  Reports: pytest-checkpoints/{inbox-baseline-205i4_vs,oracles-omcykidn}/.
  This accepts the oracle and concurrency correction, not a new function fix.
- Measured CLI traversal checkpoint (2026-09-29): class-layout caching and
  direct-child traversal preserve current instance children and consumer-specific
  exclusions.54focused tests pass with3workers; saved-baseline controls fail for
  the intended cache/fast-path/loud-error changes. Four balanced strict numeric
  runs produce identical C and tail-passed results; mean analysis CPU is14.2%
  lower on one function. Variable startup/host load prevents a general wall-time
  speedup claim. Required quality-dev attempt and exact measurements live under
  .cache/devin-reports/cli-ast-traversal-20260929/; no global obligation admitted.
- User-supplied compiler implementation references (2026-09-29): verified read-only
  directories `/home/xor/inertia_player/dos_compilers/Microsoft C v8/BIN/rebuild/gen/`
  and `/home/xor/inertia_player/dos_compilers/Borland C++ v5.02/BC5/BIN/rebuild/gen/`.
  The former contains CL/frontends/C23216/C33216/LINK generated exports; the latter
  BCC, BCC_native, TDUMP and TLINK32. Inspected headers identify patched executable
  decompiler exports, with Windows/defs context and a Hex-Rays header for BCC.
  These may guide compiler-emission diagnostics, not substitute for original
  binary behavior/typed IR or become semantic hints required by the decompiler.
  External trees are not this graph project and remain unmodified. The frozen
  MS C6 small/large acceptance set is not expanded by recording these references.
- Bounded function dispatcher integration (2026-09-29): reviewed staged IPC,
  timeout, reap and descendant-cleanup behavior is integrated, with per-job
  ordered checkpoints and a one-to-four-worker CLI contract. MS C commands
  select at most four workers from the actual selected jobs; generic batches
  retain default one. Parent red controls expose complete-frame/nonexiting
  children and missing/invalid result collection; both fail closed after the
  correction. Staged35 checks and shared129 checks pass. New regressions enter
  routine pipeline, QA and ownership; staging-only scheduler skips are removed.
  Final scoped check-files passes366tests/63warnings227.07s, with startup,
  ownership, Ruff, MyPy and ratchets. Six production owners separately pass
  configured MyPy and Pyright. Normal four-worker KVM replay retains5ordered
  results in153.89s, with2CLI successes/3timeouts, source unchanged and sampled
  aggregate process-tree PSS1.35GiB/RSS1.70GiB. The serial replay records5results,
  one CLI success/4timeouts and548.30s, but Widening and ownership sources change
  during it; it is not a controlled speedup baseline. Retained shared caches
  are explicit, no cold-cache assertion. No linked roundtrip, function fix,
  full project gate or feature acceptance; fresh quality-dev is running with
  verified KVM and ordinary unlimited address-space limits.
  Full plan remains open. Artifacts:
  .cache/devin-reports/scheduler-frame-reap-20260929/.
- Logical PUSH transport integration (2026-09-29): after reviewing Devin's two
  test-only deltas at its600s timeout, the parent reproduced5red/22existing
  passes and implemented retained SSA roots with exact input bindings in an
  isolated dirty-source snapshot. Frozen final30tests pass55.74s; source/test
  Ruff, strictMyPy5modules and same-policy snapshot Pyright pass. Wrong scope,
  byte/push/use, incomplete and VEX identities refuse; DEFAULTED storage is not
  promoted, and multi-push roots cannot masquerade as a whole argument. Staged
  final30 focused plus69 neighboring tests pass in the isolated snapshot.
  After coordinator77507 terminates, the parent verifies all six saved dirty
  baselines and integrates all seven exact staged files, enrolling the new
  owner in normal lint/type, architecture and ownership gates. Shared changed-
  file checker59045 ends0:748passed/7warnings206.52s; scoped Ruff/MyPy/Pyright,
  startup/context/ownership and type/dot/doc ratchets pass. All reviewed bytes
  remain exact. The preceding checker94804's eight GNU Make stdin-oracle
  failures disappear with repository-local TMPDIR and no code/test changes;
  both logs remain retained. Native pointer publication remains open. Pre-change
  quality-dev ends7936passed/17failed (296contracts pass). Default pipeline
  ends2/3445.845s, with7937unit passes/16failures and49binary-relational
  passes/one failure; all four pipeline lanes fail. Source/test/config/runtime
  identities stay unchanged in both phases. No failures waived and no function,
  witness or plan acceptance claim. A95s staged real-binary observation yields
  no collected evidence and is retained as an observation timeout.
  Artifacts: .cache/devin-reports/whole-push-retention-20260929/ and
  .cache/devin-reports/rep-kernel-symbol-binding-20260929/.
- Ordinary REP wrapping checkpoint (2026-09-29): the unfiltered normal run now
  passes all seven ordinary kernels, including forward/backward effective-address
  wrapping. The host oracle binds only the sole compiled public symbol's spelling
  instead of assuming an optional function name; no C/assembly parsing, semantic
  name proof or body/signature change. Saved-dirty label/ambiguity controls fail2
  before; final9controls/Ruff/Pyright pass. Full REP file16passed/3failed91.85s:
  the original segment-straddle memory failures remain visible despite passed
  tail status, not accepted/excluded silently. Earlier timeouts are retained.
  Required final-source gates are starting sequentially with verified KVM.
  No function-fixed, global gate or compiler witness/pilot completion claim.
  Artifacts: .cache/devin-reports/rep-kernel-symbol-binding-20260929/.
- Loop-header liveness checkpoint (2026-09-29): typed FLAGS effects survive
  binary lifting/SSA but were omitted by two cleanup read censuses. The canonical
  structured syntax schema now supplies for-loop initializer/iterator reads;
  shared read/write variable occurrences remain distinct. Focused saved-dirty
  controls fail5/2 before; final135neighboring tests and six oracle controls pass.
  KVM-transported real cohort ends145passed/1timeout483.43s: forward F3/F2 stores
  and both zero-count directions pass tail/GCC/full-memory checks; ordinary
  backward and both added ordinary-wrap cases remain timeout/uncollected, not
  accepted in that cohort. No original case, deadline, oracle or refusal gate is
  removed. The bounded ordinary-backward retry passes1/7warnings146.86s including
  tail/GCC/full-memory; its original failure and both wrapping timeouts remain
  recorded. Required final-source gates remain open; another
  session's live broad gate is not an owned result. No compiler witness or
  function-fixed claim. Artifacts: .cache/devin-reports/rep-flags-header-20260929/.
- Current checkpoint (2026-09-28): the reviewed modular input join is integrated
  and routine-enrolled; focused shared checks115passed, scoped Ruff/strict MyPy/
  Pyright and startup/context/ownership/type ratchets pass. This proves callee-
  bound sign-insensitive word use, not pointer/return typing or feature coverage.
  KVM pointer replay `pointer-modular-input-20260928` still fails C2100/C2106 and
  has `implementation_unchanged=false`; retain it as diagnostic-only evidence.
  A source-stable current-publication diagnostic records four input collections
  closed at2/2/2/2/0, then four RETURN_EVIDENCE_UNAVAILABLE results. The producer
  gap is now corrected: optional signatures cannot truncate a closed binary
  caller body, while unproven/library neighbors remain bounded. Independent
  red controls and172focused checks pass; the real setup now records selected
  USED return evidence2/2/2/2/0 with unchanged sources. No pointer/function fix,
  feature admission or linked roundtrip is claimed.
  Four-function batch dispatch remains
  staged until parent IPC/lifecycle review and actual KVM measurements pass.
- Current stable replay (2026-09-29 local): private-cache/KVM pointer_memory
  runs at the unchanged600s/60s budgets and exits validation_failed after320.78s;
  implementation/environment unchanged, original DOS run255. The census repair
  now enables pointer return typing, but select_word emits scaled byte-offset
  arithmetic on a void-pointer input. MS C rejects C2147 (unknown size). Tail
  checks alone do not establish acceptance. The next repair is an evidence-bound
  Types/Lowering address-expression projection preserving modular16 and segmented
  identity, not a guessed input pointee, harness cast or rewrite-stage repair.
  Dispatcher budget tests are parent-reviewed red9fail/green12pass/Ruff0, still
  staged pending actual timing/memory and full semantic acceptance.
- Near-return bridge prerequisites (2026-09-29): the original modular affine
  Value and full caller pointer-use proof now survive their typed handoffs.
  Parent checks reject wrong AX roots, reversed input roles and foreign pointer
  witnesses; focused35/34 tests pass. The explicit runtime offset/byte-add
  primitive passes compiled host wrap/null/distinct-segment controls and a native
  MS C6/KVM offset test (30checks total), including deliberately wrong helpers.
  It is not yet connected to prototype/body publication: source-pointer binding,
  callee segment preservation and exact structured-return congruence must close
  first. No pointer_memory witness, function fix, full-gate or pilot acceptance.
  Devin's bounded proof task times out before a report; its exact delta is
  independently reviewed and strengthened against saved dirty sources.
- Step 1 partial: `scripts/compiler_coverage_runner.py` delegates to
  `scripts/build_msc6_examples.py`; it does not duplicate compilation logic.
  Retained `storage_classes` run: passed, 59.29 seconds, artifact directory
  `.cache/compiler-coverage/pilot-001/`. This is one existing round trip, not
  feature coverage or full Step 1 acceptance. Source/debug-independent
  semantic-path confirmation remains open.
- Installed compiler default verified by `examples/compiler_coverage/probes/model.c`
  through the unchanged build/run owner: small model (`M_I86SM`), 16-bit int,
  32-bit long, two-byte near data/function pointers, four-byte far pointers.
  `.cache/compiler-coverage/model-probe-001/report.json` records build/run success;
  decompilation was deliberately not attempted for this compiler probe. The
  runner now selects `/AS` or `/AL` explicitly for original, rebuilt and runtime
  support objects, with matching `SLIBCE.LIB`/`LLIBCE.LIB` linkage. The large
  compile/run probe also passes at `.cache/compiler-coverage/model-large-001/`.
  Adapter reports now fingerprint source, compiler tree, emulator, interpreter
  and runner. This is not yet a full decompiler/environment snapshot.
- Step 2 partial: typed manifest and fail-closed report classification exist.
  Manifest/result regression suite: 38 passed in 5.88 seconds with seven workers;
  scoped Ruff and manifest MyPy passed. Empty optional scope groups are valid;
  compiler flags retain their order and repetitions. Duplicate obligation IDs,
  conflicting statuses, missing candidate witnesses and unknown selections fail.
- Current four manifest entries are candidates, not accepted feature witnesses.
  `compare16` now exercises signed/unsigned comparison extrema and unsigned
  16-bit addition wraparound; its DOS round trip passed at
  `.cache/compiler-coverage/arithmetic-001/case-000/`.
  `function_pointers` now includes a three-argument call with a nested first
  argument. Original execution passes; rebuilt execution exits 5. Generated
  `nested_arguments` drops the second and third `combine_args` arguments while
  final tail status reports clean. Reproducer and failed artifacts remain at
  `.cache/compiler-coverage/nested-001/case-000/`. Fix call-argument ownership and
  validation at their semantic layers, not by rewriting output or weakening tests.
  Follow-up `.cache/compiler-coverage/nested-002/case-000/` passes after the
  callsite-summary scanner crosses proven inner caller cleanup. The fix requires
  zero callee cleanup and preserves outer push widths, sources and addresses.
  Focused callsite tests: 95 passed; broader acceptance and the independent
  tail-validation completeness gap remain open.
  Subsequent `make test-pipeline` passed all three lanes: 268 contract tests,
  6,322 routine pytest tests in 354.36 seconds, QuickC and all eight tiny MS C
  round trips (including the strengthened examples). The independent validation
  gap remains open. `quality-fast` still fails on global lint debt; new rerun
  helper complexity was corrected. Full log: `.cache/compiler-coverage-test-pipeline.log`.
  Partial-overlap round-trip evidence was added afterward; see the ledger below.
- Existing `pointer_memory` was strengthened in place with same-object aliasing,
  interior array writes with edge sentinels, zero-length writes and subrange/empty
  reads. Original and rebuilt harness observations are checked for agreement.
  Host negative controls reject lost writes, destructive same-pointer aliasing
  and zero-length writes; these controls test oracle strength, not DOS semantics.
  DOS round trip passed in 85.61 seconds at
  `.cache/compiler-coverage/pointer-expanded-001/case-000/`; this exceeds the
  incremental runtime target and is not evidence of partial-overlap coverage.
- Step 3 partial: `make compiler-coverage PYTHON=./.venv/bin/python` runs manifest
  candidates through the tiny-example runner. Optional `CASE` or `OBLIGATION`
  selects exact IDs; `COMPILER_COVERAGE_OUT` must name a fresh artifact directory.
  Unsupported compiler profiles are refused, not silently ignored. Summaries
  distinguish passing round trips from still-unverified feature coverage.
  `make compiler-coverage-contracts PYTHON=./.venv/bin/python`: 56 passed in
  2.08 seconds after extracting the pointer harness constant from the heavyweight
  build module. Framework tests are enrolled in the existing pipeline; a second
  duplicate live tiny-example lane is not added. New helper Ruff/MyPy pass;
  the legacy build module retains 12 Ruff complexity/Boolean-condition findings.
- Failed-case selection is available through `RERUN_FAILED=path/to/summary.json`.
  Reports bind to the manifest SHA-256; mismatches, unknown/duplicate cases and
  incomplete inventories fail before execution. Timeout tests cover finite
  deadlines, process-group exit races and failed launches. Current framework
  contracts: 64 passed in 3.38 seconds; the legacy harness tests separately had
  56 passes. Neither result means the live nested-call regression passes.
- Latest framework contracts, including fingerprint and compact diagnostic tests:
  72 passed in 3.01 seconds. Scoped new-code Ruff and MyPy pass.
- `make compiler-coverage-batch PYTHON=./.venv/bin/python` runs small and large
  batches, continues after a failed model and exits nonzero if either fails.
  For one model use `make compiler-coverage MODEL=small` or `MODEL=large`.
  Current large admission is a global/static-storage far-call witness; far pointer
  argument/result cases still need admission. Compiler probes pass for both.
  The initial large round trip fails validation for `_sum_globals`/`bump_static`
  (`.cache/compiler-coverage/large-001/`). No success or exclusion is inferred.
  Public batch command verified at `.cache/compiler-coverage/two-models-001/`:
  small completes all four candidates (three pass, overlap compilation fails);
  large executes after that failure and retains its global-call validation
  failure. Batch exits nonzero. Framework contracts: 74 passed; legacy harness
  and adapter selection tests: 77 passed; explicit model compile/link tests:
  two passed. Both model selections are runnable, not fully passing.
- The partial-overlap witness is now in `pointer_memory`: forward and backward
  overlapping ranges, with a deliberately reversed-order mutant rejected by
  the oracle. Initially original DOS execution passed, but generated C failed compilation
  because `SEG_U16(...) = value` is not an lvalue under the rebuild contract.
  Before artifacts: `.cache/compiler-coverage/overlap-001/`.
  Root cause was the rebuild harness omitting canonical segmented-memory macros,
  not an invalid store emitted by the decompiler. The harness now consumes
  Lowering's MS C runtime header and initializes segment state using DOS
  `segread`, without modifying generated function bodies. Host tests exercise
  both GP ABIs and distinct CS/DS/ES/SS values. Focused runtime/build/model tests:
  62 passed in 18.84 seconds; scoped runtime Ruff and runtime/build MyPy passed.
  Final DOS round trip passes at `.cache/compiler-coverage/overlap-003/`.
  This is behavioral evidence, not yet completed feature-witness admission.
  Broad pipeline evidence above predates these runtime/model changes.
- Large-model failures remain blocking: `_sum_globals` leaks flattened SS
  arithmetic; `bump_static` classifies GP stack-restore facts without
  materializing any. Fix their semantic owners, not the final-token guard or
  the strict materialization invariant. Logs remain under
  `.cache/compiler-coverage/large-001/case-000/DSTOR01.batch/`.
  Binary inspection also proves an unmodeled far stack probe: the linked helper
  pops CX and DX, allocates AX bytes, pushes DX/CX and executes RETF. Current
  `compiler_helpers.py` recognizes/hooks only the near POP-CX/JMP-CX variant.
  Extend binary-backed helper evidence and all consuming stack/call effects
  coherently; adding a far-helper name to the near model is not a valid fix.
  Current-tree replay at `.cache/compiler-coverage/large-002/` still fails
  decompilation after 111.52 seconds; original DOS build/run passes (exit 255).
- Process-tree cancellation is now exercised with a real forked descendant,
  in addition to mocked exit races. The regression checks both processes stop
  and stdout/stderr remain in the artifact log; interruption propagation has
  a focused cleanup test. Framework contracts: 76 passed in 5.92 seconds,
  including the 2.01-second live timeout test. Scoped Ruff passed.
- Report acceptance now rejects malformed later function attempts instead of
  reusing earlier clean evidence, and rejects duplicate function inventories.
  Build/original-execution failures take precedence over skipped decompilation.
  Six new regression cases failed before the fix; scoped Ruff/MyPy pass.
  Reclassification of saved DOS reports preserves overlap-003 as passed and
  large-002 as decompile_failed, without rerunning either expensive case.
  Follow-up classification preserves explicit function `acceptance_reason`
  validation failures even when legacy `decompile_ok` is false: large-002 now
  correctly classifies as validation_failed, while overlap-003 stays passed.
  The regression failed before this change. No stderr parsing, suppressed
  failures or decompiler semantic changes are involved.
- Remaining: close the nested-call validation gap, fix large-model failures, complete
  source/tool provenance, remaining
  behavioral negative controls, bounded routine integration without duplicating
  tiny-example runs, the frozen 32-64-case pilot with binary witnesses, and bounded
  Csmith integration. Steps 1-5 remain open.

### Csmith Generation Checkpoint

- Rebuilt clean revision `35e702de01e158bc948a2024d0e187c1803d1ebb` using Release
  CMake and four build workers at `.cache/compiler-coverage/csmith-build-35e702de`.
  Executable SHA-256: `f75bbeaacab98f1048340db1462700d035dd1f7c03e3470e6beb010b1f0511eb`.
- `scripts/compiler_coverage_csmith.py` bounds one candidate, keeps source and
  stderr separate, fingerprints executable/source, records options/seed/deadline,
  and preserves failed/partial artifacts. Existing output directories are refused.
  Results explicitly say `roundtrip_attempted=false`; generation grants no coverage.
- Run with `make compiler-coverage-generate PYTHON=./.venv/bin/python
  CSMITH=.cache/compiler-coverage/csmith-build-35e702de/src/csmith CSMITH_SEED=2`.
  Use a fresh `COMPILER_COVERAGE_OUT` when replaying.
- Seed 2 was byte-identical across separate directories and the Make entrypoint.
  Source SHA-256: `353845463705795ea0822c0ecaf5f956828405507d956d661e2fa124a4d66939`.
  Artifacts: `.cache/compiler-coverage/csmith-seed2-{first,second,make}/`.
- Framework contracts: 99 passed in 13.42 seconds. New generator Ruff/MyPy and
  pipeline enrollment Ruff pass. Contract tests join the existing routine lane;
  generated programs do not automatically enter pytest.
- The generation CLI now accepts `--roundtrip`; `make compiler-coverage-csmith`
  selects that path. It feeds external source/runtime headers through the same
  `build_msc6_examples.py` owner, with expected DOS exit 0 and recorded header
  fingerprints. Generated source uses the DOS-safe name `csmith.c`. No competing
  compile/decompile pipeline was introduced.
- First live seed-2 attempt reached decompilation but timed out at the explicit
  180-second case deadline. Artifacts:
  `.cache/compiler-coverage/csmith-roundtrip-001/roundtrip/`.
  Detached clean workers briefly outlived the adapter's process-group kill;
  they had exited before targeted cleanup, and no trial workers remain.
  The existing real timeout test covers same-group children,
  not detached descendants: extend cancellation and its regression before
  enabling multi-seed batches. This is a demonstrated open framework defect.
- Current framework contracts: 104 passed in 12.88 seconds; changed adapter and
  generator Ruff/MyPy pass. The commit checkpoint's `quality-hard` fails at Ruff
  on repository lint debt; it is not a green whole-project gate.
- Still required: close detached-descendant cancellation, verify one generated
  behavioral round trip, then bounded seed batches and retained/minimized
  failures. Step 5 is not complete.
- Cancellation follow-up: the adapter now snapshots descendants with the existing
  pytest process-tree helper before killing the root, and kills detached workers
  as well as the original group. The real timeout test now includes `setsid()`;
  that variant failed before the fix. Both variants pass; framework contracts:
  105 passed in 11.85 seconds, scoped Ruff/MyPy passed. A deliberately short
  30-second cancellation-only replay at
  `.cache/compiler-coverage/csmith-cancellation-002/` timed out as expected and
  left no matching workers. This does not grant behavioral coverage or change
  acceptance deadlines. Snapshot cleanup covers visible descendants, not workers
  already orphaned before the snapshot; stronger containment remains a limitation.
- Seed-2 timeout investigation: the original linked EXE independently returns 0
  with `checksum = 637A4628`. Its COD lists 69 functions: `func_1`, `main`, and
  67 Csmith runtime helpers. `--max-funcs 1` bounds generated application code,
  not emitted header runtime code. Do not increase deadlines or skip by name.
  A runtime-only header translation unit compiled to an OMF object (linking
  deliberately fails because it has no main). Existing signature catalog tooling
  imported 134 entries; existing matching reported 54 unique matching specs in
  the original EXE. These are spec counts, not proof that all 67 helpers match.
  Probe evidence: `.cache/compiler-coverage/csmith-runtime-probe/`.
- The shared adapter and Csmith CLI now accept an optional signature catalog and
  record its hash. Make forwards `CSMITH_SIGNATURE_CATALOG`. No default runtime
  exclusion or source-derived semantic recovery was added. Before using a runtime
  catalog as acceptance evidence, verify matched address coverage, no application
  exclusion, preserved library-call semantics and retention of the standard
  compiler/runtime catalog. Generated behavioral acceptance is still open.
  The five missing runtime bodies were traced to incorrect OMF LOCAT byte order
  and now match after a parser-layer repair. See
  [the bounded evidence and verification](omf-fixupp-locat.md).
- Checkpoint: the combined-catalog seed-2 replay at
  `.cache/compiler-coverage/csmith-roundtrip-catalog-003/` still timed out at
  the 180-second case deadline. Generated behavioral acceptance remains open.
  Original observations now persist through `scripts/msc6_original_evidence.py`
  before the legacy runner enters decompilation. Each `<DOS stem>.original.json`
  retains the source hash, model, compiler/linker diagnostics, original exit code
  and output. It explicitly records decompilation evidence as not collected and
  cannot replace the final round-trip report or make a timeout pass.
  Small/large integration regressions failed before wiring and pass afterward;
  four negative original-result controls also pass. Both the framework contracts
  target and routine pipeline enroll them. Framework contracts: 111 passed,
  seven third-party deprecation warnings, 24.73 seconds. Scoped helper Ruff/MyPy
  pass; legacy-owner Ruff remains red with 12 findings. Logs:
  `.cache/original-evidence-{before,after}.log` and
  `.cache/original-evidence-owner-ruff.log`. This is infrastructure acceptance,
  not a new generated-program behavioral pass.
- Seed-2 diagnostic follow-up (2026-09-20, 15:00-15:02 local): direct CLI
  execution with the combined catalog and `--no-alternate-source-c` still queued
  all 69 COD-labelled functions; the 100-second diagnostic cap expired. Thus raw
  signature matches do not establish that this selection path excludes their
  bodies. No name-based exclusion was added.
  With `--ignore-local-sidecar-hints`, discovery reported 129 candidates but
  queued only `main` (`0x1158b`), not the known application body at `0x111f5`.
  It exited 2 after about 41 seconds, reporting 0/1 selected functions decompiled.
  Whole-tail validation rejected the call at `0x11639` to `0x10021`: expected two
  16-bit arguments, recovered zero. This is a genuine blocking validation report,
  not evidence that source-free selection or behavioral equivalence passes.
  Retained logs: `.cache/csmith-diagnostic.{c,err}` and
  `.cache/csmith-sourcefree-diagnostic.{c,err}`. These were bounded diagnostic
  runs, not timing benchmarks or round-trip acceptance runs.
  Next repair order: verify complete application selection and signature-backed
  runtime-body filtering, fix the missing call arguments at their semantic owner,
  then replay the same seed through the shared round-trip adapter. Do not admit
  a faster but incomplete function inventory, weaken validation, or substitute a
  vacuous seed. The legacy adapter still requests alternate-source C; removing
  that dependency with explicit source-free acceptance remains required.
- Pre-entry selection repair (2026-09-20, 15:03-15:06 local): the selector used
  the startup call target as a hard lower address bound. Helpers linked before
  `main` were discarded despite being ranked candidates. It now retains ranked,
  framed entries across the loaded pre-startup image, keeping upstream signature
  filtering and the startup upper bound. No names or source bodies guide it.
  The earlier-helper regression failed before the change; all 29 focused
  discovery/cache tests pass afterward. The new tests are enrolled in the routine
  pipeline. MyPy passes for the owner; whole-file Ruff still has 53 legacy findings.
  A binary-only candidate probe now retains both `0x111f5` and `0x1158b`, among
  69 framed candidates. That probe did not attach a signature catalog and is not
  proof of runtime exclusion, complete function recovery, validation or improved
  performance. Combined-catalog end-to-end selection and the call-argument failure
  remain open. Logs: `.cache/pre-entry-order-{before,after,csmith,ruff,mypy}.log`.
- Catalog integration repair (2026-09-20, 15:07-15:10 local):
  `_detect_flair_metadata` returned early when optional `flair_startup/` was
  absent, silently ignoring the independent explicit signature catalog. The
  directory is absent in this checkout. Removed that dependency; existing startup
  matchers already tolerate missing assets. The new regression failed before the
  repair and passes afterward; six focused catalog/merge tests pass, and owner
  MyPy passes. Whole-file Ruff still reports six complexity findings. The new
  regression is enrolled in the routine pipeline. A real runtime-only-catalog
  probe now returns 57 labels/ranges and `signature_catalog` evidence, with no
  hits at either application entry. This production result is not the earlier
  raw-match range count of 67; complete runtime exclusion remains unproven.
  Source-free CLI setup separately skips all metadata loading, including explicit
  catalogs, under `--ignore-local-sidecar-hints`. That policy coupling must be
  separated without admitting debug/source evidence before claiming source-free
  catalog acceptance. Logs: `.cache/catalog-without-flair-{before,after,csmith,ruff,mypy}.log`.
- Binary-signature policy separation (2026-09-20, 15:10-15:14 local): source-free
  CLI setup now uses `binary_signature_metadata.py` instead of discarding catalog
  evidence along with sidecars. The focused owner only invokes binary/startup
  signature matching; COD/debug/type/data fields remain empty. Existing typed
  signature addresses drive filtering, not library names. Recovery cache source
  manifests include the new owner. Tests cover no matches, real angr label storage,
  empty source/debug fields and CLI setup refusing the sidecar loader; all seven
  focused signature/discovery regressions pass. New owner Ruff/MyPy and touched
  CLI/cache MyPy pass; owner-wide Ruff retains 37 findings outside this addition.
  The real binary probe now keeps both application entries among 12 candidates,
  down from 69 without catalog evidence. Ten runtime candidates still remain,
  so neither complete exclusion nor behavioral round-trip acceptance is claimed.
  Logs: `.cache/binary-signatures-{tests,csmith,owner-ruff,owner-mypy}.log`.
- Runtime ambiguity audit (2026-09-20, 15:14-15:16 local): all ten remaining
  runtime candidates have PATs matching two locations. Production matching
  requires exactly one hit, unlike the earlier raw-hit audit. Retain that refusal;
  do not skip ambiguous functions by name. Added the unique/repeated-body control
  to the routine pipeline: two tests pass and scoped Ruff passes. Audit:
  `.cache/csmith-unmatched-runtime-audit.json`.
  A focused combined-catalog CLI run requested `--addr 0x1158b` but recovered
  `0x113bf` (`fcn_0d133`) instead, then exited 4 on uninitialized stack reads,
  missing call arguments and branch-surface validation. It is not a comparable
  `main` regression. Catalog setup took approximately 53 seconds before recovery;
  `.cache/csmith-main-signatures.{c,err}` retains the run. A subsequent metadata
  probe found 126 labels, no labels at either application entry and no catalog
  range containing `0x1158b`, so a catalog-range overlap is not established.
  Direct-function selection must be investigated before interpreting this as a
  call-argument regression. Probe: `.cache/csmith-catalog-overlap.json.log`.
- Signature-gap ownership repair (2026-09-20, 15:17-15:20 local):
  `_lst_code_region` guessed a containing interval between neighboring labels
  after explicit-range lookup failed. That let a signature label claim unmatched
  application bytes beyond its actual match. Signature-only labels now supply
  only recorded ranges; listing-label fallback remains unchanged. Two negative
  gap cases failed before the fix; 25 focused metadata/discovery tests pass after
  it, and owner MyPy passes. Routine pipeline enrolls the new cases. Whole-file
  Ruff remains red with seven findings, including existing selector complexity.
  The identical combined-catalog CLI replay now selects the requested `0x1158b`,
  not `0x113bf`. It still exits 3: caller-census setup consumes the recovery
  budget, indexed-Alias refuses an incomplete census, and validation is
  uncollected. Do not call the function fixed or the timeout a pass. Logs:
  `.cache/signature-region-{before,after,ruff,mypy}.log` and
  `.cache/csmith-main-signatures-bounded.{c,err}`.
  `quality-fast` was rerun and remains blocked by global lint findings;
  `.cache/compiler-coverage-signature-quality-fast.log` retains the full result.
- Isolated-evidence policy repair (2026-09-20, 15:21-15:24 local): fresh caller
  discovery projects dropped already-established signature matches. They now
  receive a detached signature-only subset and the include-library policy; local
  source/debug fields are not copied, and reuse clears stale metadata. The new
  isolation regression failed before the repair; 27 focused tests pass afterward,
  with scoped Ruff/MyPy clean. Same-argument `main` replay still exits 3 with
  validation uncollected after approximately 71 seconds; no speedup is claimed.
  Logs: `.cache/discovery-signature-isolation-{before,after}.log` and
  `.cache/csmith-main-isolated-signatures.{c,err}`.
  Next bounded cause: `_recover_pre_entry_source_catalog_8616` and
  `_pre_entry_source_function_ranges_8616` derive ends from selected entries only.
  Signature-excluded entries therefore cease to bound neighboring recovery
  ranges. Preserve matched entry boundaries independently of body-selection
  policy before further replay; do not widen timeouts or weaken census refusal.
- Library-boundary repair (2026-09-20, 15:25-15:28 local): recovery and caller
  ranges now share `discovery_candidate_ranges.py`. Signature entries remain
  boundaries even when their bodies are excluded. The integration test failed
  before the change; 32 focused tests now pass, including duplicate/out-of-image
  boundaries and invalid selected-entry refusal. New helper Ruff and touched
  discovery MyPy pass; owner-wide Ruff retains 53 findings. Same-argument `main`
  replay still exits 3 with uncollected validation; no performance improvement
  is claimed. Logs: `.cache/library-boundaries-{before,after,ruff}.log` and
  `.cache/csmith-main-library-boundaries.{c,err}`.
  Further inspection found a separate expansion path in
  `_recover_candidate_function_pair`: recovered bodies of at most 0x20 bytes
  trigger richer recovery even with an explicit bound. This path uses
  `_richest_bounded_recovery_region` rather than the supplied exact region;
  richer `_pick_function` calls also omit the disabled calling-convention-seeding
  policy used for census scans. Cover and repair those paths before another
  expensive replay. Exact bounds and disabled expensive analysis must survive
  fallback; do not treat small functions alone as proof of truncation.
- Richer-recovery policy repair (2026-09-20, 15:29-15:32 local): exact bounded
  short functions no longer trigger size-only region expansion. Richer CFG
  recovery now forwards and obeys the calling-convention-seeding policy; its
  default remains enabled. Four controls failed before the change. Afterward,
  35 focused discovery tests and 33 selected CLI regressions pass; owner MyPy
  passes, while whole-file Ruff retains 53 findings. New tests are in the routine
  pipeline. Logs: `.cache/recovery-policy-{before,after,cli-tests,ruff,mypy}.log`.
  Identical `main` replay now closes candidate census accounting: raw=12,
  normalized=12, classified=12, materialized=12, failures=0; logged candidate
  recovery took 2.74 seconds. It reaches the correct function's decompilation and
  still fails validation at call `0x11639` to `0x10021` (two expected arguments,
  zero recovered). This removes the census-timeout blocker, not the semantic
  failure. No repeatable end-to-end speedup or behavioral pass is claimed from
  this single diagnostic replay, which overlapped focused pytest work.
  Output: `.cache/csmith-main-recovery-policy.{c,err}`. Next: repair argument
  recovery using binary stack/value evidence; leave validation blocking.

- Complemented call-argument repair (2026-09-20, 15:33-15:38 local): decoded
  register NOT now preserves width-aware value provenance as XOR with the
  operand-width mask. Register-only NOT no longer hides earlier argument pushes;
  frame-register and memory writes remain barriers. Three controls failed before
  the change; 98 focused tests pass afterward, and owner MyPy passes. Owner Ruff
  retains 22 findings. The 60-second, source-free `main` replay now emits C with
  `validation=passed` and clean whole-tail validation. Its final call preserves
  both complemented CRC words and the flag argument. This is not a complete
  Csmith round-trip pass: wide argument grouping, pointer argument classes,
  strict recompilation and execution remain acceptance obligations. Logs:
  `.cache/callsite-complement-{before,after,ruff,mypy}.log` and
  `.cache/csmith-main-complement.{c,err}`. Existing global lint debt remains
  blocking for a green quality gate.
- Commit checkpoint validation (2026-09-20): contract lane 268 passed; standard
  pipeline pytest lane 6397 passed, 8 failed in 797.92 seconds. Failures cover
  SORTD drawtime/swapbars/insertionsort sidecar-message assertions, percolateup
  timeout, runmenu/initbars output, setgear guard logic and COD loadprog output.
  These are unresolved failures, not established pre-existing debt. The subsequent
  QuickC stage was interrupted to fulfill the commit/push checkpoint request;
  external stages are incomplete and no fresh tiny-MS-C round-trip pass is claimed.
  Full diagnostics: `.cache/compiler-coverage-complement-pipeline.log`.

- Default-catalog provenance repair (2026-09-20, implementation/test work started
  15:59 local): automatic catalog input contained compiler sample OBJ signatures,
  including SORTDEMO application functions. Matching these as runtime signatures
  could mislabel or exclude application code. Default catalog generation now
  requires library-archive provenance; explicit catalogs retain their existing
  behavior. Generated cache directories are not rediscovered as inputs, and a
  changed builder policy forces regeneration even when input files are unchanged.
  PAT metadata parsing also preserves merged `src=a || b` provenance instead of
  discarding later sources. A typed reporting predicate separates signature-only
  metadata from local source/debug evidence in live and cached CLI diagnostics.
  Twenty focused tests and ten existing PAT/catalog regressions pass. Focused
  five-module MyPy and new/helper Ruff checks pass; broader touched-owner checks
  retain 22 legacy `omf_pat.py` typing errors and 52 Ruff findings. `quality-fast`
  remains red on global lint; its 39-module mypyc import smoke passes.
  Live SwapBars now passes the unchanged semantic/behavior regression. InitBars
  no longer emits the spurious `$_init_max` call but still fails strict GCC:
  `time(SEG_PTR(inertia_ds, 0))` supplies an incompatible pointer and does not
  preserve a null pointer's meaning. Do not silence the diagnostic or count this
  function fixed. The existing `_materialize_pointer_arg_8616` nested in
  `decompiler_postprocess_calls.py` wraps scalar pointer arguments with DS;
  repair through typed pointer/ABI lowering, not a rewrite-stage exception.
  Logs: `.cache/signature-provenance-{focused,existing,live,quality-fast}.log`.
  Standard pipeline pytest rerun: 6418 passed, 3 failed in 632.03 seconds
  (previous checkpoint: 6397 passed, 8 failed in 797.92 seconds; not a controlled
  performance comparison). Remaining failures are InitBars' pointer contract,
  RunMenu's rejected branch predicates/uninitialized carrier, and SetGear's
  30-second recovery deadline. QuickC: all four selected fixtures pass with
  `validation=passed`; all eight tiny-MS-C fixtures compile, decompile, recompile
  and pass their existing execution checks. Those legacy lanes remain distinct
  from the plan's stronger source-free witness acceptance. The pipeline exits
  nonzero because of its three pytest failures. Full diagnostics are in
  `.cache/signature-provenance-pipeline.log`. Keep all three failures blocking;
  do not remove signature matching or relax validation to recover a green count.
  Checkpoint completed at 16:25 local: approximately 26 minutes since the first
  new test, including broad gate execution and waiting, not 26 minutes of coding.

- Near-null argument repair (2026-09-20, started 16:25 local): moved the legacy
  near-pointer value constructor into `lowering/near_pointer_argument_values.py`.
  Structuring binds its typed service; the compatibility shim cannot import the
  implementation or proceed without the binding. The architecture import guard
  remains unchanged. Proven integer zero in pointer context remains a C null
  constant; nonzero offsets, memory reads, floating zero and object references at
  offset zero retain their segmented meaning. Two null controls failed before
  the repair; the five negative/nonzero controls passed. Current focused contract
  suite: 83 passed. The broader call-materialization run has 191 passed and two
  failures also reproduced with the committed pre-change implementation.
  InitBars now emits `time(0)` instead of `time(SEG_PTR(inertia_ds, 0))`, the only
  structured-C diff. This matches the original source's `time(NULL)` and preserves
  all other calls/arguments. Live source-free validation and strict GCC pass;
  the unchanged InitBars regression passes in 84.38 seconds. Promoted-scope `make mypy`
  passes after enrolling the new owners in the shared Make coverage fragment.
  New modules/tests pass Ruff; legacy touched-owner Ruff findings remain.
  Logs: `.cache/near-pointer-null-{contracts,focused,live-regression,mypy-global}.log`
  and `.cache/initbars-null-{before,after}.{c,err}`. Standard pipeline rerun:
  6430 passed, 1 failed in 560.06 seconds. RunMenu's source-free escape-exit
  regression remains blocking; InitBars and SetGear passed this run. QuickC
  passed all four selected fixtures with validation passed (162.59 seconds);
  all eight tiny-MS-C round trips passed (135.98 seconds). These are the existing
  pipeline lanes, not a whole-repository test audit or stronger source-free
  witness acceptance. Full log: `.cache/near-pointer-null-pipeline.log`.
  Checkpoint ended at 16:59 local, approximately 34 minutes elapsed including
  verification and waiting. Overall plan remains open; global lint debt remains.

References: [NIST covering arrays](https://math.nist.gov/coveringarrays/) and
[Csmith research](https://users.cs.utah.edu/~regehr/papers/pldi11-preprint.pdf).

### Binary-Recovery Policy Checkpoint

- 2026-09-20, approximately 17:02-17:06 local, four minutes including checks:
  the shared MS C runner now explicitly disables alternate-source C in normal
  main/function recovery, individual retries and batched named-procedure runs.
  Metadata may still identify targets; this change alone does not prove complete
  independence from source/debug semantics. Explicit JSON batch jobs retain their
  requested policy and are not used to bypass the compiler-coverage adapter.
- Four command-level controls failed before the change. The runner/adapter suite
  now passes 78 tests; the Make compiler-coverage contract target passes 115.
  These regressions are enrolled in that target and the routine pipeline.
  Scoped MyPy passes and the new test module is Ruff-clean. Thirteen existing
  legacy-tool Ruff findings remain; `quality-fast` still fails global lint.
- Live `compare16` passed compile/run/decompile/recompile/run in 146.32 seconds,
  with all six batch commands recording `--no-alternate-source-c`, successful
  final validation and matching original/rebuilt exit code 255. Artifacts:
  `.cache/compiler-coverage/binary-policy-001/`; logs:
  `.cache/msc6-binary-policy-{before,focused,contracts,mypy,quality-fast}.log`.
  The <=60-second routine target is not met. Other cases have not yet been
  rerun under this stricter policy; previous pipeline results must not be
  presented as verification of this change. Next: run the bounded admitted
  small/large batch under this policy and repair its concrete failures.

### Small/Large Batch And Procedure Selection

- 2026-09-20, approximately 17:06-17:18 local, including both live runs and
  focused checks: the stricter-policy batch passed all four small candidates.
  Times: comparisons 32.38s, pointer writes 55.98s, flow 50.12s, nested calls
  60.73s. Large storage failed validation in 164.63s. These are candidate round
  trips, not admitted feature witnesses or a <=60s whole routine lane.
  Artifacts: `.cache/compiler-coverage/binary-policy-batch-001/`.
- Fixed a harness configuration defect: large-model unqualified procedures were
  still selected as NEAR. The memory-model contract now supplies the default
  procedure kind to batch selection and every individual retry. This is target
  selection only, not evidence for recovered ABI or support for explicit
  per-function near/far overrides. Two selector controls failed before the fix;
  65 neighboring tests and 119 compiler-coverage contracts now pass. Scoped
  MyPy and helper/test Ruff pass; the legacy build owner retains 12 Ruff findings.
- Corrected large rerun still fails validation (231.97s), now with retained batch
  reports and no false absent-procedure classification. `_sum_globals` leaks
  `ss << 4`; `bump_static` reports classified GP stack-restores without any
  materialization. The batch report preserves both failures even though the
  rebuild stops at the first rejected function. Do not relax either gate.
  Artifacts: `.cache/compiler-coverage/large-procedure-policy-001/`; logs:
  `.cache/msc6-procedure-model-{before,focused,contracts,mypy,ruff,live}.log`.
  Next semantic investigation: the small `bump_static` far-call stack frame,
  including the binary stack-probe call and SI/DI save/restore ownership.
- Pause checkpoint, 2026-09-20 17:19 local: a direct linked-binary probe of
  `bump_static` at `0x10000`, window 30, with both local sidecars and alternate
  source recovery disabled exits 4 before GP restore lowering: `KeyError: 712`,
  `clinic=None`, no generated C, validation uncollected. This is a distinct
  earlier blocker, not evidence that the sidecar-assisted restore defect is
  fixed. Retained `.cache/large-bump-before.{c,err}` and stage bundle
  `.codex_automation/stage_debug/STORE.EXE_47d5df5c7df1/0x10000_sub_10000_de74da18dd3a`.
  No semantic owner was edited during this diagnostic. Investigate this earlier
  source-free failure first on resume; keep both previously recorded large-model
  failures blocking. Work paused at the user's request after the commit/push.

### Far Control-Flow And Stack-Probe Repairs

- Resumed 2026-09-20 18:40 local from the pause checkpoint. The `KeyError: 712`
  root cause is proven from the captured traceback (requires
  `INERTIA_DEBUG_DECOMPILER_ERRORS_TRACEBACK=1`): the immediate far call
  `lcall 0x100e:0x2c8` in `bump_static` lifted its control-flow target as the
  bare offset `0x2c8` (712), so Clinic's `_recover_calling_conventions` looked
  up `kb.functions.get_by_addr(0x2c8)` and raised. Full traceback retained in
  `.cache/large-bump-traceback2.c`. Fix at the lifting layer:
  `stack_helpers.far_linear_target_8616` resolves concrete seg:off pairs to
  their flat 20-bit real-mode address (wrapped at 1MB), and
  `emit_far_call16`/`emit_far_jump16` now jump there; symbolic pairs keep the
  bare-offset target. The CFG then reaches the real helper at `0x103a8`.
- Binary-backed far stack probe (`__aFchkstk`, bytes
  `59 5a 8b dc 2b d8 72 ?? 3b 1e ?? ?? 72 ?? 8b e3 52 51 cb` from
  `STORE.EXE:0x103a8`): new `_MSC_AFCHKSTK_PATTERN_8616`,
  `CompilerHelperEvidenceKind8616.STACK_PROBE_FAR`, far SimProcedure (pop far
  return, SP -= AX, far-return to the linear pair), scan and registration, and
  the `afchkstk` name spelling. A shared typed predicate
  `is_x86_16_stack_probe_evidence_kind_8616` now gates every former
  `STACK_PROBE`-only consumer (`semantics/call_stack_allocation.py`,
  `lowering/stack_aggregate_objects.py`, both `cli_decompilation.py` gates).
  The lifter inlines registered far probes exactly like near probes
  (`far_probe_call` simple semantics in `lift_86_16.py`: CX = return IP,
  DX = return CS, BX/SP = SP-AX, allocation-0 keeps SP, no call edge).
  This is binary evidence plus coherent stack/call effects, not a
  far-name patch on the near model.
- Far functions' RETF restores CS from the caller-pushed frame at
  machine BP+4..+5; `validation/entry_stack_ranges.py` now derives that slot as
  a caller-defined entry range from terminal `UNKNOWN_REFUSE` CS-restore facts
  (alias-proved, no in-function save), so def-use validation no longer reports
  `uninitialized-read:stack-local:SS:BP+0x4/+0x5` for the materialized
  `inertia_cs` restore.
- Tests: 5 new far-target helper tests, 6 far compiler-helper tests, 5 new
  IR-level far-probe lifting tests (`test_x86_16_far_probe_lifting.py`,
  enrolled in the routine pipeline lane), 6 far-return entry-range tests.
  Focused neighborhood: 361 passed; validation neighborhood: 79 passed.
  Two `compare_semantics` tests updated to the linear-successor contract with
  sub-64K far targets (real-mode PC is 16-bit; concrete successors cannot
  follow >64K flats). Scoped Ruff/MyPy pass on changed owners; legacy
  complexity findings in `lift_86_16.py`/`stack_aggregate_objects.py` remain.
- Source-free replay progression for `bump_static` at `0x10000`:
  `KeyError: 712` -> gone (far-target fix); `GP stack-restore facts classified
  but none materialized` -> gone (far-probe inline); def-use uninitialized
  BP+4/+0x5 -> gone (entry range). The direct lane now reaches whole-tail
  validation with coverage=2 and its Inertia validation is clean; the direct
  generated C keeps proper SI/DI save/restore and the static-bump return.
  Remaining direct-lane blocker: the rebuild's `gcc -Werror=uninitialized`
  rejects the same materialized RETF CS read (`local_4`/`local_5`), because
  GCC cannot see the caller-defined slot. Next slice: model the far return as
  a 4-byte return boundary (consume the RETF CS pop like the near RET's IP
  pop) at its semantic owner instead of materializing frame machinery as
  program reads.
- Discovered open framework defect (record, do not silently accept): after the
  far-probe inline, the non-optimized shared-project slice lane decompiled a
  TRUNCATED 24-byte slice of the 30-byte function (ending at the `jmp` at
  `0x10015`) and its validation passed, so the CLI exited 0 via a fallback
  whose body lacks the pops, return, and AX result. Do not count this as a
  `bump_static` pass; the slice lane needs a function-inventory completeness
  check before its output can be accepted.
- The blob backend maps one 64K window, so synthetic fixtures must stay below
  64K; real MZ inputs use the `dos_mz` backend. Verified a synthetic 300KB MZ
  EXE loads and lifts through `dos_mz` in 0.22s, so large real binaries remain
  in scope. Logs: `.cache/blob-size-log.log`, `.cache/mz-300k-5.log`.
- Replay artifacts: `.cache/large-bump-after-farfix.{c,err}`,
  `.cache/large-bump-after-probefix.{c,err}`,
  `.cache/large-bump-after-farret.{c,err}`. Batch after these fixes:
  `.cache/compiler-coverage/large-farfix-001/` (recorded below).

### RETF Boundary Carrier Consumption

- Delivered the planned next slice: model the far return as a 4-byte return
  boundary at its semantic owner. New owner
  `X86_16/lowering/far_return_boundary_carriers.py`
  (`consume_terminal_far_return_boundary_carriers_8616`): a structured RETF
  CS-restore carrier CAssignment is removed when alias
  `SegmentStackRestoreFact8616` (`restore_register == "cs"`,
  `saved_instruction_addr is None`, verdict `UNKNOWN_REFUSE`) has its
  `restore_instruction_addr` proven at a block-terminal RET with complete
  `terminal_stack_cleanup_at_address_8616` evidence (FAR frame,
  `operand_bits == 16`, cleanup 0), and the assignment's LHS is a pure CS
  carrier (`inertia_cs` runtime variable or physical cs
  SimRegisterVariable). Mixed non-CS carriers refuse and keep code; typed
  enums only; closed stats accounting (raw == normalized + failure;
  normalized == classified + refused; classified == materialized + already).
  The consumed-set tolerates the structuring pass table's single sweep
  (re-removal of rebuilt carriers is allowed; consumed facts feed
  `already_materialized` only when the carrier is absent). `ir/vex_control_flow.py`
  gains `terminal_ret_instruction_addrs_8616`; both are wired in
  `decompiler_structuring_stage.py` after `_segment_stack_restore_carriers_8616`
  (pass table + priming-end). No IR lift change: tests still assert the CS
  restore in IR. 19 tests in `test_x86_16_far_return_boundary_carriers.py`,
  enrolled in QA_TYPED/QA_RUFF/QA_PYTEST/decompiler-contracts lanes and the
  `scripts/test_pipeline.py` routine lane. Ruff/MyPy clean on touched owners.
- The gcc `-Werror=uninitialized` blocker is resolved: the RETF CS pop is
  consumed instead of materializing caller-frame machinery as program reads,
  so far functions end with a plain `return ...`.
- Recorded results. Baseline batch `.cache/compiler-coverage/large-farfix-001/`:
  case `large_global_calls` = `validation_failed` (forbidden `ss << 4` token
  in `_sum_globals`). After the slice, focused replays on the 001 `STORE.EXE`:
  `_sum_globals` and `bump_static` both `validation=passed` with no `ss << 4`
  in the generated C. Full rerun
  `scripts/compiler_coverage_suite.py --manifest examples/compiler_coverage/large.json
  --out-dir .cache/compiler-coverage/large-farfix-002`: case
  `large_global_calls` **passed** (`roundtrips_passed=true`,
  `source_contracts_passed=true`; `bump_static` materializes the required
  global write and keeps the returned call; the rebuilt `DSTOR01.C` body has
  the static bump and `return seen`, i.e. full 30-byte-function semantics, not
  the truncated fallback). No `ss << 4` in any 002 `.dec` artifact.
- Open defect unchanged: the shared-project slice lane still lacks a
  function-inventory completeness check (the earlier truncated 24/30-byte
  `bump_static` fallback). The 002 fallback-rebuild lane produced full-body
  output this time, but the check itself remains to be implemented before
  slice-lane acceptance is trusted by construction.

### Shared-Project Slice Inventory Completeness

- Delivered the remaining slice-lane acceptance guard. The Frontend bounded
  instruction inventory now accepts an exact `end` bound: `EXACT_END_REACHED`
  continues through every byte in the metadata-bounded sidecar region instead
  of stopping at the first machine return. The sidecar fallback owner builds a
  closed instruction census from that exact bound and compares it with the
  recovered function's CFG-owned Capstone instructions. Any omitted exact
  instruction turns the otherwise decompiled attempt into an error, preserves
  the diagnostic address list, and allows the bounded recovery retry policy to
  try the next recovery mode instead of accepting a truncated 24/30-byte body.
- Added focused regressions for exact-end decoding and truncated CFG refusal
  (`test_bounded_inventory_decodes_to_exact_region_end`,
  `test_sidecar_slice_refuses_truncated_cfg_ownership`), and enrolled both in
  the `scripts/test_pipeline.py` routine lane. Focused neighborhood: 12 passed
  (sidecar entry, bounded instruction inventory, and slice recovery verdicts).
  MyPy passed on the changed implementation owners. Ruff on the changed files
  reports the pre-existing `cli_fallback_decompilation.py` complexity debt
  (baseline 12 findings); the touched frontend owner is clean after a focused
  extraction. The broad fast lane also has unrelated pre-existing failures
  (cache-key surface, SORTD sidecar-free regressions, COD `loadprog`, and
  inbox long arithmetic), so this checkpoint does not claim broad-lane health.

### Large Far-Pointer Candidate Slice

 Delivered candidate wiring for the missing large-model pointer interactions,
without admitting those obligations: `pointer_memory` gained `select_word`, a
default-far pointer-result function, and both read/write harness checks.
The source gate requires a value-returning generated `select_word`; the
existing `function_pointers` construct supplies default-far indirect calls.
The large manifest now exposes two candidate cases for `pointer.far_data`/
`calls.pointer_return` and `pointer.far_function`, while keeping all three
pointer obligations in `later` because their linked-EXE witnesses do not pass.
Cheap manifest/build contracts pass (55 focused tests; MyPy clean; the touched
legacy build owner retains its 12 known Ruff findings).
- Live source-free candidate runs correctly exposed real blockers, not oracle
failures. `pointer_memory` fails decompilation: `fill_bytes` has two
uninitialized far-frame argument byte reads (`SS:BP+6/+7`) and postprocess
changes control-flow, segmented-write, and stack-write semantics; the new
`select_word` itself reaches `status=ok` with clean tail validation.
`function_pointers` fails validation: `inc_one` still reports classified
GP SI/DI stack restores with zero materialized, and `apply_twice` reports a
classified far function-pointer parameter with `parameter_slot_missing`.
Retained artifacts: `.cache/compiler-coverage/large-far-pointer-001/` and
`.cache/compiler-coverage/large-far-function-001/`. These are the next two
semantic owners to repair; do not weaken the materialization gates or count
the candidate cases as feature coverage.

### Far-Frame Argument Base Proven (uncommitted-obligation progress)

The far-frame root cause is now owned by typed contracts rather than
hardcoded near constants. A far function (`retf`) restores caller CS at
`BP+4..+5`, so its first stack argument begins at machine `BP+6`, not
`BP+4`. `lowering/argument_frame_base.py` derives the proven base from the
terminal far-return evidence and selects `SimCC8616MSClarge`
(`STACKARG_SP_DIFF=4`) for proven far functions; seeding publishes the
prototype at `PrototypeSource.CCA_DECOMPILER` so clinic's
CompleteCallingConventions cannot reset the far convention to the near
arch default. The proven base is threaded through stack prototype layout,
positive-BP argument materialization, callee width evidence, and validation
parameter maps, and angr-native BP variables record their entry-SP
projections correctly (`real_mode_linear` publish sites).

Verified against the retained artifacts: far `inc_one` now decompiles with
its argument at `BP+6` and `validation=passed`; near-model `apply_twice`
and `inc_one` are unchanged (`validation=passed`). `apply_twice` far no
longer hard-fails on `parameter_slot_missing`: the callsite evidence
retains the indirect-call operand width, `FunctionPointerParameterFact8616`
carries `pointer_width` (4 for `call DWORD PTR [bp+6]`), the new
`SimTypeFarPointer16_8616` fixes the pointer at 32 bits, and materialization
widens the proven slot and re-sites later arguments (`value` at `BP+10`).
The far `apply_twice` body still binds reads to stale near-based merged
variables and its `value` width is still wrong, so it does not validate
and the obligation stays unadmitted. `fill_bytes`/`swap_ptrs`/`offset_copy`
far-frame argument reads remain pending. Per AGENTS.md hard rule 16 (loud
exceptions), the two silent far-proof catch-alls were removed and the
incomplete test mocks were completed instead.

### Far-Pointer Rebuild State Checkpoint (2026-09-24)

- Investigation began with the retained linked `apply_twice` replay at
  09:16:46 local time; checkpoint at 09:28 local time (about eleven minutes
  including diagnostic runs and checks, not a pure implementation timing).
- The pointer owner now reports declaration changes even when its retained KB
  prototype already matches. It also publishes widened/re-sited argument
  storage to angr's `_func_args`, the separate input used by a later
  `StructuredCodeGenerator._analyze` rebuild. Previously only the live
  `CFunction.arg_list` was updated. The new rebuild-storage regression failed
  before this change and passes afterward; the existing refresh/replay
  regression remains passing. Both are in the routine pipeline through the
  enrolled function-pointer test module.
- Focused pointer/layout/codegen neighborhood: **16 passed** (33.02 seconds,
  seven workers, JIT enabled). Touched owner/test Ruff clean; focused owner
  MyPy clean. This is not function acceptance or broad-suite acceptance.
- Linked replay `.cache/coverage-apply-twice-rebuild.{c,err}` still exits 4.
  It retains `parameter_slot_missing` in an intermediate attempt and final
  uninitialized SI/DI restore reads at `SS:BP-8..-5`. Diagnostics show a
  correct native argument layout `(4,4)/(8,2)` reverting to `(2,4)/(6,2)`
  before pre-validation callsite replay. Updating the rebuild input alone
  does not fix that reset; trace the pre-validation stack-interface consumers
  next. Temporary diagnostic source edits were removed.
- `quality-dev` was invoked with output retained in
  `.cache/far-pointer-rebuild-quality-dev.log`; its MyPy lane reports errors
  in `validation_condition_storage_views.py` and `semantics/call_stack_effects.py`,
  outside this slice. No large-pointer obligation is admitted at this checkpoint.

### Optional Stack Names Cannot Override Binary Layout (2026-09-24)

- The live argument-write trace identified the reset precisely:
  `materialize_annotated_stack_prototype_8616` interpreted normalized COD
  labels `{4: fn, 8: value}` as machine-BP argument slots. That replaced
  the already-proven far layout. Diagnostics are retained in
  `.cache/coverage-apply-twice-arg-writes.err` and
  `.cache/coverage-apply-twice-annotations.err`; temporary instrumentation
  was removed.
- COD stack aliases now carry `StackAnnotationPurpose8616.NAME_ONLY`.
  The shared annotation-contract selector excludes them (and unknown
  purposes) from layout recovery. Lowering and legacy prototype consumers
  use that selector; existing naming consumers still receive the labels.
  Explicit layout annotations retain their compatibility behavior. This is
  an evidence-authority correction, not a source-derived far-frame fix.
- Near/far naming-only regressions failed before the change. The first
  focused neighborhood passed **87 tests** in 55.05 seconds with seven
  workers. A subsequent helper extraction and unknown-purpose control are
  included in the pending default pipeline gate. MyPy passes on the three
  annotation owners. Baseline Ruff had 74 findings across the four legacy
  implementation files; the touched COD-label function's complexity finding
  was removed, leaving the unrelated debt visible.
- Linked replay `.cache/coverage-apply-twice-naming-only.{c,err}` exits 4:
  binary-only positive-BP recovery still narrows the proven pointer storage
  and drops the following value argument in the full rebased attempt.
  A fallback also fails gcc due to a missing indirect-call argument. No
  candidate or far-pointer obligation is admitted. GP restore diagnostics
  show incomplete call-stack effects invalidate save provenance across calls;
  SI/DI restore reads remain uninitialized rather than being deleted.
- Default `make test-pipeline` is running as of 09:40 local time; its
  prerequisite passed 292 tests. Log:
  `.cache/stack-annotation-authority-pipeline.log`. Confirm terminal status
  and inspect its structured summary before claiming pipeline success.

### Binary Pointer Slot Replay (2026-09-24)

- Resumed investigation around 09:48 local. The focused regression proves
  positive-BP replay narrowed native `(4,4)/(8,2)` to `(4,2)` despite a
  successfully materialized far function pointer. The pointer owner now
  projects its closed evidence into exact typed slots; argument recovery
  consumes these without asserting a complete signature or promoting
  `CCA_DECOMPILER` to `SIGNATURES`. Existing signature layouts keep precedence.
- Initial pointer neighborhood: 12 passed, 24.72 seconds. Added near/far
  projection and missing/unclosed-evidence refusal controls, enrolled in the
  routine pipeline. Focused MyPy passes; pointer owner/tests Ruff clean.
  The legacy positive-BP owner still has two complexity findings.
- Linked `apply_twice` replay finished at 09:51 local, exit 4. It now emits
  both arguments (`arg_6` pointer and `arg_a` value), but SI/DI restore reads
  remain uninitialized and validation fails. Retained artifacts:
  `.cache/coverage-apply-twice-pointer-slots.{c,err}`. No obligation admitted.
- The earlier pipeline process is gone and its summary is stale; only its
  292 prerequisite passes are confirmed. A fresh default gate is required.
  `quality-dev` currently exposes repository lint debt and an unrelated
  mypyc typing error in `validation_control_flow.py`; see
  `.cache/pointer-slot-replay-quality-dev.log`.
- Final focused neighborhood: **38 passed** in 48.42 seconds, seven workers,
  JIT enabled. Four old mock failures required supplying the missing decoder
  surface (empty body); no production exception fallback was introduced.
  Quality-dev terminated with exit 2. Fresh default pipeline started with log
  `.cache/pointer-slot-replay-pipeline.log`; its result remains pending.

### Far Stack-Allocation Frame Proof (2026-09-24)

- A seeded in-process probe (`PYTHONHASHSEED=0`, to avoid the CLI's exec
  restart discarding hooks) captured the actual `apply_twice` call-effect
  refusals: the first direct far call is `STACK_ALLOCATION_UNPROVEN`; both
  BP+6 far-pointer calls are `TARGET_UNRESOLVED`. Artifacts:
  `.cache/coverage-apply-twice-call-proof-seeded.{c,err}` (exit 4).
- Semantics accepted only near frames in `CallStackAllocationProof8616`,
  although Frontend already distinguishes near/far stack helpers by binary
  evidence. The proof now carries the exact binary return-frame kind, and
  matching requires agreement with the call frame. Conflicting proofs remain
  visible to the consumer so an unmarked allocation cannot silently become
  a zero-allocation call. This does not weaken unknown indirect-call refusal.
- Before: **3 failed / 12 passed**, 68.55 seconds, including an unmarked far
  allocation incorrectly reported as zero and a mismatched near/far frame
  incorrectly accepted. Initial after-fix neighborhood: **42 passed** in
  56.52 seconds. Focused MyPy and Ruff pass. Final unmarked-mismatch controls
  and required frame-kind constructor are being checked separately.
- Linked replay `.cache/coverage-apply-twice-far-allocation.{c,err}` is pending.
  The live default gate predates this allocation edit; do not treat it as
  full-suite acceptance for this subsequent change. No far obligation admitted.
- Linked replay has now finished, exit 4. Its typed call-effect artifact
  improves from three refusals to two: the allocation call is PROVEN with
  BP preservation; both indirect targets remain unresolved. SI/DI local
  initialization validation still fails, so this is not function acceptance.
  The final focused run encountered a transient concurrent indentation error
  in `calling_convention_compat.py`; after verifying that file compiles, a
  rerun is active in `.cache/far-allocation-final-stable.log`.
- Final focused rerun: **44 passed** in 53.60 seconds, including the required
  frame-kind proof constructor and marked/unmarked mismatch refusal controls.
  This completes the bounded allocation regression loop, not the far-function
  witness or the compiler-coverage plan.

### Native Machine CALL Frame Reconciliation (2026-09-24)

- The pre-SSA probe accepted both indirect far calls and consumed all 12
  machine-frame effects. Native VEX stack tracking independently popped only
  one architecture word, leaving SP two bytes low after each far CALL.
  Binary-only before-fix regressions: two far failures, one near pass.
- Semantics now publishes the decoded CALL frame width separately from target
  ABI, argument cleanup and preservation. The native adapter reconciles that
  frame with angr's fixed-word pop and records a closed typed census. Unknown
  frames and mismatched return edges invalidate SP evidence. Operand-size
  overridden FF /3 is identified from decoded opcode/ModRM, not Capstone's
  CALL versus LCALL id alone. Existing PUSH CS / near CALL proofs remain separate.
- Initial neighborhood: 69 passed. Added 32-bit width and refusal controls
  exposed the Capstone FF /3 id distinction; final rerun is retained in
  `.cache/native-call-frame-final-widths.log`. Scoped Ruff and MyPy pass.
- Linked replay `.cache/coverage-apply-twice-machine-frame.{c,err}` exits 4.
  The rebased native SI/DI save and restore offsets now agree and the final
  whole-tail check is clean. Compilation still rejects pointer bitwise masks
  around the materialized function-pointer calls. Direct-address fallback
  separately fails argument materialization. No far obligation is admitted.
- `quality-dev` exits 2 on existing repository lint/typing debt; full log
  `.cache/native-call-frame-quality-dev.log`. The prior default gate's pytest
  lane has 6,468 passes and 23 failures; its external stages remain pending.
  It predates this correction and cannot establish acceptance for it.
- Final focused rerun: **73 passed** in 32.19 seconds, seven workers with JIT.
  Scoped Ruff/MyPy and diff whitespace checks pass. The existing default gate
  is still running its QuickC external lane; no duplicate broad gate started.

### Pipeline Entry Regression After Refactoring (2026-09-26)

- A fresh linked replay returned empty codegen before reaching the prior
  far-pointer blocker. Source comparison identified `0388db438`: the nested
  pipeline implementation was no longer invoked, and its status-flag context
  had been placed around the validation-acceptance helper instead.
- Restored pipeline execution inside the status-flag context; validation
  acceptance retains its explicitly supplied function. Four entry regressions
  proved missing execution/exception propagation, and a fifth proved the helper
  substituted the wrong function. The already-enrolled package-exports test
  module owns these durable contracts. Scoped Ruff passes.
- The linked replay now reaches code generation and the known pointer-mask
  failure; fallback separately lacks an indirect-call argument. It still exits
  4, so no far obligation is admitted. Artifacts:
  `.cache/coverage-resume-entry-restored.{c,err}`.
- After-fix verification initially hit concurrent stack-lowering edits. Once
  those parsed again, `.cache/decompile-entry-pointer-before.log` recorded
  85 passes, including all five entry regressions, and only the intentionally
  red pointer-mask test. Do not treat this entry repair as whole-function or
  whole-plan acceptance.

### Typed Indirect-Target Projection (2026-09-26)

- Lowering consumes a full-word IP projection only when a typed binary callsite
  fact and authoritative parameter storage identify the same complete function
  pointer. The existing parameter owner performs this projection and reports a
  separate typed five-counter census; no rendered-C repair or argument fill-in
  was added. Unknown sites, other slots/regions, partial masks, and non-call
  expressions remain unchanged. Both mask orders and near/far widths are tested.
- The original mask regression failed before the change. A near-pointer control
  separately exposed missing reuse of exact argument identity when an existing
  parameter needs no coordinate publication. After that correction, 94 focused
  tests pass in 65.31 seconds (seven workers, JIT). Scoped Ruff and the final
  MyPy rerun both pass.
- Linked replay emits both unmasked calls, preserves their arguments, and reports
  a clean whole-tail check for the rebased attempt. The integrated MS C check
  still fails because its execution environment cannot see `/dev/kvm`; direct
  invocation compiled the retained target-specific input successfully, but does
  not replace integrated round-trip acceptance. A Python diagnostic confirms
  the device is absent even before importing project code, so this is not an
  import-side effect. No emulator/sandbox bypass was added. The direct-address
  fallback independently still lacks an indirect-call argument.
- Artifacts: `.cache/coverage-pointer-target-materialized.{c,err}`,
  `.cache/function-pointer-target-verified.log`, and
  `.cache/msc-kvm-import-diagnostic.log`. `quality-dev`/`quality-hard` exit 2 on
  broader lint/type debt. The fresh default pipeline is running in
  `.cache/function-pointer-target-pipeline.log`; its result remains pending.
  No new far-pointer witness is admitted and the full plan remains incomplete.

### Unavailable Compiler Execution Is Not A C Failure (2026-09-26)

- The existing MS C recompile owner now probes kvikdos execution capability
  before compiling. Probe failure or timeout produces the existing typed
  `TOOLCHAIN_UNAVAILABLE` outcome, never a compiler rejection or a pass.
  Missing/denied executables are handled at the same explicit boundary.
  The CLI gate preserves the hold, labels the infrastructure failure accurately,
  and retries unavailable results instead of caching them as payload failures.
- Three focused regressions failed before repair. Afterward 26 tests pass in
  105.27 seconds, including real invalid-C controls, healthy-toolchain compiler
  rejection, strict DOS mounts, and preservation of transient compiler retries.
  Final five availability/cache controls also pass in 60.03 seconds. The existing
  routine recompile-check module owns the new regression coverage.
- The live probe reports unavailable with exit 252 and no compile attempt;
  `.cache/recompile-capability-live.log` retains the result. Scoped Ruff passes.
  Scoped MyPy reports only existing errors outside the edited CLI collector.
  This reporting improvement does not establish any new behavioral witness or
  remove the required execution-environment fix for DOS round trips. The live
  default pipeline started before this edit and cannot certify this change.

### Preserve Memory Model On Missing-Body Retry (2026-09-26)

- 11:06-11:09 UTC, approximately three minutes including focused verification:
  the shared runner's successful-but-missing-body retry omitted `proc_kind`,
  silently changing a large-model FAR selection to NEAR. It now preserves the
  selected model, matching the other focused retry paths.
- Before: one large-model failure (`FAR`, then `NEAR`), one small-model pass.
  After: 63 runner/policy tests pass in 58.97 seconds with seven workers and JIT.
  The existing routine policy test module owns both regression controls.
  Scoped MyPy passes with explicit package bases; Ruff retains the same 12
  legacy builder findings, with the test module clean. Logs:
  `.cache/msc-retry-model-{before,after,mypy}.log`.
- Source/debug independence remains open: the focused fallback does not receive
  `decompile_ignore_local_sidecar_hints`, although the main path does. Merely
  setting that flag in the adapter would not establish independence. Follow up
  at the shared orchestration owner without losing permitted target naming or
  counting a sidecar-assisted fallback as source-free evidence.
- The earlier default pipeline is still live and has reported a failure; it
  predates this repair. Defer a new broad quality gate until it terminates.
  This is a runner correction, not a newly accepted large-model witness.

### Source-Free Fallback Boundary (2026-09-26)

- 11:10-11:13 UTC, approximately three minutes including verification: explicit
  `--decompile-ignore-local-sidecar-hints` now refuses the sidecar-backed named
  fallback, both before binary recovery and after a failed binary attempt.
  CLI help documents that boundary. The regression failed before this guard;
  afterward 64 runner/policy tests pass in 56.10 seconds, seven workers with JIT.
  Scoped MyPy passes; Ruff still reports 12 legacy builder findings. Logs:
  `.cache/msc-sourcefree-fallback-{before,after,ruff,mypy}.log`.
- The coverage adapter default is deliberately unchanged: its named fallback
  also runs additional behavioral harness checks. Dropping those checks merely
  to select source-free mode would weaken the oracle. Binary-only target binding
  must preserve those observations before changing the acceptance lane.
  No new source-free witness is admitted by this fail-closed policy correction.
- Earlier default pipeline remains live with failures; no overlapping broad
  gate was started. Required changed-surface quality-dev remains pending until
  that run terminates. Full-plan acceptance is still incomplete.

### Required Targets Cannot Disappear (2026-09-26)

- 11:20-11:23 UTC, approximately three minutes including focused verification:
  the named-function builder previously recognized a diagnostic substring and
  silently skipped a missing required procedure. Removed that exception to its
  normal typed failure/retry path. A regression proves rebuild is never attempted
  after the required target disappears, even with a trivially successful harness.
- Before: the regression failed because compilation was attempted. After:
  65 runner/policy tests pass in 40.61 seconds (seven workers, JIT). Scoped
  MyPy passes; the unused diagnostic binding exposed by the deletion was renamed,
  leaving the same 12 legacy Ruff findings. Logs:
  `.cache/msc-required-target-{before,after,ruff,mypy}.log`.
- The earlier default pipeline terminated with exit 2: its routine pytest lane
  has 6,475 passes and 48 failures in 1,784.92 seconds. It spans concurrent edits;
  in particular, its recompile-availability failures show behavior from before
  the already-focused-tested availability repair. Do not treat all 48 as stale:
  remaining failure families require current-source verification.
- With that run terminal, `quality-dev` was rerun and exits 2 on broader lint/type
  errors (`.cache/msc-runner-quality-dev.log`). Binary-only harness target binding,
  live round trips, witness admission, and full-plan acceptance remain open.

### Compiler Diagnostic Bytes And Fresh Availability Verification (2026-09-26)

- Fresh-process recompile suite: 22 passed in 33.48 seconds, including all five
  availability/cache controls that failed in the older overlapping pipeline.
  This verifies that bounded family on current source, not the other failures.
  Log: `.cache/recompile-current-after-pipeline.log`.
- A live simple-C probe subsequently reached compiler execution but raised
  `UnicodeDecodeError` on diagnostic byte `0xc1`. DOS/compiler and host-emulator
  output need not share an encoding. MS C subprocess decoding now uses explicit
  UTF-8 with visible backslash escapes for undecodable bytes; compiler exit status
  remains authoritative. No guessed code page, silent byte deletion, or exception
  masking was introduced.
- Two real-subprocess byte-stream controls failed before the correction, for
  both zero and nonzero compiler exits. Afterward 24 tests pass in 64.83 seconds
  with seven workers and JIT. Scoped Ruff/MyPy and whitespace checks pass.
  Logs: `.cache/msc-diagnostic-bytes-{before,after,mypy}.log`.
- Checkpoint ended 11:29 UTC. The retained live retry reports typed
  `TOOLCHAIN_UNAVAILABLE`, exit 252, because `/dev/kvm` is unavailable again
  (`.cache/msc-diagnostic-bytes-live.log`); no DOS round trip was accepted.
  Fresh quality-dev exits 2 on broader lint/type errors, including stack-prototype
  typing (`.cache/msc-diagnostic-bytes-quality-dev.log`). The runtime-helper
  exception in the older pipeline belongs to concurrently edited CLI fallback
  code; it was not repaired or declared resolved here. Binary-only harness
  binding and the full coverage goal remain open.

### Harness Must Not Repair Decompiled Semantics (2026-09-26)

- Regression checkpoint 11:31-11:41 UTC, approximately ten minutes including
  verification: the shared runner had been replacing unresolved `arg_*` uses
  by signature position, renaming colliding parameters, aliasing numeric globals
  to harness globals by declaration order, and synthesizing missing globals.
  Those operations could mask missing Lowering/Alias/type evidence after the
  decompiler's own validation. They are removed from extraction/preparation;
  unused harness-local repair helpers were removed too. Existing helper-only
  tests now check the real extraction boundary and preserve unresolved code.
- Retained preparation is target runtime declarations, diagnostic cleanup, and
  forward declarations copied from emitted signatures. No argument, signature,
  storage-identity or missing-global repair is performed by this harness path.
  Naming-only address binding still requires implementation; no broader CLI
  cleanup or concurrent fallback refactor was changed here.
- Four controls failed before correction. The first rerun had 65 passes and
  three trailing-newline-only assertion failures; the assertions were made
  formatting-independent. Final suite: 70 passed in 61.72 seconds, seven workers
  and JIT. Real GCC controls accept the emitted parameter and reject an unresolved
  stack carrier. Scoped MyPy and test Ruff pass; the builder retains 12 legacy
  Ruff findings. Logs: `.cache/msc-no-semantic-repair-{before,after,final,ruff,mypy}.log`.
- Fresh quality-dev exits 2 on broader lint/type debt, recorded in
  `.cache/msc-no-semantic-repair-quality-dev.log`. Previous fixture round trips
  do not establish acceptance under this stricter preparation. They must be
  rerun when DOS execution is available, and any newly exposed decompiler
  failures repaired at their owning layers. No witness is admitted here.

### Address-Only Behavioral Harness Binding (2026-09-26)

- `msc6_function_targets.py` binds every selected same-build label atomically
  to a numeric address. Labels supply selection/naming only; recovery commands
  use `--addr`, `--ignore-local-sidecar-hints`, and `--no-alternate-source-c`,
  without `--proc` or source-supplied procedure kind. Missing/ambiguous labels,
  invalid names/addresses and injected prefixes produce typed refusals. Global
  or type prefixes remain an explicit unsupported obligation, not an exclusion.
- The shared function runner preserves original generated definitions, appends
  naming aliases only before the unchanged behavioral harness, and maps source
  contract names to numeric emitted names. It still verifies every selected
  function. Source-free nonzero exits cannot salvage bodies: one bounded retry
  retains the same target and then refuses. The coverage adapter now requests
  this policy by default, including for generated cases; no easier substitute
  case or duplicate compilation pipeline was introduced.
- Initial runner/policy suite: 81 passed in 71.97 seconds. The negative
  nonzero-exit control then failed before tightening that path (one fail, one
  positive pass). Runner/policy/adapter suite: 99 passed in 58.56 seconds and
  again 99 passed in 53.02 seconds after artifact retention. Two additional
  timeout/completed-exit artifact controls pass in 46.56 seconds. Host GCC
  executes a two-function bound harness and its returned-call contract; this is
  framework evidence, not DOS behavior acceptance.
- New binding owner is enrolled in Make's static gates and test ownership;
  ownership validation and scoped MyPy/new-code Ruff pass. Existing builder
  complexity remains, and fresh quality-dev exits 2 on broader lint/type debt.
  Logs: `.cache/msc-binary-target-{after,nonzero-before,final,final-mypy,ownership}.log`
  and `.cache/msc-binary-target-artifacts-{tests,controls,ruff,mypy,quality-dev}.log`.
- The retained linked `compare16` replay bound all six targets, then rejected
  `cmp_i16` at `0x10010` (exit 4, validation_failed). A follow-up with newly
  retained raw serial artifacts exits 1 on the DCE phase return-contract error:
  `run_8616` unpacks the Boolean returned from `run_8616_part5`. Revalidate that
  owner against concurrent edits before repairing it; do not suppress DCE or
  validation. Evidence: `.cache/msc-binary-target-{live,retained-live}.log` and
  `.cache/compiler-coverage/compare16-address-only-001/cmp_i16.attempt-000.*`.
- Checkpoint ended 12:03 UTC. No original/rebuilt DOS equivalence or binary
  witness is admitted; prefix-backed cases and Csmith still need full evidence.

### DCE Recheck And Address-Only Timeout (2026-09-26)

- Concurrent DCE changes resolved the phase-return crash and a transient slots
  import failure; this coverage thread did not implement those changes. The
  fresh focused module reports 77 passed in 53.99 seconds in
  `.cache/dce-phase-contract-stable.log`.
- The retained address-only `cmp_i16` replay then terminated with CLI exit 3,
  after 119.13 seconds including setup. Its 60-second analysis budget expired;
  no function body or collected tail validation was produced. Raw evidence:
  `.cache/compiler-coverage/compare16-address-only-001/cmp_i16.dce-verified.*`
  and `.cache/msc-binary-target-dce-verified-live.log`.
- The harness reports `validation_failed` with `timeout=false` for this inner
  timeout. Exit code 3 alone cannot repair classification because the CLI also
  uses it for architecture-guard failure. A structured terminal-status boundary
  remains needed; do not introduce diagnostic-substring inference as new state.
- At 12:13 UTC a bounded, in-process 180-second diagnostic replay was started
  with compact spans (`.cache/cmp16-address-profile.{c,err,txt}`). This does not
  change the routine 60-second budget or admit the case. Its result is pending;
  actual stage observations must be checked before interpreting the profile.
- That diagnostic is now terminal (exit 4): a function body is emitted and
  whole-tail validation is clean, but the integrated MS C gate cannot open
  `/dev/kvm`. The trace records 499 actual spans: direct decompilation 51.94s,
  angr core 39.14s, structuring validation prime 16.40s. It is not a cached-body
  observation or a controlled performance improvement; the isolation mode and
  deadline differ from the routine replay. No DOS behavioral witness is admitted.

### Preserve Structured Inner Timeouts In Coverage Results (2026-09-26)

- Completed 12:17 UTC. The coverage report classifier previously discarded an
  explicit final function `timeout=true` and returned decompilation/validation
  failure. It now preserves that boolean deadline evidence before reporting
  missing validation. Only the final attempt for each function counts; exit
  code 3 and truthy strings are not timeout evidence.
- Before: one failed, 40 passed in 12.64s. After: 58 result/runner tests passed
  in 12.31s (seven workers, JIT), including superseded-timeout, malformed-field,
  and real process-tree deadline controls. The existing routine result-test
  module owns the regressions. Scoped Ruff/MyPy and whitespace checks pass.
  Logs: `.cache/coverage-timeout-classification-{before,after,mypy}.log`.
- `quality-dev` exits 2 on broader typing debt, including stack-prototype
  materialization (`.cache/coverage-timeout-classification-quality-dev.log`).
  This fix consumes existing structured evidence; it does not solve the separate
  CLI-to-harness missing-timeout-field gap above, restore DOS execution, change
  routine deadlines, or establish whole-plan acceptance.

### Structured CLI Timeout Transport (2026-09-26)

- Added the lightweight versioned `cli_terminal_status.py` contract. Terminal
  direct-analysis, canonical clean-worker, and hard-exit recovery timeouts emit
  the typed reason as a JSON record on stderr. Existing exit codes and prose
  remain unchanged. The MS C profile reader consumes that record instead of
  inferring timeout from the ambiguous exit code 3 or diagnostic substrings.
  Missing records supply no evidence; malformed/unknown records raise explicitly.
- Before integration: the new profile regression failed in 56.24s. After:
  135 policy/result/builder tests passed in 60.23s, seven workers with JIT.
  Controls cover emission before hard exit, direct terminal return, repeated
  records, unknown schemas/statuses, malformed fields, and misleading prose.
  The new owner is enrolled in static gates and test ownership; scoped MyPy,
  new-code Ruff and ownership validation pass. Quality-dev exits 2 on broader
  lint/type debt. Logs: `.cache/cli-terminal-timeout-{before,after,mypy,quality-dev}.log`.
- Live one-second-timeout replay terminated with exit 3 and the exact structured
  timeout record, retaining uncollected validation and no accepted function.
  Artifacts: `.cache/cli-terminal-timeout-live.{c,err}`. The ordinary 60-second
  coverage deadline is unchanged. This closes the observed direct-timeout
  transport gap, not general terminal-status coverage or toolchain availability.
- Reading that actual retained stderr through the shared harness returns
  `timeout=True` and `HarnessAcceptanceReason.TIMEOUT` (not validation failure),
  recorded in `.cache/cli-terminal-timeout-live-profile.log`.

### Owned Implementation Identity During Round Trips (2026-09-26)

- Added a deterministic owned-Python fingerprint over root entrypoints,
  `scripts/`, `inertia_decompiler/`, and `angr_platforms/angr_platforms/`.
  Relative names and contents include untracked/uncommitted helpers; generated
  caches are excluded. Coverage reports retain before/after identities and an
  explicit `implementation_unchanged` boolean. A would-be pass becomes harness
  failure when the two differ; existing failed-stage outcomes remain intact.
- Both pre-fix controls failed (13.96s): no recorded identity, and an edited
  implementation still accepted. After: 68 focused provenance/runner/result
  tests passed in 12.71s; a fresh final rerun after extracting the report-read
  boundary also passes. Controls cover edits, addition, deletion, renaming,
  checkout relocation, generated caches and source mutation during execution.
  These tests already belong to the routine pipeline. Scoped Ruff/MyPy pass;
  quality-dev exits 2 on broader lint/type debt. Logs:
  `.cache/coverage-source-identity-{before,after,final,mypy,quality-dev}.log`.
- One local fingerprint measured 1.19s over 1,192 files / 20,235,957 bytes.
  Two observations are taken per case; this is added verification cost, not a
  runtime improvement. Measurements are machine/load-specific. The fingerprint
  does not cover installed dependencies/native modules or detect edits reverted
  between observations, and does not freeze concurrent files atomically. Full
  environment reproducibility and the required live witnesses remain open.

### Fresh DOS Execution Recheck (2026-09-26)

- The device was visible to an outer read-only check, so a fresh shared-adapter
  `compare16` run was attempted with unchanged 60-second function / 600-second
  case deadlines. It terminated after 23.88s as `build_failed`: compiler launch
  reported `/dev/kvm` missing and no EXE/decompilation was produced. Retained
  original diagnostics and report are in
  `.cache/compiler-coverage/sourcefree-compare16-002/`.
- The implementation identity also changed during this run (concurrent work);
  `implementation_unchanged=false` is retained without hiding the earlier build
  failure. This thread made no implementation edits during the run.
- A standalone `kvikdos --kvm-check` then returned 0, but a subsequent diagnostic
  process saw the device absent both before and after importing the shared
  builder and received exit 252 from its KVM probe. Evidence:
  `.cache/coverage-kvm-boundary-current.log`. The absent device in that launch
  is not caused by project imports. Device visibility in one launch is not
  evidence of executable availability in another. No sandbox bypass, permission
  change, retry-until-pass policy, or behavioral acceptance was introduced.
- A consistent permitted DOS execution environment is still required for live
  witnesses. Prefix-backed source-free harness binding, frozen pilot expansion,
  generated-case acceptance, and full required gates also remain incomplete.

### Enforced Csmith Build Pin (2026-09-26)

- Generation now refuses executables whose SHA-256 differs from the verified
  Release build recorded above, before execution or artifact-directory creation.
  Reports explicitly retain revision `35e702de01e158bc948a2024d0e187c1803d1ebb`.
  A path or matching version string is not sufficient provenance. Other builds
  require an explicit rebuild/replay checkpoint and deliberate pin update; no
  automatic or command-line bypass was added.
- The unpinned-executable control failed before repair (15.43s); afterward all
  34 generator/runner tests pass in 31.50s. Scoped Ruff/MyPy and whitespace
  checks pass; quality-dev exits 2 on broader lint/type debt. Logs:
  `.cache/csmith-build-pin-{before,after,mypy,quality-dev}.log`.
- Actual seed-2 generation in `csmith-pinned-replay-001/` and `-002/` under
  `.cache/compiler-coverage/` produced identical source SHA-256
  `353845463705795ea0822c0ecaf5f956828405507d956d661e2fa124a4d66939`, matching
  the earlier retained source. Both report generation only, no round trip or
  feature coverage. Generated-case behavioral acceptance and the subsequent
  bounded campaign remain required; Step 5 is not complete.

### Source-Free Far-Call Recovery Budget (2026-09-26)

- A fresh numeric-address replay of retained large-model FPTR `0x10034`
  (`apply_twice`) with local sidecars disabled terminates at the 180-second
  diagnostic deadline, CLI exit 3. It emits the structured timeout record;
  tail validation is uncollected. The routine deadline remains unchanged.
- Current metrics locate the dominant cost before decompilation: calling-
  convention seeding across 24 recovered functions takes 154.04s, followed by
  a second seeding pass taking 0.317s. Only about four seconds remain for the
  actual direct decompilation. Evidence: `.cache/sourcefree-apply-twice-current.*`.
  Do not infer that the older missing-argument failure is still the first blocker.
- A bounded stack-sampling replay is active in
  `.cache/sourcefree-apply-twice-stack.{c,err}`. Its first samples contain invalid
  Python frames, so they do not establish an inner hot path. Next, inspect its
  terminal result and instrument the measured `analysis_helpers.seed_calling_conventions`
  boundary if sampling remains insufficient. No semantics or budgets changed,
  and no far-call witness is admitted.

### Refuse Synthetic External Memory As Binary Evidence (2026-09-26)

- The completed stack replay located the cost in far-return-frame proof:
  `terminal_stack_cleanup_at_address_8616` traversed the synthetic CLE extern
  region through VEX fallback. A fresh loader check confirms the DOS image is
  `0x10000..0x10c72`, while `0x100012` belongs to `ExternObject`
  (`0x100000..0x107fff`). Diagnostic evidence is retained in
  `.cache/sourcefree-seeding-{timed.err,address-owner.log}`.
- Frontend block inventory now refuses CLE synthetic external memory before
  cached/direct/VEX evidence can be consumed. This is an angr-adapter ownership
  check, not an address cutoff or function-name exclusion. Standalone decoder
  protocols and real loaded code outside the main image keep their existing
  behavior. Semantics receives incomplete cleanup evidence, not a guessed ABI.
- Before: three refusal controls failed / one passed (38.16s). Initial decode
  neighborhood: 11 passed. Final focused set: 22 passed in 58.63s, including
  terminal-cleanup refusal and real-code fallback. Scoped Ruff/MyPy, ownership
  and whitespace checks pass. Tests are enrolled in the routine pipeline and
  focused ownership. Logs: `.cache/synthetic-code-refusal-*.log`.
- The same timed source-free far-call diagnostic now reaches decompilation:
  its first 24-function seeding pass takes 19.70s instead of the prior 154.04s.
  This is diagnostic evidence under changing load, not a controlled end-to-end
  speedup claim. The replay exits 4 on a postprocess observable delta attributed
  to `_normalize_function_prototype_arg_names_8616`. Both indirect calls survive
  in partial C, but parameter storage/width and validation still require repair;
  do not fix signatures or arguments in Rewrite. Artifacts:
  `.cache/sourcefree-seeding-refused.{c,err}`. No function/witness acceptance.
- Quality-dev exits 2 on broader lint/type debt. A fresh required default
  pipeline is running in `.cache/synthetic-code-refusal-pipeline.log`; its result
  remains pending. The full compiler-coverage goal stays incomplete.

### Far Function Pointer Storage Join (2026-09-26)

- The source-free typed diagnostic `.cache/sourcefree-parameter-layout.err`
  terminates with validation failure and proves three original word slots at
  machine BP+6, BP+8, BP+10. The binary call-target fact owns four bytes at
  BP+6. Previous lowering retained three arguments and moved the final word
  to BP+12, instead of consuming the contained segment word.
- Lowering now joins fully contained slots and preserves later storage and
  CVariable identity. Crossing argument ranges refuse the join. The selected
  prototype is published coherently to codegen and the function database;
  no Rewrite signature repair was added.
- Two focused controls fail before the change (61.56s); the initial complete
  function-pointer suite passes 20 tests afterward (59.19s). Scoped Ruff,
  MyPy and whitespace checks pass. Logs: `.cache/far-pointer-slot-join-*`.
  The final suite including a crossing-range refusal control passes 21 tests
  in 66.17s. Source-free binary replay
  `.cache/sourcefree-parameter-joined.{c,err}` exits 0 with validation=passed.
  Its two parameters and both indirect calls now match the original function's
  call composition; saved-register scaffolding remains visible.
- Generated C passes gcc C99 `-Wall -Werror -fsyntax-only`. A diagnostic host
  harness exercises increment/decrement composition over all 65,536 word
  inputs, checking exactly two calls and SI/DI restoration (exit 0). This is
  generated-C behavior only, not DOS-binary equivalence or a far-call witness.
  A fresh shared large-model adapter run is active at
  `.cache/compiler-coverage/sourcefree-far-slot-join-001/`.
  Its retained `FPTR.original.json` confirms original compilation/execution
  success in this launch; prior inconsistent KVM availability is not a current
  blocker for this run. Rebuilt behavior comparison remains pending.
- First shared-adapter `inc_one` attempt hits its subprocess deadline and
  retains only startup output, no function body. Both bounded attempts have
  now timed out (182.30s and 180.27s); adapter exits 1 with `timed_out` after
  392.75s total. No rebuilt compilation/execution was reached. Implementation
  fingerprints differ due to concurrent source changes; this does not hide
  the earlier timeout. This uses normal worker settings, unlike the successful 180s
  in-process `apply_twice` diagnostic; their timings are not comparable. The
  concurrent default pipeline is also still active. Investigate terminal
  attempt records before assigning a semantic failure or changing any budget.
- A normal-worker startup diagnostic is active in
  `.cache/sourcefree-inc-startup.{c,err}` with a 180s external deadline and
  entry/exit timing around project finalization, signature loading and annotation
  setup. Its timing hooks did not execute: the CLI re-executes itself when
  `PYTHONHASHSEED` is unset, discarding launcher-installed instrumentation.
  Treat this run as invalid for boundary timings. After it terminates, rerun
  with `PYTHONHASHSEED=0` supplied before startup and require hook observations.
  No production configuration or acceptance timeout was changed.
- The uninstrumented diagnostic terminated at the external deadline (exit124).
  Corrected `.cache/sourcefree-inc-startup-seeded.{c,err}` is running with
  verified hook observations: project finalization completes in 0.534s, then
  execution enters binary-signature loading and has not returned yet. Narrow
  the next timing probe to startup PAT loading/matching and catalog matching;
  do not attribute this to function recovery or remove signature evidence.
- The detailed normal-worker probe `.cache/sourcefree-inc-signature-detail.*`
  observes startup-entry lookup at 0.000s and startup PAT loading at 0.001s,
  then enters catalog matching without returning yet. The next prepared probe
  splits catalog pattern loading from pattern matching and records pattern count.
- The default pipeline has terminated with make exit2: all three lanes failed.
  Unit lane: 42 failed / 6,535 passed in 1,644.10s. Several failures include
  missing `/dev/kvm`; do not classify all failures as environmental. The run
  overlapped source edits and its pointer assertions show old widening behavior.
  A fresh current-source pointer/argument-replay suite passes all 29 tests in
  46.30s (`.cache/far-pointer-slot-join-replay.log`). Required quality-dev is
  now running separately; full acceptance remains open.
- Quality-dev subsequently exits2 on broader lint/type findings, with no
  findings naming the changed pointer module. The detailed startup diagnostic
  times catalog matching at 116.756s and then reaches recovery, but its 180s
  external budget expires before completion. This identifies cost, not acceptance.
- A catalog-only probe now uses a new isolated result-cache directory, leaving
  shared caches untouched. Its first launcher failed before measurement on
  missing explicit loader arguments; the corrected run is active in
  `.cache/catalog-match-profile-002.log`, splitting catalog loading and matching.

### Necessary-Literal PAT Candidate Filter (2026-09-26)

- The isolated baseline completes: 49,283 patterns against 3,187 image bytes,
  Python-regex backend; pattern load 2.817s, matching 66.287s, total catalog
  69.799s, 25 labels/ranges. Result cache retained under
  `.cache/catalog-profile-mwkmenit/`; no broad speedup claim.
- Optional-evidence matching now rejects candidates only when a required
  literal from the existing checked PAT prefix/tail is absent. Wildcards and
  unchecked bytes do not strengthen evidence; surviving candidates retain the
  exact existing backend. A typed cached field and versioned pattern-cache
  filename preserve the projection; catalog result identity includes its owner.
- Before: two work-avoidance controls fail, two parity controls pass (6.31s).
  After: all 11 focused tests pass (92.83s), including existing matcher/cache
  tests and raw/cached wildcard, overlap, newline, ambiguity and tail controls.
  New helper/test Ruff and helper MyPy pass. Whole legacy catalog-module Ruff
  reports 15 findings in untouched functions. Routine/fast pipeline and ownership
  enrollment added. Logs: `.cache/pat-literal-filter-*`.
- First post-change timing attempt expires before matching because default
  catalog resolution rebuilds on implementation changes. Do not compare that
  with matcher time. `.cache/catalog-match-filtered-artifact.log` is now running
  against the retained baseline catalog directly with an isolated result cache.
  Exact full-catalog result parity, timing, post-change gates and DOS acceptance
  remain required. The full compiler-coverage objective is not complete.
- Retained-catalog comparison completes with byte-for-byte equivalent sorted
  JSON results (all 25 labels/ranges, compiler names and source formats).
  Matching takes 0.621s, but new-format pattern construction takes 130.698s;
  that first call is not an overall speedup. A second fresh-result-cache run
  reuses pattern specs: load 2.188s, matching 0.658s, catalog total 3.139s,
  again exact result parity versus the 69.799s warm-spec baseline. These are
  component timings under observed load, not whole-decompiler acceptance.
  Artifacts: `.cache/catalog-match-filtered-{artifact,warm-specs}.log`.
- Ownership and whitespace checks pass. New post-change quality-dev exits2
  on broader lint/type/mypyc debt (`.cache/pat-literal-filter-quality-dev.log`).
  A normal-worker source-free `inc_one` replay is active in
  `.cache/sourcefree-inc-filtered.{c,err}` with the identical retained catalog
  explicitly selected and unchanged 60s analysis / 180s process deadlines.
  Default-catalog rebuilding and final DOS round-trip acceptance remain open.
- The normal-worker replay terminates at its 180s external deadline (exit124).
  It rebuilt a second 62MB specs file because relative/absolute catalog paths
  used different keys; no final CLI acceptance was produced. Specs were also
  stored separately under each binary artifact directory, repeating cold work.
- Shared catalog-spec caching now defaults to the existing decompilation-cache
  root; explicit cache directories retain precedence. PAT inputs canonicalize
  before both parsing/provenance and keying, without altering OMF-generation
  input-path behavior. Pattern identity includes the literal implementation;
  missing implementation files raise instead of sharing an unknown identity.
  Two initial controls fail before repair (8.80s); 11 focused cache/filter tests
  pass afterward (43.00s). A strengthened provenance control then fails (8.28s)
  and is repaired; the final 11-test rerun passes in 48.89s, recorded in
  `.cache/pat-cache-coherent-final.log`. New test/helper Ruff, ownership and
  whitespace checks pass. Normal-worker replay with the final cache behavior
  is active in `.cache/sourcefree-inc-shared-cache.{c,err}` with unchanged limits.
- The first shared-spec catalog probe returns exact baseline results: cold load
  58.206s, matching 1.315s, total 59.853s. This precedes the final provenance
  adjustment and is not its acceptance. Existing cached files were preserved;
  no timeout, signature exclusion, or DOS oracle was weakened.
- That cold normal-worker replay also reaches its 180s process deadline
  (exit124): startup occupies about 114s before recovery, which reaches
  decompilation but does not return final acceptance. One explicitly warm-cache
  comparison is active in `.cache/sourcefree-inc-shared-warm.{c,err}` with the
  same command and deadlines. Retain the cold timeout independently; a warm
  result cannot prove cold-start acceptance. Post-cache-change quality-dev is
  separately running in `.cache/pat-cache-identity-quality-dev.log`.
- The warm normal-worker `inc_one` replay completes with exit0,
  `validation=passed`, and the expected single `arg_6 + 1` return. Its generated
  C passes gcc C99 `-Wall -Werror -fsyntax-only`. The cold timeout remains a
  failure; these observations do not establish cold-start acceptance.
- Post-cache quality-dev exits2 on broader lint/type/mypyc debt. A fresh full
  large-model shared-adapter run is active at
  `.cache/compiler-coverage/sourcefree-far-shared-catalog-001/`, explicitly
  selecting/fingerprinting the same full catalog and retaining unchanged case
  and function deadlines. This tests spec reuse across a new artifact directory;
  default-catalog construction and full feature-witness admission remain open.
- In the new full-adapter run, original compilation/execution succeeds and
  catalog startup takes about six seconds, confirming cross-artifact reuse.
  First `inc_one` attempt then exhausts the unchanged 60s recovery budget,
  with only 14s left for decompilation. The existing second attempt passes
  validation and the adapter advances. Both attempt artifacts remain retained;
  the fixture run is still active and is not accepted.
- The shared-adapter run terminates with `outcome=timed_out`: original DOS
  execution succeeds; `inc_one` (second attempt) and `dec_one` validate, but
  `apply_twice` times out on both attempts. Builder decompilation time is
  487.74s. Retained attempt logs and `coverage-result.json` distinguish this
  failure from the earlier focused semantic proof; no witness is admitted.
  The earlier default pipeline already terminated unsuccessfully as recorded
  above; it is not pending. Required post-change gates remain open.
- Address-only fixture targets now reuse the existing batch job-file transport.
  The job carries numeric addresses and explicitly disables alternate-source C
  and local sidecar hints; fixture names remain artifact/harness bindings only.
  Normal direct-worker isolation and all validation/oracle checks are retained.
  Two controls fail before implementation; afterward all 95 adapter and
  binary-recovery-policy tests pass (54.20s). Batch/test/ownership Ruff passes;
  the builder retains 12 complexity/condition findings. Quality-dev exits2 on
  broader lint/type/mypyc findings (`.cache/sourcefree-batch-quality-dev.log`).
  A full large-model run is active at
  `.cache/compiler-coverage/sourcefree-far-batch-001/`, using the same retained
  catalog and unchanged deadlines. Runtime benefit and DOS acceptance are
  unproven; this is not a new witness or completion of the coverage plan.
- The batch run terminates `timed_out` after 601.29s at the case deadline.
  `implementation_unchanged=false` also records concurrent source changes;
  this run cannot be acceptance evidence even apart from its timeout. Its retained
  batch report has three exit0/validated functions (`select_and_apply`,
  `combine_args`, `nested_arguments`) and three exit3/timeouts (`inc_one`,
  `dec_one`, `apply_twice`). Serial fallback begins afterward but does not
  complete the round trip. Observed host load is about 28 on 8 CPUs; these
  timings do not establish an end-to-end speedup or isolate a regression.
- Two bounded normal-isolation diagnostic replays also time out. Parent stacks
  in `.cache/direct-parent-wait-1408032.stacks` show CFG construction, lifting,
  and emulator setup during recovery; one seeding pass takes 28.256s. The
  custom worker sampling hook fires but its files remain empty, so they are
  not evidence of an idle worker. A further probe now uses the existing
  `INERTIA_FORK_STACK_DUMP_SEC` / `INERTIA_THREAD_STACK_DUMP_SEC` diagnostics
  in `.cache/direct-native-stacks.{c,err}` to cover nested workers. No timeout
  limit, isolation policy, validation requirement, or oracle has been relaxed.
- Native nested-worker diagnostics complete with exit0 and `validation=passed`
  for `inc_one` (`.cache/direct-native-stacks.{c,err}`). Samples include
  lifting/Capstone, project callsite census and trusted-C rollback copying.
  This is a diagnostic function result, not a DOS round trip or proof of one
  dominant hotspot; the earlier timeouts remain recorded independently.
- Batch fallback previously discarded every accepted body on its first failed
  function, and the newly enabled source-free batch path inherited the named
  path's nonzero-exit exception. Five focused controls reproduce the defects
  before repair (60.16s): timeout, nonzero exit, missing body, missing record and
  uncollected validation. The adapter now retains accepted bodies by target,
  retries only missing/failed jobs, and reconstructs original function order.
  Source-free batch acceptance requires zero exit, matching its serial policy;
  named legacy behavior is unchanged. Existing per-function checks and DOS
  oracle remain required. Post-repair focused tests are running; quality-dev
  exits2 on broader debt (`.cache/batch-partial-quality-dev.log`).
- The first post-repair suite catches another acceptance gap (99 pass / one
  fails): an unrecognized or absent whole-tail verdict was accepted because
  only known failures were rejected. The shared acceptance owner now requires
  affirmative typed clean/passed status and otherwise returns the existing
  uncollected refusal; specific failure reasons retain precedence. No added
  text-pattern heuristic is used. A sixth missing-validation control is added.
  All 101 adapter/policy tests pass in 57.64s
  (`.cache/batch-partial-proof-after.log`). Test Ruff and whitespace pass;
  builder Ruff still reports 12 complexity/condition findings. Fresh full
  large-model replay is active at
  `.cache/compiler-coverage/sourcefree-far-batch-partial-001/` with unchanged
  catalog and deadlines. No new witness or full-plan completion is claimed.
  Final post-edit quality-dev exits2 on broader lint/type/mypyc findings in
  `.cache/batch-partial-proof-quality-dev.log`; the required gate is not green.
- A normal-isolation repeated-work probe (`.cache/coverage-repeated-work.*`)
  terminates exit3/timeout. Confirmed hooks measure two completed child census
  calls at 0.516s wall / 0.081s CPU and 72 child neighbor scans at 0.377s wall /
  0.078s CPU (nested timings, do not add them). These completed collections
  are not the dominant cost in this run. No rollback snapshot completes, so
  the empty snapshot measurements do not prove absence or identify its cost.
  The source-free partial-batch replay has completed its batch with two
  validated functions and four timeouts; serial retries are still active.
  The next required small-model recheck is `compare16`, whose latest retained
  run failed at compiler launch due to missing KVM, not decompiler acceptance.
  Far-model obligations remain open and are not replaced by that recheck.
- The partial-batch far-model run terminates `timed_out` after 601.30s;
  `implementation_unchanged=false` records concurrent source edits. It is not
  accepted. Both successful batch artifacts remain retained; the serial retry
  still exhausts the case budget before a complete DOS rebuild/run.
  The required small-model `compare16` adapter recheck is now active at
  `.cache/compiler-coverage/sourcefree-compare16-batch-003/` with the same
  catalog and unchanged 60s function / 600s case deadlines. No new witness.
- `compare16` now builds and original DOS execution returns the expected 255,
  passing the former KVM launch failure. Its initial functions time out; the
  run remains diagnostic and has overlapped the optimization below.
- An explicitly non-acceptance 180s-analysis/240s-process profiling replay of
  `inc_one` completes with validation passed. Normal 60s failures are retained.
  `.cache/coverage-repeated-work-long.*` measures 120 rollback AST snapshots:
  19.384s wall / 2.803s CPU. Ten completed census calls cost 0.173s wall /
  0.155s CPU; 294 neighbor scans cost 0.147s wall / 0.134s CPU (nested values).
  Counts and CPU time identify snapshot work; wall times remain load-sensitive.
- The CLI call-loss guard previously copied the AST before every pass even
  when its exact pre-pass count was zero and named-call coverage was inactive.
  A zero count cannot decrease: this branch now omits only the unusable copy,
  retaining post-pass checks and all snapshots for existing/named calls. Two
  work-avoidance controls fail before repair; three call-loss/named-call controls
  pass (68.97s). The full rollback test file is enrolled in the routine pipeline.
  Touched-file Ruff passes; focused post-change tests and quality-dev are
  running. Runtime/C-output parity and normal-budget acceptance remain due.
- The first after-run still fails both work-avoidance controls: the patch had
  matched a different snapshot site. That site was restored unchanged; the
  final diff changes only `_rewrite_round_apply_8616`. All 11 rollback tests
  now pass (69.97s), including actual call deletion and named-call replacement
  refusals. Scoped Ruff and whitespace pass. A same-budget diagnostic comparison
  is active in `.cache/coverage-repeated-work-no-empty-snapshot.{c,err}`; it
  remains profiling-only, not a normal-budget acceptance run. Final quality-dev
  is running separately; no whole-pipeline or DOS-witness claim is made.
- Final post-edit quality-dev terminates exit2 on broader lint/type/mypyc
  findings (`.cache/zero-call-snapshot-final-quality-dev.log`). The touched
  optimization, tests and pipeline enrollment pass scoped Ruff; full gates
  remain open.
- The retained small-model `compare16` run terminates `timed_out` at 601.35s
  with `implementation_unchanged=false`. Its batch validates `clamp_u16` and
  `in_window_i16`; four other functions time out. Original compilation and
  execution passed, but the fixture is not accepted and no witness is admitted.
- The post-optimization profiling replay completes exit0 with validation passed.
  Snapshot calls fall from 120 to 22; observed snapshot cost falls from 19.384s
  wall / 2.803s CPU to 2.319s wall / 0.338s CPU. Counts identify avoided work;
  timings are component observations under changing load, not an end-to-end
  speed claim. Full generated stdout is byte-identical to the retained before
  artifact and passes GCC C99 `-Wall -Werror -fsyntax-only`. The normal 60s
  analysis / 180s process replay is active at `.cache/zero-call-snapshot-normal.*`.
  Both profiling runs used a diagnostic-only 180s analysis budget; they do not
  supersede normal-budget failures or establish DOS round-trip acceptance.
- The first normal-budget replay exits0 with byte-identical C and validation
  passed, but explicitly reports direct-request/function cache hits. It proves
  validated reuse only, not fresh execution within 60s. A new probe relocates
  JSON recovery/result entries into `.cache/zero-call-fresh-json-001/` while
  preserving shared caches and existing immutable PAT specs. It is running
  with normal 60s analysis / 180s process bounds in
  `.cache/zero-call-fresh-json.{c,err}`; actual stage work must be confirmed.
- The hard development gate exits2 on repository Ruff findings, including
  builder complexity debt (`.cache/zero-call-snapshot-quality-hard.log`). This
  is a failed required gate, not a pass inferred from focused optimization tests.
- The fresh-JSON normal-budget probe terminates exit3/timeout, with actual
  recovery/decompilation work and uncollected validation. The snapshot reduction
  alone does not establish fresh 60s acceptance under current load.
- A fresh-JSON normal-isolation cProfile diagnostic uses a clearly separate
  180s analysis / 240s process allowance. It completes exit0/validation passed,
  with generated C byte-identical to the retained post-snapshot artifact.
  `.cache/direct-job-profile-1428223.prof` records about 12.0M calls and 56s
  profiled worker time. Deep C-AST traversal accounts for 16.406s cumulative;
  `_structured_codegen_node_8616` is called 619,247 times, and slot discovery
  103,160 times. These are profiler/load-sensitive costs, not a speed claim.
  The next bounded investigation is repeated AST boundary classification and
  traversal, preserving every validation pass, edge, ordering and refusal.
- Exact `CConstant`/`CVariable` traversal now uses their explicit child-field
  schema, omitting inherited display-only metadata. Subclasses and same-named
  extensions retain dynamic discovery; nested constant reference children remain
  traversed. Two work-avoidance controls failed before the change; all 39 AST
  and rollback tests passed afterward (61.90s). The full AST test file is enrolled
  in the routine pipeline. A focused typing check caught untyped third-party
  `__slots__` access; explicit tuples resolve it, with an installed-schema drift
  assertion added. Final focused MyPy and Ruff pass; all 39 final-source tests
  pass in 68.10s (`.cache/leaf-schema-final-tests.log`).
  Quality-dev exits2 on broader lint/type/mypyc findings
  (`.cache/leaf-schema-quality-dev.log`); required gates remain open.
- The fresh-JSON profiling replay completes exit0/validation passed and produces
  byte-identical, GCC-clean C (`.cache/leaf-schema-profile.{c,err}`). Classifier
  calls fall from 619247 to 521583; the principal deep walker records 16.406s
  before versus 13.640s after. Other component timings vary under load, so this
  demonstrates avoided work, not an end-to-end speedup. The diagnostic worker
  used the pre-typing-cleanup form of the equivalent field schema and a separate
  180s analysis / 240s process budget. Final-source normal-budget replay is active
  in `.cache/leaf-schema-normal.{c,err}`, with fresh JSON namespace, shared
  immutable PAT specs, normal isolation and unchanged 60s/180s bounds. No new
  DOS round-trip witness is admitted.
- The final-source fresh-JSON normal-budget replay completes exit0 with
  `validation=passed` and whole-tail clean. Logs show actual recovery and
  decompilation, not a direct-request/function result-cache hit. Generated C is
  byte-identical to the baseline and passes GCC C99 `-Wall -Werror -fsyntax-only`.
  This establishes one fresh `inc_one` completion under the unchanged 60s
  analysis budget, not stable timing or the outstanding full large-model round
  trip. Probe observations span 17:18:00-17:19:14 local time on 2026-09-26;
  startup is outside the analysis budget. Next acceptance work remains the full
  source-free fixture, original/rebuilt DOS oracle and required project gates.
- The full large-model adapter replay at
  `.cache/compiler-coverage/sourcefree-far-leaf-schema-001/` terminates
  `build_failed` after 24.43s, with unchanged implementation. Both compiler and
  linker report `/dev/kvm` missing; no decompilation runs. A subsequent direct
  execution confirms KVM is available again and the retained original EXE returns
  the expected 255. A fresh full replay is active at
  `.cache/compiler-coverage/sourcefree-far-leaf-schema-002/`, with the same
  signature catalog and unchanged 60s function / 600s case deadlines. The failed
  attempt remains retained; neither the original-only execution nor this pending
  replay admits a witness.
- Replay `sourcefree-far-leaf-schema-002` also terminates `build_failed` (23.28s)
  with unchanged implementation and missing `/dev/kvm` at compiler/linker launch.
  Device presence differs across direct checks; one Python subprocess probe also
  confirms it absent. Do not infer stable availability from a successful isolated
  check. No device permissions or execution sandbox were changed. The existing
  six-address source-free batch is now running against the retained linked EXE in
  `.cache/compiler-coverage/retained-far-leaf-schema-batch-001/` with 60s function
  budgets. This is decompiler-only evidence, not an original/rebuilt DOS round
  trip. Full acceptance still requires reliable KVM-backed compiler/runtime runs.
- The retained-EXE batch exits3 before writing a batch report, leaving only
  `inc_one` timeout artifacts. Its recovery seeding reports 51.421s and the
  decompiler receives only a 1s remaining allowance. One earlier successful
  single-function run does not establish reliable batch acceptance. The abrupt
  termination cause is still unproven; no functions or witnesses are accepted.
- Batch output was buffered entirely in memory until each CLI job returned;
  exceptions and process termination could discard the active function's logs.
  Three focused controls reproduce absent live/error artifacts before repair
  (3 fail / 2 pass, 11.34s). The existing runner now writes line-buffered artifact
  streams, retaining completed lines without waiting for function return, while
  preserving SystemExit codes, loud unexpected errors and restored process
  globals. Runtime tests are enrolled in the routine pipeline and ownership map.
  All 42 runtime/binary-policy tests pass (65.93s); scoped Ruff and MyPy with
  explicit package bases pass. Plain MyPy encounters duplicate module discovery;
  quality-dev exits2 on broader lint/type/mypyc debt
  (`.cache/batch-stream-quality-dev.log`). A retained-EXE replay using streamed
  logs is active at `.cache/compiler-coverage/retained-far-stream-batch-001/` to
  expose the abrupt-stop boundary. This tooling repair is not DOS acceptance.
- Streamed replay `retained-far-stream-batch-001` terminates exit3 during startup:
  the runtime import guard detects concurrent decompiler-source changes. No job
  starts. The next diagnostic attempt uses `retained-far-stream-batch-002`, with
  unchanged budgets and evidence policy. Runtime has a hard timeout exit path
  (`emit_timeout_and_exit`); without the missing active-job log this remains only
  a candidate explanation for the earlier batch termination, not a proven cause.
- Batch reports now checkpoint completed jobs atomically before the next job,
  starting with an empty report so reused directories cannot expose stale accepted
  records. Two controls fail before implementation (10.51s); 108 runner/adapter/
  policy tests pass afterward (60.34s). Interrupted/missing jobs stay absent and
  must be retried; nonzero records retain their failure codes. No acceptance
  policy, function selection or timeout is weakened.
- Live streamed replay002 exposes a capture regression: loggers lazily created
  in the first CLI job retain its file after closure and emit logging errors in
  later jobs. A focused two-job control reproduces it (9.34s). Console handlers
  attached to the exact batch streams now follow each active job and are rebound
  before closing its files; unrelated file handlers are not redirected. Final
  runtime/adapter/policy suite: 109 passed (63.60s); scoped Ruff and MyPy pass.
  Replay002 still uses the pre-fix loaded code and has reached its third function
  after two timeouts, so it cannot validate the logger fix or establish reliable
  compiler coverage. The prior hard-exit hypothesis remains unconfirmed.
- Final checkpoint/logger quality-dev exits2 on broader lint/type/mypyc findings
  (`.cache/batch-checkpoint-quality-dev.log`). Focused passes do not supersede
  this failed required gate or the open DOS round-trip obligations.
- Streamed replay002 is terminal (exit3), not still running. `inc_one` and
  `dec_one` time out normally; `apply_twice` retains the explicit recovery-timeout
  comment emitted by `emit_timeout_and_exit`, followed by terminal TIMEOUT and
  process exit3 before any final batch report. Streaming therefore exposes the
  hard-exit boundary that the former buffers lost. Do not replace the hard exit
  with an ordinary return while timed-out analysis threads may remain alive.
  Next repair: isolate each CLI job at a process boundary so hard timeouts become
  failed records and subsequent jobs can run, preserving existing deadlines,
  semantic refusals, deterministic ordering and partial-result checkpoints.
- Focused batch jobs now run in disposable children of the warmed parent using
  the existing bounded-fork/process-tree owner. `ForkChildExitError` carries the
  OS-decoded return code without parsing prose; nonzero hard exits become failed
  batch records, while zero-without-result and unexpected exceptions stay loud.
  Parent checkpoints survive, subsequent jobs run, and descendant cleanup remains
  owned by the existing fork helper. The 120s setup allowance is extracted into
  one shared tooling owner used by serial and batch paths; the inner analysis
  budgets and outer case deadline remain unchanged.
- A real subprocess control fails before isolation and passes afterward: its
  first CLI job calls `os._exit(3)`, the second emits output and returns0, and the
  batch returns1 with ordered failed/successful records. Final runtime/adapter/
  policy/fork suite: 118 passed in 71.92s, including hard-exit codes, missing IPC
  refusal, job-specific outer budget and descendant cleanup. Tests now consume
  report argv rather than assume child mutations reach the parent. Fork tests are
  enrolled in the routine pipeline. Eighteen warnings include fork/thread
  deprecations and the existing firmware layout warning; they are not suppressed.
  Scoped Ruff/MyPy pass after correcting the fork decoder's unconstrained return
  TypeVar at its existing serialization boundary. Builder Ruff retains 12
  complexity/condition findings; quality-dev exits2 on broader debt
  (`.cache/batch-isolation-quality-dev.log`).
- The final isolated six-function replay is active at
  `.cache/compiler-coverage/retained-far-isolated-batch-001/` with the retained
  EXE/catalog, unchanged 60s analysis / 180s process allowance and 600s external
  bound. It must demonstrate continuation through the previously fatal timeout;
  no speedup or DOS round-trip acceptance is inferred from focused tests.
- Live isolated replay confirms the intended boundary: `inc_one` hard-exits3
  after 141.00s, the parent writes its failed checkpoint, and `dec_one` starts.
  The retained diagnostic explicitly records `fork child exited without result
  (exitcode=3)`. This proves continuation through one formerly fatal timeout, not
  successful decompilation. The six-function replay remains active.
- Isolated replay001 reaches its 600s external deadline (exit124). Checkpoints
  preserve `inc_one` exit3/141.00s, `dec_one` exit3/160.35s and `apply_twice`
  exit3/180.63s; the last is an outer process timeout. `select_and_apply` starts
  but remains incomplete, and the final two jobs are not reached. There are no
  accepted functions or witnesses. Both hard-exit and outer-timeout continuation
  are observed, but total runtime is still unacceptable. Shell `timeout` leaves
  the active isolated child's separate process group alive; it exits before the
  explicit cleanup signal is delivered, and a process-list check confirms the
  group is gone. Future diagnostics must use the existing
  process-tree-aware runner, not a bare shell timeout around this batch.
- `dec_one` reports 42.493s wall time in calling-convention seeding. The next
  measured investigation is that phase, not speculative semantic pruning. A
  fresh-JSON diagnostic launcher at `.cache/profile_cc_seeding.py` profiles the
  actual seeding thread with `time.thread_time`, separately recording wall time
  and thread CPU; immutable PAT specifications remain shared. It is prepared,
  not yet acceptance evidence or a completed profile. The probe is now active in
  `.cache/cc-seeding-diagnostic.log` under the existing process-tree-aware runner,
  with diagnostic-only 180s analysis / 240s external bounds. Normal acceptance
  deadlines remain unchanged.
- The first thread-CPU probe reaches its 240s diagnostic bound; the runner kills
  and reaps its tree. Only the initial one-candidate profile completes: 1.321s
  wall / 0.208s thread CPU, 46806 calls, with wide-stack prototype analysis and
  block lifting dominating that small sample. The larger CFG profile begins but
  does not finish, so no cost breakdown is inferred for it. The diagnostic now
  saves each completed candidate/finalization/terminal-return operation into its
  fresh cache namespace, avoiding both all-or-nothing CFG profiles and reused-PID
  filename collisions. Probe002 is active in `.cache/cc-seeding-diagnostic-002.log`
  under the same diagnostic-only bounds and process-tree cleanup. No production
  semantic change or normal-budget acceptance is claimed.
- Probe002 terminates at the same diagnostic bound but retains 27 completed
  operation profiles. Several nontrivial candidates are dominated by wide-stack
  argument analysis: the largest saved candidate records about 2.222s thread CPU,
  with 2.001s in wide-stack prototype evidence and repeated block construction.
  One other candidate records 12.603s wall / 0.508s thread CPU. These establish
  local CPU work and a distinct wall/CPU gap, not an end-to-end speed guarantee.
  Current source shows ABI instruction collectors call `factory.block` without
  a size; installed angr eagerly lifts such blocks to determine their extent,
  whereas a supplied CFG-proven size permits Capstone decoding without that lift.
  A bounded optimization is under test: reuse available positive integer CFG
  sizes, preserve unsized fallback otherwise, and propagate provider failures.
- The size-reuse baseline first has a test-import collection error (not behavioral
  evidence); after correction, two intended controls fail and five fallback
  controls pass in 55.75s. The frontend ABI block iterator now uses only positive
  integer CFG-proven sizes, retaining unsized discovery when that evidence is
  unavailable/invalid and propagating size-provider failures. Both consumers are
  instruction decoders; no signature guessing, text recovery or semantic pass
  deletion is introduced. The 28-test ABI suite passes in 67.20s; an additional
  installed-angr byte-decoding control passes in 75.02s with VEX lifting forbidden.
  The full test file is enrolled in the routine pipeline. Scoped Ruff/MyPy pass;
  quality-dev exits2 on broader lint/type/mypyc findings
  (`.cache/abi-block-size-quality-dev.log`).
- A fresh-JSON `inc_one` replay is active at `.cache/abi-block-size-normal.{c,err}`
  using normal 60s analysis / 180s process bounds and process-tree-aware cleanup.
  Output parity, validation and end-to-end runtime improvement remain unproven;
  focused work-avoidance tests alone do not admit a DOS witness.
- The fresh normal-budget size-reuse replay terminates exit3/timeout with
  uncollected validation, not a successful parity result. A separate fresh-JSON
  `inc_one` diagnostic is active at `.cache/abi-block-size-parity.{c,err}` with
  explicitly non-acceptance 180s analysis / 240s process bounds and tree cleanup,
  to check generated-C parity and validation independently of deadline acceptance.
- The parity diagnostic exits3 at the runtime import guard because sources change
  during startup; it does not decompile. The user is asked non-blockingly to pause
  concurrent edits during validation. Separately, batch startup inspection confirms
  the CLI proxy resolves `main` lazily into `cli_core` inside each disposable
  child. The batch parent is not yet actually sharing those heavy imports.
  A bounded regression is being added to require entrypoint resolution in the
  parent, without running analysis there or removing process isolation.
- The lazy-entrypoint parent-PID control fails before the warmup change, then
  the runtime/builder/binary-policy suite passes all 113 tests in 63.40s
  (`.cache/batch-warm-import-after.log`). Scoped Ruff/MyPy pass. The batch now
  resolves the CLI entrypoint once before forking; actual analysis and hard exits
  remain isolated. Quality-dev exits2 on broader lint/type failures
  (`.cache/batch-warm-import-quality-dev.log`), not a green development gate.
  A retained six-job replay runs in
  `.cache/compiler-coverage/retained-far-warm-parent-001/` with the unchanged
  60s function deadlines and 600s external bound, using tree-aware cleanup.
  This is a runtime diagnostic; no new witness or end-to-end gain is yet proven.
- Warm-parent replay checkpoints `inc_one` exit3 after 100.13s: the normal
  analysis budget expires, tail validation is uncollected, and no function is
  accepted. The batch continues into `dec_one`. Calling-convention seeding for
  25 functions records 3802ms, but shared caches, concurrent edits and machine
  load preclude attributing timing differences solely to this patch. Keep the
  remaining jobs running under the original bound; do not relax acceptance.
- The warm-parent replay terminates at 600.93s with tree-aware cleanup; its
  batch root is confirmed gone. Completed records: `inc_one` exit3/100.13s,
  `dec_one` exit3/115.57s, `apply_twice` exit3/100.66s, `select_and_apply`
  exit0/96.13s and `combine_args` exit0/82.72s. Both exit0 functions report
  validation passed; the final `nested_arguments` job is interrupted without
  a completed record. This is not full round-trip acceptance or a new witness.
  A fresh-JSON normal-isolation `inc_one` CPU profile/parity run is active in
  `.cache/abi-block-size-parity-002.{c,err}` with the separate 180s analysis /
  240s diagnostic process allowance. It must not be counted as normal-budget
  acceptance. The profile will select the next measured repair, not guesses
  based on timeout logs alone.
- The parity-002 diagnostic reaches its 240s process bound (242.45s including
  cleanup) before entering the profiled analysis worker. Its log ends after
  project construction; no CPU profile, output parity or validation evidence is
  produced. Do not interpret the missing profile as a cheap analysis stage.
  Startup stack sampling is required before another worker-only profile.
- Startup sampling (`.cache/startup-stack-001.err`) terminates at 180.76s.
  After the initial import sample, repeated stacks are in PAT parsing and
  regex-spec construction, before recovery. The current canonical catalog
  cache key `09645b9378d1` has no spec artifact; older generations exist.
  The 36,896,804-byte catalog is therefore being rebuilt, not warm-loaded.
  A bounded standalone warmup of the existing cache owner is running
  (`.cache/catalog-spec-warm-current.log`, 600s tooling bound). This does not
  relax decompiler deadlines or grant coverage; a fresh-result replay follows.
- The standalone current-key spec warmup completes successfully: 49,283 specs
  in 115.54s. A fresh-JSON `inc_one` retry is active at
  `.cache/post-warm-normal-001.{c,err}` with normal 60s analysis / 180s process
  bounds, source/debug hints disabled, and tree-aware cleanup. Only immutable
  signature specs are warm; analysis/result caches use a new namespace.
- The post-warm normal retry exits3 after 118.80s: it gets through catalog setup
  but recovery leaves only 4s for decompilation. Calling-convention seeding for
  25 functions records 34,589ms; validation remains uncollected. The wide timing
  variation under shared load is not evidence of deterministic speedup or
  slowdown. Fresh diagnostic profiling is active at
  `.cache/post-warm-profile-001.{c,err}` using the existing worker hook and
  separate 180s/240s diagnostic bounds. No new DOS witness is accepted.
- The first post-warm worker profile attempt is rejected by the runtime source
  guard after 40.33s, with no worker data. The next fresh diagnostic attempt
  finishes exit0 in 133.70s with validation passed, no watched source timestamp
  changes, and generated C byte-identical to `.cache/direct-job-profile.c`.
  It records about 58.37s profiled worker CPU/wall: 14.77s cumulative in
  Structuring validation baseline and 10.20s in the CLI rewrite loop. The
  180s diagnostic allowance is not normal-budget acceptance.
- A separate fresh-JSON normal retry exits3 in 127.35s. The 25-function ABI
  seeding pass takes 10.17s, but decompilation starts with 13s remaining and
  times out; tail validation is uncollected. The 60s functional budget is still
  unmet. A full-process cProfile probe, retaining a profile on terminal timeout,
  is active at `.cache/full-process-normal-001.{c,err}` to explain the remaining
  pre-decompilation time before selecting a safe optimization.
- The full-process normal profile exits3 after 155.77s; cProfile records
  `_recover_target_cfg_8616` at 13.63s and neighbor CFG extension at 41.85s,
  of which CFGFast uses 24.63s and ABI seeding 17.20s. The function reaches
  decompilation with 9s left. This explains the normal deadline failure on
  that loaded run without weakening the deadline or skipping recovery.
- A corrected source-free neighbor probe records a direct far-call seed at
  callsite `0x10006` targeting `0x104b0`, so the neighbor extension has real
  binary evidence. The first probe missed the CLI's imported reference; its
  absence of data was not evidence that no calls existed. After host load
  changed, the corrected probe exits0/validation passed in 10.34s. A fresh-JSON
  normal-budget retry exits0/validation passed in 16.81s with C byte-identical
  to the prior diagnostic artifact. This proves one normal-budget function
  result on the current host; it does not establish the full compiler witness.
- The `function_pointers` small-model full round trip is retried three times
  but each builder reports `build_failed` before decompilation. Its compiler and
  linker report `/dev/kvm` ENOENT. A direct invocation of the identical MS C
  compile command succeeds; a subprocess-depth KVM check also succeeds.
  Instrumentation immediately before the builder's kvikdos calls reports
  `/dev/kvm` absent, and syscall tracing confirms both compiler/linker child
  opens return ENOENT. Thus the available device differs by execution context;
  no source-free or generated-C success is inferred from these build failures.
  A six-address retained-EXE batch with fresh JSON results and unchanged 60s
  function deadlines is active at
  `.cache/compiler-coverage/retained-far-fresh-batch-001/` under a 600s
  tree-aware bound. It can advance decompiler evidence while compiler execution
  remains unavailable in this runner context.
- The retained six-address batch completes exit0 in 137.23s. All six function
  jobs return 0 with tail validation passed and their individual emitted C units
  pass `gcc -std=c99 -Wall -Werror -fsyntax-only`. This is function-level evidence,
  not a full compiler round trip. Comparing their actual source-required call
  interfaces finds a program-level defect: `apply_twice` defines `sub_10034`
  with a function-pointer argument, while `select_and_apply` declares/calls the
  same target with three scalar words. GCC LTO `-r` rejects this as
  `lto-type-mismatch`, confirming that six independent syntax passes do not
  establish a coherent emitted program.
- `scripts/compiler_coverage_cross_unit.py` now owns a typed optional GCC LTO
  cross-unit gate, exposed by `scripts/batch_decompile_procs.py --check-cross-unit`.
  A requested check runs after all focused jobs, persists the verdict and full
  diagnostics in `batch_report.json`, and makes the batch exit nonzero unless
  the cross-unit link passes. Four focused controls cover matching and mismatched
  interfaces, unavailable compiler, and one-unit refusal; the batch regression
  failed before the flag existed and passes after. The real six-unit artifact
  returns `compilation_failed` with the exact `sub_10034` mismatch. The gate is
  opt-in until the owning interprocedural type recovery is repaired and the
  compiler-coverage runner can use it without conflating batch drafts with
  final rebuilt C. Failed function jobs now record a typed `not_attempted`
  cross-unit verdict instead of omitting the requested stage. It does not
  repair the missing logical far-pointer argument.
- A fresh `function_pointers` small-model full-round-trip retry finally built
  and ran the original linked EXE after `/dev/kvm` became visible: original exit
  code 255. Under heavy shared CPU load, three initial focused jobs timed out
  at the unchanged 60s analysis deadline and were retried; the 843.10s runner
  ultimately returned `behavior_failed`. The rebuilt DOS EXE ran and exited 4,
  not 255. Its generated `select_and_apply` passes a literal original-binary
  function offset (`16` or `40`) as the callback to `apply_twice`, so the
  recompiled address is not rebound to the generated function symbol. The
  source contract confirms only call presence, not callback identity. This
  run overlapped active source edits, so it is diagnostic failure evidence,
  not a stable acceptance measurement. Artifacts are retained at
  `.cache/compiler-coverage/function-pointers-retry-006/`.
- A separate skipped-pass defect was reproduced with a failing focused test:
  the high-byte cleanup walker omitted required context when descending
  `condition_and_nodes`, raising `TypeError` and skipping that pass during
  source-free `select_and_apply` decompilation. Its context forwarding is now
  fixed, with the new test admitted to routine QA. The 19 focused batch/gate
  and walker tests pass; Ruff passes on the changed files. The large legacy
  postprocess module still has pre-existing MyPy debt, and `make check-files`
  remains blocked by the unrelated structuring wide-condition ownership check.
- The normal 60s source-free `select_and_apply` rerun after that cleanup fix
  timed out before postprocess and left validation uncollected. A separate
  180s diagnostic rerun reached `validation=passed` with no skipped-pass
  `TypeError`, but emitted the same numeric callback argument and therefore
  does not satisfy normal-budget or behavior acceptance. Artifacts:
  `.cache/select-after-high-byte.{c,err}` and
  `.cache/select-after-high-byte-diag.{c,err}`.
- `make quality-dev` was attempted after the scoped regressions and failed in
  existing repository-wide Ruff complexity findings in
  `scripts/build_msc6_examples.py` and broad MyPy/mypyc debt, before its
  downstream regression suite could establish a green gate. Scoped
  `linters-files` on the new batch/cross-unit files and focused tests passes;
  this is not a green global quality or compiler-coverage gate.
- Source-free stack-move diagnostics for the small-model caller confirm two
  exact binary `MOV [BP-2], immediate` facts, with values 16 and 40;
  both are classified/materialized, with zero fact failures. The Lowering
  near-function-pointer conversion nevertheless returns no symbol because
  its target resolver requires a pre-existing synthetic global, label, or
  known KB function at each target. Sidecar labels are disabled, and these
  functions are referenced as callback constants rather than direct calls.
  Thus this is an interprocedural code-address identity/prototype proof gap,
  not a missing stack-write fact. Do not replace numeric constants by names
  solely because their values happen to fall in code; prove the typed flow
  into an indirect-call parameter first. Diagnostic artifact:
  `.cache/select-stack-debug.err`.
- Binary-only callback rebinding now joins the exact caller BP-slot push source
  with the callee's decoded indirect-call parameter fact and an exact
  same-segment, closed code entry. This is Types/Lowering evidence, not a
  rendered-C repair; unknown, far, or conflicting facts refuse conversion.
  The source-free `select_and_apply` regression changed from numeric offsets
  `16`/`40` to `sub_10010`/`sub_10028`, preserved the `sub_10040` call, and
  passed tail validation at the ordinary 60s deadline. Its emitted pointer
  type is derived from the callee's one-word argument and return widths.
- A fresh full six-function small-model MS C round trip at the unchanged 60s
  per-function deadline succeeded: all six function jobs returned 0 with
  `validation=passed`; generated C rebuilt and the DOS executable returned
  255, matching the original's 255. The source contract passed, and the six
  separate emitted function units also passed the opt-in GCC LTO cross-unit
  type gate. Report and artifacts are retained at
  `.cache/compiler-coverage/function-pointers-binary-callback-007/`.
- The expanded callback/parameter/stack focused suite passes 268 tests, and
  the new proof module passes Ruff, MyPy, and Pyright. `make test-pipeline`
  passed its initial 296-test lane, but the later large pytest lane showed
  many failures and remained silent at 99%; it was interrupted without a
  complete failure summary, so the global gate is not green. A bounded
  `--maxfail=1` replay likewise did not emit collection progress before it
  was stopped. `make quality-dev` fails on broad pre-existing MyPy debt;
  scoped Ruff and the new proof module's type checks pass. Do not infer broad
  acceptance from this isolated green compiler witness.
- The retained large-model `select_and_apply` mismatch remains separate. Its
  linked EXE has exact 16-bit stores of callback offset `0`/`26` at BP-4 and
  code segment `0x1000` at BP-2, then pushes value, segment, offset before a
  far call to `apply_twice`. The callee's recovered first parameter is a
  function pointer, but the caller emits three scalar arguments and GCC LTO
  rejects the interface. The direct binary callsite summary at `0x1009b`
  records physical widths `(2,2,2)`, exact push sources BP+8, BP-2, BP-4,
  and six-byte cleanup; the missing piece is a proven logical `(4,2)` join.
  The next repair belongs to typed far-pointer
  storage/argument joining, not a C-text signature patch.
- The first source-free far-callback shape classifier now joins exact three-word
  direct-far caller PUSH evidence with a decoded callee indirect-call parameter
  fact, publishing logical widths `(4,2)` only when the complete binary ABI
  evidence agrees. A binary-backed publisher test and near/incomplete/nonadjacent
  refusal controls pass (4 tests); scoped Ruff, MyPy, and Pyright pass. This
  proves argument widths, not a four-byte caller C object or correct emitted C.
- A trial Structuring-stage publication was removed after a 60s source-free
  `sub_10065` run timed out with validation uncollected. The same run without
  that trial also timed out at 60s on the current shared worktree, so the
  timeout cannot be attributed to the publication. No large-model function
  acceptance or DOS rebuild is claimed. The typed proof remains unintegrated;
  the next work is the Lowering-owned caller storage/argument join and a
  stable end-to-end comparison, followed by the broader required gates.
- A current-source 120s diagnostic did emit the same three-scalar caller C but
  exited with validation unavailable: this sandbox has a separate `/dev` tmpfs
  without `/dev/kvm`, although host KVM modules are loaded. This is an execution
  environment boundary, not a passing or failing semantic-equivalence result.
  The far-shape publisher now refuses to advertise `(4,2)` without an exact
  widened four-byte caller object; two adjacent two-byte locals are insufficient.
  Five focused tests pass, including the binary-backed publication and refusal
  controls. Scoped Ruff, fresh non-incremental MyPy, and Pyright pass; the
  incremental MyPy cache currently triggers an internal stale-module assertion.
- The far-callback publisher now closes every attempted direct-far candidate as
  either one materialized logical shape or a typed refusal: missing callee
  evidence, unproven ABI, or no widened caller object. The binary-backed
  separate-word case reports one refusal rather than an unexplained zero
  materialization. Six focused tests pass (66.65s under shared load), including
  a red-before missing-contract check. The far-callback and call-shape focused
  files pass together (52 tests in 53.25s); scoped Ruff, nonincremental MyPy,
  and Pyright pass. A boolean annotation defect found by `quality-dev` in the
  touched call-shape module was fixed; its rerun still exits 2 on broader
  MyPy/mypyc debt, with no findings in these two changed modules. This
  classifier is still not wired into the pipeline and does not fix the
  large-model caller or establish DOS round-trip equivalence.
- A fresh current-source, source-free `FPTR.EXE:0x10065` baseline at the
  unchanged 60s deadline times out before validation
  (`.cache/far-callback-current-baseline.{c,err}`). One 180s diagnostic with
  identical binary/catalog/hint policy exits 0 and reports
  `validation=passed`, but still emits three scalar arguments
  (`.cache/far-callback-current-diagnostic.{c,err}`). GCC LTO `-r` rejects
  that caller unit against the current validated `sub_10034` callee unit with
  `-Werror=lto-type-mismatch`; per-function validation is not a coherent
  program interface proof. No large-model witness is admitted.
- The IR logical-word value owner now proves nonzero 16-bit immediate STOREs
  only when both byte lanes share one exact scalar constant root and the
  high-lane shift. The durable typed fact checks its retained lane roots;
  corrupted constants or disagreeing lanes refuse. A binary-backed synthetic
  far-call SSA test proves that the first logical four-byte argument consumes
  BP-4/BP-2 and that straight-line stores carry offset `0` and segment
  `0x1000`. The existing zero and old-word-plus-one kinds remain distinct.
  Three neighboring focused suites pass 26 tests (59.12s); scoped Ruff,
  nonincremental MyPy, and Pyright pass. `make quality-dev` still exits 2 in
  broader MyPy/mypyc debt, with no diagnostics naming these changed files
  (`.cache/far-callback-ir-word-quality-dev-final.log`). This is prerequisite Value evidence,
  not CFG branch correlation, caller object widening, target-symbol rebinding,
  a corrected C call, or DOS round-trip acceptance.
- A later unrestricted execution profile exposes `/dev/kvm`; opening it
  read-write succeeds. The fresh source-free `sub_10065` 120s diagnostic
  `.cache/large-fptr-kvm-001.log` nevertheless times out during function
  recovery before tail validation. This supersedes only the earlier device
  availability observation, not the unresolved far-call mismatch.
- Compiler-coverage runner provenance now records Python/platform identity,
  all installed distribution name/version rows, and a typed KVM open verdict,
  alongside existing source/compiler/emulator hashes. It records the effective
  child environment overrides and refuses a reported pass if the runtime
  snapshot changes during execution. This version snapshot is not a binary
  hash of installed dependencies, so full environment identity remains open.
  Focused provenance/runner tests pass (30), scoped Ruff/MyPy/Pyright pass,
  and `make compiler-coverage-contracts` passes 167 tests in 108.64s. Three
  snapshot captures took 1.215s total with 87 distributions in this host run;
  this is a measured local overhead, not a full routine-target timing claim.
- `make quality-dev PYTHON=./.venv/bin/python` exits 2 at the broad `mypy-dev`
  lane; the retained log is `.cache/compiler-coverage-provenance-quality-dev.log`.
  No reported MyPy diagnostic names the changed provenance or runner modules,
  whose scoped MyPy and Pyright checks pass. The required global gate remains
  open; its failures are not covered by the 167 passing framework contracts.
- The IR logical-word READ owner now traces a selected word through exact
  byte SSA STORE versions and one complete immediate memory-phi predecessor
  set to constant logical WRITEs. A binary-backed four-block callback caller
  proves aligned per-path offset values `0`/`0x1a` and segment `0x1000` at
  the two BP-local PUSH sources. Missing one branch writer, incomplete phi
  input, corrupted value, and dropped durable path controls refuse. The new
  typed proof is admitted to the fast pipeline and ownership/typed/Ruff lists;
  three neighboring suites pass 29 tests, scoped Ruff/MyPy/Pyright and
  `make test-ownership-check` pass. `make check-files` stops at the existing
  `condition_materialization.py` shared-body wide-condition architecture
  violation; `make quality-dev` exits 2 on broader MyPy/mypyc findings not
  naming the new proof. This does not yet widen the caller storage, rebind a
  far target, change the three-scalar emitted call, or admit the DOS round trip.
- The source-free large-model far-callback Value join now consumes the exact
  direct-far caller PUSH identities, callee indirect-call ABI, and two logical
  word READ reaching-value proofs. It publishes path-correlated offset/segment
  pairs without treating the separate BP words as one C object. On the real
  `FPTR.EXE:0x10065` binary it closes at `1000:0000` and `1000:001a` on the
  two CFG predecessors, with counters `(1,1,1,1,0)`. A separate binary-only
  target proof resolves both pairs to closed far-return DOS code entries;
  invalid addresses, near returns, open decodes, and corrupted contracts
  refuse. Both new owners and deterministic tests are registered in the fast
  pipeline and ownership/typed/Ruff lists. Four neighboring focused suites
  pass 25 tests; ownership check and scoped Ruff/MyPy/Pyright pass.
  `make check-files` remains blocked by the existing
  `structuring/condition_materialization.py` wide-condition owner violation
  (one earlier attempt also raced concurrent source edits). The far callback
  call AST still has three scalar arguments: the next repair is atomic
  Types/Lowering materialization of one typed callback expression, `(4,2)`
  callsite shape, and callee prototype before large-model acceptance. No DOS
  behavior equivalence is claimed yet.
- The source-free `FPTR.EXE:0x10065` far-callback caller now reaches an atomic
  binary-backed Types/Lowering materialization: both exact path Values and
  closed far-return targets select a typed callback argument, the direct callee
  prototype and callsite projection become `(4,2)`, and both target forward
  declarations survive AST replay. The physical three-word pre-decompilation
  seed carries a JSON-safe provenance record so only its own signature can be
  refined; an unrelated non-guessed prototype still refuses. Two separate BP
  word stores remain explicit and are not falsely widened or deleted. The
  real source-free 180s diagnostic exits 0 with `validation=passed`, portable
  GCC compilation, and `sub_10034((arg_6 ? sub_10000 : sub_1001a), arg_8)`;
  this improves the prior validated three-scalar call. Focused replay, target,
  prototype-conflict, and CFG-topology tests pass. This is function-level
  acceptance only: the full test pipeline, coherent multi-unit interface,
  compiler-coverage harness, DOS round trip, and remaining plan steps are
  still open.
- The large-model `function_pointers` harness round trip now passes at the
  unchanged 60s per-function deadline in
  `.cache/compiler-coverage/large-far-callback-roundtrip-004/` (72.93s): all six
  function jobs complete, original and rebuilt MS C executables both exit
  255, the source contract passes, and implementation/environment snapshots
  remain unchanged. Its `FPTR.EXE` SHA-256 matches the binary used by the
  typed path-correlated far-callback Value and target-entry proofs above.
  All six fresh generated C units pass GCC LTO with
  `-Werror=lto-type-mismatch`; two preserved BP-word locals produce only
  unused-but-set warnings. The harness itself labels this an existing-case
  round trip, not automatic feature coverage; the independent typed binary
  proofs establish the far-function-pointer mechanism. Earlier attempts
  `-001` and `-002` were not accepted because concurrent owned-source edits
  changed the implementation snapshot (and `-001` hit a transient import
  cycle). `large.json` now admits `pointer.far_function` with this witness;
  far-data pointers and pointer returns remain explicitly deferred, and their
  nonadmitted case is not selectable. The manifest regression and all 168
  compiler-coverage contracts pass. A new red-before refusal regression also
  rejects an existing 32-bit callback pointer whose pointee ABI conflicts
  with the binary proof; the final-source focused callback suite passes 15
  tests, and the latest six-unit LTO check still passes.
- The post-repair focused callback/prototype/path and COD mock suite passes
  15 tests; scoped Ruff, nonincremental MyPy, and Pyright pass. The default
  `make test-pipeline` is still red: its large pytest lane has 11 failures,
  QuickC passes, and the MSC6 tiny lane has `mixwidth` uncollected validation,
  `pointer_memory` pointer-return C compilation failure, and
  `scalar_types_io` rebuilt exit 7 instead of 255. The COD caller-evidence
  failure was an incomplete test mock and now passes alone; isolated SORTD
  RunMenu still fails postprocess validation on AX def-use and two branch
  predicates. The earlier `quality-dev` and `quality-hard` runs exited 2 on
  `validation_calls.py` MyPy debt; that typed-boundary defect has since been
  repaired, so those earlier gate results no longer describe the current
  source. These failures and remaining Steps 1-5 are not closed by the
  large-model witness.
- Parallel follow-up slices remain prerequisites, not function acceptance.
  For `TYPES.EXE:add_long`, the exact `mov/mov/add/adc` instruction bytes now
  close Widening evidence for two 4-byte BP arguments without misclassifying
  their AX:DX seed as a failed terminal passthrough; all 23 focused width
  tests pass, including a self-contained byte-for-byte regression that needs
  no optional EXE or skip. Source-free direct discovery reports `wide_stack=1`
  for the target, but the 60-second run times out after discovery with tail
  validation uncollected. A later 180-second source-free direct run emits
  `long sub_10110(long arg, long arg_8)` with `return arg + arg_8`, improving
  the previous eight-argument C; its validation still fails because the MS C
  validation toolchain cannot open `/dev/kvm` in this sandbox, so DOS
  equivalence remains open.
  For `POINT.EXE:select_word`, closed logical-memory operand evidence now
  carries exact return-pointee width through typed trials, joins, and SimType
  projection, with unknown/conflict refusals. Focused pointer tests and scoped
  Ruff/MyPy/Pyright pass. A cache-isolated source-free run still emits the
  scalar return and reports `INCOMPLETE_CALLER_CENSUS` before return trials;
  input-pointer classification and scaled return expression remain separate
  prerequisites. The repaired `validation_calls.py` boundary has 53 passing
  focused tests, and the two mypyc dataclass annotation fixes pass compiled
  import smoke for all 39 modules. None of these focused results supersedes a
  final `quality-dev`, `quality-hard`, or end-to-end DOS round trip.
- The post-parallel `quality-dev` run, with project-local `TMPDIR`, passes its
  296-test fast unit lane but fails the external fast pipeline: 22 failed and
  6732 passed in the large pytest lane, before DOS fixture completion. Two
  failures were a synthetic pointer-return snapshot missing the newly required
  2-byte pointee witness; that fixture now carries explicit evidence and its
  six focused replay tests pass, but the broad lane has not been rerun since.
  The post-parallel `quality-hard` attempt exits 2 at the architecture check
  on a wider set of ownership/header/Makefile registration and fast-target
  findings. It does not reach its semantic gates. The scoped pointer and wide
  regressions are green, while these broad gate results remain red.
- A fresh source-free direct-address probe of `POINT.EXE:select_word` closes
  the caller census (two callsites, two consistent arguments); the older
  `--proc` census refusal is not the direct-address blocker. In-process
  publication diagnostics instead show both trials for the index argument
  refused as `SIGNEDNESS_UNKNOWN` (`raw=2`, `normalized=2`, `classified=0`,
  `materialized=0`, `failure=2`), so the return-pointer trial is not reached.
  A sign-insensitive classification requires a closed typed use proof, not a
  default from missing signed comparisons. The emitted C remains scalar and
  the direct validation fails because `/dev/kvm` is unavailable; the function
  is not fixed. Parallel QA repairs registered the missing hard-lane targets
  in `Makefile` and corrected 11 script layer headers; scoped checks pass and
  the architecture check no longer reports those two classes of findings,
  but it remains red on unrelated findings.
  A subsequent read-only triage counted 164 remaining architecture findings
  across 14 rules. The isolated promoted-public-assignment finding was then
  removed by annotating `TDINFO_BUILTIN_TYPE_NAMES` as `dict[int, str]`;
  its focused checker, regression, Ruff, MyPy, and Pyright pass. No broad
  architecture rerun has followed that one-line repair.
  A read-only IR/SSA probe of `select_word` found the candidate use chain
  `SS:BP+6` word read, 16-bit shift by one, add to `SS:BP+4`, and AX return.
  It is not a closed sign-insensitive proof: the isolated artifact leaves the
  preceding call at `0x100f7` without a semantic summary and the post-call
  block without a CFG predecessor (its raw target appears as `0x5bc`). A
  follow-up using the real exact binary range boundary instead proves all
  three blocks and both CFG edges, normalizes the call to `0x105bc`, and
  records a complete, BP-preserving call-stack effect. Thus the isolated
  artifact's missing edge is a diagnostic construction limitation, not the
  current live-path blocker. The remaining work is a typed closed-use proof
  for the index, followed by atomic pointer-return and scaled-expression
  materialization. A self-contained rebased-byte regression now guards the
  exact boundary's two CFG edges, normalized call target, complete call effect,
  and two logical SS:BP word reads; its existing routine test file passes all
  10 tests and the changed-file gate passes. Its deliberately minimal helper
  proves only call-effect closure, not the real binary's BP-preservation fact.
  No pointer-return publication is accepted yet.
- The next source-free `select_word` slice now has an IR-owned typed modular-use
  proof with five-stage counters. It follows exact logical SS:BP word reads
  through SSA definitions, permits only explicit sign-insensitive operations,
  and refuses a signed shift, missing CFG edge, unproven preceding call,
  unknown definition, or tainted store. Six self-contained focused tests pass;
  the real `POINT.EXE:select_word` exact-boundary probe returns `PROVEN` with
  `(raw, normalized, classified, materialized, failure)=(1,1,1,1,0)`.
  `make check-files` passes with 81 tests; scoped Ruff/MyPy/Pyright pass.
  The full architecture ratchet has no findings for the new files but remains
  red on pre-existing findings. A fresh `quality-fast` exits 2 in MyPy before
  its test lane, with broad existing typing debt. This proof is not connected
  to interprocedural publication or emitted-C materialization yet: it proves
  bit-pattern use, not the original signed `int`, pointee type, or scaled
  pointer-return expression, so `select_word` is still not fixed.
- The `select_word` IR proof was hardened against contradictory pre-read call
  effects, incomplete stack deltas, refused or malformed logical-memory
  operands, and foreign read blocks. Corrupted controls failed before the
  repair; all 12 modular-use focused tests now pass. A separate IR-owned
  `stack_argument_scaled_return.py` joins two complete modular-use facts with
  the existing scalar-affine SSA trace, exact four-byte LOAD-site binding,
  and one AX return. It proves only
  `AX = (word(SS:BP+4) + 2 * word(SS:BP+6)) mod 65536`; six source-free
  focused tests pass. The real exact-boundary `POINT.EXE:select_word` probe
  returns `PROVEN` with `(1,1,1,1,0)` counters for both IR facts. The new
  module/test are registered in routine lint, type, ownership, and pytest
  lanes; the combined changed-file gate passes 478 tests and
  `git diff --check` is clean. `quality-hard` passes serial linters but stops
  at older full-architecture findings, none on these new files.
  Final-source `quality-dev` passes its 296 local tests, then reports 28
  failures and 6,727 passes in the external fast pipeline: exactly the same
  failure IDs as the immediately preceding pre-patch run. `/dev/kvm` is
  unavailable and explicitly fails at least one DOS execution check; no tail
  validation success is claimed. The binary callee does not dereference its
  BP+4 base input, current input trials omit `pointee_width_bytes`, and the
  returned pointer's observed width is not independent proof of the base
  pointee width. A bounded binary-only caller audit found both direct sites in
  one caller, each pushing `LEA AX,[BP-0x14]`; that caller also has nearby
  2-byte local writes/compares. This is a candidate contiguous word object,
  not a typed element-family proof: current input trials do not bind the LEA
  target to a Widening-owned adjacent-word layout. Any eventual pointer
  publication must be atomic across input/return types and the structured
  return expression, with replay and refusal tests. No generated-C repair has
  been made yet.
- The caller audit cannot promote neighboring direct 2-byte locals into a
  pointee-width proof: neither the callee's scaled arithmetic nor its returned
  pointer's downstream dereference proves the input base is a word array.
  A byte-pointer fallback is not yet safe either. Ordinary C pointer addition
  does not model 16-bit offset wrap or arbitrary guest addresses, while the
  portable-flat `PTR_U16` macro extracts host-address bits rather than a
  proven guest near offset; `SEG_PTR(ds, ...)` also guesses the segment of a
  caller stack address. Retain the scalar output and typed refusal until a
  guest-offset/segment binding or independent element-family proof closes
  those obligations. A self-contained rebased-byte regression now tests the
  scaled AX fact without external EXE files: removing an unproven preceding
  call proves it, mutating its shift refuses, and a decoded RET-only helper
  correctly refuses because BP preservation is unproven. This is IR evidence,
  not C publication or function acceptance.
- A separate read-only audit of the rebased nonoptimized `select_word` rescue
  found its tail guard's `reg+0x0:size2` uninitialized read denotes AX. The
  binary writes AX before the helper call, so exempting AX as an entry live-in
  would hide a real writer/identity loss. The archived log lacks the failing
  AST node and definition events; it cannot distinguish removed writer from
  SSA-key mismatch. The next bounded diagnostic is an isolated
  `INERTIA_DEBUG_DEF_USE=1` replay, then repair the owning producer/pass and
  add write-to-read plus deletion/rebinding refusal tests. This rescue-path
  failure is distinct from the direct path and from `/dev/kvm` availability.
- A read-only publication audit ruled out connecting the modular-use proof to
  input `SIGN_INSENSITIVE` trials alone. Once those trials close,
  `collect_and_publish_function_storage_contract_8616` proceeds to
  caller-derived return trials; prototype preflight/application can publish a
  pointer return without checking a matching modulo-16, segment-correct
  callee return AST. That would make the current scalar body invalid or
  double-scaled. The existing unknown-signedness refusal is retained; the
  first publishable implementation must consume the scaled-return IR fact and
  materialize/check the return expression atomically with the prototype.
- The current self-contained rebased scaled-return regression passes 9 focused
  tests and `make check-files`; its decoded RET-only helper deliberately
  refuses BP preservation, while its no-call control proves the arithmetic.
  The subsequent `quality-hard` run passed serial linters but stopped at the
  broad architecture audit's existing unrelated findings. `quality-dev`
  passed its 296 local tests, then was interrupted as incomplete after more
  than 30 minutes in the external fast lane (20% emitted); it is not a pass.
  A focused `INERTIA_DEBUG_DEF_USE=1` replay identifies the rebased rescue
  read as AX carrier `v8` (`ir_3`) with no reaching AX writer in the final
  structured AST. The existing pre-rollback C dump shows `return v8 + arg;`
  with `v8` never assigned, while the direct address C remains the scalar
  `arg_4 + (arg_6 << 1)` form. The validator correctly refuses the rescue;
  no AX live-in exemption or fallback success is allowed. The direct address
  path separately reaches a clean internal tail summary but fails MS C 5.1
  recompilation because `/dev/kvm` is absent. Neither path validates the
  pointer-return source contract. Next: keep the return proof nonpublishing,
  establish a typed guest-address/segment return binding, and diagnose the
  rebased Structuring producer only if that fallback is needed independently.
- A prototype-only guard is insufficient: accepted storage contracts also
  feed `callsite_prototype_declarations._storage_contract_return_decision_8616`
  directly. Any new near-pointer C return projection needs one shared typed
  proof/verdict consumed by both the function-prototype preflight and callsite
  declaration path. Caller-derived return shape and dereference width remain
  ABI evidence, not proof that the callee's structured return expression has
  the correct segment, modular offset, or pointee scaling. Existing positive
  pointer-interface tests cover the former and must not be mistaken for the
  latter. A separate trace found no accepted rebased postprocess pass before
  the orphaned AX read; the rejected C is therefore not evidence that the
  final named cleanup pass caused it.
- A bounded Semantics improvement now proves that an exact near `E8` callsite
  targets a mapped, non-synthetic one-byte `RET` body, which preserves
  BP and caller BP-relative input words. The existing call-stack-effect fact
  carries that proof into the IR modular/scaled return collectors. A
  source-free rebased machine-byte regression went red before the change and
  now proves the scaled AX result through the real call; NOP/RET, wrong
  callsite/target/return address, far-frame, synthetic-stub, and incomplete
  stub-registry controls refuse. The final-source changed-file gate passes
  333 tests. An earlier full pipeline run before the exact E8 binding had 28
  failures, 6,726 passes, one skip; one failure was a new synthetic-frame
  regression caused by accepting unrelated RET bytes. It is corrected: the
  final-source external fast sweep has 27 failures, 6,727 passes, one skip,
  and the synthetic-frame regression is absent. The fast target remains red;
  the MS C round-trip lane also cannot build without `/dev/kvm` here.
  `quality-fast` remains red on broad MyPy debt. The full architecture audit
  no longer flags this new module but reports 164 other findings.
  This is a deliberately narrow real-body proof, not an ABI assumption about
  arbitrary helper calls or permission to publish a pointer return. The
  `POINT.EXE:select_word` call is actually a far `9A` stack-probe call. Its
  linked callee has an existing binary-recognized `aFchkstk` signature and
  Frontend inlines exact register/SP effects before IR import; therefore an
  arbitrary-helper BP/SP scanner is not this witness's next prerequisite.
  Unrecognized helpers still require closed all-exit BP/SP and segment-aware
  SS-write proofs, with unknown paths and indirect writes refused.
- The far-probe recognition now requires both overflow branches to bypass the
  returning path; one-byte branch-diversion controls refuse inlining for near
  and far variants. A self-contained, source-free test uses the linked POINT
  far-probe displacement and the exact `select_word` instruction shape. It
  proves the scaled AX offset through inlined effects and refuses when the
  helper branch is changed. The real linked `POINT.EXE` exact-boundary probe
  independently confirms the same `(1,1,1,1,0)` AX result with no remaining
  unmodeled CALL at the probe site.
- A typed IR far-return evidence contract now joins that AX result with an
  independent, exact `DX = word(SS:BP+8)` segment path. The modular-use
  collector explicitly supports AX or DX return carriers; the far contract
  requires adjacent offset/segment input words, a common return site, one
  complete logical segment read, and an affine identity with exact LOAD
  leaves. Altered DX arithmetic, late DX clobber, nonadjacent segment input,
  and unrecognized probe all refuse without partial publication. The real
  linked `POINT.EXE:select_word` probe returns `PROVEN` with closed five-stage
  counters and the exact segment-read/return addresses. This covers the
  normal returning probe path; the overflow path beyond the short recognized
  prefix is not an all-path function proof. The focused 52-test suite and
  changed-file gate pass; direct Pyright reports zero errors. The
  full architecture check remains red on broad pre-existing ownership/promotion
  findings. A required `test-pipeline` attempt passed its 296-test local lane,
  but its external runner lost the process handle at turn rollover and left no
  new summary, so the external verdict is uncollected. A subsequent
  `quality-dev` retry passed its promoted linters, mypyc import smoke, startup
  checks, and 296 local tests, then failed before the external fast lane
  because the Makefile hardcodes a `/tmp` lock that this workspace-only sandbox
  cannot create. The final-source changed-file gate still passes 52 tests.
  Running the same fast external runner directly bypasses that lock and
  finishes with 35 failed, 6,721 passed, one skipped; the prior retained sweep
  had 27 failed, 6,727 passed, one skipped, so a regression-free broad result
  is not established. A focused rerun confirms at least one additional
  cache-surface failure (`key is None`) and the stack-aggregate coordinate
  replay mismatch, neither exercised by the far-return contract tests; their
  cause and the full failure-set delta remain untriaged.
  The quality-gate lock paths were then moved from unwritable `/tmp` into
  project-local `.cache/locks/`; three Makefile contract tests went red before
  the edit and green afterward, and `make mypyc` acquired its local lock with
  import smoke intact. `make -n test-pipeline-fast` resolves to the local
  pipeline lock, and a direct `flock` acquisition succeeds. This repairs gate
  access only; it does not erase the 35 external fast-lane failures or prove
  semantic acceptance.
  This is IR evidence, not C pointer
  materialization or tail-validated function acceptance. Next: bind guest
  segment/offset to a Lowering-owned structured return expression and an
  independently proven pointee element family, then publish input/output
  contracts atomically across function and callsite projections.
- A Lowering aggregate-replay regression was repaired while checking the
  external baseline. Exact full-width candidate selection had discarded a
  narrower variable already recorded by the coordinate registry as an alias
  of the canonical aggregate, leaving its live C AST reference unbound.
  Rebinding now consumes that exact recorded identity; an unregistered
  same-offset view and unrelated storage remain untouched. The focused
  regression failed before the repair, then all 19 tests in its file and the
  49-test changed-file gate passed. The project-local Makefile locks also
  allowed `quality-dev` to reach the external fast lane: its 296 local tests
  passed, while the external lane finished with 26 failures, 6,730 passes,
  and one skip (479.04 seconds). The aggregate replay test is absent from
  that failure list. No full semantic gate or `select_word` tail validation
  passed; far return pointer publication remains refused. `quality-hard`
  passed its serial lint/mypyc stage but stopped at existing full-architecture
  findings outside the changed aggregate replay files. The required default
  `test-pipeline` attempt passed 296 local tests, then its unit-focused
  external lane again reported 26 failures, 6,730 passes, and one skip.
  The other two selected lanes, Ultra Quick C fixtures and the MS C tiny
  full pipeline, also failed before decompilation. All four selected Quick C
  fixtures and eight reported MS C constructs lack compiler evidence; their
  reports say `fatal: failed to open /dev/kvm: No such file or directory`.
  This is an unavailable validation environment, not evidence that generated
  C is equivalent.
- The legacy aggregate frame collector now decodes exact immediate far-call
  segment:offset targets, allowing binary-recognized far stack probes to
  contribute frame-allocation evidence. A source-free mapped-byte test went
  red before the change and now proves a full-frame aggregate; changed far
  segment, far offset, indirect call, and helper branch all refuse. The new
  test is in the routine fast pipeline and hard QA list. Its 5 tests plus the
  existing aggregate tests pass (35 total), and `make check-files` passes 137
  tests. The real linked `POINT.EXE` caller advances from
  `missing_stack_allocation_evidence` to
  `missing_indexed_partition_evidence` with 41 normalized raw facts, but no
  materialized word-array family. Thus this step neither types the
  `select_word` input nor publishes its far-pointer return; the remaining
  proof must come from Alias/Widening rather than this legacy shape collector.
  The final-source `quality-dev` run passed 296 local tests; its external fast
  lane had the exact same 26 failure IDs as the preceding run, with five more
  passes (6,735 passed, one skipped). The required default `test-pipeline`
  independently repeated that 26-failure/6,735-pass/one-skip unit result;
  its Quick C and MS C lanes failed before decompilation because `/dev/kvm`
  remains absent. `quality-hard` passed serial lint/mypyc work but stopped at
  existing full-architecture debt, with no finding naming the new test or
  changed aggregate collector. No DOS round-trip or tail validation for
  `select_word` is claimed.
- The next source-free far-return use fact is now owned by
  `lowering/far_return_pointer_use.py` and its typed contract. It joins exact
  DX:AX CALL_OUTPUT definitions across one exclusive post-call CFG edge to
  separate DX-to-ES and AX-to-BX copies and one complete logical ES:BX access.
  A copied byte/word clobber, wrong physical output pair, missing segment or
  offset copy, incomplete CFG, missing logical memory, and absent dereference
  all refuse without changing C. The source-free regression failed collection
  before the module existed and now has nine passing cases; the test is in fast
  pipeline, hard QA, and file-ownership checks. On the linked `POINT.EXE`
  caller, exact callsites `0x12f2` and `0x1316` independently prove two-byte
  accesses at `0x12fe` and `0x1322`. This records access width, not an input
  pointee family or array extent; it does not publish a far-pointer return.
  A fresh current-source source-free `select_word` decompile showed the FAR
  BP+6/+8/+10 argument frame is already correct, superseding an older saved
  generated-C artifact that suggested a phantom BP+4 input. The current
  result still returns a scalar `long`; no pointer C expression or tail
  validation pass is claimed. `make check-files` passed 167 tests, and Ruff,
  MyPy, and Pyright accepted both new owned modules. `quality-dev` passed 296
  local tests but its external fast lane finished with the exact same 26
  failure IDs as the preceding run (6,744 passed, one skipped). The required
  default `test-pipeline` repeated those 26 failure IDs and counts; its Quick
  C and MS C compiler lanes still fail before decompilation because `/dev/kvm`
  is unavailable. After registering both modules in the full typed-promotion
  inventory and adding their required ownership headers, the final changed-
  file gate passed 552 tests using project-local `TMPDIR`; an earlier attempt
  without that setting had eight GNU Make temporary-file failures on read-only
  `/tmp`. Final `quality-hard` still stops at unrelated full-architecture
  promotion/header and focused-skip findings, with no finding naming either
  new module. Next: close an all-callsite Lowering return contract and
  bind the callee's proven modular segment:offset return to one structured C
  expression and prototype atomically; do not infer the input pointee family
  from this downstream access width.
- The next source-free caller-census slice preserves exact 20-bit immediate
  far CALL targets in the frontend direct-call index, separate from near-call
  low-word identities. A synthetic DOS blob checks a true far caller, a
  different segment with the same offset, and an AX clobber; an index test
  checks two far targets with identical low words do not alias. The bounded
  AX-use scan now passes an exact DX-to-ES copy before observing AX, without
  calling that copy an AX use. On linked `POINT.EXE:select_word`, the previously
  empty direct census now closes two used value callsites (`0x12f2`, `0x1316`):
  raw=2, normalized=2, classified=2, materialized=2, failures=0. This is
  caller inventory and AX-use evidence, not a joined four-byte return proof
  or C pointer publication; the prior paired Lowering proof must still be
  joined for every caller before changing a return declaration. The 16-test
  focused regression and final changed-file `check-files` gate
  pass (124 tests). Scoped Pyright reports zero errors. `quality-dev` passes
  296 local tests and compiled-import smoke, but its external fast lane has
  the same 26 failure IDs as the preceding baseline (6,747 passed, one
  skipped). The required default `test-pipeline` repeats those 26 failure
  IDs and counts; Quick C and MS C both fail at compile/link before
  decompilation because `/dev/kvm` is unavailable. `quality-hard` passes
  its serial lint/type/mypyc stage, then fails the existing full-architecture
  debt (headers, documentation size, dynamic attributes, typed promotion and
  focused skips); no finding names the new far-call index contract. This
  slice is not a tail-validation or DOS-round-trip success.
- A Lowering-owned, nonpublishing far-return caller join now requires one
  paired DX:AX-use witness for every included direct caller and refuses open,
  missing, duplicate, extra, mismatched, or unproven evidence. A newly added
  duplicate-inventory control first failed because one proof could satisfy
  two repeated census facts; the join now refuses that false complete result.
  A second red/green control makes `complete` recheck the source census
  verdict. The final-source changed-file gate passes all 19 focused tests;
  scoped Pyright reports zero
  errors. The pre-latter-control `quality-dev` passed its 296 local tests, then
  the external fast lane remained red with 26 failures, 6,753 passes, and one
  skip in 1,311.04 seconds. The prior ledger also recorded 26 failures, but
  the complete failure-ID comparison has not been independently repeated.
  `/dev/kvm` is still absent in this sandbox, so no compiler round trip or
  tail-validation success is claimed. The join currently receives supplied
  proofs only; it is not yet wired into return publication. Next: bind exact
  callee target provenance, guest segment:offset C expression, and independent
  input pointee family before atomically changing function/callsite contracts.
- The paired far-result proof now retains the callee's exact 20-bit CALL target
  after checking it against the CALL_OUTPUT provenance and exact callsite. The
  all-caller join requires that target to equal the direct-call census target.
  Two source-free foreign-target controls failed before the change and pass
  afterward; the synthetic call and census fixtures now refer to the same
  target. The final-source 21-test changed-file gate passes, including typing,
  startup architecture, ownership, and focused tests. This is still a
  nonpublishing Lowering proof, not a far-pointer C return: a production
  all-caller collector, guest segment:offset expression, independent input
  pointee family, atomic function/callsite publication, and end-to-end DOS
  acceptance remain open. The prior 26-failure external development sweep
  predates this target-binding edit and does not validate final source.
  Scoped Pyright reports zero errors. Final-source `quality-hard` passed
  serial lint/type/mypyc work, then stopped at the existing full-architecture
  header/promotion/focused-skip debt; no finding names the target-binding
  modules.
- A linked, large-model `POINT.EXE` static replay now checks the exact-target
  join in the actual DOS MZ address space. The linked `select_word` entry is
  `0x100f1`, and its two direct calls are `0x102f2` and `0x10316`; the older
  `0x12f2`/`0x1316` notes refer to a rebased view, not the loaded image.
  Listing data supplied only the caller/function bounds, while the direct
  caller census, semantic SSA, CALL_OUTPUT target, DX:AX copies, and ES:BX
  logical accesses came from binary evidence. Both callsites prove the same
  target and the join closes `(2,2,2,2,0)` without changing C. A separate
  embedded-byte two-call regression makes the behavior independent of that
  cached EXE; the final-source changed-file gate passes 22 focused tests.
  This is not tail-validation or DOS behavioral acceptance. A production
  all-caller collector and atomic return-expression/type publication remain
  open, and the full external pipeline has not been rerun on this source.
- The Lowering all-caller collector now computes its own closed direct-call
  census, proves the callee's DX:AX terminal carrier from binary paths, builds
  exact caller Semantics SSA once per caller, resolves physical CALL_OUTPUT
  definitions, and joins every paired far-result use. It takes only a loaded
  project, target address, and independently bounded function ranges; no caller
  may supply an unverified return-carrier enum. A new sidecar-free two-call
  machine-byte test was red before the collector existed and now passes with
  two refusal controls for a scalar-only callee and a missing callee boundary.
  Replaying the linked `POINT.EXE` through this entrypoint closes both actual
  callsites (`0x102f2`, `0x10316`) with `(2,2,2,2,0)` evidence counts. The
  final-source changed-file gate passes 25 focused tests and scoped Pyright
  reports zero errors. The collector remains nonpublishing: its result does not
  yet retain a callee guest segment:offset C return expression or independent
  pointee family, and no tail-validation, MS C rebuild, or DOS behavioral
  equivalence is claimed. A fresh linked `POINT.EXE` callee replay also proves
  the exact far scaled return from SS:BP+6/+8/+10 to DX:AX with `(1,1,1,1,0)`
  IR counts and no function refusal. This still lacks an owned C expression
  and independent pointee type. The first `quality-dev` attempt reached 296
  passing local tests and compiled-import smoke, then stopped at six xdist
  collection-inventory errors after other sessions changed test files during
  worker startup (their mtimes and differing IDs confirm the race). A stable-
  tree retry completed: 296 local tests passed; external fast lane had 6,757
  passed, one skipped, and 26 failed in 1,648.55 seconds. The 26 failure IDs
  exactly match the prior recorded baseline, with no new ID. This is not a green
  default `test-pipeline`; `/dev/kvm` remains absent in this sandbox.
- Two nonpublishing far-return prerequisites are now present. Lowering binds the
  callee's proven far scaled-return IR access keys to exact SS:BP C variables
  and builds a candidate `SEG_PTR`/`MK_FP` return expression with 16-bit offset
  wrap. Post-Devin review added a red/green control for signed input words:
  unsigned bit-pattern views are required before C left shift and segment
  macro evaluation. The storage SimType projector accepts an exact DX:AX FAR
  pointer type only when an independent pointee type is explicitly supplied;
  downstream access width alone refuses. Review controls first exposed two
  false accepts—generic 32-bit pointer ABI and equal-width struct/scalar
  pointee matches—and both now refuse with typed reasons. The expression and
  type suites pass 13 and 21 focused tests respectively; scoped Ruff/Pyright
  pass, and the final registered `check-files` gate passes 229 tests plus its
  lint, startup-architecture, and ownership checks. These are proof/preflight
  units, not production far-return publication: the linked `POINT.EXE`
  caller's stack object still lacks an independent word-family proof, input
  slots and callsite C projections are not atomically changed, and no
  `validation=passed` or DOS round trip is claimed. `/dev/kvm` is still absent
  inside this sandbox. A bounded Devin Csmith audit confirmed that seed 2 has
  no terminal round-trip result and still queues runtime helpers; a deeper
  read-only catalog probe was stopped after exceeding its diagnostic window,
  with no code changes or new acceptance claim. The post-review `quality-dev`
  run passed its strict lint/type/import lanes and 296 local tests; the external
  fast lane finished with 6,780 passed, one skipped, and 26 failed in 1,754.16
  seconds. All 26 failure IDs exactly match the pre-change recorded baseline,
  so this remains a red global gate without a newly failing test ID.
- KVM became usable in this workspace on 2026-09-27:
  `/home/xor/kvikdos/kvikdos --kvm-check` exited 0 and the previously
  device-blocked MS C signed-width recompilation regression passed (one test).
  A pinned seed-2 Csmith replay retained the same generated-source SHA-256
  `353845463705795ea0822c0ecaf5f956828405507d956d661e2fa124a4d66939`.
  Its original MS C DOS executable built and ran with exit 0 and checksum
  `637A4628`; the full all-functions adapter then reached its 600-second bound
  without a decompilation case report (`timed_out`, 607.54 seconds). Its
  implementation and runtime-environment fingerprints were unchanged, with
  KVM `read_write` both before and after. Artifacts are retained under
  `.cache/compiler-coverage/csmith-kvm-replay-001/`. This proves the emulator
  is no longer the seed-2 blocker, but does not establish a generated-C round
  trip or Csmith feature coverage. A timeboxed read-only Devin probe of the
  independent caller pointee family ended without a closed proof or edits;
  far-return publication remains refused.
- The linked Csmith source-function entries were checked against the executable
  bytes: `main=0x1158b` and `func_1=0x111f5`. Earlier probes that used raw COD
  offsets without the linked placement delta addressed different instructions
  and are discarded. Fresh source-free direct probes of both correct entries
  reached the 180-second bound with validation uncollected; neither function
  is fixed. The simultaneous `main` probe first found only 11 of 69 candidate
  functions in 66.03 seconds, while a later solo diagnostic with an exact
  bound closed 69 of 69 in 47.72 seconds. These are different timing/cache
  conditions, so the 58 failed candidates are not treated as a stable defect.
  The solo diagnostic then spent more than three minutes before its function
  decompilation marker and was stopped; its unflushed span file cannot support
  a finer bottleneck claim. Full-source Csmith acceptance remains open.
- Review of a timeboxed read-only Devin audit found no accepted pointee-family
  proof or patch to integrate. In the source-region discovery path, a separate
  red regression showed that an unexpected candidate `RuntimeError` was being
  swallowed as a failed seed; the owned boundary now refuses only analysis or
  daemon-thread timeouts and missing candidate CFGs (`KeyError`), while an
  unexpected error propagates with its cause. The same rule now applies to
  cached candidate recovery. Red/green controls cover both paths and all
  three named boundary conditions. With deterministic `PYTHONHASHSEED=0`, all
  24 discovery-region tests and the final changed-file gate (52 tests plus
  lint, startup-architecture, and ownership checks) pass. A standalone
  Pyright run still reports five errors elsewhere in this
  already-modified discovery module; no new error is at the changed boundary.
  A post-fix source-free replay of the correct linked Csmith `main` was stopped
  at its 175-second wall bound before new source-region evidence appeared.
  This is a failure-visibility fix, not evidence that the 600-second seed-2
  Csmith round trip or far-return publication now passes.
- A bounded seed-2 `main` profiler run (2,117 samples over 85 seconds, one
  worker, deterministic hash seed, JIT enabled) located repeated terminal
  stack-cleanup path walks before source-region discovery: 555 samples contained
  that proof, and sampled recursive stacks reached 159 frames. A new eight-
  diamond CFG regression was red with 256 copies of one return fact. Semantics
  now visits each reachable block once with an iterative worklist, retains
  missing-edge refusals, and counts distinct return facts; the regression and
  all ten focused cleanup tests pass. The final changed-file gate passes 306
  tests plus lint/architecture/ownership checks, and scoped Pyright has zero
  errors. A correct-address source-free Csmith replay still timed out in
  decompilation after classifying 46/69 catalog entries in 64.54 seconds; the
  earlier catalog count varied across runs, so no stable end-to-end speedup or
  Csmith round-trip acceptance is claimed. The profiler sample is retained at
  `.cache/csmith-main-current.raw`.
- The final-source `quality-dev` gate completed after the terminal-cleanup
  change: 296 local tests passed; its external fast lane reported 6,782 passed,
  one skipped, and 25 failed in 1,531.81 seconds. Comparing exact failure IDs
  with the preceding 26-failure run found no new ID; the sole removed failure
  is the KVM-dependent signed-width recompilation test, which also passed in a
  focused KVM replay. The count change is therefore not credited to the CFG
  walker. This remains a red global gate and does not prove a Csmith round
  trip or a fixed large-model far-pointer return.
- With KVM available, the first admitted small-model `word_comparisons` pilot
  case still ended `timed_out` at 601.92 seconds, without a complete case
  report. Its six serial focused jobs were checkpointed: five returned timeout
  status after roughly 89-100 seconds each, while `clamp_u16` returned zero.
  The jobs retained `timeout=60` and their own logs under
  `.cache/compiler-coverage/pilot-kvm-word-20260927/case-000/`. A separate
  source-free direct run of linked `cmp_i16` at `0x10010` with a 180-second
  decompilation budget completed with `validation=passed` after about 63
  seconds; it is a budget diagnostic, not a passing admitted case or a claim
  that all six functions are fixed. The original C returns signed `int`, so
  generated-C shape and the complete rebuild/DOS behavior remain unaccepted.
- A timeboxed read-only Devin audit of that pilot did not produce a report in
  its first 240-second invocation; a resumed, no-tools response was reviewed
  against the retained artifacts and code. The case's 600-second outer limit
  killed the run before the batch process allowance (1,080 seconds) or any
  per-job fork allowance (180 seconds). The five rc=3 jobs reported CLI
  recovery/decompilation timeouts under their shared 60-second direct-address
  deadlines. `cmp_i16` began recovery at 20:37:12, began decompilation at
  20:37:32, and timed out at 20:38:19; the log also records two project builds,
  the second in the isolated project lane. This timing does not prove that
  either build can safely be removed. Devin's suggestion that the successful
  180-second direct probe might have used sidecar hints is inapplicable: that
  probe did use `--ignore-local-sidecar-hints`. An exact-flag 60-second replay
  returned immediately from the validated direct-request cache, so it is not
  a fresh success or a useful performance comparison. A subsequent
  `INERTIA_DEBUG_TIMING=1` source-free replay disabled both final-C cache
  paths, executed live structuring/postprocess/tail validation, and finished
  `validation=passed`; its reported decompilation time was 12.91 seconds, with
  about 15 seconds from first recovery marker to C output. Lower-level caches
  and machine state were warm, and the diagnostic mode changes logging, so
  this does not establish a cold-run speedup or full case acceptance. No
  owner-layer speedup or budget change is accepted from the audit; preserve
  project isolation and validation while locating the cold-run cost.
- Replaying the exact six-job `word_comparisons` batch on the unchanged owned
  Python implementation (`2fcdd40fb052ba99bc316ca68644e62b1bb93980065d15c95bf1664ab8f08326`)
  returned six rc=0 results with clean per-function tail validation. The
  `cmp_i16` job reused an accepted direct-request cache entry; the other five
  completed live. A separate one-job diagnostic with `PYTHONHASHSEED=1` and
  `INERTIA_DEBUG_TIMING=1` disabled semantic/result cache reuse and still
  validated `cmp_i16` in 16.01 seconds. These measurements do not explain the
  earlier 89-100-second job times. The full admitted small-model case then
  passed in 137.47 seconds, including original MS C DOS execution, six source-
  free focused decompilations with `validation=passed`, generated-C rebuild,
  and matching original/rebuilt DOS exit code 255. Artifacts are under
  `.cache/compiler-coverage/pilot-kvm-word-rerun-20260927/`. Its structured
  summary says `roundtrips_passed=true` but
  `feature_coverage_verified=false`; the <=60-second routine target and all
  other pilot cases remain open. This is a passing round trip, not proof that
  its four listed feature obligations have binary witnesses.
- The next admitted small-model case, `array_pointer_writes`, now runs with
  KVM but ends `recompile_failed` after 189.98 seconds. Its original MS C DOS
  executable runs successfully, and all five source-free focused functions
  (`fill_bytes`, `sum_words`, `swap_ptrs`, `offset_copy`, `select_word`) return
  rc=0 with clean tail validation. The generated whole-case C is not valid MS
  C: `sub_100f1` is declared/defined as scalar `unsigned short` and returns
  `(arg_6 << 1) + arg_4`, while the retained harness dereferences its result
  at two callsites. MS C reports C2100 illegal indirection and C2106 non-lvalue
  assignment there. No rebuilt executable or DOS behavior comparison exists.
  Artifacts are under `.cache/compiler-coverage/pilot-kvm-array-20260927/`.
  The earlier IR proof of the 16-bit scaled AX return is not wired to near
  pointer publication, and neither the scalar return nor the harness C is
  binary proof of an input pointee family. The next fix must close independent
  caller/storage-family and C address-expression evidence, then publish input,
  return, and callsite types atomically in Lowering. No timeout or rewrite
  workaround would satisfy this case.
- A subsequent binary-evidence review found an independent *candidate* for a
  two-byte caller stack family: `POINT.EXE` passes the same `BP-0x14` address to
  other callees that use scaled two-byte indexed loads/stores. This is not yet a
  family proof: exact cross-call Alias identity, extent, and SS-to-DS guest
  address binding remain open. The callee pointer collector previously missed
  a BP-argument carrier when it occupied the `SI` term of `[BX+SI]`; it now
  records that use as typed indexed ambiguity, preserves it in the evidence
  codec, and makes input-trial classification refuse rather than guess a
  pointer base. A focused regression failed before the fix; the focused
  evidence/codec/trial set passed 23 tests and `make check-files` passed 285
  tests afterward. This does not type `select_word` or resolve recompilation.
  A read-only Devin audit was reviewed against current code: the callee
  prototype preflight can be bypassed by callsite return declarations reading
  the storage contract directly, so near pointer return publication needs one
  shared typed binding gate. Its proposed `SIGNEDNESS_UNKNOWN` first failure is
  still an inference, not a measured publication verdict. `quality-dev` was
  attempted on the shared dirty tree: 6,783 tests passed and 24 failed,
  including decompilation timeouts; the broad gate remains non-green and the
  individual failures have not been attributed to this slice.
  A fresh admitted-case rerun under
  `.cache/compiler-coverage/pilot-kvm-array-index-20260927/` ended
  `timed_out` at the 600-second outer limit: `fill_bytes`, `sum_words`,
  `offset_copy`, and `select_word` reported rc=3 recovery/decompilation
  timeouts, while `swap_ptrs` returned rc=0. It therefore supplies no new
  whole-case semantic or recompile verdict. A separate source-free direct
  diagnostic of linked `sum_words` at `0x10045`, with a 180-second analysis
  budget and cache-disabling timing diagnostics, finished with
  `validation=passed`; reported decompilation time was 55.43 seconds and the
  emitted input remained `unsigned short *`. This is one-function evidence,
  not an admitted-case pass or a speed claim.
- A subsequent source-free, in-process direct probe of the identical linked
  `POINT.EXE` at `select_word=0x100f1` measured the actual typed publication
  verdict rather than inferring it from C: every observed attempt returned
  `INPUT_REFUSED`, with `SIGNEDNESS_UNKNOWN` for logical input 1 at both direct
  caller sites (`0x102c8`, `0x102e6`). Direct tail validation still passed,
  but the C return remained scalar. This confirms the first live refusal;
  it does **not** authorize calling the index signed, unsigned, or a pointer.
  The existing IR scaled-return proof may establish sign-insensitive 16-bit
  bit-pattern use, but independent input pointee family, SS/DS address
  binding, and atomic pointer expression/type publication remain open.
  An initial probe failed while creating a `/tmp` recompilation directory
  because the root filesystem had zero free space; setting `TMPDIR` to this
  workspace's `.cache/` allowed the diagnostic to complete. No files were
  removed from `/tmp` or elsewhere.
- A read-only segment-state audit resolved the apparent caller-site address
  discrepancy: the two linked CALL instructions are `0x102c8` and `0x102e6`;
  the later addresses are return dereferences. The caller passes
  `LEA AX,[BP-0x14]`, but current per-function segment state seeds DS and SS
  as distinct architectural live-ins, and no interprocedural startup relation
  or closed CALL preservation proves DS=SS at either site. The binary has an
  earlier `PUSH SS; POP DS` before entering main, but that instruction pattern
  is not by itself a published program-wide segment invariant. A near-pointer
  return using the caller's stack base must keep this address binding refused
  until IR/Semantics proves and carries the relation through the calls. A
  source-free `PUSH SS; POP DS; RET` control already proves the local SS-to-DS
  copy in Alias/SegmentState, so the remaining owner is the interprocedural
  entry relation and preservation, not basic instruction decoding.
- A bounded Devin batch added a Lowering-owned, binary-only near scaled-return
  **candidate** and byte-backed tests; parent review found and corrected three
  issues before acceptance: unregistered SSA was being built/published despite
  the read-only contract, a same-address boundary from another project was
  accepted, and a refused upstream proof counted as classified with nothing
  materialized. All three review regressions failed before the correction;
  the final focused candidate suite passes 12 tests, with scoped Ruff, MyPy,
  and module Pyright clean. The collector now reads an already-registered
  Semantics SSA artifact or returns a typed refusal, retains the exact
  `AX = base + 2*index` IR proof, and publishes no prototype, C expression, or
  storage contract. This is not `select_word` pointer-return acceptance: its
  independent pointee family, segment relation, representable C, and complete
  linked-EXE round trip remain open.
- Candidate integration checks on the shared tree: `make check-files` passed
  87 selected tests plus architecture/context/ownership checks; scoped Ruff,
  MyPy, and module Pyright passed. `make quality-dev` completed its linter,
  startup, ownership, and 296-test contract lanes, but the external fast
  pipeline ended non-green with 6,783 passed and 24 failed (36 minutes), the
  same aggregate count as the preceding broad run. Named failures were in
  existing COD, SORTD, REP-store, BIOS, and CLI tests, many with decompilation
  timeouts; no failure named the new candidate test. This does not prove those
  failures are unrelated, and the gate remains open. No admitted pointer case
  or whole-case validation status changed.
- A linked-binary startup probe exposed a narrower prerequisite to the
  interprocedural segment relation. `POINT.EXE` has an exact typed-IR
  `PUSH SS; POP DS` pair at `0x103b0/0x103b1`, but preceding calls make the
  block-entry SP offset unknown. Alias previously refused that pair despite
  its two local SS byte stores and matching loads. Alias now collects a
  block-local relative-coordinate proof from empty local byte evidence when
  incoming SP is unknown, discarding that coordinate at the block exit rather
  than publishing it to successor blocks. Byte-backed positive and negative
  controls cover an intervening SP clobber, uncertain SS store, split blocks,
  and the same local proof for GP register restoration; all 14 focused
  segment-stack-restore tests and `make check-files` (228 selected tests plus
  checks) pass. The linked startup now reports a
  proven `ss` save at `0x103b0` and `ds` restore at `0x103b1`, with five of
  five Alias facts materialized. The downstream segment-state solver still
  reports both DS and SS unknown before the `main` call at `0x103be`; this
  fixes Alias evidence only, not a program-wide DS=SS relation, pointer
  publication, recompile, or the admitted case.
- The existing interprocedural segment-summary join had a fail-open edge:
  an `UNKNOWN_REFUSE` control transfer to a known target was classified as a
  proven callee effect. A focused regression reproduced it before repair;
  the join now refuses that effect and propagates the refusal to callers.
  All seven focused summary tests and scoped `make check-files` pass. This
  strengthens the preservation gate but does not prove any call preserves
  DS/SS. On linked `POINT.EXE`, exact binary reachability gives zero IR
  refusals for `main` and the five focused application functions; `main`
  has 13 direct calls and no local DS/SS write, and each focused function
  calls the same target at `0x105bc` without a local segment write. That
  target matches the existing 17-byte binary stack-probe pattern, but exact
  bounded reachability refuses its indirect return and error jump. Pattern
  recognition alone is not a closed segment-preservation proof. The next
  program-level relation must account for those calls or keep the caller
  binding refused.
- A bounded `swe-2-high` Devin batch under the 4 GiB virtual-memory cap added
  the nonpublishing IR direct-call DS=SS candidate. Parent review reproduced
  four failing controls and corrected the patch before retaining it: branches
  outside the local save/restore/CALL interval must not refuse an otherwise
  closed caller, unrelated callers must not duplicate the selected callsite,
  a different physical code segment must not borrow a near low-word target,
  and an incomplete direct-call index must refuse. Principal positives now
  derive their index from real decoded bytes rather than synthetic entries.
  The final candidate suite has 21 passing tests; combined scoped
  `make check-files` passes 186 tests plus its guards and linters, and module
  Pyright is clean. The new candidate and summary regression are enrolled in
  the routine pipeline; the broad semantic gate has not been rerun here.
  On linked startup, the direct index closes seven of seven facts and binds
  `0x103be` exactly to `0x1010d`, but the candidate still returns
  `CFG_NOT_CLOSED`: the imported IR has `0x1032a -> 0x1032d`, whereas the
  same Frontend boundary records `0x1032a -> 0x10337/0x10347`. All block
  identities match. The next owner is the exact boundary-to-IR CFG projection
  (inspect overlapping block normalization); do not discard that disagreement
  to publish a segment relation. No pointer type, C expression, function
  validation status, or admitted-case verdict changed.
- Further parent review added byte-backed corruption controls for a stale
  Alias source whose IR restore destination disappeared and for a conflicting
  DS write after the restore at the same machine-instruction address. Both
  initially produced an incorrect `PROVEN`; the candidate now binds the
  actual restore destination and checks every later effect, including effects
  sharing that address. Boolean code addresses also fail construction instead
  of being accepted as Python integers. The original 21-test suite passed
  before this repair; the final focused suites pass 27 tests in 32.94 seconds,
  with scoped Ruff, MyPy, Pyright and the changed-file ratchet clean. The six
  new controls are enrolled in routine tests. The exact linked startup CFG
  disagreement was assigned to a bounded Devin Frontend normalization task;
  a separate read-only Devin audit owned the helper preservation diagnosis.
  No segment-entry state or pointer expression has been published, and the
  broad semantic gate remains open.
- The normalization Devin invocation stopped making tool progress after its
  initial source reads; one saved-session retry on the free SWE-2 Medium
  variant also made no tool progress. Both were stopped without source edits,
  and the parent completed this bounded prerequisite. Six byte-backed controls
  first reproduced duplicate suffix ownership, acceptance of an out-of-bounds
  RET, and a mid-instruction overlapping entry. Frontend now partitions only
  suffixes with matching exact bytes, contiguous instruction extents and
  terminal edges, retaining all unproven blocks/edges with typed refusals.
  IR import consumes the exact owned block extent rather than reintroducing
  unbounded overlapping captures. Additional controls cover nested suffixes,
  backward discovery, conflicting bytes/decodes/extents/edges and an unexpected
  decoder defect that must propagate. The initial focused integration suite
  passes 120 tests in 53.02 seconds, with scoped Ruff, MyPy and Pyright clean;
  the new tests and owner are enrolled in the routine gates.
  Linked startup now has matching Frontend/IR CFGs (20 blocks, 22 edges), zero
  IR refusals, zero successor-rewrite failures and zero discarded overlapping
  logical-memory captures. The direct-call index closes seven of seven facts,
  Alias closes five of five restore facts, and the nonpublishing equality
  candidate at `0x103be -> 0x1010d` is now `PROVEN` (1/1/1/1/0). This proves
  only local live DS=SS at that CALL; propagation into main, transitive CALL
  preservation and pointer publication remain open.
  Final scoped `make check-files` passes 459 selected tests in 96.28 seconds
  plus Ruff, MyPy, the docs/types ratchet, startup architecture, context and
  ownership checks. The recorded regression-to-scoped-check interval was
  2026-09-27 23:54:02 UTC to 2026-09-28 00:06:29 UTC (12m27s elapsed,
  including command waits and the independent diagnostic review, not a speed
  benchmark). `quality-dev` and the required default pipeline are the next
  serialized broad gates; their status is pending, not assumed green.
- Parent review independently confirmed Devin's useful helper diagnostic:
  `0x105bc` still has four facts with two unresolved exits; its returning
  path has an entry SS word feeding CX/IP and no local segment write.
  Its error target's bounded decoded census closes 38 facts but contains
  further direct/indirect/far/interrupt calls, local segment destinations and
  a decoded RET. The worker's stronger preservation/clobber claims were not
  accepted: no local write does not prove preservation across unresolved
  calls, and a local write does not prove final clobber after possible restores.
  A decoded reachable RET also does not prove feasibility under the helper's
  AX=0 context. Generic near-return frame linkage, complete callee effects and
  condition-sensitive error-path proof remain obligations. No helper effect,
  entry state, pointer type, C expression or admitted-case verdict changed.
- The serialized broad checkpoint completed non-green. `quality-dev` passed
  its static/startup/ownership and 296-test contract lanes, but its fast unit
  lane reported 6,849 passed and 10 failed in 952.58 seconds. The required
  default pipeline reported 6,850 passed and 9 failed in its unit lane
  (845.74 seconds). Its four selected QuickC fixtures passed with four
  validations passed; the MS C full lane passed five of eight constructs and
  failed `mixwidth`, `pointer_memory` and `scalar_types_io`. Overall default
  result: one of three lanes passed, two failed, none skipped or timed out.
  Unit failures include COD signatures/call arguments and corpus timeouts;
  they are not assumed unrelated. Complete logs are retained under
  `.cache/frontend-partition-*-20260928.log`. This is not a green gate or
  an admitted pointer-case result.
- A bounded Devin audit reproduced an IR/Alias evidence transplant: two
  byte-backed programs at identical addresses/CFGs differ only in PUSH SS
  versus PUSH DS. The latter correctly refuses by itself, but foreign IR or
  even just the former's Alias relation falsely produced PROVEN. Parent
  review independently reproduced all three transplants. Two 4 GiB-capped
  Devin batches prepared patches only in ignored staging directories while
  broad gates held a live-source freeze. Parent reviewed both exact deltas
  against recorded SHA-256 baselines and reproduced the live/shadow checks
  before application. Raw IR lookup now refuses without creating a registry;
  the candidate's acceptance requires the exact project-registered raw IR
  object and its Alias source's retained object identity. Bare, foreign,
  equal-content-copy and serialized-only relations refuse with closed counts.
  The initial integrated focused suites passed 47 tests in 34.27 seconds.
  Parent review then reproduced three additional failures: two mutation-oracle
  controls missed changes inside the same registry dict, and a corrupt existing
  registry entry was mislabeled as absent. The oracle now checks entry keys
  and object identities, and corrupt registration has its own typed refusal.
  The corrected focused suite passes 64 tests in 24.11 seconds. Final scoped
  `make check-files` passes 486 selected tests in 86.05 seconds plus Ruff,
  MyPy, the docs/types ratchet and startup/context/ownership guards. Module
  Pyright reports zero errors after making the already-selected non-optional
  instruction address explicit at Alias's two private helper boundaries;
  no missing-address or restore behavior was changed. The linked startup
  recheck retains 20 blocks/22 edges, zero IR refusals, Alias 5/5 and direct
  index 7/7; its registered local candidate remains PROVEN (1/1/1/1/0).
  The observed live integration/scoped-check interval was 2026-09-28
  00:54:02 UTC to 01:08:21 UTC (14m19s, not a speed benchmark).
  The final tree's broad gates have not been rerun after these safety changes;
  the preceding non-green gate remains an open obligation.
  No function-entry state, prototype, C
  expression or admitted-case verdict is published by this checkpoint.
  Decoded-index provenance, in-place binary rebuild freshness, generic helper
  return/preservation and the pointer vertical slice remain obligations.
- Two further 4 GiB-capped Devin batches earned local helper-return evidence
  and prepared an IR unknown-CALL guard. Parent's raw-byte replay retained
  both open helper exits and all four refused SP-memory accesses; the worker's
  closed-boundary container is not accepted as a whole-function proof. AX is
  0 at `select_word`'s helper call and 22 at main's; AX=0 still cannot exclude
  the DS-global comparison/error route. Parent review then caught and fixed
  a second guard defect: CALL target operands were misread as output values.
  Nine controls went red before correction; final focused checks pass 39 tests.
  Scoped `check-files` passes 364 selected tests (76.93s) plus static/ownership
  guards, and both changed modules have zero Pyright errors. Both regression
  modules are enrolled in routine lanes. An existing dword-call AST failure
  reproduces identically with exact pre-Devin source copies; it stays tracked.
  No entry equality, positive callee preservation, pointer publication, tail
  validation or admitted witness changed. Broad final-source gates remain due.
- The CALL-boundary final-source `quality-dev` recheck completed non-green:
  static/startup/ownership and 296 contract tests passed; fast unit lane
  6,875 passed and 20 failed in 1,014.90 seconds. These include timeouts and
  COD/live-corpus checks; no failure is waived as unrelated. Completion was
  observed at 2026-09-28 02:22:18 UTC. The required default pipeline started
  afterward (observed by 02:22:56 UTC) and remains pending. Live sources stay
  frozen during the run. Two 4 GiB-capped Devin jobs own ignored artifacts only:
  an exact helper-error DOS-termination diagnostic and a staged constant-lane
  IR proposal. Parent review, baseline/corruption controls and final integration
  checks are still required. No positive callee effect, entry relation, pointer
  publication, function validation or admitted witness is claimed.
- Parent reviewed both completed Devin jobs. Within the retained helper-error
  census, byte/IR replay independently proves the three local INT21 selectors
  35h/25h/44h and altered-selector/vector controls. The no-return-interrupt
  hypothesis does not close the helper. Service 44h lacks a spec row, so the
  worker's Boolean "not no-return" is not accepted as a returning proof;
  selector counters are 3/3/3/3/0, service metadata 3/3/2/2/1. Ordinary/indirect/
  far callees and return feasibility remain open. The staged known-lane owner
  improves a real sibling-byte-write precision gap but failed independent
  malformed-write, implicit-widening and conversion-source-width controls.
  One is a new false proof and two are inherited debts at the touched boundary.
  It stays unintegrated; the exact prior Devin session was resumed for narrow
  staging-only correction, with its 4 GiB cap verified. Default pipeline's
  contract lane passed 296 tests and unit lane reported 6,882 passed/13 failed
  in 1,128.12s; external results remain pending. No callee effect, entry relation,
  pointer type, function validation or admitted witness is published.
- The default pipeline is now terminal exit2 (observed03:04:56UTC Sep28):
  296 contract tests passed and the unit lane recorded6,882passed/13failed
  in1,128.12s. Its three-selected/three-failed final summary is lane-level;
  individual external construct acceptance must use the retained lane artifacts.
  Devin v2's original four controls independently pass, but four additional
  malformed-write/conversion-provenance/CALL-target controls fail. The valid
  converted-temporary reread passes. Parent rejects v2 pending another bounded
  staged correction; no live semantic owner is replaced. Independent saved-log
  triage has separate read-only ownership. Both new batches use an explicitly
  verified read-only-host/writable-repository Bubblewrap boundary and a4GiB cap.
  No callee preservation, entry relation, pointer type, validation or admitted
  witness is claimed by these checks.
- Completed Devin v3 is reviewed and integrated at the early IR value owner.
  Parent independently reproduces all nine controls; the new modules recorded
  23 failures/20 passes before the fix, and three native-byte Alias consumer
  tests separately failed with missing constants. Initial integration passes
  157 focused tests; final scoped `check-files` passes436tests in65.32s with
  static/startup/ownership checks and module Pyright reports zero errors.
  Routine Make/pipeline/ownership enrollment covers both new modules. Proven
  sibling bits now survive valid partial writes; conversion re-decoration
  requires retained production provenance; malformed writes refuse; CALL
  targets cannot overwrite immutable definitions. Native Alias materialization
  has1/1/1/1/0counts. Parent-only lint/type corrections preserve those semantics.
  No generated-C/tail/admitted-case improvement is claimed before broad final
  gates. The helper's open return/frame/callee frontier and pointer slice remain
  required. Verified prior-lane artifacts show QuickC3pass/1fail and MS C1pass
  of8constructs; scalar_types_io's compiled execution exits7. These are retained
  failures, not exclusions. A saved cmp_i16 timeout names segmented-memory
  structuring, not a measured whole-budget profile.
- Final-source quality-hard began03:46:43UTC and terminal exit2 was observed
  03:50:02UTC on Sep28, before unit execution. Full architecture findings remain
  open (dynamic attributes, promotion registrations, CLI markers and focused
  skip/xfail); no matching pre-change baseline classifies them as preexisting.
  Serial quality-dev began03:54:17UTC with live source frozen. A separate
  staging-only Devin CLI quality batch began03:56:19UTC, limited to docstring
  ownership and the architecture promotion registry; Make already enrolls that
  module. Parent reviews before integration; no semantic witness is admitted.
- Final-IR quality-dev is terminal exit2, observed04:14:00UTC Sep28:296contract
  tests passed; fast unit15failed/6928passed in997.78s. The final one-selected/
  one-failed summary is the unit lane, not external acceptance. Retained COD
  signature/call failures and typed timeouts remain unclassified against a
  matching broad baseline. Parent reviewed and integrated only Devin's CLI
  docstring/one-registry-entry quality delta after this freeze ended;37focused
  policy tests and scoped lint/type/ratchet/architecture checks pass. Runtime
  body/acceptance policy are unchanged. Required default pipeline21617 began
  04:17:04UTC, serially with live sources frozen. Independent Devin84764 is
  staging entry-prefix Alias byte origin only; return/callee closure and pointer
  publication remain open. No function fix or coverage witness is claimed.
- Parent's final entry-byte proposal replay reproduces five review failures on
  exact SHA4678b1d17f2c403d0b5b2b0aed645ed681f6c49c303a7c8f88565cbca6451cd4:
  four unsupported origins materialize and diagnostic projection is
  nondeterministic. The proposal remains unintegrated. Batch84764 terminal1 was
  observed04:41:38UTC after clean interruption of its verified owned process;
  exactly session rotating-patch resumed as42062 at04:48:01UTC. Bounded staged
  correction must consume one Alias coordinate owner and preserve native/legacy
  behavior, with independent refusal controls before integration. Default21617
  has completed: terminal exit2 observed04:58:09UTC, contract296passed and
  unit6927passed/16failed in1028.99s. MS C round trips1passed/8constructs;
  simple_control passes, seven constructs fail. Final selected3/failed3 counts
  lanes. Source freeze ended; no semantic acceptance or new witness is claimed.
- Reviewed and integrated the corrected entry-prefix Alias byte primitive and
  its shared-snapshot extension, keeping the original snapshot owner unchanged.
  Canonical new/legacy tests89passed7warnings35.39s; complete scoped gate53passed
  7warnings29.94s with static/startup/ownership checks. Three new modules are
  enrolled in routine QA. Proof remains initial-entry SS bytes only; the native
  frontend frontier4/4/4/2/2 and external helper edge remain open. Caller-frame,
  complete return/callee effects, DS=SS, pointee and pointer publication still
  require independent evidence. No generated-C or admitted witness is claimed.
- Final entry-byte scoped gate passes53tests/7warnings36.50s. Required
  quality-dev is terminal2:296contract passed, unit6984passed/12failed1452.98s;
  no matching baseline attributes that failure-count change. Parent integrated
  the independently verified verbatim evidence-guide extraction without
  changing checker caps or acceptance rules. Architecture72957 is terminal2,
  observed08:09:09UTC, with167findings/12categories; remaining debt is unwaived.
  Devin's staged shared scalar-projection extraction failed parent review:
  losing register+register Add's operand-name decoration changes both a proven
  and a refused read. Independent red2failed/7warnings92.62s; bounded correction
 75590 began08:21:12UTC with repository-only writes and4GiB cap. Nothing from
  that proposal is integrated, and no word/frame/callee/C witness is admitted.
- Parent captured correction75590's last-minute patch after its cap124 and
  independently reviewed the exact delta. The two semantic review controls
  pass in isolated IR and the normal16-test retry; initial collection errors
  from an unrelated concurrent lifter edit were retained, not waived. Shared
  scalar-operation/conversion metadata is integrated in IR, with constant-flow
  consuming one authoritative owner. New public producer/refusal controls are
  enrolled across QA/pipeline/ownership. Final scoped gate330passed/7warnings
  141.10s, terminal0 observed09:33:28UTC; scoped Pyright0errors. Published values
  and immutable identity relations remain stable; refused conversions no longer
  allocate discarded private views. Broad gates, word-value recomposition,
  caller-frame/callee/return closure and all compiler-witness obligations remain
  required. No generated-C or function-fix improvement is claimed.
- Parent reviewed Devin's small CALL-target SSA delta and independently reproduced
  baseline4failed/2passed and corrected6passed/7warnings. IR now versions CALL.dst
  as a pre-call input without binding or replacing a producer; later explicit
  outputs remain independent. Durable routine/ownership controls are integrated;
  final scoped gate68984 remains pending. Native staged Word value replay gives
  1/1/1/1/0, but Alias/frontend/callee/return boundaries remain unchanged and no
  word API, C improvement or compiler witness is admitted yet. Hard31232 is
  terminal2 with173architecture findings; quality-dev60028 is terminal2 after
  296contract passes and an interrupted fast unit command143. Required gates
  remain open, with no invented unit totals or matching-baseline waiver.
- The selected initial-entry Word value API is now integrated at Widening after
  canonical Alias and locally built SSA. Parent's saved-engine controls reject
  9previous false proofs; repeated producer IDs additionally refuse until unique
  lineage exists. Final canonical161focused tests pass/7warnings119.16s, and the
  SSA scoped gate112passes. New modules pass Ruff/MyPy/ratchet/Pyright with owned
  types resolved rather than skipped-import Any. Native word1/1/1/1/0 retains
  Alias2/2/2/2/0 and frontend4/4/4/2/2/incomplete. This is not a C consumer or a
  function/witness admission. Full scoped gate15256 stops before pytest on two
  real16 ownership skips; the required broader gates remain open and unwaived.
- Parent reviewed Devin's bounded staged real16 skip-removal delta against its
  saved dirty baseline, narrowed the new test catcher, and independently
  reproduced2failed/2passed baseline and4passed correction. Original binary and
  CLI assertions remain; invalidated evidence propagates, never skips/passes.
  Final binary/provenance16tests pass; Ruff and ownership pass. The later full
  changed-file gate is non-green:12passed/1CLI failed(exit1 instead of0), with no
  matching failure attribution or waiver. Required Word quality-dev49718 ended2
  on type-ratchet command143 before units; no unit total follows. A fresh
  source-free select_word run still exhausts60s recovery and reports timeout/
  uncollected tail validation(exit3). No generated-C/function/witness admission
  changes. Read-only Devin startup audit capped124 without a report; its catalog
  hypothesis requires direct verification and measured profiling before a fix.
- The failed CLI report is UNKNOWN/stale_provenance with1/1/1/1/1counts, not a
  waived success. After ownership correction, final Word scoped gate84096
  passes46tests/7warnings93.22s plus its checks. Parent independently profiles
  signature metadata with retained caches:5.516740s wall/0.491211s CPU,
  16labels/ranges. The fresh baseline cache also contains signature-match
  results, so its286s setup gap cannot establish a comparable performance
  regression or speedup. No production performance patch, C acceptance or
  witness admission follows; keep cache conditions explicit in future probes.
- CALL-input coherence is now also enforced by the shared scalar definition
  index and its complete-record contract. Parent's exact saved-dirty-source
  reds10failed/6passed plus a separate1failed contract control become47focused
  passes/7warnings129.44s. The full scoped53050 is terminal2, observed12:30:17UTC:
  static/startup/context/ownership checks pass,101tests pass and1SORTD inventory
  subprocess exceeds180s(7warnings447.53s). No matching baseline attributes that
  timeout; no deadline/assertion is weakened. The cross-block transport proposal
  remains staged:30own tests pass but20parent effect controls fail, then three
  selected-site false proofs and inconsistent counts are reproduced. Parent's
  geometry/counter correction passes5controls before final scope/type refinement.
  Conditional known-cone relation is not whole-frontier/callee/frame/return or
  C proof. Disjoint bounded Devin tasks correct effect ownership and split the
  transfer/CFG engine; every delta requires parent review. Broad acceptance,
  stale-provenance CLI, select_word timeout and all witness obligations stay open.
- Parent reviews and integrates two bounded Devin VEX-result width deltas from
  saved dirty sources. Instruction/destination/retained result share actual VEX
  type evidence; operands retain independent widths and unsupported ITE values
  stay UNKNOWN. Independent reds4failed/3passed and3failed/3passed become48live
  passes/7warnings60.23s;13new typed tests have importer/fast-pipeline enrollment.
  Required quality-dev is pending; no function/C/tail/witness admission follows.
  Staged branch controls42pass and custom-emitter effect controls119pass are
  component evidence only. Stock-registry-only ordered-comparison refusals are
  withdrawn: real custom VEX emits LT16U and the broader emitter domain. Snapshot
  task caps124 with no final report; its fixture and coherence defects require
  parent review. Proposal, frontend closure and all wider obligations stay open.
- Corrected snapshot fixture and independent parent controls reproduce4fail/
  9pass. Parent fixes full-register-view and known-version requirements and
  duplicate capture/word coherence; final shared stage174passes/7warnings82.62s.
  Fresh deterministic native transport PROVEN1/1/1/1/0 and190observed/190closed/
  0refusals remains typed known_acyclic_target_cone, not whole frontier. The105cd
  exit, incomplete frontend4/4/4/2/2 and whole-callee/C obligations stay open;
  transport is not integrated. Width quality-dev ends2 on sandbox temp storage;
  repository-TMPDIR retry36383 is pending after39-module mypyc smoke passes.
- Fresh post-width select_word diagnostic91806 is terminal3, observed14:31:53UTC:
  the unchanged60s recovery limit still times out; validation is uncollected/hold
  and stdout is generic preamble only, not a function body. This does not close
  the admitted application-function failure. The retained before diagnostic also
  timed out; concurrent source changes preclude sole-width attribution. Parent
  ran the function check after the bounded Devin launch failed before start at
  its scoped nested KVM bind; host KVM API12 was verified. Static-only Devin83172
  checks staged normal-import/type readiness with no live-source edits, under
  hostRO/repoRW/4GiB limits. Broad gates and all witness obligations stay open.
- Width quality-dev retry36383 is terminal2, observed14:36:49UTC: checks and
  39-module mypyc smoke pass;296contract tests pass39.38s. Fast unit lane has
  33failed/7248passed/1skipped/20warnings1545.07s. Five failure sections explicitly
  report missing /dev/kvm; this does not classify remaining failures or establish
  patch causality. Far-return EIP/far-probe CX assertions and timeouts remain
  unwaived. This fast-tier run did not exercise default/release external lanes.
  Static Devin83172 caps124 without report; parent independently verifies the
  six unchanged staged owners through ordinary imports/Ruff and strict MyPy
  with the actual IR core/scalar-projection owners included. This clears one
  integration-readiness check, not live integration, callee/C or witness proof.
- The reviewed transport/effect/snapshot owners are now integrated with ordinary
  imports, explicit Make/pipeline/ownership enrollment and the resolved shared-IR
  MyPy cohort. Existing Word liveness consumes the authoritative effect owner:
  independent2failed/5passed before becomes227neighboring passes. Final scoped
  gate26855 is terminal0, observed15:20:51UTC: checks and227tests pass/7warnings
  74.45s. Fresh linked POINT replay preserves Word/transport1/1/1/1/0 and
  190observed/190closed/0refused effects, but only known_acyclic_target_cone.
  whole_frontier_closed=false; frontend4/4/4/2/2 and105c9/105cd remain unresolved.
  Whole-callee/generated-C acceptance are false. Broader33failures, select_word
  timeout, full project gates and every witness obligation remain open. Parent
  is reproducing the far-control assertions against the declared coordinate
  domains; no assertion or acceptance rule is weakened to obtain green tests.
- Parent-reviewed repository-only sandbox launcher preserves hostRO/repoRW,
  private proc/dev and4GiB; six independent refusals reject its initial proposal
  and pass after exact canonical scope/early validation fixes. Optional Python
  KVM descriptor transport is verified in the child as character10:232/API12;
  default launches expose no host KVM. The real compiler reveals C1043, resolved
  solely by DOS TMP=C:\\ on the writable case mount; two red inherited-TMP
  controls become green,56neighboring tests pass, and the real MS C5.1 alias
  regression passes91.42s. Original-byte Unicorn oracles independently replace
  six confused offset/loader assertions and reject corrupted projections;
  production far semantics/acceptance are unchanged. Final combined gate34965
  is terminal0, observed16:09UTC: scoped checks and92tests pass/7warnings67.73s.
  Profile/thread select_word diagnostic emits a tail-passed body with actual
  worker1/1, but normal-lane/call/shape/round-trip acceptance remains open.
  Broad gates and the prior33-failure checkpoint are unwaived. No new feature
  witness, function fix or performance improvement is claimed.
- The actual routine pointer retry initially fails before decompilation:
  compiler C1043, then LINK L1093. The identical POINT.C source with only DOS
  TMP=C:\\ added compiles(exit0,0.85s). Parent reviews Devin17536's exact dirty
  runner delta: that flag/comment in both source/runtime compile commands and
  four new controls, no link/evidence/semantic changes. Independent saved-source
  controls4fail become8live passes; tests are enrolled in routine/contracts/
  ownership. Final gate62270 is terminal0, observed16:32:45UTC: scoped checks and
  143tests pass/12warnings117.62s. The new-namespace routine pointer retry is
  pending. Fresh unprofiled select_word10747 still exits3, unchanged sources:
  discovery79.78s leaves1s decompilation; tail uncollected. Read-only REP triage
  cannot name the older stdout acceptance blocker, and one bounded current
  replay exits3 timeout instead. No function/witness/performance acceptance or
  waiver of required broad gates follows.
- The actual post-TMP pointer retry88403 is terminal2: original compilation/run
  pass, but all five normal source-free numeric targets timeout3 and the outer
  case is timed_out. Source/implementation identities stay unchanged; no final
  recompilation/behavior report or witness follows. Normal worker-stack samples
  show analysis executing, not a demonstrated IPC deadlock; the CPU probe
  produces no snapshot before timeout and proves no hotspot. Required quality-dev
  and default pipeline now run sequentially in34598, observed16:45:07UTC, verified
  KVM/four external workers/frozen Python sources. Both results remain pending.
  Read-only Devin2519 checks the loader/image-extent coordinate contract without
  tracked edits. No deadline, acceptance gate or prior failure is waived.
- Parent independently reproduces the live loader projection mismatch: public
  max_addr is absolute inclusive, so nine discovery double-adds extend the image
  beyond backed bytes. The loader-domain/relative-Clemory contract is documented
  in the decompiler map. Devin52383 stages a bounded correction in ignored
  copies; read-only11742 measures generation-DAG costs. Tracked Python remains
  frozen under34598. No timeout causality, speedup or function/witness admission
  is claimed from the diagnostic; all three job results are pending.
- Generation-DAG diagnostic11742 is terminal0. Parent independently reproduces
  tuple-equality and repr-sorting path expansion on small legal atom graphs and
  passes semantic controls17692. This is component evidence, not POINT timing
  causality. Staged75876 must retain exact comparison, literal cycle IDs, all
  fields and hash/key coherence; digest-only equality, global interning and
  changed canonical order are rejected. Image fix52383 remains staged and
  broad34598 is active with worker-exit/ordinary failures, not green. No live
  implementation, semantic status, feature admission or deadline changes yet.
- Quality-dev in34598 is terminal2, observed17:46:20UTC: unit run reports
  29failed/7516passed/20warnings3193.35s and xdist internal KeyError(gw8), without
  a final failure inventory. The full owned-Python fingerprint changes while
  all eleven proposal owners remain identical to their dirty baselines; source
  churn prevents stable acceptance/patch attribution. Other register/affine
  test and QA-script mtimes are candidates, not a proven exact delta. Required
  default pipeline starts sequentially and remains live. No failure or identity
  guard is waived; staged fixes are not integrated or admitted.
- Parent review rejects Devin75876's original recursive generation comparator:
  valid builder-produced depth275 inputs regress, Pyright reports three new
  errors, and a legal scalar subclass changes native equality behavior. A
  separate staged correction uses an iterative request-local comparison only
  for proven built-in values, retaining native subclass behavior, all fields,
  exact-class protocol and hash coherence. Independent saved-source regression
  fails on the existing equality path; final staged checks pass12tests, scoped
  Ruff/MyPy/Pyright. Observed18:42:10UTC; no live integration, macro speedup,
  semantic function fix or feature witness. Default pipeline's unit phase also
  fails:4failed/2397passed plus xdist KeyError(gw8), no final failing-test
  inventory. Coordinator34598 remains active; no gate is waived. Image52383
  continues its staged handoff; its reported56passes await parent reproduction.
- Reviewed loader projections and generation comparison are now integrated,
  with routine regression enrollment. Independent image controls fail6/6 on
  saved sources and pass58live tests. All55staged CLI typing findings strictly
  match the dirty baseline; existing debt is not waived. Additional native
  Python3.14 scalar-field controls catch and correct outer-tuple equality;
  final generation controls pass15tests with native self/field/hash protocols.
  One neighboring switch-delta failure is reproduced in both source variants;
  no shape-only suppression is broadened to hide it.
- Unprofiled source-free select_word now emits C with tail passed in36.493s,
  unchanged implementation and empty function/recovery caches, retaining only
  signature metadata. This is not a pointer-prototype, whole-case, speedup or
  feature admission: emitted C remains an integer-offset carrier. The actual
  array_pointer_writes round trip is running at its original600s case budget.
  Required gates and Steps1–5 remain incomplete; no acceptance threshold changes.
- The latest linked small pointer case is terminal `recompile_failed`: all five
  selected source-free function jobs return0 with clean tail reports, but the
  integer `select_word` result causes MS C C2100/C2106 at caller dereferences.
  Both roundtrip and feature coverage remain false; no harness cast is added.
- The four touched object-image reads now catch only CLE's genuine KeyError
  missing-memory boundary. Parent red8fail/4pass, staged green12pass and final
  shared-tree53pass establish that unexpected loader defects are no longer
  silently refused. Routine/ownership enrollment and scoped checks are recorded
  in the parent report; five inherited Pyright findings remain visible.
- A bounded static-sandbox worker observation reports input publication refused
  for logical index1 at both selected-function callsites, before pointer-return
  classification. Its missing-KVM exit4 is not tail-validation acceptance.
  Independent parent IR replay proves only sign-insensitive modular word use
  for the exact callee's two SS:BP inputs (counts1/1/1/1/0 each). A staged typed
  Lowering join is in progress; source signedness, pointer/domain/pointee and
  coherent return-expression obligations remain separate and unaccepted.
- A fresh source-free frontend recorder obtains a complete selected-target
  caller-return census (two used value witnesses, counts2/2/2/2/0). Separately,
  direct CLI phase review identifies a clean-worker snapshot copied before
  late target/neighbor records. A disjoint staged task preserves those facts
  at the final transport boundary. Both staged changes await parent review;
  neither closes the pointer-return representation or compiler roundtrip.
- Current pointer-batch dispatch is independently confirmed serial: the five
  retained function times sum155.7349s against157.564s for the outer batch.
  A bounded disjoint task stages at-most-four function workers, deterministic
  ordered checkpoints and the existing timeout/failure/cleanup contracts.
  Construct-level pipeline parallelism is a separate boundary and is unchanged.
  This is a pending optimization; no measured end-to-end gain, semantic witness
  or routine-runtime acceptance is claimed before parent review and KVM replay.
- Parent integrates the final direct clean-worker evidence boundary with
  routine enrollment: independent saved-source4fail, staged4pass and shared
  tree22pass. All50Pyright findings strictly match the dirty baseline; the
  inherited MyPy no-any-return remains visible. This optional canonicalized
  transport lane is not attributed as fixing hint-free pointer recovery.
- The modular input candidate remains isolated after parent review. Six new
  fixture typing errors are corrected, not excused as sibling debt. A new
  control demonstrates borrowing another callee's modular proof; a selected-
  callee guard retains refusal. Independent old-source3fail/4pass, foreign-
  proof1fail and corrected15pass; scoped Ruff/MyPy/Pyright pass. The controlled
  blob fixture is not a real POINT collection witness. Integration, normal KVM
  replay and all required semantic/feature/broad acceptance gates remain open.
- Near-return operand preflight checkpoint (2026-09-29): a bounded staged worker
  ends124 without completed checks; independent parent review reproduces15
  staged positives/refusals and finds9additional failing controls. Corrected
  exact raw/unified variable identities, retained result fields and bounded
  nonmodular shift counts pass25controls; the proof/wiring family passes182.
  Make/pipeline/ownership enrollment and scoped production typing are checked.
  This nonpublishing Lowering owner proves only numeric congruence to retained
  IR. Actual selected-function result uses are SS and DS at distinct callsites;
  native pointer binding and atomic body/type/caller publication remain required.
  The prior quality-dev fast unit lane is terminal18failed/7859passed, including
  six REP-store behavior failures. Default/external lanes were not run there.
  Neither that gate nor Steps1–5, the frozen pilot or Csmith is accepted.
- Caller-BP transport review (2026-09-29): the isolated IR consumer follows one
  exact reaching definition, requires explicit complete CALL preservation and
  retains each consumed site. Saved-source8fail/7pass, two width refusals and
  four parent-found provenance/census failures precede final62pass with verified
  snapshot imports. The Analysis adapter retains the real predecessor census;
  no missing-map waiver is introduced. Both real whole-PUSH roots still refuse
  because all12 actual CALL effects lack BP-preservation proof. A substituted-
  flag diagnostic is not semantic or pointer acceptance. Three leaf callees
  have unresolved non-SS writes, so restoration candidates alone cannot admit
  preservation. Production integration/routine enrollment remain pending while
  a neighboring gate holds the pipeline lock; Devin stages registration-only
  changes, now independently reviewed with a merge-safe patch dry-run. A separate
  bounded Alias worker expires without a patch; no proof is accepted from it.
  The source-stable broad quality-dev is terminal2
  with8010pass/22fail/67warnings, not green. Final-source gates, roundtrip and
  Steps1–5 remain unchanged and incomplete.
- Exact BP-call integration checkpoint (2026-09-30): real mapped near-call and
  return coordinates bind closed Alias leaf proofs to production CALL effects,
  retaining typed proof/refusal diagnostics. Frontend image-bounded reachability
  removes optional function-range requirements. Target/IR disagreement and
  cross-selector corruption controls reproduce false proofs before their guards.
  Final41 focused controls pass; restore-dependent non-SS stores remain refused
  without caller-context disjointness. In the real pointer witness select_word
  calls preserve BP, offset_copy remains refused, and both numeric PUSH roots
  remain unproven across that prior call. An earlier all-positive diagnostic is
  explicitly superseded. Parent reviewed the sandboxed Devin test-only delta,
  independently reproduced the saved dirty baseline's4fail/23pass, and added
  independent store-census and closed-accounting checks. Final scoped gate
  passes651 tests in46.80s with3 workers; the bounded fixture repair is accepted.
  Existing segmented storage relations classify logical spaces, not runtime
  cross-selector byte disjointness, and cannot discharge this BP obligation.
  Native pointer representation, full gates and original milestones remain open.
- Saved-BP lifetime refinement (2026-09-30): byte-backed before-save and
  after-final-restore controls are red before the Alias change. Instruction-order
  CFG reachability now limits cross-selector refusal to save-to-restore paths,
  retaining backedges and full machine-instruction groups. Scoped checks pass
  309 tests with3 workers; the real offset_copy refusal remains unchanged.
  Its two DS:[BX+SI] byte stores lie inside the lifetime, so this refinement
  does not replace the caller-bound address/extent and segment-relation proof.
- Contextual entry propagation (2026-09-30): existing startup DS=SS evidence
  now binds exact registered caller/callee coverage and seeds a request-local
  callee state. Default/live project analysis is not changed. Stale identity,
  wrong callee, explicit writes and unknown nested calls refuse/drop the fact;
  universal callee-summary closure rejects contextual state. Final scoped
  checks pass392 tests with3 workers. Real startup/main coverage is complete,
  context closes1/1/1/1/0, and equality reaches main entry but is dropped at
  its first raw-IR CALL0x10123. The ordinary solver still seeds DS/SS distinctly.
  This is not transitive preservation or pointer acceptance. Initial NOP/RET
  fixture intake exposes an effectless-NOP census gap, kept as an obligation.
- Entry-context safety review (2026-09-30): a real DS:[SP-derived BX]
  overwrite between PUSH SS and POP DS reproduces a false entry proof. The
  direct-call candidate and BP proof now share an Alias-owned saved-byte
  lifetime guard; missing physical disjointness refuses with a typed reason.
  Final scoped gate passes393 tests with3 workers, and the real startup
  context remains proven. Conditional entry provenance is CALL_ENTRY_RELATION,
  not a guessed architectural DS live-in. No function or plan step accepted.
- Nonpublishing transitive context probe (2026-09-30): five closed leaf
  callee segment effects bind all12 actual main CALLs. Reusing one registered
  raw artifact per target keeps startup-derived DS=SS live at every CALL
  entry, including both select_word sites. Rebuilding repeated targets makes
  earlier retained proofs stale and must not be used by production collection.
  Durable collection/routine controls and caller-bound write-range disjointness
  remain pending. No pointer, tail-validation or original milestone accepted.
- Production segment collection (2026-09-30): extended the existing owner,
  not a duplicate collector. Missing catalogs use closed mapped-entry raw IR
  and the authoritative segment-contract coverage fallback; repeated targets
  retain one registered artifact. A byte-backed repeated-call control is red
  before repair; explicit DS clobber, nested-call and no-return controls pass.
  Final scoped gate passes21 tests with3 workers. Cold real production
  collection closes12/12/12/12/0 and contextual equality reaches all12 calls.
  Caller-bound write ranges, BP disjointness and pointer publication remain
  open, as do broad final-source gates and original acceptance milestones.
- Numeric memory-offset prerequisite (2026-09-30): exact SSA-bound modular
  word projection composes both canonical address roots without conflating
  separate loads. Byte-backed and corruption/refusal controls are enrolled in
  routine pipeline and ownership gates; scoped check-files27green6.63s with
  three workers, configured lint/type checks and Pyright zero errors. Real
  fill_bytes and both offset_copy store lanes close1/1/1/1/0 independently.
  Full effective-address width, caller-bound dynamic ranges, stack coordinates
  and saved-BP disjointness remain separate unproved obligations. No original
  milestone or function acceptance; broad final-source gates remain open.
- Range-proof intake (2026-09-30): current binary SSA/Condition evidence
  proves natural loops for fill_bytes and offset_copy with signed16 `slt`
  against SS:BP+8, not the existing unsigned constant-bound contract. That
  owner must not be weakened or supplied a fabricated constant. Dynamic count
  binding, load stability and signed induction bounds are required before
  caller-range publication. Numeric offset contracts now also reject Boolean
  and floating-point constants/coefficients that compare equal to integers;
  all four corruption controls reproduce red before repair. Final scoped
  check-files31green10.29s and Pyright zero errors; function acceptance remains
  open. Real intake evidence is retained in the ignored offset-affine probe.
- Signed range prerequisite (2026-09-30, validation in progress): the existing
  range owner now retains signed LT/GE separately and permits zero-init,
  unit-step positive constant bounds only with matching condition width,
  induction storage and exact constant, before the sign bit. Dynamic bounds
  remain refused. Three binary positive-bound controls reproduce red before
  repair. The intermediate scoped gate84green68.98s precedes final corruption
  checks; final source is Ruff/Pyright-clean but its focused rerun is pending.
  Full test-pipeline is running, logged under .cache/signed-loop-range-pipeline.log;
  its contract pre-gate296green is not end-to-end acceptance. Caller-bound
  dynamic count/load-stability proofs and original milestones remain open.
- Signed-range review counterexample (2026-09-30): parent byte-backed probe
  reproduces both signed and legacy unsigned acceptance of [0,4) after a
  mid-body overwrite sets the induction word to7 before the indexed access.
  This invalidates acceptance until complete induction-write accounting is
  enforced; initializer/increment recognition alone is insufficient. Probe is
  retained under .cache/signed-range-clobber-probe.py. Real caller diagnostics
  separately prove count3 at both offset_copy calls with closed1/1/1/1/0 input
  transport, not a universal callee constant or a published range. Full pipeline
  and read-only Devin audit remain live; no production proof acceptance.
- Parent review checkpoint (2026-09-30): Devin exits0 with no source edits;
  owned hashes match its pre-review baseline. Parent independently reproduces
  word, byte and refused-expression induction overwrites, plus accesses before
  the guard or after the latch increment. All eight durable corruption controls
  are red9.46s with three workers. A fresh final-source signed-bound suite is
  six green12.03s. Full pipeline unit lane reports8454green/14red896.55s;
  three mixed-source relabeling failures do not reproduce in that fresh suite.
  Other11 unit failures remain unclassified. Relational lane121green139.07s;
  external lanes remain live. Acceptance requires complete mutation census,
  instruction-order and all-entry initialization evidence, not a weaker gate.
- Mutation-census checkpoint (2026-09-30): raw STORE byte-lane accounting,
  initializer dominance and access/load ordering now reject the eight reviewed
  binary corruption cases. The initial repair passes the scoped92-test gate
  in32.55s; Pyright reports0 errors. Dynamic bounds retain DYNAMIC_BOUND as
  the prerequisite refusal rather than inventing a local constant.
  Candidates additionally retain typed raw-effect verdicts, exact sites,
  expected byte slices and checked/refused blocks with five-counter accounting.
  Seven retention controls reproduce red9.58s; intermediate14green7.50s.
  Final omission/relabeling source passes check-files92green40.87s with three
  workers and configured lint/type/startup/ownership checks; Pyright0 errors.
  This retained
  generation census is not yet an authoritative certificate for the separate
  explicit range-candidate/fact boundary. Caller-bound binding, bound-load
  stability, pointer address extent and saved-frame disjointness stay open.
  Full pipeline has terminated non-green: contract296pass, unit8454pass/14fail,
  relational121pass; final lanes1pass/3fail. No function or milestone accepted.
- Explicit range boundary (2026-09-30): binary-backed red7.12s demonstrates
  that the collector formerly accepted a candidate after its census was removed.
  Collection and fact completeness now require retained mutation evidence bound
  to the exact function, induction identity, initializer/increment byte slices,
  loop header/blocks and initializer dominance. Missing, relabeled, omitted or
  mismatched evidence refuses. Accepted facts retain the census through Alias
  consumption. Synthetic layout fixtures explicitly provide their closed test
  lifetime instead of relying on the absent-proof shortcut. Focused54green8.53s;
  final scoped check-files92green40.99s with three workers, configured lint/type/
  startup/ownership checks and Pyright0 errors. The codebase-memory skill guided
  collector/caller discovery; changed-source coverage was read directly.
  Caller-bound count/load stability and pointer/store disjointness remain open;
  full pipeline remains non-green. No function acceptance claimed.
- Required quality-dev follow-up retains stricter typing: the development
  target now checks the same owned SSA/condition-provider closure as scoped
  range checks. Two consumers import SSABlock from its actual SSA owner,
  not an unexported incidental import. Far-return focused22pass10.74s. First
  two quality-dev runs failed at these typing gaps. Third run passes lint,
  startup and296 contract tests8.09s, then terminated non-green: fast unit lane
  8452passed/31failed/1skipped664.09s. Several failures explicitly report missing
  /dev/kvm; a fresh stat confirms the device is absent. Other failures remain
  unclassified. Log `.cache/range-boundary-quality-dev-owned-imports.log`.
  Session40412 is terminal; no green development-gate claim.
- Caller-count intake (2026-09-30): real count PUSH lanes at both calls map
  to SS:callee-entrySP+6/+7; Alias frame evidence proves BP=entrySP-2, mapping
  BP+8 to those lanes. This does not establish stability or publish a bound.
  Existing IR word-value collection refuses both as MIXED_INSTRUCTION: the
  constant AX producer precedes the PUSH. A bounded interinstruction constant
  proof needs explicit CALL/clobber controls before early-layer contextual
  input binding; do not move the successful Lowering diagnostic upstream as
  presumed semantic authority or erase the guard. Retained scratch coordinate
  probe is diagnostic only; caller-byte and callee-load stability remain open.
- Caller-count replay/window diagnosis (2026-09-30): the IR-owned retained
  constant-flow receipt now proves count3 at both POINT caller PUSH sites,
  with no word-value refusals. Fresh exact-prefix diagnostics inventory8 raw
  STORE byte slices per caller window: count at relative offsets65534/65535,
  later arguments at65532/65533 and65530/65531, and the CALL envelope
  at65528/65529. Both blocks have no IR refusals and their only observed CALL
  barrier is the selected terminal CALL. These block-local coordinates are
  relative to arbitrary incoming SP, not proof of function-entry SP values.
  Production acceptance still requires a retained Alias-owned window census
  bound to current source/coverage, both count lanes, selector stability and
  the exact pre-callee boundary. Unknown addresses/effects, overlap, selector
  writes and unproved control entries must refuse. Do not infer callee-load
  stability or pointer disjointness from this diagnostic. Scratch inventory:
  `.cache/caller-count-store-window-probe.py`.
- Local caller-word lifetime prerequisite (2026-09-30): implemented
  `alias/stack_word_call_window.py`, consuming the existing IR constant receipt,
  strict coordinate snapshots and scalar-effect classification. The exact
  raw-to-SSA structured comparison includes source_tmp/access provenance;
  ordinary dataclass equality falsely accepted a forged temporary in a binary
  regression (1red/7green6.23s), now refused. Retained proof replays all local
  effects and later STORE sites. Overlap, unknown/cross-selector addresses,
  SS writes, earlier CALLs, opaque effects and absent selected boundaries have
  typed refusals. Final check-files8green17.66s; focused owner/constant/snapshot
  cohort45green8.81s with three workers; Pyright0 errors. Routine Make,
  pipeline and ownership enrollment is complete. Fresh POINT calls0x10254 and
  0x10290 each prove local count3 at IR CALL offsets6/7, with six later STORE
  slices checked and1/1/1/1/0 candidate accounting. This is conditional on
  supplied IR: exact binary coverage/registered-source authority and CALL
  boundary association must still be consumed before contextual callee binding.
  Callee bound-load stability, pointer extent and saved-BP disjointness remain
  open. No function or original compiler milestone accepted. Diagnostic:
  `.cache/caller-count-lifetime-proof-probe.py`.
- Binary-associated count prerequisite (2026-09-30): implemented
  `alias/stack_word_call_binding.py` to consume registered raw coverage, identical
  local-lifetime source, Semantics-owned real near-CALL target validation,
  exact IR target projection and a two-byte raw CALL envelope with SP delta-2.
  Missing envelope lanes, foreign equal-content sources, absent coverage and
  conflicting targets/returns refuse. Registry replacement invalidates retained
  proofs. Only the complete binding exposes the contextual value and callee
  offsets. New tests are enrolled in Make/pipeline/ownership lanes. An additional
  binary UNKNOWN-status SS STORE control exposes a false local disjointness
  acceptance (1red/8green7.70s); the shared byte-coordinate predicate now requires
  stable selector/address evidence and coherent byte widths before either owner
  uses it. Final scoped check-files15green6.20s; focused binding/window/constant/
  snapshot/coverage cohort68green10.04s, pytest -n3; Pyright0 errors.
  Fresh POINT raw coverage and both bindings pass, retaining count3 at callee
  entry offsets6/7 with1/1/1/1/0 candidate counts. This is per-call evidence,
  not an exhaustive caller census or a constant global callee bound. No source/
  COD/name evidence supplies the value. Call-frame stored return value remains
  unknown to constant flow and is not promoted by this coordinate proof.
  Next: prove the callee bound LOAD invariant and pointer-store footprint without
  circularly assuming bound stability to prove the writes preserving it. DS/SS
  spelling alone cannot prove physical disjointness. Saved-BP preservation,
  production contextual consumption and original compiler milestones stay open.
  Scratch reproduction: `.cache/caller-count-binary-coverage-probe.py`.
- Induction-effect closure prerequisite (2026-09-30): before reusing the
  census for callee bound stability, binary-backed opaque-effect corruption
  exposes three false range publications (DIRTY/INT/unclassified operation,
  3red9.40s). Non-STORE effects now require the shared typed scalar classifier,
  including retained census revalidation; relabeling does not grant proof.
  Valid direct literal JMP receives an explicit IP-only effect and exact target
  (positive red1/negative green6 in6.28s). The initial broad gate's one failing
  real word-indexed loop identifies a missing backend Iop_Xor1 flag effect.
  Boolean Xor1/And1/Or1 now validate byte-predicate operand/destination widths
  in the effect owner (3red9.78s before implementation), without inventing values
  or treating them as eight-bit arithmetic. Final scoped ownership check-files
  334green34.07s, pytest -n3; Pyright0 errors. Existing enrolled tests carry all
  new controls. The earlier330green/1red31.80s gate is superseded for this scope,
  not for the previously non-green full pipeline/development lane.
  Fresh POINT callee intake has4 raw indexed byte facts,2 normalized/coalesced
  words,2 classified refusals and0 materialized accesses. Both0x100db and
  0x100e6 refuse MULTIPLE_DYNAMIC_TERMS for BX+SI; therefore no range candidate
  reaches the bound proof yet. Next: binary-derived loaded-base/induction term
  separation at the existing typed address/scalar owner, preserving refusal
  for unproved roles. Then close callee bound/pointer-write invariants without
  circular stability assumptions. No function or compiler milestone accepted.
  Diagnostics: `.cache/{induction-effect-closure-probe,callee-bound-lifetime-probe}.py`.
- Wide-register census correction (2026-09-30): two binary signed/unsigned
  controls falsely publish a range after MOV EBP,1000h changes the frame base.
  Red2fail/6pass7.35s precedes replacing spelling-only BP/SS writes with the
  architecture-owned storage-overlap family. Final check-files94pass42.44s
  with three pytest workers and configured lint/type/startup/ownership checks;
  Pyright0 errors. The generation and retained-fact census share this check.
  No pointer-range, function, or original compiler milestone accepted.
- Multi-component address prerequisite (2026-09-30): the replayable IR owner
  retains every normalized register component with exact scalar provenance,
  without selecting pointer/induction roles. Binary NOT BX exposed a false
  affine copy proof (1failed/4passed6.11s); the scalar owner now consumes the
  shared typed projection contract and refuses unearned decorations and
  unproved conversions. Focused address/scalar suite19passed10.97s, pytest -n3;
  Pyright0 errors. Both real POINT accesses decompose completely:
  0x100db has SS:BP-2*2 plus SS:BP+6; 0x100e6 has SS:BP-2*2 plus SS:BP+4.
  Each closes2raw/1normalized/1classified/1materialized/0failures,1coalesced.
  These are loaded values, not proved stable memory or guessed pointer roles.
  Next: consume decompositions in a typed induction-role/range proof and close
  the callee pointer-write invariant without circular stability assumptions.
  Final scoped check-files142passed34.33s includes lint, typing, startup and
  ownership gates. New owner/tests are enrolled in routine Make/pipeline lanes.
  KVM is now openable in this session and returns API12; earlier environment
  limitations are not current evidence. Full semantic acceptance remains open.
- Affine induction-role bridge (2026-09-30): `ir/affine_induction_role.py`
  selects a loaded address term only from one supplied natural loop's
  dominating zero initializer, latch increment and strict typed guard. Signed
  and unsigned witnesses, unrelated guard/step, nonzero initializer, equality
  guard, ambiguous terms, missing conditions, unproved address, altered capture
  identity and count corruption controls are enrolled in routine gates.
  Initial missing-owner regression fails before implementation; final scoped
  check-files14passed12.21s with three pytest workers and lint/type/startup/
  ownership checks, Pyright0 errors. Both real POINT accesses select BP-2*2
  with role counts1/1/1/1/0 and retain BP+6/BP+4 residual loaded values.
  Those values are not guessed pointers; neither role selection nor the prior
  decomposition proves a range, memory stability or complete binary CFG.
  Production range publication remains refused. Next: contextual memory
  lifetime/disjointness proof before using the caller count as a callee bound;
  retain the existing single-register lane instead of fabricating its input.
- Current admitted-case refresh (2026-09-30): ordinary child DOS execution
  misses /dev/kvm despite the command environment permitting API12 and VM
  creation. The existing `workspace_sandbox.py --with-kvm` descriptor transport,
  launched directly without shell output redirection, successfully executes the
  frozen-source `array_pointer_writes` case. Original MS C compilation/run pass
  with exit255. Four numeric source-free targets return0 with validation=passed;
  select_word returns4/validation=failed in13.97s because MS C rejects integer
  addition to void* (C2147 unknown size). Its emitted function returns
  unsigned short* but arg_4 remains void*, and its body retains scalar-add
  syntax. This is a current Lowering type/address coherence obligation, not
  permission for rendered-C replacement or guessed pointee typing.
  The case is terminal validation_failed in51.85s; both source/environment
  guards remain unchanged. Artifacts:
  `.cache/compiler-coverage/array-role-kvm-direct-20260930/`.
  No complete rebuild, behavior match or feature-witness acceptance follows.
  The earlier missing-device retries are environment-limited, not equivalent
  decompiler runs. The admitted target is array_pointer_writes; an attempted
  pointer_call_preservation selection is rejected because it is not a case ID.
- Worker-observed type provenance (2026-09-30): fresh timing/pointer diagnostics
  reproduce select_word C2147. The pointer-argument Lowering hook reports0facts
  and changed=false. A parent-only monkeypatch is not observed in the clean
  worker, so its empty counters provide no absence claim. An ignored diagnostic
  site hook is then installed in the actual worker and logs the exact signature
  before priming: (void*, unsigned short)->unsigned short*. That signature is
  unchanged after stack semantics/prototype, callsites, return shape/chains,
  typed conditions, segmented-memory replay and baseline restore. Thus late
  return-shape priming does not introduce this current mismatch. Investigate
  upstream type/codegen creation and feed independently proved near-address
  semantics into Lowering; never infer pointee width solely from the affine
  scale or use rendered-C repair. Terminal diagnostic returns4. Evidence:
  `.cache/near-return-probe-site/{sitecustomize.py,stage-results.log}`.
  No production semantic changes, function acceptance or speedup is claimed.
- Exact publication owner identified (2026-09-30): a worker-side CFunction
  constructor/assignment hook shows initial ()->int, then positive BP argument
  materialization gives (ushort,ushort)->int. The pointer transition is owned:
  `interprocedural_storage_pipeline.publish_and_reconcile_callsite_interfaces_8616`
  calls `interprocedural_storage_prototype_application.apply_accepted_function_storage_prototype_8616`,
  whose `_mutate_prototype_surfaces_8616` publishes (void*,ushort)->ushort*.
  Thus this mismatch is not merely third-party inference. Exact source confirms
  the preflight consumes accepted input/return type projections but does not
  establish a congruent, representable callee return-address expression before
  changing the signature. Caller dereference proves a result's pointer class,
  not that scalar-add C remains valid after input promotion. Next integrate
  body/address preflight and publication at this Types/Lowering transaction,
  consuming existing near scaled-return/operand congruence and independent
  segment/representation evidence. Do not guess the base pointee width from
  the return width, remove live code or substitute a text-body repair.
  Diagnostic terminal4; exact assignment stacks retained in
  `.cache/near-return-probe-site/assignment-results.log`. No function accepted.
- Pointer retyping safeguard (2026-09-30): prototype preflight now refuses
  numeric binary arithmetic on canonical arguments whose pointer type would
  change. The typed POINTER_ARITHMETIC_UNPROVEN verdict is recorded before
  cvars, metadata, prototypes or replay snapshots mutate. The isolated
  guard-bypass oracle produces4semantic failures8.69s; final application
  cohort12passed5.71s includes unrelated-arithmetic positives and mutation-free
  Add/Sub/Shl/Mul refusals. Initial mock failures were fixed by supplying the
  required codegen cstyle_null_cmp field; they are not semantic red evidence.
  Ruff/MyPy/type ratchet/startup/ownership checks pass; Pyright0 errors.
  Broad scoped check-files remains non-green:244passed/8failed20.83s. A bounded
  bypass replay of the failing return-split/trial-collection cohort reproduces
  the same8failures with20passes8.44s, so this safeguard does not explain them.
  Live POINT select_word no longer publishes the inconsistent pointer
  signature and returns0/validation=passed with the proved scalar offset
  interface. This is deliberate refusal, not a fixed pointer-return function,
  source-shape acceptance, complete round trip or full compiler milestone.
  Next implement independent near-address/body representation publication and
  rerun the admitted linked case; do not use scalar fallback as final success.
  Live diagnostic: `.cache/near-return-probe-site/retyping-guard-live.log`.
- Contextual segment transfer prerequisite (2026-09-30): the IR context owner
  now retains an inherited DS==SS theorem at an exact nested direct near CALL.
  Completeness replays registered caller effects and bound leaf preservation;
  it rejects lost equality, unbound/stale parent or body evidence, wrong/far
  calls, and same-address segment assignments hidden by instruction-entry
  maps. State solving and diagnostics consume the shared typed context union.
  Contextual equality remains forbidden as a universal callee summary.
  Source-free binary controls cover a third call depth and corrupted receipts.
  The real POINT diagnostic proves all12 main-to-helper transfers, including
  both select_word calls, with each receipt1/1/1/1/0. This is not production
  pointer publication: native representation, body-address lowering and
  linked compiler acceptance remain open. Existing enrolled context tests and
  segment-state ownership cohorts retain the new coverage.
- Current executable checkpoint: after the pointer-retyping guard, the admitted
  array_pointer_writes run decompiles all5 functions with clean tail validation
  but finishes recompile_failed91.12s. MS C C2100/C2106 exposes the remaining
  scalar select_word interface at dereferencing caller uses. Original build and
  exit255 pass; implementation/environment guards unchanged. No function-shape
  or linked-behavior acceptance claimed. Artifacts under
  `.cache/compiler-coverage/array-context-kvm-direct-20260930/`.
  Quality-dev is non-green: fast pipeline8528pass/31fail/1skip778.62s. The stale
  binary-relational lane expected-set assertion was reproduced red and repaired
  without changing lane membership; test_test_pipeline56pass1.31s and Ruff pass.
  Other broad failures remain open pending bounded cause/baseline analysis.
  Devin AST construction is staged only; parent review and the independent
  segment/native-representation/body-publication obligations remain required.
