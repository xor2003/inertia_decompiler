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
- Use `PYTHON_JIT=1`, pytest `-n 7 --tb=short --durations=10`, and scoped
  `ruff check --fix`; mandatory types/docs and project acceptance rules still apply.
- Do not overlap broad gates. Bound workers by observed memory/CPU use; seven
  pytest workers do not authorize seven independent full decompiler pools.
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
  `scripts/msc6_original_evidence.py` is an initial evidence-checkpoint helper,
  not yet integrated into the legacy runner or covered by dedicated tests.
  Wiring and testing it remains pending; it does not currently preserve original
  execution observations automatically when decompilation times out.

References: [NIST covering arrays](https://math.nist.gov/coveringarrays/) and
[Csmith research](https://users.cs.utah.edu/~regehr/papers/pldi11-preprint.pdf).
