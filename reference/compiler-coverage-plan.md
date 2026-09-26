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
