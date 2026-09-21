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
