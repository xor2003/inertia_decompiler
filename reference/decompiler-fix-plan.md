# Decompiler Delivery Plan

## Goal

Make decompiler development safe and fast before adding more semantic scope:
the complete runnable test suite stays green, local feedback is fast, all
project linters pass, strict mypy covers the full decompiler, and mypyc can
compile and execute the full decompiler without changing behavior.

This plan governs delivery gates. Semantic fixes still follow the layer order
and acceptance contracts in `AGENTS.md`; a gate must never be made green by
deleting coverage, weakening validation, hiding diagnostics, or moving
semantics into Rewrite.

## Current Measured Baseline

- pytest collection: 6,746 tests
- fast external pipeline: 1,806 passed, 35 warnings, 0 failed in 55.25s with
  seven workers; this is green but does not prove the full-suite gate
- complete CLI module: 416 passed, 62 skipped, 190 warnings in 136.29s with
  seven workers; discovery and `_dos_free` call/declaration regressions are
  green
- latest default full pipeline after the current DrawFrame fix: 6,585 passed,
  172 skipped, and 32 failed in 23:16 with seven workers. Several failures
  reproduce only as resource-sensitive subprocess timeouts or xdist ordering
  effects; serial reruns passed the telemetry, recovery-status, HeapSort, and
  several SORTDEMO cases. DrawFrame was the remaining deterministic semantic
  failure in this batch and is now fixed in Types/Lowering; the authoritative
  full-suite gate remains red; the focused DrawFrame regression passes, while
  the xdist run still exposes its heavy-load timeout path.
- MS C runtime-gate parametrizations now share an explicit xdist group so the
  external compiler/runtime state is not mutated concurrently; this is
  verified at collection, but needs a full-run measurement before acceptance
- mypyc host probe: all eleven strict-clean CLI/reporting candidates now compile
  and import in compiled mode; `work_items` required replacing unsupported
  `object` dataclass boundary annotations with explicit dynamic-boundary `Any`
  annotations while retaining strict mypy coverage
- mypyc host build is now isolated under `.cache/mypyc/lib` with build objects
  under `.cache/mypyc/temp`; the default no longer writes import-shadowing
  extensions into the source tree. A fresh subprocess smoke check imports all
  eleven configured hosts from the isolated library and passes. `--inplace`
  remains an explicit legacy opt-in, and `make mypyc-smoke` runs the isolated
  compile/import gate.
- expanded cached failing-set audit selected 148 historical failures and now
  reaches 23 failed, 1 passed in 6:38 with seven workers before xdist drains the
  `--maxfail=20` stop request; this is not a complete-suite result
- fixed collection errors: stale decompiler entrypoint and stack-lowering
  imports
- fixed shared call-lowering defect: exact `BP-3` and `BP-2` argument storage
  identities no longer collapse through nearby-slot fallback; the complete
  call-materialization module passes 169 tests
- fixed generated return-contract drift: a complete caller census plus complete
  empty AIL terminal returns now records typed evidence at Clinic and replays it
  at final Types/Lowering codegen; the PercolateUp binary regression emits
  `void`, removes synthetic `return 0`, and its 18-test focused batch passes
- fixed silent exact-image truncation: recovery now emits a typed closed
  instruction-ownership census and pipeline governance rejects missing CFG
  ownership before semantic passes; BYTEOPS reports 30 omitted instructions,
  while the full COD sample module passes 23 tests with 65 intentional skips
- split the independent SORTDEMO HeapSort/QuickSort/RunMenu/Beep scorecard
  audit into four xdist-schedulable cases; focused wall time fell from 210.35s
  to 109.81s with unchanged assertions
- consolidated eight overlapping SORTDEMO regressions after matching their
  subprocess inputs and retaining every distinct assertion; the module now
  collects 44 tests instead of 52, five duplicate HeapSort launches that took
  81.00s serially became one launch, and the three passing consolidated owners
  complete in 20.90s under seven workers
- `/home/xor/pytest_deduplicate/pytest_deduplicate.py` is useful for in-process
  coverage candidates, but it cannot observe decompiler subprocess coverage
  and currently raises `IndexError` when no parent-process arcs are collected;
  subprocess overlap therefore also requires structured call-argument and
  assertion review before consolidation
- fixed `_SetGear` condition loss at its owning layers: Frontend emits typed
  TEST/DEC facts, Alias binds the proven AX carrier to stack argument `G`, and
  Structuring maps copied multi-arm tags back to exact CFG taken edges; output
  now distinguishes `G == 0` from `G == 1`, preserves `Message(ax, 2)`, and
  passes whole-tail validation plus the strengthened CLI regression
- open P0 validation gap: binary-proven stack writes are not yet represented as
  required final memory-effect obligations, allowing an already-truncated body
  to appear stable across structuring and postprocess validation
- fixed DrawFrame (`0x101f0`) at Types/Lowering: when a late wide-call stack
  owner is proven, low-word uses are now materialized as typed projections of
  that owner instead of replacing them with the full-width C variable. This
  preserves the 16-bit loop condition and the 32-bit owner independently;
  sidecar-free DrawFrame passes in isolation, the 87-test stack/condition
  owner suite remains green, and the architecture guard rejects no imports.
- fixed DrawBar's sidecar-free void-callee contract at Types/Lowering: callsite
  declaration lowering now consumes the already-materialized typed callee
  prototype from physical callsite seeding. A proven `SimTypeBottom(label="void")`
  is emitted as `void sub_<addr>(...)`; ignored caller results alone still
  conservatively remain `int`. The focused DrawBar regression and the 62-test
  return/declaration contract batch pass with validation enabled.
- fixed the CMP16 retry duplication at the CLI/function-discovery boundary:
  LST recovery now accepts an explicit `allow_rebased_exact_slice` policy, and
  fresh/sidecar retry lanes disable the already-spent rebased CFG discovery
  without mutating the process-global environment. The exact CMP16 `main`
  probe now emits one rebased marker, preserves whole-tail validation, emits
  the accepted sidecar fallback C, and completes in 78.49s under a 120s bound;
  focused retry-policy tests pass.
- latest full-suite failure classes: 32 total; several are serial-green but
  xdist-load-sensitive (SetGear, recovery worker, and some runtime cases),
  while deterministic owners include DrawBar declaration identity, the
  projection-contract unit expectation (now updated), and multiple slow
  SORTDEMO/CMP16/COD paths that need measured timeout-root-cause work rather
  than larger test limits.
- latest authoritative cached-failure classification: the complete seven-worker
  suite stopped after 27 failures (20-failure cap), with 4 passes in 8:14.
  The slowest observed cases were SORTDEMO subprocesses at 241.15s, 177.81s,
  and 169.55s, plus one MS C runtime case at 190.63s. The first failure
  clusters are: COD structuring timeout, sidecar-free Sleep validation/return
  contract loss, SORTDEMO call-interface and aggregate-argument mismatches,
  and CMP16/runtime timeout behavior. These are current reproducible failures,
  not merely stale `lastfailed` entries; fix and classify them before expanding
  strict typing or mypyc coverage.
- focused Sleep analysis: the binary and typed void prototype prove a normal
  architectural `ret`, but structured output ends after the loop as an implicit
  fall-through. A trial Structuring append of `return;` was correctly rejected
  by tail validation because the current observable contract also changed the
  loop condition/return fingerprint. Do not bypass validation; first add a
  generic CFG-to-structured equivalence proof for this representation, then
  materialize the return only when that proof is consumed.
- follow-up verification: two attempted fixes were rejected and fully reverted.
  Appending a CFG-proven `return;` without a complete structured-equivalence
  proof changed the validation scorecard and made the raw-binary wide-condition
  path worse; a temporary validator suppression was therefore not retained.
  The remaining work is one shared Structuring/validation contract that proves
  both the void fall-through return and the loop-condition normalization before
  either output mutation is accepted.
- CMP16 call-order follow-up: the existing final shared-call occurrence
  normalizer and a late replay of typed call-return conditions were each tested
  at the Structuring boundary and fully reverted. Both focused Structuring
  suites stayed green, but the end-to-end CMP16 regression still emitted the
  duplicated `cmp_i16(7, 7)`, `cmp_i16(9, 3)`, and
  `in_window_i16(4, 1, 7)` calls while whole-tail validation remained clean.
  This rules out mutable condition-node splitting as the root cause and points
  to exact physical callsite-to-condition binding during value-return lowering;
  do not retain a late replay or weaken the call-sequence assertion.
- CMP16 callsite evidence follow-up: repeated-call matching now consumes only
  one AST node for one tagged physical callsite and uses the complete proven
  immediate-argument tuple to bind surplus same-target nodes to remaining
  callsites. Debug evidence shows the internal retry lane now maps the repeated
  calls one-to-one (`0x102e5`/`0x10303` and distinct `cmp_i16` callsites), while
  the public CLI still emits the older sidecar-slice fallback. The remaining
  defect is therefore CLI candidate acceptance/selection; do not move this
  correction into Rewrite or weaken the integration oracle.
- COD timeout classification: `test_cod_segmented_proc_does_not_publish_unclassified_access_traits`
  passes serially in 47.64s under a 120s subprocess bound, after reproducing as
  a seven-worker load-sensitive timeout. Keep its assertions and timeout
  contract unchanged; investigate bounded scheduling/resource isolation under
  P0.1 rather than changing semantic code or enlarging limits.
- resolved one cached failure as an outdated test contract: side-effect-only
  `Swaps` is declared `void` in `SORTDEMO.C`, has no value return, and its
  callers do not consume AX. The aggregate-interface regression now requires
  `void sub_107b8(struct g_08F0_entry *, struct g_08F0_entry *)`; the paired
  sidecar-free Swaps semantic regression and the updated caller regression pass
  in 23.15s. This does not count as a decompiler semantic improvement, but it
  removes a false P0 failure without weakening behavior coverage.
- fixed call-lowering declaration refresh: Beep's `__aNldiv` groups four
  physical pushes into two proven logical `long` arguments, and the recovered
  `Sleep(unsigned long)` declaration survives the final CLI render; the
  complete callsite declaration/export batch passes 74 tests
- fixed `loadprog` at Types/Lowering: the five physical DOS pushes are grouped
  into the four logical ABI arguments `(near file pointer, segment, mode, far
  command-line pointer)`, portable-flat `SEG_PTR` has a compatible byte-pointer
  type, and the binary-proven 16-bit `cs`/`ss` stores are consumed as adjacent
  typed byte-pair stores into `cs[0]`/`cs[1]` and `ss[0]`/`ss[1]`; the focused
  CLI regression now passes and the generated wrapper recompiles
- fixed variadic call lowering at Types/Lowering: known variadic helper
  signatures such as `_ERROR(const char *, ...)` now contribute only their
  fixed-prefix contract and cannot regroup all physical pushes into one
  fictitious argument; declaration emission also preserves the actual emitted
  call identifier (`ERROR` versus compiler-symbol `_ERROR`); the complete CLI
  module passes 416 tests and the focused generated-C recompilation passes
- fixed the MS C `select_max` output-selection owner: when the Structuring
  compare recognizer proves a complete 32-bit compare/return shape from exact
  instructions, CLI output now selects that proven source-shaped result even
  when the generated AST has a canonical wide signature but an incomplete
  word-level predicate; the public fallback selector still preserves valid AST
  text by default, and the focused `select_max` regression passes
- focused MS C comparison audit: 421 tests passed and 62 skipped in 142.47s
- fixed the sidecar-free MS C return-contract diagnostic: closed caller-use
  evidence now prevents the return-shape classifier from retaining a default
  `void` prototype when a value return is proven, restoring stable postprocess
  validation; all four `COMP32` regressions pass in 36.19s
- fixed the sidecar-free SORTD aggregate return owner in Types/Lowering:
  proven-unused pure negative-BP local return carriers are replaced by a typed
  scalar zero while preserving the aggregate swap statements; the focused
  aggregate-interface regression and the 11-test return-evidence module pass
- fixed the HeapSort signed-condition owner in Types/Lowering and Structuring:
  proven 16-bit condition views no longer mutate shared storage declarations or
  leak redundant casts into indexed accesses; the complete HeapSort widening
  module passes 7 tests in 125.68s
- fixed MS C scalar return-type overwrite in Rewrite/Postprocess ownership:
  non-guessed source-backed `signed char` and `long` return prototypes are no
  longer replaced by the generic `unsigned short` AX fallback; both focused
  `TYPES.EXE` regressions pass in 9.44s. The complete MS C module remains
  blocked by the separate CMP16 timeout/guarded-return path.
- isolated the CMP16 remaining failure: caller-side declarations in `main` lower
  all recovered helper results to `unsigned short`, losing the signed/wide
  return contracts proven by the helper bodies. Tail validation reports the
  exact call-result predicate mismatch; the fix belongs in typed callsite
  declaration lowering, not generated-C rewriting.
- CMP16 integration follow-up: validation now accepts exact call-result
  comparisons against nonzero constants, detached direct-call nodes can be
  matched through established target-name/arity evidence, and invalid positive-
  BP argument names are normalized. The direct worker now discards a stale
  pre-refresh failure snapshot when the current project snapshot is complete
  and passing. Portable-flat emission also normalizes unsupported recovered
  `main` parameters while preserving standard `argc`/`argv`; the full guarded
  `main` regression now passes in 77.46s.
- bounded `/home/xor/pytest_deduplicate` audit reports candidate overlaps in
  the HeapSort widening module, but the candidates have different subprocess
  addresses, windows, sidecar policies, or assertions; no test was removed.
  The tool was interrupted after the expensive subprocess cases, confirming it
  is useful for candidates but not an acceptance oracle for this suite
- changed-surface mypy remains red in the legacy 1,600-line call postprocess
  module (47 existing errors, mostly `Any` return leakage and unannotated
  local collections); the new condition and declaration-lowering modules add
  no reported errors in focused runs
- after the CMP16 fixes, the fast parallel pipeline remains green: 1,806 tests
  passed, 35 warnings, and 0 failures in 52.44s with 7 workers. The touched
  CLI text module still exposes pre-existing global mypy debt; no new untyped
  definitions were introduced by the `main` signature normalization.
- current callsite-pairing change keeps the regenerated-node contract for a
  single physical callsite while enforcing one-to-one ownership for repeated
  physical callsites; Ruff and the focused callsite/Structuring suites pass.
  The fast external pipeline is green again at 1,806 passed, 35 warnings in
  47.31s with seven workers. CMP16 remains red only because the CLI emits an
  older sidecar-slice candidate despite an internal retry trace showing the
  corrected one-to-one callsite mapping.
- latest full-suite measurement remains red: 6,575 passed, 171 skipped, and
  40 failed in 26:28 with seven workers. Several failures reproduce only as
  resource-sensitive subprocess timeouts or stale retry artifacts; isolated
  reruns have already passed the terminal-return, CMP16, HeapSort, retry, and
  portable-main owners. The remaining reproducible SORTDEMO sidecar-free
  output uses explicit signed/unsigned casts for already-proven comparisons;
  its test oracle is being normalized to semantic equivalence, while the
  decompiler layer snapshots retain the required branches.
- current touched-module gate is green for the return-type and CLI text
  modules: Ruff, focused mypy, and 106 focused tests pass. The global mypy
  inventory remains red at 1,226 errors across 142 files, and configured
  mypyc compilation still covers only the eleven strict-clean host candidates.
- clean isolated SORTDEMO verification now passes for both the portable `main`
  emission and the sidecar-free QuickSort control-flow regression. The latter
  retains the exact two-element branch in every unique layer snapshot; its
  explicit signed/unsigned casts are accepted by the regression as equivalent
  typed expressions rather than treated as semantic loss.
- fixed a shared Types/Lowering guard defect in
  `terminal_register_return_types.py`: the eligibility check for AX-word
  fallback was accidentally reachable only when terminal-return debugging was
  enabled. Normal runs could therefore downgrade explicit near-pointer and
  already-wide return contracts to `unsigned short`. The focused near-pointer,
  `sub_ulong`, terminal-return, and mypy checks now pass; this fix does not
  change the required Structuring pass order.
- the attempted early Widening replay before condition transfer was reverted
  after its pass-order regression and because it did not establish the missing
  DrawFrame wide stack owner. DrawFrame remains open at the
  Types/Lowering-to-Structuring handoff; no postprocess workaround was added.

## Strict Priority Order

### P0. Restore the full test baseline

Do this before global lint cleanup or compilation work. Fix the first failing
owner and rerun its focused test, then rerun the complete suite. Semantic test
failures are fixed at their earliest owning decompiler layer.

Definition of done:

- `make pytest-all PYTHON=./.venv/bin/python` completes with zero failures and
  zero errors using the repository's bounded `pytest -n 7` default
- intentional skips are counted and carry an explicit platform/toolchain
  reason; no unexpected xfail or xpass hides a regression
- `make test-pipeline PYTHON=./.venv/bin/python` passes before a semantic
  improvement is accepted
- `make test-pipeline-expanded PYTHON=./.venv/bin/python` passes before the
  baseline is declared complete
- no semantic assertion or distinct behavior coverage is removed, weakened, or
  given a larger timeout merely to make the gate green; proven identical test
  invocations may be consolidated only when all distinct assertions survive

### P0.1. Make the complete suite fast

Start after failures have a stable focused reproducer; profile before changing
test execution. Prefer immutable session-scoped binary/decompilation artifacts,
safe fixture reuse, xdist scheduling, and removal of duplicated subprocess work.
Do not share mutable angr/decompiler state between tests.

Definition of done:

- the complete `pytest-all` run is measured with seven workers and slow-test
  durations are recorded
- warm-cache wall time on the eight-CPU development host is at most 15 minutes,
  with a follow-up target of 10 minutes
- the focused changed-file loop completes within 3 minutes for ordinary files
- no semantic, validation, MS C runtime, or generated-C behavior coverage is
  dropped to meet the budget
- overlap candidates from coverage tooling are confirmed against exact fixture,
  subprocess argument, environment, timeout, and assertion contracts before
  duplicate execution is removed
- repeated runs produce the same collected count, verdicts, and deterministic
  generated output

### P1. Make base linters globally green

Keep this gate distinct from strict mypy and mypyc so failures have one owner.
Ruff remains configured globally and runs in `ruff check --fix` mode. Pyright,
architecture/context checks, docs/types/dot-access ratchets, dead-code checks,
and complexity checks must report honestly.

Definition of done:

- one Make target runs all base linters on all tracked source files and passes
- one Make target runs the same applicable checks on selected changed files
- independent linters run concurrently with a bounded job count
- `make quality-hard PYTHON=./.venv/bin/python` is a deterministic mandatory
  development gate, not a one-module smoke test
- new suppressions require a documented third-party boundary or migration
  owner; owned code is not silenced with broad ignores

### P2. Make strict mypy pass for the full decompiler

Fix contracts in dependency order: owned IR/value/address/condition contracts,
alias and widening, types/lowering, structuring and validation, then CLI and
fallback orchestration. Preserve public docs and explicit annotations while
removing avoidable dynamic attribute access.

Definition of done:

- `make mypy-all PYTHON=./.venv/bin/python` reports zero errors for all non-test
  decompiler code under `inertia/frontend/x86_16/` and
  `inertia/cli/`, plus their owned entrypoints
- strict mode remains enabled; no blanket `ignore_errors`, broad `Any`, or
  unchecked owned boundary is added to obtain a green result
- every touched non-test module retains `Layer:` and `Responsibility:` and all
  touched owned public definitions retain useful docstrings and explicit types
- focused type regressions cover each repaired owned contract
- the full test and pipeline gates remain green after every typing batch

### P3. Compile and validate the full decompiler with mypyc

Expand mypyc only after P2 is green. Compile in dependency batches so one
unsupported dynamic boundary does not obscure the rest of the graph. Third-party
angr/codegen/plugin boundaries may use small typed adapters, but owned modules
remain explicit and compiled.

Definition of done:

- the mypyc target builds every non-test module in the decompiler core and CLI,
  not only `inertia.cli.decompile_file_summary`
- clean pure-Python and compiled-mode import smoke tests pass without stale
  local extension artifacts influencing the result
- the complete pytest suite and default/expanded pipelines pass in both
  pure-Python and compiled modes with identical semantic verdicts and generated
  output hashes
- compiled artifacts are reproducible build outputs and are not committed
- representative sidecar-free SORTD and MS C tiny benchmarks show a measured
  wall-time improvement; compilation is not accepted on build success alone

### P4. Resume pending SORTD semantic/readability work

After P0-P3 are stable, continue the pending interprocedural-contract and
proof-backed-readability steps in `SORTD_GHIDRA_PLAN.md`. A failure discovered
while establishing P0 that belongs to those layers is fixed immediately rather
than deferred to P4.

Definition of done:

- all remaining per-step definitions of done in `SORTD_GHIDRA_PLAN.md` pass
- fixes remain in IR, Alias, Widening, Types/Lowering, or Structuring according
  to ownership; Rewrite performs cleanup only
- generated C remains complete, validated, recompilable, and behavior-covered

## Development Loop

### Current SORTD condition-width finding

The sidecar-free `DrawFrame` regression remains reproducibly failing with
`validation=failed` at `jcc=0x10268`. The typed fact is correct (`SS:BP-2`
compared as a 16-bit `jle`), but structuring materializes a standalone 2-byte
stack variable before the proven 4-byte wide stack owner is available. Later
widening exposes the owner and tail validation expects its explicit low-word
projection (`And(stack_slot:size4, 0xffff)`). The next fix belongs at the
Widening/Types-to-Structuring handoff: materialize the proven wide owner before
condition lowering, or carry the owner identity into the condition materializer.
It must not be repaired in postprocess text cleanup. The current IR contract
retains condition width metadata and focused IR/lowering tests pass; the binary
acceptance test is intentionally still red until owner ordering is corrected.

1. Reproduce one failure with its focused owner test.
2. Apply the smallest correct-layer fix and run changed-file checks.
3. Run the relevant focused semantic/behavior regression.
4. Run the fast development gate periodically.
5. Run the complete pytest gate after each coherent batch.
6. Run default and expanded pipelines before closing a semantic milestone.

Do not begin broad mypy cleanup while the full suite has unexplained failures,
and do not expand mypyc coverage while strict mypy remains red.
