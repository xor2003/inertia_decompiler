# Full-Suite Baseline And Repair Order

## Verified Baseline

Command: `PYTHON_JIT=1 PYTHONHASHSEED=0 make pytest-all PYTHON=./.venv/bin/python PARALLEL_JOBS=7`.

- 11,814 expected and observed tests: 11,618 passed, 26 failed, 170 skipped.
- Execution: 1,360.94s (22m 41s), excluding preceding collection overhead.
- No missing or duplicate node IDs; source-state hashes match throughout.
- Peak recorded RSS: 1,786,192 KiB, below the configured 2 GiB ceiling.
- Machine report: `.cache/pytest/partitioned-summary.json`.
- Complete log: `/tmp/inertia-full-suite-refresh.log`.
- The previous audit had 23 failures. Three of those now pass and six additional
  nodes fail. Additional failures are not yet individually proven causal
  regressions; reproduce and attribute them before choosing a repair.

The preceding curated lanes each had one BIOS failure. That subset was not an
adequate substitute for refreshing this full baseline. A green full suite is
the required regression baseline, not proof that untested behavior is correct.

## Failure Inventory

All identifiers below are under `angr_platforms/tests/`.

- `test_decompiler_architecture_check.py`: current architecture contract (seven findings).
- `test_x86_16_bios_strict_compilation.py`: generated BIOS C has two unused stack locals.
- `test_x86_16_cli.py`: ConfigCrts copy loop; DOS load-program pointer stores;
  DrawRadarAlt branch logic; SetGear guard logic; small COD byte-condition logic;
  TIDShowRange layout; small-COD batch `_mset_pos`; small-COD batch `_InBoxLng`.
- `test_x86_16_cod_regressions.py`: loadprog binary arguments/recompilation;
  overlay function-address object bindings.
- `test_x86_16_life_decompile_regressions.py`: clear_mat intrinsic rendering;
  pause_screen and timer non-source-backed decompilation.
- `test_x86_16_sortd_indexed_aggregate_regression.py`: indexed load/store recompilation.
- `test_x86_16_sortdemo_regressions.py`: DrawBar byte fields; InitBars far-pointer
  setup; SORTD DrawFrame; SORTD ReInitBars; BubbleSort calls; HeapSort lane
  acceptance; HeapSort call arguments; main signature; SwapBars arguments.
- `test_x86_16_string_corpus_anchors.py`: MONOPRIN fimemset fallback anchor.

Newly failing relative to the prior audit: ConfigCrts, CLI load-program pointer
stores, `_mset_pos`, and all three LIFE nodes. Newly passing: both HeapSort
widening-regression nodes and the Sleep regression. A passing related test
does not clear a failing node in a different module.

## Repair Order

### Verified Follow-Up (2026-09-11)

Two failing nodes now pass focused verification; the full-suite baseline above
is deliberately not recalculated from these repairs.

- Architecture: all seven findings are resolved. New native integer/terminal
  return and stack-overlap modules have complete ownership headers and are
  registered in the enforced promoted typing list and both Make quality lists.
  The string helper header identifies its frontend execution helper boundary.
  The full checker passes, plus 374 architecture/Make-input tests in 43.09s.
  No checker rule or exclusion was weakened. Ruff/MyPy/Pyright pass for the four
  touched decompiler modules; the checker retains 70 unrelated Ruff findings.
- CLI DOS load-program: reproduced the failing `return err` spelling assertion.
  The existing compiled behavior oracle accepts unchanged output returning an
  AX copy and verifies call arguments, eight error values and conditional output
  writes. The assertion now uses that oracle and requires validation success;
  existing pointer/store guards remain. Timeout-as-success and timeout-as-skip
  exits were removed from this behavior regression. Nine focused tests pass in
  17.17s, including the oracle's corruption controls. The large CLI test module
  retains 174 Ruff findings, not suppressed. The separate COD loadprog test
  remains unresolved and is not covered by this pass claim.

Logs: `/tmp/inertia-full-baseline-architecture.log`,
`/tmp/inertia-loadprogram-cli-before.log`,
`/tmp/inertia-loadprogram-cli-final.log`.

### ConfigCrts Follow-Up (2026-09-11)

The failure was semantic before it was a stale test assertion. Lowering's
`ir_segmented_load_carriers.py` replayed an already-defined AX SSA read as
`SEG_U16(inertia_ds, bx + 546)`, fabricating an unrelated, undefined BX carrier.
The original value was already loaded correctly from `CrtConfig[i]`.
An uncached constructor probe identified `_helper_for_address_8616` called by
read-side logical replay as the producer, not CLI cleanup or rendered text.

Read-side replay now refuses identities with existing structured definitions,
as it already refused identities assigned by its own insertion pass. This is
conservative preservation, not new dominance proof or permission to eliminate
loads. A focused regression fails before the change and passes afterward.
The production module shrinks by one line; its diagnostic refusal logging no
longer filters on particular temporary names.

The actual function now reports `validation=passed` and clean whole-tail
validation. The remaining exact `tmp_4112` assertion was replaced with strict
compilation and execution of unchanged C: eight copied words, last-word return,
source and DS preservation, and no unrelated global-memory writes over three
input patterns. This oracle does not claim machine-stack/register equivalence.
Seven corruption controls verify its sensitivity. Twenty focused tests pass
in 17.35s, with the CLI case taking 4.66s. The oracle module is admitted to both
Make test lists, the routine pipeline and segmented-runtime test ownership.

Scoped MyPy and Pyright pass. Ruff reports 19 findings in the existing carrier
module/tests; the new oracle module is clean. `quality-fast` stops at global
Ruff failure before its test prerequisite executes; it is not a passing gate.
Logs: `/tmp/inertia-carrier-definition-before.log`,
`/tmp/inertia-configcrts-acceptance.log`,
`/tmp/inertia-configcrts-quality-fast.log`.
This clears the focused ConfigCrts failure, not the whole-suite baseline.

Post-fix `make test-pipeline PYTHON=./.venv/bin/python PARALLEL_JOBS=7`:
3,770 passed, one BIOS strict-C failure, eight warnings in 240.32s for its
pytest lane. BIOS still reports `local_2` and `local_4` set but unused under
`-Werror`. All seven selected MS C tiny examples complete build, original run,
decompilation, recompilation and decompiled run: compare16, simple_control,
loops_jumps, storage_classes, function_pointers, pointer_memory and
scalar_types_io. The aggregate reports two passing lanes and one failed lane;
those are lane counts, not example counts. Slowest pytest calls: InitMenu
114.39s, InitBars 101.20s, RunMenu 97.16s. Complete log:
`/tmp/inertia-configcrts-pipeline.log`. No fresh full-suite result is claimed.

### Mset Pos: Confirmed Undefined Generated Arithmetic

The small-COD `_mset_pos` failure is not safely classifiable as a spelling
assertion. Its decoded CWD/IDIV sequences compute signed remainders by 80 and
25. Current generated C builds the dividend with
`((0 - ((x >> 15) & 1)) << 16) | x`, which left-shifts a negative host-C value
for inputs with bit 15 set. Tail validation nevertheless reports passed.

The existing failing CLI case now also invokes an unchanged-C executable
oracle, compiled with strict warnings and UBSan with recovery disabled. The
oracle exhausts all 65,536 values of each independent input (not all input
pairs), verifies both global remainders and zero return, and reports the actual
UBSan failure: `left shift of negative value -1`. Six oracle tests pass in
1.62s, including unsigned-remainder, wrong-divisor, return and undefined-shift
mutations. The production regression still fails (17.72s total, 4.59s call).
No semantic fix, relaxed `%` assertion or successful function claim is made.

Source investigation: `instr16.py::cwd` expresses sign bits as subtraction;
`idiv_dx_ax_rm16` constructs the signed dividend by shifting and joining the
register halves. These are defined bitvector operations. Native angr
`CStructuredCodeGenerator._handle_Expr_BinaryOp` creates C operations without
directly carrying the AIL operation's signedness/width, and implicit cast
collapse is another boundary to trace. The next repair belongs in typed
native lowering, with exact AIL evidence and preservation of necessary casts;
do not extend late instruction-pattern recovery or rewrite rendered C.

Logs: `/tmp/inertia-mset-before.log`, `/tmp/inertia-mset-oracle.log`,
`/tmp/inertia-mset-ubsan-before.log`. The oracle is admitted to routine test
lists and passes Ruff. This finding strengthens a known failing test and
exposes a validation coverage gap; it does not reduce the failure count.

### Mset Pos Native Lowering Repair

The uncached native-handler trace established explicit AIL `Shl(bits=32,
signed=False)` becoming a signed 16-bit native C expression, and
`Div(bits=32, signed=True)` becoming unsigned. Native cosmetic casts are also
hidden during rendering. Adding ordinary CTypeCast nodes did not repair the
output; the sanitizer remained red. Those experiments were not accepted.

`lowering/native_integer_operations.py` now consumes those explicit AIL facts
and uses the existing `CSemanticCast8616` contract with fixed-width C types.
Valid constant-count dword shifts cast the left operand unsigned; dword
division/remainder casts both operands according to the AIL signedness.
Non-scalar operations, other widths and unproved shift counts are refused.
The existing native arithmetic entrypoint dispatches this lowering and counts
materialized operations. No frontend, Rewrite, CLI recovery or text repair was
added. Both quality file lists and the architecture/ownership registry include
the new owner.

The live `_mset_pos` case now passes validation and its strict UBSan executable
oracle. Only then were its `%` and exact signature assertions replaced with
basic output-presence checks, retaining the executable contract. The code is
still verbose; modulo recovery and general bitvector-C equivalence remain
separate work, not claimed solved by this bounded correction.

Scoped Ruff, MyPy and Pyright pass for the production changes. An initial MyPy
internal error and interrupted pytest run were traced to a full filesystem;
untracked disposable `.mypy_cache`/`.ruff_cache` were cleared and scoped MyPy
was rerun successfully using a temporary cache. Those interrupted runs are
not acceptance evidence. New unit fixtures needed missing native formatting
attributes corrected; final focused verification passes 51 tests in 14.44s,
including the live CLI case in 4.47s and all oracle corruption controls.

Post-change routine pipeline: 3,789 passed, one known BIOS strict-C failure,
seven warnings in 335.71s. All seven selected MS C tiny round trips pass.
The aggregate remains red (two passing lanes, one failing pytest lane).
Slowest tests: RunMenu 167.18s, InitMenu 161.11s, InitBars 111.27s. This run
was not a controlled performance comparison and does not establish either a
speedup or an acceptable regression. `quality-fast` still stops at global
lint failure; scoped production typing and Ruff pass. No full-suite refresh
or whole-plan completion is claimed.

Logs: `/tmp/inertia-mset-acceptance-final.log`,
`/tmp/inertia-mset-pipeline.log`, `/tmp/inertia-mset-quality.log`,
`/tmp/inertia-mset-mypy.log`, `/tmp/inertia-mset-pyright.log`.
The full architecture checker passes after adding the promoted module's
required future-annotations import (`/tmp/inertia-mset-architecture-final.log`).

### InBoxLng: Derived Predicate Provenance

Reproduced the live failure: a proven four-byte BP+20 argument was emitted as
two bytes, and partial output compared full operands to unrelated high words.
An uncached materialization probe showed the recovered ConditionIR already
had the correct four-byte stack operands. The derived predicate retained its
source 16-bit CMP's `producer_semantics` and `register_bindings`, however;
Alias operand binding then replayed DX's old high-word value onto a new wide
operand. This was not a missing CFG comparison or a cosmetic test failure.

All three wide-condition constructors (graph, chain, single-body branch) now
clear obsolete scalar producer semantics/register bindings when constructing
their proven wide operands. Instruction addresses and original raw conditions
remain available as provenance. The repair belongs to Structuring's derived
condition construction, not a relaxed Alias binding rule, later signature
repair or Rewrite.

Three focused provenance regressions fail before the fix and pass afterward.
Final focused acceptance: 24 passed, seven warnings in 22.47s; live CLI 4.52s.
The function passes validation and emits six wide parameters with the four
expected comparisons. Unchanged C passes strict compilation and UBSan execution
across signed extrema, low/high-word boundaries, equality and reversed bounds.
Four corrupted implementations are rejected. Tests are admitted to routine
Make/pipeline lists and structuring ownership. Scoped MyPy/Pyright pass; Ruff
reports 11 existing findings in the touched production modules, not suppressed.

Observed investigation/focused-fix interval: 2026-09-11 05:47:42 to 05:54:47
CEST (7m05s, includes test/process waiting; derived from log creation/completion
timestamps). Broader gate time is additional, not included in that interval.
Logs: `/tmp/inertia-inbox-before.log`, `/tmp/inertia-inbox-probe.log`,
`/tmp/inertia-wide-provenance-before.log`, `/tmp/inertia-inbox-acceptance.log`.

Broader verification: full architecture checker passes; `quality-fast` stops
at global lint as before. The separate routine pipeline reports 3,797 passed,
one known BIOS strict-C failure, seven warnings in 253.38s. All seven MS C
tiny build/run/decompile/recompile/run cases pass. Slowest tests: RunMenu
126.44s, InitMenu 122.47s, InitBars 96.90s. Timings are observational, not a
controlled speedup claim. Logs: `/tmp/inertia-inbox-pipeline.log`,
`/tmp/inertia-wide-quality.log`, `/tmp/inertia-inbox-architecture.log`.
No full-suite refresh or recalculated repository failure total is claimed.

### MousePOS: One Runtime Helper Identity

Reproduced the three remaining CLI probes: MousePOS failed strict compilation,
SetGear timed out, and DrawRadarAlt timed out then failed an obsolete timeout
message assertion. The latter two remain open; changing their timeout wording
assertions would not establish successful function recovery.

MousePOS's body called `int33` while its declared runtime helper was
`interrupt_int33`. The service-target registry consumed the fallback name from
`analysis_helpers.interrupt_service_name`, whereas declarations consumed the
actual SimOS handler's `INT_NAME`. Recovery metadata now uses that same handler
identity for unmodeled vectors. No new name table, emitted-C rename, prototype
patch or instruction-specific semantic assumption was added. Known service
tables and API styles remain unchanged.

The generic-name regression fails before and passes after the fix, checking
BIOS, DOS, multiplex and generic vector examples. MousePOS then validates and
strictly compiles. Its old fixed-AX=4 return assertion was replaced with an
executable check of the owned generic interrupt ABI: disabled/enabled mouse,
all 16-bit coordinate values on each independent axis, wrapping, writes before
the helper call, exact arguments/call count, and propagation of its AX result.
The stub is not proof about a particular DOS mouse driver; no unmodeled AX
preservation is assumed. Five corrupted wrappers are rejected. Both CLI
variants use the oracle, which is admitted to routine lists and test ownership.

Focused verification: 45 passed, seven warnings in 17.14s, live CLI 4.40s.
Scoped MyPy/Pyright pass. New/touched small test modules pass Ruff; the large
analysis helper retains 73 existing findings. `quality-fast` remains blocked
by global lint. Observed investigation/focused acceptance interval: 2026-09-11
06:03:18 to 06:09:35 CEST (6m17s including process waiting; broad gates extra).
Logs: `/tmp/inertia-cli-remaining-before.log`,
`/tmp/inertia-interrupt-name-before.log`, `/tmp/inertia-mouse-acceptance.log`.

Broader checks: full architecture checker passes; routine pipeline reports
3,803 passed, one known BIOS strict-C failure, eight warnings in 181.39s.
All seven MS C tiny round trips pass. Slowest tests: InitMenu 74.16s,
RunMenu 69.25s, InitBars 63.95s. This is not a controlled speedup comparison.
Logs: `/tmp/inertia-mouse-pipeline.log`, `/tmp/inertia-mouse-quality.log`,
`/tmp/inertia-mouse-architecture.log`. Global lint and the full-suite goal
remain open; these counts do not replace the last complete audit.

### SetGear: Uncached Diagnosis (2026-09-11)

The existing CLI regression still fails. A warm invocation completes but fails
the exact `else if (G == 1)` assertion; this does not establish whether the
remaining output is behaviorally correct. Do not remove that assertion without
a stronger executable oracle. The generated body retains packed flag equations
and flag guards. No SetGear semantic fix is claimed.

Two private-cache diagnostic runs with `PYTHON_JIT=1 PYTHONHASHSEED=0`,
`--proc _SetGear --proc-kind NEAR --timeout 60` and in-process telemetry completed
in 31.017s and 36.239s. Both report `validation=passed` and clean whole-tail
validation. Their C SHA-256 is identical:
`a00e9360c3e5c1e971742c3ebc53cab5ddc5beaf031401729e498fb6ad58525c`.
These are diagnostic timings, not controlled performance results: the second
run overlapped focused frontend tests, and neither records aggregate memory/CPU.
The larger timeout was diagnostic only; regression budgets are unchanged.

The second trace retains all 757 spans. Inclusive durations include angr core
18.832s, postprocessing 7.281s, structuring validation prime 3.038s and codegen
regeneration 1.454s. Nested spans overlap and must not be added. Several repeated
validation-summary and CLI rewrite passes take hundreds of milliseconds.
This supports investigating the retained expression volume before adding workers
or weakening validation; it does not yet prove the dominant exclusive hotspot.

An actual byte TEST/Jcc lift emits the expected typed DS mask and branch polarity.
The existing full-lift word regression now also covers byte masks 1/4 and JE/JNE,
replacing no behavioral assertion and adding no duplicate expensive CLI run.
The expanded module passed 21 tests in 8.25s after named-constant lint cleanup;
Ruff `check --fix` and `git diff --check` pass for this checkpoint.
It is already selected by Make, the routine pipeline and ownership manifest.
Next: trace these exact predicates through IR/Alias and Lowering, establish a
strict unchanged-C SetGear behavior oracle, then repair the first losing owner.
Keep live flags until their lack of consumers is proven.

Evidence: `/tmp/inertia-setgear-before.log`,
`/tmp/inertia-setgear-uncached.{c,log,trace}`,
`/tmp/inertia-setgear-full.{c,log,trace}` and
`/tmp/inertia-setgear-frontend-after.log`. Full-suite totals remain unchanged.

### LIFE Follow-Up: Tests Versus Function Acceptance

`clear_mat`'s fallback assertion required unsafe whole-body replacement. The
decoded range 10AB1h..10AC5h includes PUSH/POP BP, stack-argument loads and
DS-to-ES setup in addition to REP STOSB. Its typed artifact is correctly
partial-function. The renamed regression retains the original compact
diagnostic-rendering checks and requires the CLI replacement to refuse it.
Seventeen related tests pass (9.82s); the LIFE module passes Ruff. This is not
successful clear_mat decompilation: a normal sidecar-free run exits 4 because
the destination parameter is a value where validation requires a pointer.
Rejected partial C also uses incoming DF despite the decoded CLD; investigate
that evidence without accepting the failed payload as equivalent output.

The timer test's region ended at 104B3h, excluding its loop body and epilogue.
Sequential decoding from entry establishes RET at 104E6h, so the fixture now
ends at 104E7h and requires the increment/body/epilogue blocks in its CFG.
The pause_screen region is already complete through RET at 1092Ah; do not
apply the same correction there without evidence.

The full LIFE module passes eight tests in 19.54s; an explicit timeout-scale=4
rerun passes eight in 20.01s. These results do NOT close timer/pause_screen:
their sidecar-independence tests accept timeout payloads and still ran near
eight seconds. The claimed full-budget equivalence was not established by
that environment override. A separate complete-range timer diagnostic with
60 seconds reaches the real unresolved-stack hard failure. Do not hide it
with exception swallowing, turn partial C into success, or subtract these
nodes from the semantic failure inventory merely because a short run passes.

Logs: `/tmp/inertia-life-current.log`, `/tmp/inertia-life-full-budget.log`,
`/tmp/inertia-life-clear.log`, `/tmp/inertia-life-timer-complete60.log`.
Timer still needs coherent stack-object/word-lane recovery around its calls
and loop. No production semantic change was made in this follow-up.

### Ordered Tasks

1. Completed: reconcile the seven architecture findings, starting with touched modules.
   Reason: restore the checked ownership contract before semantic changes.
   DoD: the full architecture checker and its regression module pass.
   Failure: weakening the checker, exclusions, or inaccurate ownership headers.
2. Reproduce the six additional failures and classify their actual causes.
   Reason: stop newly introduced or newly exposed problems from accumulating.
   DoD: each node has a reproduced cause and passing focused acceptance.
   Failure: assuming every output assertion is cosmetic, accepting fallback
   loss, suppressing uncollected validation, or merely raising timeouts.
3. Resolve the remaining semantic/compilation failures by shared root cause.
   Reason: correct one producer rather than repair individual output strings.
   DoD: affected functions validate, strictly recompile and retain required
   behavior, with focused negative/refusal tests at the responsible layer.
   Failure: deleting live effects, source-specific recovery, or semantic repair
   in Rewrite/CLI. BIOS allocation/read/escape proof remains in this group.
4. Replace demonstrably brittle spelling/naming assertions with stronger
   behavioral contracts, reusing existing oracles where possible.
   Reason: numeric names and equivalent loops/casts are not correctness defects.
   DoD: unchanged generated C satisfies the original required behavior and the
   replacement oracle rejects relevant corrupted implementations.
   Failure: replacing assertions with weaker substrings or ignoring lost calls,
   incorrect pointer/value argument classes, or compilation/validation errors.
5. Rerun full inventory/execution and all required linter/type gates to green.
   Reason: only the complete verified baseline establishes regression readiness.
   DoD: all inventoried tests accounted for, zero failures, skips justified,
   stable source, passing lint/type gates and MS C round trips.
   Failure: reporting curated counts as full results, dropping tests to improve
   totals, or marking the goal complete while any acceptance remains red.

Performance work is deferred unless it blocks reliable test completion. The
current 22-minute full suite still exceeds the accepted runtime target; report
that honestly without exchanging correctness coverage for speed.
