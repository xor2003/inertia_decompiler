# SetGear Investigation: Frontend Width And Condition Consumption

## Verified Checkpoint

### Equality Purity Fix (2026-09-11)

An observed private-cache worker run resolves the uncertainty below: the
cycle proof ran, collected two FLAGS definitions, but classified neither RHS
as pure. The loop update contains `CmpEQ` for ZF, which the purity whitelist
omitted. The runtime live-in read remains deliberately ineligible.

Lowering now recognizes equality with recursively pure operands. The new
comparison regression failed before the fix (1 failed, 17 passed); the expanded
FLAGS set passes afterward (47 passed, seven warnings, 9.45s). Live returns,
loop guards, and missing/incomplete condition evidence still prevent deletion.
The real worker records counters 2/1/1/1/0 and then 0/0/0/0/0, with
`validation=passed`. Generated `sum_to` retains its parity branch and total
updates but no longer contains the unused FLAGS chain or live-in. It matches
the control-flow shape of `examples/msc6_constructs/simple_control.c`.

The isolated MS C compile/decompile/recompile/execute round trip passes:
original and recompiled exit codes are both 255. Scoped Ruff/MyPy/Pyright pass.
Routine pytest: 3,839 passed, one known BIOS strict-compilation failure, eight
warnings, 194.43s. Global `quality-fast` remains red on Ruff debt. These are
routine-gate results, not refreshed full-suite totals or closure of SetGear.

The completed pipeline at 07:24 CEST confirms all seven MS C round trips pass
again, with no timed-out lanes. Overall pipeline exit remains nonzero because
of the known BIOS failure. `git diff --check` passes.

Evidence: `/tmp/inertia-cycle-probe{,2,3}.log` and
`/tmp/inertia-cycle-equality-{before,after,msc,pipeline,quality,mypy,pyright}.log`.

### Packed-FLAGS Cycle Checkpoint (2026-09-11 07:15 CEST)

The new Lowering-owned dependency proof remains experimental: the isolated
`simple_control` MS C round trip still fails recompilation, and `sum_to`
still contains the `inertia_flags` live-in and self-dependent update. Do not
claim this regression fixed or the direction experiment accepted. Whether
the real pipeline refuses the proof or reuses output remains to be diagnosed
with an observed, uncached worker invocation.

The cycle proof now requires positive, complete condition-materialization
evidence; missing evidence refuses it without disabling historical unread
definition cleanup. Regression cases cover unobserved cycles, live returns,
live loop guards, missing evidence, and incomplete evidence. The expanded
focused set passes: 38 tests, seven dependency warnings, 8.72s. The tests are
admitted to the routine pipeline and Make selection.

Scoped Ruff, MyPy, and Pyright pass for the new Lowering owner (and Pyright
also passes its compatibility shim). Broader touched-file Ruff remains red:
12 findings in condition materialization and 70 in the admission-tool scope.
No rules were disabled. Full-suite totals have not been refreshed.
The full architecture check passes after adding its required ownership-header
markers to the new Lowering module; `git diff --check` also passes.

Logs: `/tmp/inertia-flag-cycles-{final,msc,mypy,pyright,structuring-ruff,admission-ruff}.log`.

This follows the [full-suite baseline](p0-full-suite-baseline-20260910.md).
SetGear is not fixed and full-suite totals have not been refreshed.

The direct-byte fast-path load in `lift_86_16.py::_load_abs8` executed an
8-bit load but used `_record_mem_access`'s default two-byte operand width.
It now explicitly records one byte. Frame-relative and wrapped word helpers
are unchanged. This is a Frontend evidence correction, not output cleanup.

The new actual-lift regression captured `(DS, 0x1234, 2)` before the fix and
`(DS, 0x1234, 1)` afterward. A following Jcc deliberately selects the optimized
TEST path. Without it, this decoder uses the generic path, whose provisional
address is not a direct-offset capture; that is not evidence of this defect.
The initial IR-level test trial compared incidental address provenance and was
replaced with the direct capture contract before assessing the fix.

## Verification

- 32 focused frontend/logical-memory tests passed in 9.09s.
- Scoped MyPy and Pyright pass for the lifter and pipeline admission owners.
- Ruff `check --fix` passes for pipeline admission files; 76 existing findings
  remain across the lifter and logical-memory test module. No checks disabled.
- Full architecture check and `git diff --check` pass.
- `quality-fast` stops at global Ruff debt.
- Routine pipeline: 3,816 passed, one known BIOS strict-C failure, eight
  warnings in 184.02s. Slowest: InitMenu 87.36s, InitBars 72.38s, RunMenu 69.78s.
- All seven MS C build/run/decompile/recompile/run examples pass.
- The logical-memory module is now also in routine pipeline and ownership
  selection; it was already selected by Make.
- A private-cache SetGear rerun validates with a clean whole tail and exactly
  the previous C hash: `a00e9360c3e5c1e971742c3ebc53cab5ddc5beaf031401729e498fb6ad58525c`.
  Therefore this correction is not a SetGear readability or performance fix.

Observed interval: 2026-09-11 06:26:32 to 06:37:20 CEST, 10m48s including gates
and waiting. Logs: `/tmp/inertia-byte-width-{before,after,ruff,mypy,pyright,quality,pipeline,architecture}.log`
and `/tmp/inertia-setgear-width.{c,log}`.

## Next Investigation

The condition-transfer trace collects all eight SetGear predicates, including
Status byte masks, with counters 8/8/8/8/0. Collection is not final C consumption.
Both baseline and follow-up logs reject and restore `optimization:dce` and
`_dead_code_elimination_after_flag_prune_8616` with verdict `changed`.

`Processor.set_gpreg` synchronizes derived direction state after FLAGS writes;
`direction_step.py` emits an ITE selecting -1/+1 from DF. This is a candidate
source for unwanted downstream branch structure, not yet a proven root cause.
Investigate branchless exact DF projection and the rejected DCE effect diff.
Preserve architectural FLAGS, stale-direction synchronization, typed projection
proofs and validation. Require existing direction execution tests, an IR-shape
regression, SetGear behavior/recompilation and corpus gates before acceptance.

## Direction Arithmetic Experiment: Acceptance Still Red

The working tree now uses exact unsigned dword `1 - 2*DF` instead of the ITE
inside `direction_step.py`. Source-bit projection, its evidence reports and
every FLAGS/direction write are retained. Eight native IR-shape cases failed
before this change and pass afterward. A symbolic execution proof covers all
16-bit FLAGS inputs, and existing stale-direction/string execution tests pass.
The modified production/test files pass Ruff; scoped MyPy/Pyright and the full
architecture check pass. No semantic deletion was added to postprocess.

SetGear's private-cache diagnostic is 10.520s versus the earlier 31-36s,
with no flag equations or duplicated DF branches, clean tail validation and
strict GCC compilation. A subsequent isolated run took 14.45s wall, 14.09s
user, 0.30s system, peak process RSS 264,968 KiB. This variation is not a
controlled speedup result. Further repeats were stopped when the corpus gate
failed. The CLI regression still fails its exact `else if (G == 1)` assertion;
do not replace it without a stronger behavior oracle. Signed Knots semantics
remain suspect: source/COD uses signed JG but output declares Knots unsigned.

Focused acceptance: 45 passed plus the known failing SetGear CLI node, 25.83s.
Routine pytest: 3,817 passed, one known BIOS failure, 182.94s. However, only six
of seven MS C round trips pass: `simple_control` now fails recompilation.
Therefore the direction change is experimental, not a completed fix.

The failing `sum_to` retains a self-dependent packed-FLAGS assignment inside
its loop. Its standalone output declares `extern unsigned short inertia_flags`
and compiles with strict GCC. The assembled MS C harness drops the declaration;
MS C reports C2065 at DSIMP01.C:42, and linking subsequently fails because the
object was not produced. Do not add a guessed FLAGS initializer to make this pass.
Current unused-flag cleanup counts the self-read as a use; any removal needs
closed dependency/liveness evidence at the appropriate IR/analysis owner, not
new semantic recovery in postprocess. Independently audit runtime declaration
transport so valid live inputs cannot silently lose their declarations.

Next priority: resolve this round-trip regression, then repeat SetGear and all
seven examples before accepting branchless direction synchronization. The full
test inventory and global lint goal remain open. Logs and artifacts:
`/tmp/inertia-direction-{before,after,acceptance,quality,pipeline,architecture}.log`,
`/tmp/inertia-setgear-direction.{c,log,trace}`,
`examples/build_msc6_tiny/simple_control/report.json`, and its `DSIMP01.batch`.
Checkpoint observation: 2026-09-11 06:48:44 CEST.

## TEST Proof Consumption: Fixed Handoff, Round Trip Still Open

Worker instrumentation confirms the CFG has the right proof for sum_to's TEST:
at rebased 0x1026, written=2261, live_after=64 (ZF), dead_writes=2197. However,
`suppression_supported=False` because the projection's supported writer set
omitted `test`. Both register TEST and byte-memory TEST already execute through
the shared EFLAGS owner that consumes partial dead-write masks.

The IR CFG projection now includes TEST in that supported set. Two new cases
failed before the change and pass afterward. The existing partial-mask test
checks that ZF remains, parity operations disappear, publication counters close,
and packed-preservation evidence survives. Added full-live register/memory TEST
cases verify that the absence of a dead-bit proof keeps all required writes.

95 combined CFG, lifting, direction execution and symbolic-boundary tests pass
in 10.10s. Changed files pass Ruff; the production owner passes MyPy/Pyright.
These tests are already selected by the routine pipeline and ownership rules.
Full broad gates were not repeated at this checkpoint because the isolated
MS C round trip still reproduces the open compilation failure.

The isolated simple_control rerun completes decompilation with clean validation
but still fails MS C on undeclared `inertia_flags`. Its sum_to no longer contains
parity/sign equations; the remaining loop assignment is a self-dependent ZF
update preserving other packed bits. Unused-flag cleanup counts that self-read
as a use. Enabling TEST proof consumption is necessary but not sufficient:
the next owner must prove dead dependency cycles after typed branch consumers
are materialized, without inventing FLAGS values or weakening tail validation.

Artifacts for this isolated run are at `examples/build_msc6_tiny/report.json`
and `examples/build_msc6_tiny/DSIMP01.batch` (not the earlier simple_control
subdirectory). Logs: `/tmp/inertia-test-flags-{before,after,final,msc}.log` and
`/tmp/inertia-sum-{masks,projection}.log`. Diagnostic scripts reside in /tmp,
not production. Observed checkpoint: 2026-09-11 06:56:46 CEST.
