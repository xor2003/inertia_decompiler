# MONOPRIN Repeat-State Investigation

Observed 2026-09-10, 20:03-20:13 CEST. This is an unresolved semantic failure,
not a stale assertion that may simply be relaxed.

## Current Checkpoint

Verified through 2026-09-10 22:11 CEST. Exact active-work duration was not
recorded; this checkpoint does not imply completion of the MONOPRIN wrapper.

The sidecar-free count-only REP kernel no longer loops forever. Production
`string_helpers.repeat_jump` emits an unconditional backedge after the existing
zero-count header guard for non-ZF-sensitive repeats. Native SSA then carries
the post-body CX/DI definitions. CMPS/SCAS retain their existing conditional
backedges; their native SSA correctness is not established by this slice.

Two additional prerequisites preserve the kernel's values:

- Pre-SSA terminal-return binding consumes the existing typed AL/AH/AX proof
  without inventing a calling convention (see the historical section below).
- `lowering/native_integer_constants.py` evaluates same-width scalar literal
  AIL arithmetic modulo its explicit width, and preserves unsigned constant
  narrowing when native implicit-cast simplification removes the cast. The
  adapter records the five evidence counters. It refuses mixed widths,
  floating/vector operations, unsupported operations and unproven narrowing.
  This preserves existing type/AIL evidence before its loss, not text recovery.

The executable matrix has eight cases: F2/F3 count-only STOSW, zero/one/three
iterations, forward/backward movement, writes crossing FFFFh, and INC AX from
FFFFh returning zero. Every case requires `validation=passed`, clean whole-tail
validation, strict GCC compilation and execution of unchanged generated C.
The oracle compares all memory and the return, with initial DF opposite to the
instruction's requested direction. It does not independently compare every
machine-register live-out. Five compilable corruption controls remain rejected.

Verification:

- 114 focused tests passed in 103.22s, including executable REP and wiring.
- After the bootstrap inventory correction and an additional packed-operation
  refusal test, 43 focused tests passed in 12.28s.
- Scoped Ruff `check --fix`, MyPy and Pyright pass for the changed native
  integer, bootstrap and string-helper production modules. Scoped Ruff also
  passes for the REP, integer, string-helper and package-inventory tests.
- Broad quality/default pytest lanes each reported 3,722 passed and 2 failed
  (346.81s / 217.43s): BIOS strict-C and the subsequently corrected bootstrap
  inventory. No REP failure remained. Broad lanes were not rerun after that
  assertion correction; do not present inferred totals as observed results.
- All three executable quality guards and all three MS C tiny examples pass
  their real compile/decompile/recompile/execution round trips. The pipeline's
  aggregate `failed=1, passed=2, selected=3` counts lanes; pytest failed.
- Global lint remains red. No refreshed full-suite total is claimed.

Remaining blockers:

1. MONOPRIN `__fimemset` still exits 4 with failed tail validation. Its updated
   loop retains CX/DI updates and return zero, but destination/count parameters
   are byte-sized and a BP+5 read is unresolved. Continue at Alias/Types;
   do not replace the wrapper with a guessed intrinsic.
2. A failed temporary cast experiment exposed a separate unsafe fallback:
   whole-body string-intrinsic recovery discarded setup and INC AX, returned
   CLI success and left whole-tail validation uncollected. Require typed
   whole-body effect coverage before such recovery. The partial-coverage bypass
   is now repaired as described below; full fallback soundness remains open.
3. BIOS strict compilation still rejects unused stack carriers. Do not weaken
   stack-write preservation without ownership/lifetime/escape proof.

The temporary cast experiment initially raised a comparison of unknown type
width (`None`) with an integer. That was a diagnostic guard bug, not evidence
that native walkers reject semantic-cast subclasses. Accepted production
checks use the normal CLI, without the diagnostic monkeypatches.

## Shared String Replacement Admission

The normal codegen override checked typed exact-function coverage, refusals and
nonempty records. The timeout fallback instead called the diagnostic renderer
directly. Both now consume `render_complete_string_function_8616` at the
existing X86_16 codegen boundary. CLI consumes the decision and adds no semantic
classification. Diagnostic rendering remains separate and available.

Four machine-byte regressions failed before the repair: REP plus INC AX,
an absolute memory store, INT 21h, or PUSH AX all incorrectly produced a
replacement body. Afterward all four refuse it. The helper/lowering/override
selection passes 18 tests (10.16s); three CLI timeout tests pass (16.02s).
Scoped Ruff, MyPy and Pyright pass. Both fallback and override test modules
are admitted to routine Make/pipeline selection and ownership mapping.

Broad gates finished by 22:26 CEST on 2026-09-10. Quality-fast and default
pytest each report 3,734 passed and one BIOS strict-C failure (234.03s and
164.81s respectively). All three executable quality guards pass, and compare16,
simple_control and scalar_types_io each pass build, original execution,
decompilation, recompilation and generated-program execution. Global Ruff
remains red; aggregate Make exit is 2. This is not a full-suite refresh.
The quality guards report one shared active import surface, so their equal
baseline/candidate timings are not an independent before/after speedup claim.

Mixed-overlap and scan-tail classifiers currently retain partial-function
coverage. Their former CLI tests incorrectly required whole-body replacement;
they now require refusal, while diagnostic-rendering tests remain unchanged.
Do not promote those classifications to exact merely to restore their output.

This is not a complete proof of string fallback correctness. The instruction
artifact currently allows some MOV/XOR setup instructions in its exact census,
although the compact renderer does not explicitly emit their assignments.
Exact decoded scope is therefore not sufficient proof of preserved effects.
The next repair must represent and consume setup/live-out effects at the typed
owner, or refuse replacement. It must also require validation of the actual
replacement before reporting success; uncollected validation is not success.

## Original Evidence

The full-suite `test_monoprin_fimemset_emits_string_intrinsic_fallback_anchor`
still fails. Its COD fixture describes a wrapper that loads a far destination,
word count and word value, executes REPNZ STOSW, restores saved registers and
returns zero. Source/listing content is diagnostic evidence only.

Direct command: `PYTHON_JIT=1 PYTHONHASHSEED=0 .venv/bin/python decompile.py
cod/f14/MONOPRIN.COD --proc __fimemset --proc-kind NEAR --timeout 20`.
Exit status is 4 and whole-tail validation fails. Current output has byte-sized
destination/count parameters, an unresolved pointer expression, and no CX/DI
updates inside its loop. Do not accept it by replacing the missing intrinsic
assertion with a mere memory-store substring.

## Located Loss

An uncached in-process stage probe shows the missing updates already in C at
entry to `_structuring_codegen_8616`, before Inertia structuring/postprocess.
Native SSA before DCE contains the updates, but its self-loop phis incorrectly
select the phi itself on the backedge:

- DI phi vvar_2 receives vvar_2 rather than updated vvar_19.
- CX phi vvar_3 receives vvar_3 rather than decremented vvar_18.
- Native DCE then removes the apparently unused DI update.

The AIL block contains an internal zero-count exit and a terminal conditional
backedge. Installed angr's `is_head_controlled_loop_block` explicitly rejects
blocks ending in ConditionalJump. Both SSA rewriting and `s_liveness` consume
this predicate. Thus the block is not treated consistently with its recorded
mid-block exit state.

Beware confusing native state names: in `_run_on_node`,
`head_controlled_loop_outstates` retains the post-body state, while `out_states`
is replaced with the early-exit snapshot. Do not swap these by name alone.

## Diagnostic Trials, Not Production Changes

1. Changing only the self-loop phi inputs was insufficient: later native
   processing still lost effects. Do not repeat it as a complete solution.
2. Broadening the classifier in both native SSA rewriting and liveness restored
   CX decrement and DI update in generated C. This confirms the implicated
   boundary, but is NOT accepted: pointer/argument defects remain, DI still
   contains an unresolved expression, and the loop bound remains suspicious
   after the counter becomes explicitly mutable (`cx -= 1` with `cx != 1`).
3. Whole-tail validation remains failed in all trials. Its current diagnostic
   is uninitialized stack reads, not an independent proof of loop equivalence.

All trials are temporary `/tmp` diagnostics; no classifier monkeypatch or
semantic recovery was installed in production.

## Next Implementation And Acceptance

1. Normalize the native multi-exit block or make native edge-state consumption
   explicitly destination-aware before SSA/DCE. Preserve early-exit versus
   post-body state, register/stack phi widths, zero-trip behavior and backedges.
   Reason: correct reaching definitions are the premise for every later layer.
   DoD: focused native-SSA and executable repeat tests preserve updates for both
   repeat prefixes and direction states; non-repeat and ambiguous edges refuse
   unsafe inference. Failure: retaining every register write blindly or repairing
   rendered loop bodies in structuring/Rewrite.
2. Trace the independent far-pointer/word-argument and loop-condition defects at
   their owning IR/Types/Condition layers after native state is coherent.
   DoD: binary-derived pointer/count/value widths, exact stores/count/index
   behavior, saved-register preservation, zero return, strict recompilation,
   validation=passed and whole-tail clean. Failure: COD/source-driven semantics,
   wrong zero-count handling, off-by-one loop bounds, or false validation success.
3. Replace the historical intrinsic spelling requirement only with compiled
   behavioral acceptance that rejects corrupt store values/counts/directions.
   DoD: full wrapper effects remain checked; routine and external lanes pass.
   Failure: accepting a helper call or store substring as functional equivalence.

## Test Isolation Repair

The existing corpus test used to overwrite and restore shared
`cod/f14/MONOPRIN.dec`. It now copies the COD fixture to pytest's private
directory and reads its sibling output there. This prevents overlapping runs
from clobbering corpus artifacts; no assertion was removed or weakened.
Ruff passes. Focused result: 10 passed, the same one corpus failure, in 21.79s.

Logs: `/tmp/inertia-monoprin-before.log`, `/tmp/inertia-monoprin-isolated.log`,
`/tmp/inertia-fimemset-native3.log`, `/tmp/inertia-fimemset-head-trial.c`,
`/tmp/inertia-fimemset-head-trial.log`. The first native and DCE snapshots are
in `/tmp/inertia-fimemset-native.log`. These results do not refresh full-suite
counts or close P0/BIOS lifetime work.

## Executable False-Pass Regression

Subsequent sidecar-free mixed-effect kernel:
`CLD; MOV DI,0200h; MOV AX,1234h; MOV CX,3; REP STOSW; INC AX; RET`.
Unlike an intrinsic-only wrapper, this has a separate return effect. The new
`test_x86_16_rep_store_codegen.py` requires exactly three word stores, no writes
to other memory bytes, return 1235h, and termination after strict GCC compilation.

Current decompilation returns success, reports `validation=passed` and a clean
whole tail, and compiles strictly. Execution then loops indefinitely. This is
a demonstrated false acceptance, not just an unsupported-expression failure.
The subprocess timeout terminates the broken executable after two seconds.

The oracle accepts a correct implementation and rejects five compilable
mutations: too few/many stores, wrong stored byte, wrong return, and an extra
write outside the destination range. Final focused execution plus ownership
and pipeline wiring: **115 passed, one real kernel failure, 5.15s**. Ruff passes
for the new test and touched tooling. The regression is admitted to Make and
routine pipeline selection; it is neither skipped nor xfailed. Historical
routine counts above predate this admission and cannot be called current green.

Two more diagnostic approaches are recorded to avoid repeating partial work:

- Splitting the multi-exit AIL block before SSA produces separate header/body
  indices but exposes downstream block-index handling: generated code contains
  an `else continue` before its stores. Not accepted or installed.
- For count-only REP, an unconditional backedge to the existing zero-count
  header guard restores loop state and avoids the stale `cx != 1` termination.
  A trial retains CMPS/SCAS ZF-sensitive behavior unchanged. However, once live
  updates survive, the kernel exposes unresolved direction expressions and
  byte-store width projection errors; CLI strict acceptance rejects the result.
  This frontend trial was removed completely, including its test expectation
  changes. No production string helper changed in this checkpoint.

Highest next priority: close this executable false-pass before accepting a
native/REP repair. Reason: tail validation currently misses an infinite loop.
DoD: the admitted kernel and wrapper compile and execute correctly with passed
validation, plus zero/one/multiple-count, direction and wrap refusal/boundary
coverage as appropriate. Definition of failure: relaxing the oracle, accepting
an intrinsic-only whole-body replacement, or landing only the loop-state trial
while its generated code still cannot compile.

Additional logs: `/tmp/inertia-rep-store-before2.log` (strictly compiled infinite
loop), `/tmp/inertia-rep-store-after.log` (rejected frontend trial),
`/tmp/inertia-rep-store-final.log` (admitted failure and passing oracle/wiring),
`/tmp/inertia-fimemset-split-trial.c`, `/tmp/inertia-fimemset-rep-trial.c`.

## Expression Display Truncation

Follow-up on 2026-09-10: the REP trial's `i += ...` is not an unsupported
direction instruction. Native codegen collapses binary expressions whose depth
exceeds its configured display cutoff. The CLI selected depths as low as two
for wrappers/tiny functions. This is a source-export policy defect, separate
from the lost loop state.

`_preferred_expr_collapse_depth` now supplies `sys.maxsize`, retaining the
native integer API while disabling practical display truncation for every
function profile. This changes rendering configuration only: no instruction,
alias, width, or return semantics are recovered in the CLI. Six profile tests
failed before the change. Native codegen tests also retain a low-cutoff control
to distinguish the display behavior from the export policy. The regression is
admitted to Make, routine selection and test ownership.

An uncached in-process REP trial at 20:32 CEST now renders both complete DF
conditionals in the index increment. It still exits 4 on strict GCC byte-store
overflow (`SEG_U8 = 4660`), and its return is still absent after CLI rollback.
Thus the canonical REP frontend trial remains diagnostic-only; neither REP
semantics nor the wrapper is fixed. Logs: `/tmp/inertia-repeat-render-check.c`
and `/tmp/inertia-repeat-render-check.log`. MyPy and Pyright pass for the CLI
module; Ruff reports 75 existing findings outside the changed helper.

Verification: **67 focused tests passed in 8.93s**, including the native
truncation control and ownership checks. New test/tooling Ruff passes.
`make -k quality-fast test-pipeline PYTHON=./.venv/bin/python PARALLEL_JOBS=7`
reports **3,667 passed / 2 failed** in both fast (183.03s) and default (148.54s)
pytest lanes. Failures remain the BIOS unused-local and REP infinite-loop
regressions. All three executable quality guards and both default external
lanes pass, including MS C tiny round trips. Overall Make exits 2 because of
those failures and existing linter debt. No complete-suite refresh is claimed.
Gate log: `/tmp/inertia-codegen-policy-gates.log`.

## Native Width And Return Boundaries

Follow-up probes on 2026-09-10, 20:46-20:56 CEST, narrowed the remaining
canonical-REP trial failures without changing production behavior:

- Native AIL has `Store(size=1, data=Convert(16, 8, Const(4660, 16)))`.
  Native codegen constructs a `CTypeCast` for that data. The first C snapshot,
  before Inertia structuring/postprocess, already renders `char` stores of
  `4660` and `4660 >> 8`. Thus the machine store width is not missing in the
  lifter. Native `MakeTypecastsImplicit.collapse` deliberately removes narrowing
  casts when the destination assignment provides an implicit conversion. This
  is valid C conversion behavior but fails the strict constant-overflow gate.
  A direct callback probe confirms `CTypeCast -> CConstant` for value 4660
  with destination `char`; this is observed removal, not just hidden rendering
  (`/tmp/inertia-repeat-cast-collapse.log`).
  Any repair must preserve or evaluate the existing typed conversion; do not
  infer width from rendered `SEG_U8` text or change segmented execution.
- At entry to `_recover_calling_conventions_8616`, the real kernel has
  prototype `() -> unsigned short`, source `PrototypeSource.GUESSED`, and
  `calling_convention=None`. After native recovery both prototype and convention
  are `None`. Clinic then enters `_stage_make_return_sites` and `_make_returns`
  in that state. Native `_make_returns` returns immediately when no convention
  exists, leaving the machine RET as `Return ()` before the first SSA pass.
- The first SSA graph still contains `AX = AX + 1` before that empty return.
  The second graph retains its constant-folded producer, but native C has only
  an empty return. This is not a CLI rollback-only loss. The existing native
  ReturnMaker compatibility callback cannot help because ReturnMaker is never
  constructed on this path.

The schedule itself is not the cause: its observed range is 0 through 15 with
no skipped stages, and the return stage does execute. Earlier profile runs
without a return-stage event were insufficient evidence to claim a skipped
stage; the explicit later observations supersede that hypothesis.

Next repair order:

1. Carry the already-proven terminal AX effect into native return/liveness
   consumption before SSA even when argument/calling-convention recovery is
   incomplete. Consume the existing typed terminal-return owner, respect
   explicit void contracts and unknown/refused evidence, and do not promote
   a guessed whole signature to authoritative merely to bypass native CCA.
2. Preserve/evaluate the existing typed byte conversion at the native lowering
   boundary. Check signedness, nonconstant inputs and modular conversion cases;
   avoid blanket `show_casts` or indiscriminate cast retention as semantic proof.
3. Re-run the executable REP oracle with the canonical backedge trial. Only
   land it together with passing validation, strict compilation and behavior.

Evidence: `/tmp/inertia-repeat-width-probe.log`,
`/tmp/inertia-repeat-return-ssa.log`, `/tmp/inertia-repeat-clinic-cc.log`.
These are diagnostic runs with an unlanded frontend trial, not production
acceptance, performance measurements, or a fresh suite result.

## Pre-SSA Return Binding Candidate

The Types/Lowering native adapter now binds an empty AIL return from the
existing complete terminal-storage proof when native calling-convention
recovery supplies no convention. It handles exact AL/AH/AX carriers, preserves
existing return expressions and explicit void prototypes, and refuses unknown,
call-only and split-pair storage. It does not modify the function prototype or
calling convention. Binding occurs in Clinic's return-construction stage,
before SSA. A closed raw/normalized/classified/materialized/failure census
raises an error if a classified return site is not materialized.

The canonical REP trial now has `Return (vvar_17{r0|2b})` in its first SSA graph
and emits `return 4661;` instead of losing the INC AX result. Strict compilation
still fails on byte-store narrowing; the frontend backedge trial is still
unlanded. This proves the isolated return dependency, not whole-function repair.
Log: `/tmp/inertia-repeat-return-binding.log` and sibling `.c`.

Focused adapter, segment-liveness and ownership checks: **77 passed, 9.49s**.
The first broad audit found **3,676 passed / 3 failed** in fast (188.32s) and
default (161.63s) lanes. Besides known BIOS/REP failures, `_dos_loadProgram`
failed an exact return-spelling assertion: native binding retained `ax = err;
if (err) return ax;`, which is behaviorally equivalent to direct `return err`.
No error value was dropped. The generated output was inspected before changing
the assertion.

The exact spelling requirement is replaced by strict compiled execution of
unchanged generated C over eight error codes. It checks all five call arguments,
exactly one call, error propagation, success-only CS/SS output writes, adjacent
output sentinels and unchanged parameter globals. Both direct/copied returns
pass; six compilable mutations are rejected. The real wrapper plus oracle and
binding tests pass **19 tests in 24.73s**, with the wrapper taking 13.00s.
These controls are admitted to the routine pipeline and ownership manifest.

Scoped Ruff, MyPy and Pyright pass for the new adapter, existing compatibility
module and oracle helper. The legacy COD regression module still has 35 Ruff
findings outside the changed assertion. Its test is not relaxed to a regex or
alternate spelling allowlist. The first broad audit cannot be called green.

Final default routine run: **3,685 passed / 2 known failures, 310.88s**.
The extra spelling failure is closed by the behavioral oracle. This run was
slower than the earlier 161.63s run; no performance improvement or unchanged
performance is claimed. Slowest tests were RunMenu escape (120.43s), InitMenu
pause-zero (118.73s), and sidecar-free InitBars (87.83s).

The final aggregate pipeline still exits 2: besides pytest failures, its MS C
`simple_control` recompilation encountered `unexpected KVM exit: reason=9`.
The DOS compiler produced no object file and linking consequently failed.
Decompilation of all three functions itself passed. The original failed report
is preserved. An isolated rerun to `/tmp/inertia-msc6-simple-return-check`
passes build, original execution, decompilation, recompilation and rebuilt
execution (decompilation 47.63s). This does not retroactively make the aggregate
run green; backend instability remains a follow-up issue. The preceding broad
audit had passed both external lanes and all three executable quality guards.

Logs: `/tmp/inertia-native-return-gates.log`,
`/tmp/inertia-native-return-pipeline-final.log`,
`/tmp/inertia-native-return-loadprogram.log`,
`/tmp/inertia-msc6-simple-return-check.log`. This checkpoint ended after the
isolated external rerun on 2026-09-10. It closes the independent native
return-binding defect, not the REP function or P0 goal.
