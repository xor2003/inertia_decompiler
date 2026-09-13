# RunMenu Switch Coverage Investigation

## Shared Exit And Executed Dispatch (2026-09-13)

RunMenu now passes semantic and whole-tail validation. Structuring publishes
an immutable shared-loop-exit binding from binary dispatch evidence, exact
loop/predicate ownership and a straight-line epilogue. Tail validation accepts
that alternative only while the current guard, ancestor path, loop condition,
target and epilogue match the published snapshot. Mutation tests cover stale
predicates, removed breaks, changed returns and ambiguous or missing CFG/SSA.
Fresh fingerprints avoid identity-cache reuse across in-place AST mutations.

The proof exposed an actual lowering bug: unobserved scalar-return cleanup
created `return 0` for a void return. Restricting that cleanup to scalar return
types preserves the original epilogue; validation was not relaxed to accept it.
The final four predicate mismatches were equivalent unit-decrement zero tests.
Validation-only fingerprint normalization now recognizes exact decrement as
subtraction, without moving ordered comparisons across modular arithmetic.
Fail-first decrement tests: 12 failed / 1 passed in 6.00s; combined post-fix
surface: 105 passed / 1 legacy output-shape failure in 36.30s.

The output-shape failure is replaced by a stronger compiled behavior oracle:
unchanged generated portable-flat C executes all 256 keys across five pause
values and both sound states (2,560 cases). It checks dispatch/call order,
arguments, counters, cursor toggles, pause and sound changes, default keys,
ESC termination and SI/DI preservation. Deliberate lost-call, lost-break and
wrong-argument mutations must compile and then fail execution, not merely fail
compilation. The final live regression including these controls passes in
7.60s. Numeric names remain acceptable; the if/else representation is not
replaced with a switch that would discard live definitions.

New tests are enrolled in routine gates. Quality-fast remains lint-blocked;
the 39-module mypyc import smoke passes. Broad pipeline refresh completed at
14:53 +02:00: 5,364 passed / 1 failed in 237.61s, plus 268 preliminary passes.
InitBars is the only remaining routine pytest failure. QuickC remains 3/4;
the MS C tiny round-trip lane remains failing. These are not full-suite totals.
The separate full-file transcript ratchet still assumes a literal ESC switch
case and needs evidence-backed reconciliation. Readability/flag cleanup and
whole Step 9 acceptance are not claimed by this execution checkpoint.

## Remaining Branch Owners (2026-09-13)

Investigation resumed with the live probe at **13:37:43 +02:00**. The final
focused live run at **13:51** has **no missing branch-owner diagnostics**.
RunMenu is still rejected: the separate switch-exit obligation requires a
literal `case`, whereas this definition-preserving output uses a conditional
break and shared epilogue. No validator was changed or disabled in this batch.

Root causes and owning-layer changes:

- The loop-exit binder ignored constant `while (1)` guards. It now requires
  matching loop-header and first-statement provenance plus a unique proven
  natural loop before using the existing exact exit/polarity proof. This closes
  the `10443/10440` ESC branch owner without changing its break body.
- Binary and multi-arm conditions now share one exact empty-connector polarity
  proof. Physical CFG facts remain unchanged; effects, phi nodes, refusals and
  uncertain paths still prevent normalization.
- Label-only bodies now obtain entry identity from the codegen address map,
  cross-checked against their source tag, never parsed names. Nested conditions
  expose an entry only from an already-materialized matching root owner. These
  close `1044b/10448` and `10480/1047f` after the child condition is proven.
- A sole conditional goto uses its structured destination and immediate
  continuation as endpoints of the exact CFG proof. Prefix effects and unknown
  targets refuse. This closes `1045a/10457` without moving the goto or effects.

Fail-first evidence: unconditional-loop regression **1 failed / 16 passed**;
binary endpoint API **10 failed / 13 passed**; label/nested-entry regressions
**2 failed / 25 passed**; conditional-goto API **4 failed / 23 passed**.
Final related tests: **158 passed in 7.41s**. Last live RunMenu surface:
**71 passed / 1 failed in 41.61s**, now reporting only the switch-exit obligation.
The 26 added cases live in already-enrolled routine test modules.
Scoped/promoted MyPy and 39-module compiled-import smoke pass. New helper and
test surfaces are Ruff-clean; existing condition-materialization and legacy
multi-arm selection lint findings remain. `quality-fast` exits 2 on lint.
Gate refresh completed **14:02:41 +02:00**, 24m58s wall time after the first
live probe (including tests and waiting; not an active-coding estimate).
Routine collection: **5,338 passed / 2 failed in 241.36s**, plus 268 preliminary
passes in 7.58s. RunMenu and InitBars remain red. QuickC stays **3/4** (36.04s);
MS C tiny stays **5/7** (137.23s), with `simple_control` and `loops_jumps`
failing. The broad RunMenu run confirms only the switch-exit diagnostic remains.
No full-collection, function or Step 9 closure is claimed.

### Next Exit Proof

Reason: an obligation must survive changes between equivalent structured forms,
but simply ignoring `missing-case` would repeat the lost-ESC failure.

DoD: Structuring owns a typed proof joining the exact binary dispatch branch,
its empty exit connectors, the enclosing loop and shared function epilogue.
Tail Validation consumes that proof against the current guard, break scope and
epilogue/return path. Mutation controls must reject a changed key/polarity,
removed break, wrong loop, redirected exit, altered return and stale ownership.
RunMenu must then pass whole-tail validation, strict recompilation and its
source-independent ESC/call behavior regression before function closure.

Implementation constraint from the current validator: branch predicate matching
accepts both expected and inverted fingerprints. A green branch report alone
therefore cannot discharge this exit obligation. Bind the proven exit polarity
and immutable predicate identity, then verify that exact current arm still
breaks the owning loop and reaches the same epilogue. Existing condition
precision evidence can support identity-preserving projections; it must not
turn a stale or opposite-polarity exit binding into success.

Failure: accept any matching numeric constant, copied tag or syntactic break
without the binary ownership and current exit-path proof; disable switch-exit
checks, skip epilogue effects, or assume branch coverage alone proves the exit.

Logs: `/home/xor/.cache/step9-{unconditional-exit,binary-exits,arm-entry,goto-owner}-*.log`
and `/home/xor/.cache/step9-runmenu-owners-{focused,ruff,quality,pipeline}.log`.

## Empty Connector Ownership (2026-09-13)

The completed physical-target probe finds empty, binding-free SSA jump blocks
between JCC exits and emitted bodies. Exact multi-arm ownership previously
required body entries to equal physical JCC targets, rejecting these paths.
Structuring now consumes the existing `transparent_condition_exit_8616` proof
with all body entries and condition owners retained as boundaries. Original
ConditionIR facts and physical replay targets remain unchanged. No effects are
moved, no switch definitions are discarded, and no validation is relaxed.

The first regression run was 4 failed / 10 passed (new artifact contract absent).
The final focused surface is **33 passed in 5.96s**, including ten connector
controls for both polarities, missing SSA, refusal, conflicting edges and calls
that must not be bypassed. This existing test module is already enrolled in
Make and the routine pipeline. Scoped MyPy passes; the touched test is Ruff
clean. The two production files retain 13 existing complexity/style findings.
`quality-fast` still fails lint; the 39-module compiled-import smoke passes.

The live RunMenu regression remains red (**27 related passed / 1 failed in
36.21s**). Missing owners shrink from six to four: JCC/block `10443/10440`,
`1044b/10448`, `1045a/10457`, `10480/1047f`. Owners `10436/10433` and
`1043b/1043b` no longer fail. The ESC switch-exit obligation remains. The binary
branches and nested no-else regions require their own endpoint/effect evidence;
do not generalize this proof to arbitrary reachable blocks.

DoD for this prerequisite: exact empty paths are accepted in either polarity,
uncertain/effectful paths are refused, physical facts remain unchanged, and
the live missing-owner diagnostics improve without suppressed checks.
Failure: bypass effects, alter physical CFG evidence, or count partial branch
coverage as RunMenu/Step 9 completion.

Gate refresh completed at **13:35 +02:00**: routine collection **5,312 passed /
2 failed in 234.82s**, plus 268 preliminary passes in 9.98s. RunMenu and InitBars
remain red. QuickC stays **3/4** (36.87s); MS C tiny stays **5/7** (127.45s),
with `simple_control` and `loops_jumps` failing. This is not the complete pytest
collection, and no performance improvement is claimed from a single run.

Evidence logs: `/home/xor/.cache/step9-connectors-{before,after,focused,ruff,mypy,quality,pipeline}.log`.

## Direct Result JCC Prerequisite (2026-09-13 13:14 +02:00)

The frontend probe found that RunMenu's CMP/JCC already used direct operands,
but adjacent SUB/JCC and DEC/JCC returned no direct predicate and read packed
FLAGS instead. This obscures the result test before AIL structuring; it is
separate from the unsafe SeqNode replacement and its missing coverage proof.

New frontend helper `jcc_result_condition.py` expresses JE/JZ/JNE/JNZ as a zero
test of the just-written word register after adjacent ADD/SUB-immediate or
INC/DEC. Exact decoded adjacency, operation shape and word-register view are
required. Nonzero gaps, other predicates and unsupported producers retain the
existing flag path. No flags are deleted, no liveness is guessed, and the
segmented byte-access methods are untouched.

Before: **16 failed / 8 passed, 5.82s**. Final focused surface: **79 passed,
6.26s**, including 33 new tests. Four real-pyvex controls demonstrate that
the branch reads AX instead of FLAGS while flag writes remain; disabling the
new helper restores the FLAGS dependency. Tests also reject shift-by-zero,
wrong register widths, malformed producers, gaps and other JCC families.
The separate RunMenu acceptance test still fails after this change.

Scoped and promoted typing pass; the symbolic comparison boundary uses an
explicit object annotation without suppressing a type error. New code/tests
pass Ruff. The legacy lifter reports 68 lint findings; global `quality-fast`
remains red on lint debt, with the 39-module compiled-import smoke passing.
New source/tests are enrolled in typing, architecture, routine Make/pipeline
and ownership checks.

Fresh pipeline: **5,302 passed / 2 failed, 267.65s**, plus 268 preliminary
passes. RunMenu and InitBars remain red; QuickC stays **3/4**, MS C tiny
**5/7**, with unchanged failing cases. Lane wall times: 268.106s, 43.250s,
135.741s. This is not a full-suite refresh, a measured end-to-end speedup,
or a completed function fix.

Reason: expose an exact machine-result predicate at the frontend instead of
requiring later recovery through packed flag equations. Prerequisite DoD:
failing-before predicate tests, actual VEX dependency controls with flag
writes retained, refusal coverage, mandatory types/docs, routine enrollment
and broad failure-set comparison. Definition of failure: using a stale result,
changing non-ZF branches, deleting flag effects, discarding wrap semantics,
or treating this prerequisite as complete RunMenu equivalence.

Evidence under `/home/xor/.cache/`: `step9-runmenu-lift.log` and
`step9-jcc-result-{before,after,focused,ruff,mypy,quality,pipeline}.log`.
Observed work window: after 12:53 through 13:14, including tests and gates;
active implementation time was not separately measured.

## Definition Survival Guard (2026-09-13 12:53 +02:00)

**Correction to the earlier producer trace:** angr constructs the C node, but
Inertia's `materialize_typed_switch_seqnode_8616` first replaces the original
decision ladder with a nine-case SeqNode switch. The optional C-AST switch
replacement remains uninvolved. The first trace stopped too late to identify
this upstream owner; the new pre-codegen probe establishes it directly.

The replacement is not merely missing provenance. It removes dispatcher SSA
assignments still read by retained cases and the surrounding function. The
live trace identifies IDs **20, 68, 71, 74, 78, 80, 81, 130, 134, 137**.
These are diagnostics for this run, never an allowlist or recovery rule.

New Structuring owner `switch_definition_coverage.py` compares removed
definitions with retained reads before replacement. It includes case/default
bodies, selector and the surrounding function, excluding the replaced subtree.
The materializer now refuses atomically with `LIVE_DEFINITION_LOSS` and the
exact missing IDs. It does not fabricate definitions, move effects, infer
values, or claim switch equivalence. Unknown external values remain unknown.

The focused regression proves the old materializer accepted deletion of a
definition used by a case. Seven new tests cover the producer refusal and
retained case, tail and condition reads, wholly discarded uses, external
definitions and retained definitions. Existing safe materializations remain
green. Focused result: **26 passed / RunMenu failed, 35.58s**. Scoped MyPy
passes; new code/tests pass Ruff. Two complexity findings remain in the legacy
materializer. Test, typing, architecture and ownership enrollment is complete.

In the guarded live run, the previous uninitialized-register diagnostics are
absent. Condition coverage and the ESC-exit representation are still rejected.
This is an early refusal of a proven destructive transformation, not completed
RunMenu acceptance or a substitute for a correct switch transformation.

Fresh pipeline: **5,269 passed / 2 failed, 237.67s**, plus 268 preliminary
passes. Remaining curated failures: InitBars, RunMenu. QuickC **3/4**, MS C
tiny **5/7**, with the same failing cases as before. Lane wall times:
238.133s, 36.383s, 136.861s. Global `quality-fast` remains red on lint debt;
promoted typing and the 39-module compiled-import smoke pass. Step 9 is open.

Reason: fail before a structural rewrite deletes definitions of surviving SSA
reads, instead of discovering the damage after code generation. Guard DoD:
reproduced failing-before mutation, atomic refusal with exact IDs, safe and
negative controls, live trigger confirmation, routine enrollment, and broad
failure-set comparison. Definition of failure: tag-only acceptance, silently
dropping retained uses, inventing initializers, or calling the function fixed.

Next: preserve or prove unnecessary the live dispatcher definitions at their
owning layers, then establish complete selector/case/default predicate proof.
The diagnostic readiness dictionaries alone must not authorize shared
condition coverage. Preserve the original ladder while proof is insufficient.

Logs under `/home/xor/.cache/`: `step9-runmenu-switch-seqnode.log`,
`step9-runmenu-switch-tree.log`, `step9-runmenu-switch-definition-guard.log`,
and `step9-switch-definition-{before,after,ruff,mypy,quality,pipeline}.log`.
Observed work window: after the 12:33 checkpoint through 12:53; active coding
time was not separately measured. No full-suite refresh is claimed.

## IR Prerequisite Fixed (2026-09-13 12:33 +02:00)

The next SSA probe found bare VEX exit destinations represented as
`UNKNOWN("Ico_U16")`. CFG successor discovery already retained the edge, but
the CJMP instruction lost its target value. This was an IR projection defect,
not evidence that the switch case was absent from the original binary.

`ir/vex_import.py` now recognizes bare unsigned integer constants in addition
to wrapped `Iex_Const` expressions. `ir/vex_types.py` preserves the bare
constant's advertised width. No address rebasing, segmented-memory behavior,
branch meaning or validation policy changed.

Seven regressions in `test_x86_16_vex_direct_constants.py` use real pyvex
objects: five integer widths, an actual Exit imported through the function
artifact builder, and refusal to classify a bare floating constant as an
integer. Before: **6 failed / 1 passed, 5.92s**. After, with existing importer
checks and RunMenu: **55 passed / 1 failed, 34.84s**. RunMenu remains the
failure. The new tests are in both routine Make lists, the pipeline and the
IR ownership manifest.

Fresh broad pipeline: **5,262 passed / 2 failed, 249.00s**, plus 268
preliminary passes. The two curated failures remain RunMenu and InitBars.
QuickC remains **3/4** (`args` fails); MS C tiny remains **5/7**
(`simple_control`, `loops_jumps` fail). Lane wall times: 249.472s, 41.075s,
133.685s. No newly failing curated or external case was observed.

`quality-fast` remains red on lint debt; promoted typing and the 39-module
mypyc smoke pass. Scoped Ruff `check --fix` leaves 15 existing findings in
the legacy importer; the new test, width helper and enrollment files are
clean. This is neither RunMenu nor Step 9 completion.

Reason: typed branch instructions must retain the same destination evidence
as CFG edges. DoD for this prerequisite: real-object failing-before tests,
exact value/width preservation, floating-value refusal, routine enrollment,
and no additional failures in the required pipeline. Definition of failure:
fabricating targets, changing segmented addresses, suppressing unknown values,
or counting this prerequisite as a completed switch proof.

Logs under `/home/xor/.cache/`: `step9-direct-constant-before.log`,
`step9-direct-constant-after.log`, `step9-direct-constant-ruff.log`,
`step9-direct-constant-quality.log`, `step9-direct-constant-pipeline.log`.
The work occurred between the 12:18 diagnosis checkpoint and the 12:33 gate
completion; active implementation time was not separately measured.

## Initial Diagnosis (Historical)

2026-09-13, diagnostic runs 12:14-12:15 +02:00; focused baseline completed
by 12:18 +02:00. These are observation times, not implementation estimates.
Unresolved. No production code or validation acceptance was changed.

The sidecar-free RunMenu regression still fails: **1 failed, 7 warnings in
30.67s**, using `PYTHON_JIT=1 PYTHONHASHSEED=0`, pytest `-n 7`, short
tracebacks and duration reporting.

## Verified Evidence

- In-process constructor tracing identifies angr's `_handle_SwitchCase` as
  the actual C switch producer. It constructs nine cases (69, 60, 62, 66, 72,
  73, 81, 83, 84), carrying only an `ins_addr` tag on the switch.
- The later observed switch also contains case 27. The owned Structuring
  path `_repair_one_switch_loop_exit_return_8616` appends a return case from
  its CFG evidence; its case body carries the case-target instruction address.
- The final selector is a call result, with an SS:BP-2 byte argument.
  The remaining typed dispatch conditions refer to AX and include compare,
  subtract and decrement producers. Their constants cannot all be interpreted
  as selector values without accounting for intermediate register updates.
- Eleven condition identities lack shared materialized ownership:
  `10436/10433`, `1043b/1043b`, `10443/10440`, `1044b/10448`,
  `10452/10450`, `1045a/10457`, `10465/10462`, `1046b/1046a`,
  `10473/10470`, `1047a/10478`, `10480/1047f` (JCC/block, hex).
- Postprocess also reports two uninitialized reads of the same register
  carrier. Do not assume dispatch ownership alone resolves these reads.

The optional `materialize_typed_edge_switch_ast_8616` constructor is not the
observed producer. Its replacement path is disabled by default. Adding tags
there would not repair this observed execution path.

Graph evidence was Tier 2 with generation 2026-08-27T11:51:06Z. Relevant
tracked files reported changed metadata; new coverage modules were untracked.
Current source and live traces, not the stale graph, establish these findings.

## Next Repair Obligations

Reason: a structured switch consumes several binary predicates; validation
must distinguish a proven dispatch projection from missing control flow.

1. Establish an authoritative typed dispatch proof from IR/CFG and register
   value flow. Reuse existing evidence where sufficient. Cover selector
   identity, cumulative arithmetic, each case destination and the default.
2. At Structuring, match that proof to the actual switch and its case bodies,
   including the separately recovered return case. Publish shared provenance
   only for predicates whose complete mapping is established.
3. Diagnose the register-carrier reads independently if they remain. Do not
   manufacture an initializer or bypass storage validation.

DoD: before/after focused regression; positive and refusal controls for
dispatch proof; wrong selector, case value, target, missing default and
effectful connector mutations rejected; ESC exit preserved; live tail
validation passed; strict generated-C compilation and behavioral acceptance;
then routine quality and pipeline gates. No full Step 9 completion claim from
this single function.

Definition of failure: attaching all missing identities merely because a
switch exists, trusting source presence of `case 27`, accepting stale tags,
discarding register/memory effects, weakening validation, or adding semantic
recovery to CLI/postprocess.

## Local Diagnostic Artifacts

Artifacts are outside the repository under `/home/xor/.cache/`:

- `step9-probe-runmenu-switch.py`: isolated-cache observation probe.
- `step9-runmenu-switch-origin.log`: constructor stack and current facts.
- `step9-runmenu-switch-origin.c`: partial output, not accepted generated C.
- `step9-runmenu-switch-baseline.log`: focused failing pytest result.

These artifacts are diagnostic aids, not durable regression coverage.
