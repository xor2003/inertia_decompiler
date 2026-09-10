# InitMenu GP Zeroing Dependency (2026-09-10)

## Frontend Correction

The optimized register-arithmetic lifter now writes a word constant zero for
exact same-register SUB and XOR. This is a decoded operand-identity proof
before native SSA, not a C-expression matching rule. Original operands still
feed the unchanged flag calculation and condition publication. Other registers,
memory operands, and the full instruction path are not reclassified.

The native C-assignment constructor trace confirmed the subtraction was already
present in native AIL, not synthesized by a later C cleanup. Correcting the
frontend is therefore earlier than changing C live-in collection or removing
runtime GP ownership. Neither of those owners was modified.

The first regression run failed all six constant-write checks; execution
checks passed. Three remaining XOR failures after the fix exposed a fixture
that selected the full instruction path: the optimized XOR path requires a
following branch. With that explicit fixture, 53 tests passed in 8.53 seconds.
Additional branch-consumption cases exposed a separate live-flags defect below.
Tests preserve upper EAX, defined flags, distinct-register arithmetic, and
existing INC/DEC value provenance. The existing module is already routine.

A fresh direct InitMenu command exits 0 with `validation=passed`. Its output
has no `inertia_eax` references; the division call and materialized pointer
arguments survive. The unchanged acceptance test still fails its final
pause-zero shape assertion because SP/BP execution carriers remain. Strict GCC
reports 22 parenthesization errors in those remaining expressions. This is a
bounded frontend correction, not InitMenu or whole-plan acceptance.

Evidence: `/tmp/inertia-self-zero-{before,after,initmenu}.log`,
`/tmp/inertia-self-zero-initmenu.c`, `/tmp/inertia-self-zero-initmenu-direct.log`,
`/tmp/inertia-self-zero-gcc.log`, and `/tmp/inertia-initmenu-gp-creator.log`.

## Executable Flag Publication

The first broad gate rejected the patch: 3 failed, 3,160 passed. All three
failures were new execution cases for XOR AX,AX followed by JNZ; the branch
read stale FLAGS and incorrectly jumped even though AX was zero.

The existing `_should_update_binop_flags_8616` returned false whenever logical
condition metadata was recorded. That metadata is not proof that an executable
JCC consumes it: the runtime branch can fall back to architectural FLAGS. The
gate now omits flag writes only when the existing decoded/CFG liveness proof
shows they are dead. No deadness proof or validation check is weakened.

All 115 focused arithmetic, condition-transfer and status-flag-liveness tests
pass (8.93 seconds, seven dependency warnings). They include new branch cases
with stale incoming ZF, upper-EAX preservation, and the existing overwrite/dead
flag checks. The second quality-fast run reports 3,162 passed and one failure
(142.83 seconds). The DOS load-program wrapper still validates and retains its
error guard, but direct segment stores become AX runtime-carrier stores instead
of `cs[0] = exeLoadParams[10]` / `ss[0] = exeLoadParams[8]`. Its assertion remains
unchanged. This newly exposed carrier dependency must be resolved before the
patch is accepted. The default pipeline reproduces the same single unit
failure: 3,162 passed, one failed (115.05 seconds pytest / 115.458 seconds lane).
QuickC passes in 46.419 seconds and all seven MS C tiny full roundtrips pass in
61.865 seconds. The pipeline exits 2, not success. The unit lane remains over
budget. Log: `/tmp/inertia-self-zero-test-pipeline.log`.

- Reason: a semantic metadata projection cannot replace an observable machine
  state update without an execution-consumer proof.
- DoD: preserve live flags across the logical operation/JCC boundary, retain
  proven dead-flag elimination, pass execution and broad DOS roundtrip gates.
- Definition of failure: wrong branch, stale architectural flags, suppressing
  the new test, or forcing every dead flag write back into the pipeline.

Next diagnostic: the runtime JCC adapter only accepts IRValue operands, while
logical-result condition publication uses IRBinaryValue. That explains the
architectural-FLAGS fallback; it does not authorize removing live flag writes.
Trace the newly exposed DOS wrapper carrier's SSA origin and preserve its
value/storage projection at its owner. Do not solve the output
regression by reinstating the unsound metadata-based flag-elision shortcut.
Logs: `/tmp/inertia-self-zero-flags.log` and
`/tmp/inertia-self-zero-quality-fast-final.log`. Scoped Ruff, MyPy and Pyright
pass on the current frontend and test surface.

The current wrapper probe finds undefined AX identity `(0, 2, ir_2, 4096)`
inside a flags-derived assignment at rebased instruction 0x101f, block 0x1019,
VEX statement index 55. Its root operation is Shl and destination is recovered
register identity `ir_3`, offset 4145, width 2; that offset has no direct
Arch86_16 register name. Trace its native definition rather than guessing a
specific flag or architectural register. The probe exits 0 with validation
passed. A proposed missing call-result destination was ruled out: this angr
version has expression-only CFunctionCall nodes, with results in enclosing
assignments already counted by the collector. No collector change was made.
Evidence: `/tmp/inertia-gp-wrapper-probe.{c,log}`.

Observed timing window: the first regression log completed at 00:22:02 local
and the final default pipeline at 00:39:40 on 2026-09-10 (17m38s). This includes
waiting and repeated verification, excludes earlier investigation and later
wrapper probes, and is not a remaining-work estimate. The patch is not ready
for an accepted commit while its wrapper regression remains.

## Observed Cause

An observation-only probe wrapped the GP Lowering owner and both imported
aliases in Structuring and segmented-memory Lowering. The earlier probe wrapped
only Structuring and missed the initial state projection. Always observe all
active aliases before inferring when an artifact was introduced.

The complete trace records these successive inputs:

1. IR live-in parents: EBP, EDI, ESI, ESP. No undefined C register carriers and
   no runtime GP state yet.
2. Existing runtime state: EBP and ESP; still no undefined C carriers.
3. One undefined C identity appears: AX, register offset 0, width 2,
   identifier `ir_5`, region 4096. IR still does not report EAX live-in.
4. EAX joins persistent runtime state; subsequent scans find no undefined C
   register identity because it has already been projected to a global.

The only observed use of that undefined identity is a subtraction assignment
tagged at instruction 0x1017 in the rebased analysis function:

```text
AX ir_6 = AX ir_5 - AX ir_5
```

Both operands have the same register identity. The corresponding instruction
is the self-subtraction used to produce zero before the background-color call.
This diagnostic address is not an implementation condition or an allowlist.

`gp_live_in_names_from_c_ast_8616` currently counts the two syntactic reads as
exposed input. `lower_architectural_gp_register_state_8616` then projects all
views of the selected parent, including other defined AX values. Later zero
simplification cannot undo that persistent ownership decision. This explains
the EAX promotion; it does not prove that SP/BP state is dead.

## Required Repair

- Reason: an algebraically cancelled value dependency must not turn unrelated
  local register definitions into persistent architectural state.
- Next: trace the zeroing value through its IR/native projection owner and
  normalize the exact integer self-subtraction before GP live-in publication.
  Preserve the instruction's flag effects separately. Do not add a rendered-C
  rewrite, remove the runtime-state fallback wholesale, or assume register
  spelling proves equal SSA values.
- DoD: a failing-before/passing-after focused regression for this dependency,
  distinct-SSA and effectful-operand refusal cases, preserved partial-register
  and numeric-frame behavior, and an InitMenu comparison with validation and
  strict recompilation. Admit new coverage to routine gates.
- Definition of failure: erase a genuine live-in, equate different versions or
  widths, discard operand side effects, lose flags, weaken the existing InitMenu
  assertion, or claim this one correction closes SP/BP liveness.

## Evidence And Scope

The full-alias and expression probes exited 0 with `validation=passed`.
Generated C was byte-identical to the unmodified direct-command baseline:
SHA-256 `e25db867d8ea3621c1b118c72a96947a129d246f1aa91686f72acdeac0b997d4`.
Both probes used isolated temporary decompilation caches, in-process threaded
analysis, `PYTHON_JIT=1`, and `PYTHONHASHSEED=0`. They changed no production
semantics. Logs: `/tmp/inertia-initmenu-gp-probe-all.log` and
`/tmp/inertia-initmenu-gp-expression.log`; baseline:
`/tmp/inertia-initmenu-carriers-before.c`.

The observation results above predate the frontend correction. They are not a
refreshed test-suite result. InitMenu acceptance and whole-plan gates remain open.
