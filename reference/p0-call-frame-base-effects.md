# CALL Frame Base Effects (2026-09-10)

## Safety Defect

The runtime CALL-frame classifier checked the ESP preservation mask, low-word
mask and frame-size subtraction, but did not inspect the subtracted base.
Consequently, a carrier containing a function call or memory read could be
classified as consumed and deleted, taking that evaluation with it. A matching
instruction tag is not proof that the entire expression is disposable.

The Types/Lowering classifier now accepts only an owned SP/ESP view or the
address of an existing stack variable as a passive base. Calls, dereferences,
division and unrelated register bases refuse normalization. The surrounding
consumer already publishes typed refusal status and closed evidence counters;
it retains the original statement on refusal.

- Reason: CALL materialization must not silently discard additional evaluation
  effects when removing synthetic execution bookkeeping.
- DoD: fail before and pass after on unsafe bases; retain passive SP and stack
  address cases; preserve external-observer refusals; admit regressions to
  routine gates; pass scoped lint/types and default DOS roundtrips.
- Definition of failure: lose a call or memory evaluation, accept an unproven
  arithmetic base, weaken external SP-use checks, or claim this closes InitMenu.

Six new cases initially produced four failures and two passes in 7.96 seconds.
After correction, all 21 focused frame-consumption tests pass in 8.22 seconds,
including the existing external-observer matrix. Seven dependency warnings
remain visible. Ruff `check --fix`, scoped MyPy and Pyright pass. The six new
cases are admitted to Make, the default pipeline and the ownership manifest.
Final `quality-fast test-pipeline` exits 0: 3,178 tests pass in the fast lane
(134.34 seconds), all executable quality guards pass, and the default lane
passes 3,178 tests (121.94 seconds pytest / 122.403 seconds lane). QuickC passes
in 40.726 seconds and all seven MS C tiny full roundtrips pass in 61.580 seconds.
The unit lane remains over budget. Scoped Ruff, MyPy and Pyright are clean.

Observed verification window: first failing regression completion 01:14:18 to
final gate completion 01:25:20 local on 2026-09-10 (11m02s), including the
initial InitMenu probe and verification waits. Earlier investigation and the
later SP assignment inventory are outside that interval. No remaining-plan
ETA is inferred from it. Gate log: `/tmp/inertia-call-frame-base-gates.log`.

## InitMenu Investigation

An isolated-cache, observation-only probe wrapped the frame-consumption owner
and both active imported aliases in condition materialization and frame replay.
It recorded 18 distinct active-project callsites. Every observed verdict was
NOT_APPLICABLE with zero raw, normalized, classified, materialized and failure
counts. Thus this consumer is not refusing identified InitMenu frame carriers:
no assignment at the expected callsite tag is reaching its candidate set.

The subsequent inventory observes ten distinct runtime-SP assignment tags,
all outside that callsite set: 0x1019, 0x1039, 0x1074, 0x108f, 0x10a0, 0x10cf,
0x10f2, 0x1111, 0x1146 and 0x116e. Their root operation is the runtime lane's
masked Or projection. This is an observed inventory at the consumer boundary,
not proof that every earlier SP definition or instruction effect is covered.
Do not equate these assignments to calls by address proximity. Trace the
native definitions feeding each expression and their retained provenance.

Next: inventory SP definitions and their tags before and after native SSA and
GP projection, then trace the definitions feeding the surviving combined SP
expressions. Do not relax the external-observer guard or infer effect ownership
from nearby instruction addresses. If multiple instruction effects are merged
into a value, preserve their typed provenance before attempting consumption.
Numeric SP/BP uses and upper-register preservation remain obligations.

The probe exits 0 with `validation=passed` and clean whole-tail validation.
Its C is byte-identical to the earlier zeroing-fix direct baseline, SHA-256
`08e8bc643d98e18c39a3f91da4e2c8e6569114e0e8d3ec44caf65664d155bea8`.
This establishes non-degradation for the bounded function, not complete
InitMenu acceptance or a refreshed whole-suite result.

Logs: `/tmp/inertia-call-frame-base-{before,after,mypy,pyright}.log`,
`/tmp/inertia-initmenu-call-frames.{c,log}`. Probe settings: `PYTHON_JIT=1`,
`PYTHONHASHSEED=0`, in-process threaded analysis and an isolated temporary
decompilation cache. No diagnostic hook is installed in production.
The final inventory also exits 0 with validation passed and byte-identical C;
its artifacts are `/tmp/inertia-initmenu-frame-inventory.{c,log}`.

## Pre-SSA Caller Evidence (2026-09-10)

The focused InitMenu test still fails its unchanged adjacency/bookkeeping
assertion: one failed, seven dependency warnings, 45.81 seconds total,
37.87 seconds call time. All preceding call, array and validation assertions
pass; the subsequent compiled behavior harness is not reached.

A read-only observer in the actual Clinic execution now verifies the early
CALL-frame consumer, rather than inferring its state from final C. It sees
19 calls, 19 normalized calls, 93 classified and materialized effects, and
zero failures. The selected SP/store/call inventory shrinks from 271 to 178
statements. CALL and proven PUSH-CS return-frame consumption is therefore
working for this run; do not repeat the earlier extra-return-pop experiment.

The final zero-pause output path retains individually tagged argument effects
after this consumer (addresses are active-slice addresses, not binary patches):

- 0x1158 and 0x115f: argument PUSH SP updates and byte stores before call 0x1162.
- 0x1165: caller SP cleanup by four bytes.
- 0x116b and 0x116c: argument PUSH SP updates and byte stores before call 0x116f.
- 0x1172: caller cleanup by four bytes, projected into two distinct graph blocks
  (0x1173 and 0x1174) with the same source instruction/VEX identity.

The installed angr Clinic orders constant propagation and callsite construction
before PRE_SSA_LEVEL0_FIXUPS. Nevertheless, the observed graph still retains
these individual source tags. Two earlier observer runs lacked hook records;
they are not negative evidence. Only the final run, with observed Decompiler,
Clinic, stage and consumer entry, supports the census above. Its generated C
is byte-identical to the strict-C baseline (SHA-256
`4a41e50d2e9dd5a85c438df8fee336b5c679ccfe28483c2677cacb87ca01ae3f`),
with `validation=passed` and clean whole-tail validation.

### Next Implementation Boundary

1. Resolve existing nested producer tags to exact SP writes and their argument
   owners. Reason: assignment-level tags omit contributing instructions, but
   the nested arithmetic retains them (verified below). DoD: join each producer
   to the exact VEX write through data dependencies, then match existing
   callsite PUSH/cleanup evidence with CFG occurrence identity; cover duplicated
   cleanup projections and ambiguous merges. Failure: invent a parallel
   provenance system without demonstrating missing evidence, assume a producer
   index is a Put index, identify ownership by nearby addresses or expression
   shape, or collapse distinct CFG occurrences sharing an instruction tag.
2. Consume those effects only after proven argument materialization, preserving
   numeric SP/BP observations and upper-register semantics. Reason: early CALL
   materialization owns the return frame, not argument storage. DoD: connect
   existing callsite push/cleanup facts to recovered argument values and storage,
   close all evidence counters, and retain unknown or externally used effects.
   Failure: remove a PUSH before its value/address is materialized, double-count
   cleanup, erase a live register/memory effect, or recover semantics in Rewrite.
3. Pass the unchanged InitMenu test through its compiled behavior harness, then
   run scoped types/Ruff and routine/default DOS roundtrip gates. Reason: a
   correct intermediate census is not function acceptance. DoD: validation,
   strict compilation and behavior pass with all required calls intact.
   Failure: weaken the test, claim byte-identical C as an improvement, or treat
   a partial test selection as a green full repository suite.

Artifacts: `/tmp/inertia-caller-frame-entry.{c,log}` and
`/tmp/inertia-initmenu-caller-before.log`. The temporary observer changes no
production methods permanently and restores every wrapper on exit. Final
observation and output-hash verification completed by 04:00:15 CEST; this is
not an active-work measurement or remaining-goal estimate. No production edit
or new broad-gate claim is part of this investigation checkpoint.

## Nested Arithmetic Provenance Follow-Up

A final contract-boundary observer traversed each retained SP/BP assignment's
native expression tree, not rendered C. Across ten assignments it found 60
Add/Sub nodes, 60 distinct producer keys and zero arithmetic nodes missing any
of `ins_addr`, `vex_block_addr`, or `vex_stmt_idx`. The generated register-mask
And/Or wrappers lack original tags, as expected; they are not instruction
producers and must not be mistaken for missing source instructions.

The last ESP assignment's nested producer sequence, outermost first, is:

| Operation | Instruction | VEX producer index |
| --- | --- | --- |
| Sub 2 | 0x116c | 38 |
| Sub 2 | 0x116b | 12 |
| Add 4 | 0x1165 | 2 |
| Sub 2 | 0x115f | 50 |
| Sub 2 | 0x1158 | 5 |

These match the independently observed argument/cleanup instruction origins,
but producer tags are not themselves consumption proof. For example, the
0x116c arithmetic producer is index 38, while its SP Put is index 39. The
implementation must resolve that relationship through actual VEX dependencies,
never an index increment heuristic. Reuse the existing callsite summary's
push instruction addresses, widths and cleanup instruction address; require
materialized argument/storage and live-use proof before removing effects.

This evidence reduces the next task: no general cross-SSA provenance transport
is currently justified for these carriers. Untagged or ambiguous cases must
still refuse; this bounded observation is not a completeness claim for other
binaries, other expression kinds, or every native transformation.

The observer exits zero, validation passes and whole-tail validation is clean.
C remains byte-identical to the hash above. Artifacts:
`/tmp/inertia-stack-expression-origins.{c,log}`. No semantic patch or new test
pass is claimed; the preceding 3,296-test routine gates remain the last broad
verification. The temporary observer restores its wrapper on exit.
