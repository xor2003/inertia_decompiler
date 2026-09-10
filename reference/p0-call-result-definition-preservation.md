# Stored Call-Result Definition Preservation (2026-09-10)

## Root Cause

Native C initially assigns the DOS wrapper's call result to AX SSA identity
`ir_2`. `materialize_stored_call_result_assignments_8616` in Structuring then
changes that assignment destination to the proven stack local `err`. A
flags-derived assignment still reads the old AX definition. C live-in
collection sees an undefined value and promotes the entire AX parent to
runtime state, making subsequent direct segment stores use runtime carriers.

The exact mutation was observed at the old `occurrence.statement.lhs = lhs`
line, through `finalize_shared_call_occurrences_8616` during Structuring
priming. This is not an error in GP live-in detection. The definition was
actually removed while its reads survived.

## Repair

When rebinding a same-width register definition to a proven stack destination,
the existing Structuring owner immediately captures that stored value back
into the original scalar definition. The original call executes once. Later
reads keep their original value identity even if the stack destination is
overwritten. Existing later elimination can discard the scalar copy when its
reads disappear; no new DCE rule was introduced.

Store-artifact collection now excludes register definitions. A matching
instruction tag alone does not prove that such a definition is a consumed
memory-store artifact. This also protects captures on replay when native C
tags the call assignment with the store instruction rather than the call.

This preserves an existing definition at the owner that moves it. It does not
recover alias identity, call arguments, types, or storage from rendered text.
The existing callsite/store proof remains the prerequisite. The new capture
is limited to equal-width SimRegisterVariable destinations; mixed-width lane
merges and other existing retargeting cases are not claimed fixed by it.

- Reason: changing a definition's destination must not orphan its remaining
  uses or accidentally make a local SSA value architectural live-in state.
- DoD: retain the captured value before a later stack overwrite, execute one
  call, make replay idempotent, restore the unchanged DOS wrapper regression,
  and pass scoped typing/lint plus routine and DOS roundtrip gates.
- Definition of failure: redirect old SSA reads to a mutable stack slot,
  duplicate the call, guess cross-width equivalence, suppress live flags,
  weaken the wrapper assertion, or claim full InitMenu acceptance.

## Evidence

The new preservation regression failed before the fix: three statements instead
of the required call assignment, scalar capture, stack overwrite and old-value
return. The corrected architecture fixture and final implementation pass all
14 focused stored-result and DOS wrapper tests (19.97 seconds, seven dependency
warnings). The slowest is the wrapper at 9.73 seconds. Ruff `check --fix`, scoped
MyPy and Pyright pass, without ignores or missing-doc/type suppression.

The wrapper validates and again emits the existing required shapes:

```c
err = loadprog(...);
if (err)
    return err;
cs[0] = exeLoadParams[10];
ss[0] = exeLoadParams[8];
return 0;
```

A rejected process-local experiment simply refused rebinding; it failed with
an unassigned stack local. Do not repeat that as a standalone fix. The accepted
direction came from a separate immediate-capture experiment, which validated
and restored direct stores. No diagnostic monkeypatch is installed in production.

The initial fast gate passes 3,171 tests and all executable quality guards.
The added store-tag case then failed before the artifact-classification guard
and passes afterward. Final focused stored-result checks pass 14 tests in 8.58
seconds; scoped Ruff, MyPy and Pyright pass again. The final new test has two
parameter cases. The owner remains 331 lines and the new test module 70 lines.

The new tests and seven existing assignment tests now have routine Make/pipeline
admission and explicit ownership. Final `quality-fast test-pipeline` exits 0.
The fast lane passes 3,172 tests in 136.46 seconds, and all executable quality
guards pass. The default lane passes 3,172 tests in 123.35 seconds (123.780
seconds lane), QuickC in 40.709 seconds, and all seven MS C tiny roundtrips in
60.527 seconds. The unit lane remains over budget; warnings remain visible.
Scoped Ruff, MyPy and Pyright are clean. This closes the introduced wrapper
blocker in the [zeroing report](p0-initmenu-gp-zeroing.md), not the broader
InitMenu or full-suite goal.

The final InitMenu acceptance rerun remains red at the unchanged final
pause-zero shape assertion (40.07 seconds call / 48.02 seconds pytest). It
passes validation and all preceding call/pointer assertions. SP bookkeeping
still separates the final calls; the behavioral oracle after the shape
assertion is not reached. Log: `/tmp/inertia-return-definition-initmenu.log`.

Observed verification window: the first failing regression finished at
00:50:30 local and final broad gates at 01:08:22 on 2026-09-10 (17m52s), including
the additional store-tag failure, fixture typing corrections and repeated
gates. Earlier root-cause investigation and later InitMenu rechecking are
outside that interval. It is not an estimate for the remaining plan.

Logs: `/tmp/inertia-gp-wrapper-{lifetime,rebind,keep,copy}.log`,
`/tmp/inertia-return-definition-{before,after,mypy,pyright}.log`,
`/tmp/inertia-return-definition-store-tag-before.log`, and
`/tmp/inertia-return-definition-final-{focused,mypy,pyright,gates}.log`.
