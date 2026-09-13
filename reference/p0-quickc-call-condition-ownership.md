# QuickC Call-Result Condition Ownership

## Cause And Correct Layers

The QuickC `args` fixture's original execution and generated-C contract pass,
but its decompilation failed branch coverage at `0x100ac` and `0x100df`.
Call predicates survived as `!(call(...) ? 0 : 1)`. Structuring preserved the
calls, but did not publish these predicates as materialized branch owners.

`structuring/bound_call_condition.py` now canonicalizes exact Boolean wrappers
only after `call_return_conditions.py` proves the callsite, target and return
register relationship. It preserves the existing call object and arguments.
Unknown wrappers and non-Boolean outcomes remain unchanged. This is not
name-based call recovery or a rendered-C rewrite.

Publishing the guards exposed a second ordering defect: branch validation
required a generic rendered IR fingerprint before trying its existing exact
typed call-return proof. That proof can establish the comparison without the
old register carrier being representable in final C. Validation now checks
that specific proof first; missing fingerprints still fail without it.

## Acceptance

Reason: semantic call preservation is necessary but does not itself establish
branch coverage; the exact bound predicate must survive every representation.

DoD:
- both Boolean polarities preserve the original call and arguments;
- normalization is idempotent and refuses non-Boolean outcomes;
- an exact typed call-return proof works without generic IR rendering;
- a wrong return-block binding remains rejected;
- live `args` reports passed semantic and whole-tail validation;
- fixture contract and routine gates are refreshed without suppressions.

Failure: duplicate/remove a call, invent arguments, infer a callsite from its
name, accept arbitrary unavailable fingerprints, or mark a merely preserved
but unproven guard as successfully materialized.

## Evidence

At 15:15 +02:00 the live trace showed preserved call conditions with missing
branch surfaces. Fail-first wrapper tests: 2 failed. The separate proof-order
regression: 1 failed / 1 passed in 5.79s. Final focused coverage: 50 passed in
6.63s. The live command now exits successfully with `validation=passed` and
clean whole-tail validation. Scoped MyPy passes; the new helper is Ruff-clean.
Quality-fast remains lint-blocked; the 39-module mypyc import smoke passes.
The broad pipeline started at 15:28:53 +02:00 and completed by 15:36:29:
5,385 routine tests pass in 259.13s, plus 268 preliminary checks in 9.66s.
QuickC's four required fixtures pass in 35.88s, including `args` and its
generated-C contract. MS C tiny remains 5/7 in 136.94s; `simple_control` and
`loops_jumps` remain failing. The complete pytest collection is unrefreshed.

Logs: `/home/xor/.cache/step9-{bound-call,call-proof-order,quickc-args-fixed}*`.
The observed 15:15-15:28 interval includes fixture correction, verification and
waiting, not exclusively implementation time. Step 9 remains open.

The other fixture failures are separate: MS C `switch_fold` reports a return
delta `Or(stack_slot:SS:BP+0x4:size2)` versus the slot itself; `nested_loops`
reports missing condition owners at `0x10053` and `0x1006d`. Reproduce each at
current HEAD before selecting its repair; do not normalize away a mismatch
without proving the underlying expression or CFG equivalence.
