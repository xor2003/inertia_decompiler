# Callee Argument Cleanup At The Native Call Boundary

Subsequent closure: [direction-bit projection](p0-direction-bit-projection.md)
removes the remaining false SP/BP liveness and passes InitMenu acceptance in
both tested metadata modes. The observations below retain the earlier checkpoint.

## Verified Observation (2026-09-10)

InitMenu's surviving `SP - 8` is a candidate missing callee-effect projection,
not permission to delete a stack write. The direct-address slice call at
`0x10d3` targets `0x23da`; the original-project delta is `0xf060`, giving
original target `0x1143a`. Addresses here identify evidence only, not rules.

The existing Semantics collector resolves that out-of-slice target through
the exact original-project mapping. Its complete terminal census reports:

- cleanup amounts: `{8}`;
- return kind: near; operand width: 16 bits;
- raw/normalized/classified/materialized: 88 each; failures: zero.

These are collector counts, not a claim of 88 unique return instructions.
The callee's native convention is `SimCC8616MSCsmall`. That class defaults to
caller cleanup; do not change the class globally to accommodate this callee.

The previously captured pre-SSA block retains four two-byte argument PUSH
effects and ends with the native call. No scalar argument-cleanup assignment
follows it in that block. Native SSA's call-expression handler rewrites target
and arguments; native stack-pointer tracking separately handles callee cleanup
through convention/prototype information. Tracker state and scalar AIL effects
must not be assumed to be interchangeable.

The final observer run exits zero, reports `validation=passed` and clean
whole-tail validation. C remains byte-identical to the accepted normalization
checkpoint: SHA-256
`3ddd2bf375cc778c4a1cfa8798a367901545aed6548b81f9203575ccfada7b8d`.
This does not establish InitMenu acceptance or prove causality for the final
eight-byte expression. The unchanged bookkeeping regression remains open.

## Implementation Contract

Reason: explicitly represent binary-proven callee argument cleanup in the
native call effect model, so subsequent numeric SP values reflect execution.
The earliest consumer belongs at the source-call/IR boundary; Semantics owns
the return proof. Rewrite and CLI must not repair the resulting C.

DoD:

- Reproduce missing cleanup with a small native-IR caller/callee regression.
- Consume complete, agreed binary return evidence with exact source mapping.
- Model cleanup after argument evaluation on the returning call edge only.
- Preserve low-SP wrapping and high ESP, including explicit 32-bit consumers.
- Prove no double application by native tracking or preexisting scalar effects.
- Refuse unknown, conflicting, indirect or unsupported return evidence.
- Preserve calls, argument classes, memory effects, CFG and return values.
- Pass focused InitMenu acceptance, strict C compilation, validation, scoped
  linters/types, then routine quality and executable roundtrip gates.

Definition of failure: subtracting or deleting eight bytes by output shape,
using helper names as proof, treating a convention default as binary evidence,
confusing return-address width with argument cleanup, changing shared successor
state for unrelated predecessors, or calling unchanged validation alone a fix.

Three additional regression cases preserve rebased cleanup amounts independently
of 16/32-bit return width and refuse agreement for two different RET immediates.
They exercise the existing evidence owner, not a new cleanup materializer.
The focused file passes all 37 tests with seven dependency warnings in 8.25
seconds (`pytest -n 7`); the ten slowest durations are all below one second.
Scoped Ruff `check --fix` and `git diff --check` pass. Broad gates were not rerun
for this test/documentation-only checkpoint; their prior result is not a new
whole-repository pass.

## Native Projection Checkpoint

`call_cleanup_compat.py` now consumes the accepted machine-frame call census
from `call_frame_compat.py`. It adds a narrow scalar SP increment after a
terminal, uniquely projected, returning call only when the Semantics-owned
`callee_return_evidence_8616` proves an agreed nonzero 16-bit near-return cleanup.
The existing source-project resolver is now public, not duplicated. Far/wide,
unknown and conflicting returns remain unsupported by this consumer.

The inserted assignment has fresh native atom IDs, a callsite instruction
address and a typed cleanup fact. It does not fabricate VEX producer tags.
It writes 16-bit SP rather than ESP, leaves call arguments unchanged, and
does not modify shared successor blocks. An existing statement after the call
refuses insertion, including a previous materialization, avoiding duplicate
effects on repeated execution. The report counts newly inserted effects;
zero-cleanup and already-applied calls remain unselected in its failure count.

The first temporary insertion omitted the instruction address and failed native
analysis with a None/int ordering error. It was corrected before production.
The corrected experiment and production output are byte-identical. The only
C difference from the prior normalization checkpoint is that the residual
`SP - 8` becomes an identity update. All 18 call inventories are identical.
CLI exit is zero, strict portable-C compilation passes, and validation reports
passed with clean whole-tail evidence. Output SHA-256 is
`2023d77f1963fd34c668864ae30902185d67b61f25b3849481df3031121dab01`.

Twelve new routine tests cover narrow writes and fresh identities, unchanged
call arguments, refusal boundaries, repeated application and shared successors.
The first run exposed a fixture mistake: assigning a nested Rust-backed Call
target did not replace its enclosing expression. The corrected fixture replaces
the whole Call expression. The focused run passes 61 tests; InitMenu still fails
its unchanged final-call bookkeeping assertion (44.44 seconds overall, 34.81
seconds InitMenu). The remaining `SP - 4`, frame effects and identity cleanup
are not solved. The full function DoD above therefore remains open.

Scoped Ruff `check --fix`, MyPy and Pyright pass. The new module and tests are
included in Make's routine selections and the test ownership manifest; no test
assertion was weakened.

The first broad run passed 3,401 tests and failed one native-stage fixture
because its fake Clinic lacked the now-required AIL manager. Updating that
fixture passed 29 focused tests in 8.32 seconds. The final rerun of
`make quality-fast test-pipeline PYTHON=./.venv/bin/python` exited zero:

- fast: 3,402 passed, seven warnings, 119.10 seconds;
- all three executable quality guards passed;
- default: 3,402 passed, seven warnings, 129.60 seconds;
- QuickC: passed, 45.190 seconds;
- MS C tiny: all seven full roundtrips passed, each return code zero,
  60.225 seconds for the lane.

The default unit lane remains over budget at 130.033 seconds including
overhead. These are routine gates, not proof of a full-repository pytest pass.
Final `git diff --check` passed. No controlled performance improvement is
claimed. Verification ended at 06:27:22 CEST on 2026-09-10.

## Probe Limitations And Timing

Investigation resumed around 06:00 CEST; binary evidence was observed by 06:05.
Two pre-SSA-hook attempts produced no hook output and provide no new pre-SSA
evidence. The final-codegen observer did execute and supplies the terminal proof
above. The pre-SSA statement observation comes from the earlier retained census,
not those unsuccessful hooks. The subsequent native-stage insertion probe did
execute. Its corrected run finished at 06:10; production live verification was
available by 06:15. These timestamps are checkpoints, not an overall ETA.

Artifacts: `/tmp/inertia-callee-cleanup-observe.{c,log}` and
`/tmp/inertia-pre-ssa-argument-uses.log`. Temporary artifacts are diagnostics,
not repository deliverables or substitutes for permanent regressions.
