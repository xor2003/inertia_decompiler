# Selector Return Storage Effects

## Ownership And Reason

Layer: Structuring. Return-value reconstruction does not authorize deletion of
already-materialized stack, runtime-register or indirect-memory writes. The
instruction inventory's historical PUSH/POP exemption was insufficient proof.
Lowering replay correctly detected lost restore obligations, but only after
Structuring had replaced the body.

The shared projection owner now collects these C-AST write obligations using the
central traversal. The selector materializer refuses before its decrement-switch
or CFG-pair replacement, and the shared unsafe-effects predicate applies the same
check to other return-chain consumers. Native register computations remain under
the existing return-value proof; this is not a complete instruction-effect audit.

No code is deleted, no replacement effect is guessed, and no stale materialized
count is carried forward. A future optimization may discharge a write only with
explicit evidence from its owning analysis, or preserve it in the replacement.
The guard does not infer dead storage from balanced stack syntax or names.

## Definition Of Done

- Regressions reject loss of runtime-register, stack and indirect-memory writes
  at both the selector materializer and its shared unsafe-effects predicate.
- Refusal occurs before root mutation; clean return-only controls still work.
- Actual compiler examples decompile, recompile and preserve execution results.
- Focused checks, routine pipeline and quality gates are run and failures are
  reported without narrowing Step 9's acceptance criteria.

Definition of failure: lost writes, stale completion evidence, skipped mandatory
validation, a passing return value used as proof of all effects, or a compiler
round-trip regression. This guard alone does not establish Step 9 completion.

## Evidence

Work began approximately 05:54 +02:00 on 2026-09-12.

1. Worker traces showed the selector wrapper replacing a tree with 13
   assignments with a return-only tree. Three focused corruption controls failed
   before the initial preflight and passed afterward (159 related tests, 15.19s).
2. The MS C lane still failed. A fresh probe showed the subsequent return-chain
   wrapper also replacing 13 assignments with none after selector refusal. This
   disproved the initial single-entry-point fix as sufficient.
3. Three shared-predicate controls failed before extending the common check.
   Afterward, 162 focused tests passed in 15.76s, including the real __fimemset
   strict compile/behavior oracle.
4. cmp_i16 now completes with validation=passed and clean whole-tail validation,
   but via the sidecar-slice fallback. This is not direct-path or sidecar-free
   acceptance, nor yet a completed compiler round trip.
5. Scoped MyPy passes. Ruff check --fix was run; the existing return-chain and
   projection collector debt remains. quality-fast remains red on global lint
   debt; its 39-module mypyc import smoke passes.

Routine verification after the shared guard: 268 early contracts pass, followed
by 4,469 pytest passes and the same three SORTD failures in 197.29s. MS C tiny
improves to six of seven successful round trips: compare16 and scalar_types_io
are restored. simple_control still fails, although recompilation succeeds.
QuickC has three passing fixtures and one failure (args). Full architecture
passes. The broad stack-restore work and Step 9 remain unaccepted.

The final enrollment check found this module in Make's inventories but absent
from the Python pipeline list. It is now added there, with a regression against
future omission. The selector/enrollment/tooling set passes 59 tests in 5.82s;
tooling Ruff and scoped MyPy pass. The 4,469-test broad result precedes this
test-list-only addition, so it does not claim execution of the newly enrolled
module in that broad run. Rerun the routine pipeline at the next checkpoint.

This checkpoint ended approximately 06:18 +02:00, about 24 minutes including
two external runs, the routine gate and diagnostic work. It is not a remaining
Step 9 estimate.

## Failure Found Here (Resolved)

The simple_control executable exits 5 instead of the original's 255. Its source
asserts that switch_fold(2) returns 22. The generated function routes x=2 to
the x-5 default instead of the shared case-1/case-2 x+20 branch. Register saves
and restores are retained. Investigate the condition/value version at the
earliest responsible semantic layer, not a rendered-C repair or disabling the
storage guard. Preserve the existing whole-program execution oracle and add
focused coverage of all neighboring switch inputs.

Resolved at Alias by allowing a unique taken-edge root into a DEC dispatch
chain. See [root-edge proof and acceptance](p0-decrement-root-edges.md): all
65,536 generated-C input cases pass and all seven MS C round trips are restored.

Logs: `/home/xor/.cache/selector-effects-{before,after,msc6}.log`,
`/home/xor/.cache/selector-shared-{before,after,cmp,mypy,quality,pipeline}.log`.
Transition probes: `/home/xor/.cache/gp-cmp-return-chains.jsonl` and
`/home/xor/.cache/selector-guard-boundary.jsonl`.

The regression module is now enrolled in both Make and Python test inventories.
No separate slow gate was added for this check.
