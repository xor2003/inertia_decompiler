# QuickSort Partition Comparison Investigation

## Sidecar-Free Acceptance Follow-Up (2026-09-10)

Current `f37229fa1` production output passes validation and portable-flat
compilation but the old test rejected its unbraced early return and following
plain `if`. The source's outer `iLow < iHigh` guard is equivalently represented
as `if (low >= high) return;`. An `else` after that return is unnecessary.

The test now matches the early-return guard and immediately following
one-element guard together, permitting braces and an optional `else` without
allowing intervening statements. Partition guards, pivot initialization/use,
pointer arguments, recursive-call order/bounds and call counts are unchanged.
No production semantics or validation checks changed.

- Before: one failure in 32.27 seconds, test call 24.21 seconds; failure was
  after the validation and compilation assertions.
- After: the complete regression passes in 9.30 seconds with accepted-result
  cache reuse. This is not a decompiler performance improvement measurement.
- An executable check of the actual matcher accepts three equivalent forms and
  rejects six mutations: missing return, inverted guard, reversed subtraction,
  wrong distance, intervening side effect and a valued return.
- Pyright reports zero errors/warnings. Ruff `check --fix` reports 34 existing
  findings in the large regression file; no suppression or threshold change.
- Logs: `/tmp/inertia-sortd-quicksort-current.log`,
  `/tmp/inertia-sortd-quicksort-guard.log`. The follow-up was observed complete
  at 10:52:15 CEST; exact active implementation effort was not measured.

This closes the recorded sidecar-free guard-shape failure, not the complete
repository audit or all output-quality debt. Broad gates on identical production
source passed immediately before this test-only correction; they were not
repeated afterward.

## Status: Open

### Root Cause Repaired; Quality Debt Remains

The first corrupting consumer is
`inertia_decompiler/cli_c_ast_rewrites.py::_simplify_structured_c_expressions`.
Structural snapshots on one codegen instance show correct partition operands
on entry and an array-address replacement on exit. This is not a JCC recovery
failure. The legacy simplifier memoized widening analyses using bare node IDs,
including temporary `resolved` expressions that it discarded between calls.
Python can reuse those IDs for unrelated expressions; the cache retained the
analysis result but not the input. Mutable operands/alias maps also make a
pass-wide result cache unsound without invalidation.

The unsafe widening-result cache is removed. No new semantic recovery was
added to CLI or Rewrite, and no address/name-specific recovery was introduced.
The simplifier still delegates analysis to its existing owner. Other legacy
cleanup and migration debt remains outside this repair.

- Deterministic regression: `test_structured_simplifier_identity.py` simulates
  colliding expression IDs and supplies a valid identity analysis to isolate
  memoization from matching. Before repair an unrelated `Add` replaces `Sub`;
  afterward the original operands survive. Four existing simplifier tests also
  pass: five total, 9.15 seconds, pytest `-n 7`.
- Uninstrumented QuickSort acceptance: failed before at strict GCC's
  self-comparison check (56.41-second call, 72.23 seconds total); passed after
  (35.56-second call, 43.58 seconds total). Required partition comparison,
  pivot, swaps, recursive call argument classes, compilation and validation
  assertions all pass. These timings are not a controlled performance claim.
- Scoped MyPy and Pyright pass. Ruff `--fix` reports 99 legacy findings;
  running the current configuration on the HEAD version of this file reports
  the same 99: 58 C901, 40 PLR2004, one PLR0916. Do not call this lint-clean.
- Regression admitted to routine Make/pipeline lists and its own ownership rule.
- Logs: `/tmp/inertia-simplifier-identity-before.log`,
  `/tmp/inertia-simplifier-identity-after.log`,
  `/tmp/inertia-quicksort-unhooked-check.log`,
  `/tmp/inertia-quicksort-cachefix.log`. Broader gate output:
  `/tmp/inertia-simplifier-cache-gates.log`.

Broader verification completed with
`PYTHON_JIT=1 PYTHONHASHSEED=0 make -k quality-fast test-pipeline PYTHON=./.venv/bin/python`:

- Fast and default suites each passed 3,463 tests, in 143.89 and 122.91 seconds.
- Three executable quality guards and the architecture/context/ownership checks
  passed. All seven MS C tiny build/run/decompile/recompile/run rows report OK.
- The combined command exited 2 because Ruff failed: 6,322 findings in the
  promoted scope (4,220 magic-value comparisons, 1,894 complexity findings,
  206 Boolean-condition complexity findings, two dictionary-iterator findings).
  These newly visible global-policy findings remain debt, not suppressed passes.
- Scoped MyPy/Pyright pass for the production owner and admission scripts;
  the new test passes Ruff/Pyright after declaring its fixture's `cfunc` field.
  The ownership manifest also has an existing complexity finding.
- The complete repository suite was not rerun. Earlier 40-failure audit counts
  remain historical evidence, not a current count after this repair.

Diagnostic caution: boundary rendering produced one correct result before the
repair, while an unhooked isolated run failed and structural-only hooks retained
the corruption. Diagnostic allocations/rendering can change manifestation of
identity-reuse bugs. Do not accept a hooked run as normal-path equivalence.
The structural consumer trace is `/tmp/inertia-quicksort-consumers.log`.

### Earlier Investigation

Clarity-gate follow-up: the naming helper now uses typed constants for the
16-bit signed-offset boundaries and a named range predicate. Its 11 focused
tests pass, including unsigned/signed boundary cases, in 8.29 seconds under
pytest `-n 7`; scoped Ruff `--fix`, MyPy and Pyright pass. This is behavior
preservation, not a repair of the remaining QuickSort comparison.

The late-activation Python profiler also timed out at the 180-second recovery
limit, without identifying the mutation owner. Its terminal log is
`/tmp/inertia-quicksort-late-mutation.log`. Neither broad profiling attempt
establishes an absent pass or a root cause. Do not repeat these profiling
approaches without first demonstrating bounded overhead and hook activation.
Use targeted pass-boundary observations within one identified recovery attempt
to isolate the earliest incorrect expression instead.

Latest checkpoint: the machine-coordinate naming defect is repaired in
`lowering/machine_stack_names.py`, consumed by the existing preferred-name
path. The old raw-offset helper is unchanged for its other callers. The new
regression first failed three of six cases; after repair, all 30 naming and
coordinate tests pass. Source owners retain types/docs and pass scoped Ruff,
MyPy and Pyright. Routine admission and ownership manifests include the helper.

QuickSort now exits successfully and strict C compilation passes, but the
saved comparison is still wrong:

```c
if ((iHigh << 1) + 2892 < iHigh - iUp)
```

Only the right operand is corrected. The accepted result has matching validated
and GCC payload hashes `eb8948ced579d533c4d81942c05ce15468a622e2445684673415682f5e106c05`.
This is direct evidence that compilation plus the current tail snapshot does
not establish binary equivalence. Do not close QuickSort from those statuses.

The existing QuickSort regression now explicitly requires the partition-size
comparison and rejects the current result. Recursive-call checks permit the
same unsigned-short view on both argument positions, including their negative
checks. No extra expensive decompilation test was introduced.

`make quality-fast test-pipeline PYTHON=./.venv/bin/python` passed before that
assertion-only update: fast 3457 passed in 162.60 seconds; default 3457 passed in
148.31 seconds; executable guards, QuickC and seven MS C round trips passed.
Full log: `/tmp/inertia-stack-names-gates.log`. The full suite was not rerun.
The strengthened focused QuickSort regression remains red, as intended until
its left operand is repaired. Logs: `/tmp/inertia-stack-names-before.log`,
`/tmp/inertia-stack-names-after.log`, `/tmp/inertia-quicksort-names-after.log`,
`/tmp/inertia-quicksort-partition-guard.log`.

The unchanged `test_sortdemo_quicksort_preserves_pivot_swaps_and_recursive_calls`
fails on the current checkout: one failed, seven warnings in 90.98 seconds;
test call 81.36 seconds. Invocation used `PYTHON_JIT=1 PYTHONHASHSEED=0`,
pytest `-n 7 -q --tb=short --no-header --durations=10`.
Log: `/tmp/inertia-quicksort-current.log`.

Strict portable-flat GCC rejects a self-comparison at generated C line 115.
Tail validation nevertheless reports clean. No warning suppression, branch
deletion, production patch or acceptance relaxation has been applied.

## Binary Evidence

Decoded original MZ image bytes, not source-name recovery:

```text
10e09: mov ax, word ptr [bp - 6]
10e0c: sub ax, word ptr [bp + 4]
10e0f: mov cx, word ptr [bp + 6]
10e12: sub cx, word ptr [bp - 6]
10e15: cmp ax, cx
10e17: jl 0x10e1c
10e19: jmp 0x10e3b
```

The source oracle identifies these as `(iUp - iLow) < (iHigh - iUp)`.
Both recursive paths and argument classes must survive; partition ordering
must not be deleted merely because both branches eventually sort the data.

## Observed Boundaries

Read-only in-process diagnostic hooks captured native pre-SSA, post-SSA and
selected C-AST boundaries, with a temporary final-output cache directory.
The CLI also uses recovery paths outside the hooked process: absent hook output
is not evidence that a pass did not execute, and observations across different
recovery attempts must not be treated as one uninterrupted pipeline.

1. Native pre-SSA computes distinct AX and CX subtraction expressions.
2. Post-SSA retains distinct register versions, including the expected stack
   load offsets: BP-6 minus BP+4, versus BP+6 minus BP-6.
3. An observed structuring pass-list entry contains the correct C comparison:
   `(short)local_6 - arg_4 < arg_6 - (short)local_6`.
4. Around `_apply_structuring_direct_stack_materialization_8616`, the rendered
   BP+6 reference changes from `arg_6` to `local_6`, affecting other comparisons
   too. `_prime_structuring_segment_global_semantics_8616` restores it in the
   observed replay. Whether this is variable-object mutation, binding metadata
   or another substitution remains to be established from exact object facts.
5. Final output contains `(iHigh << 1) + 2892` on both sides. The selected
   wrappers do not yet identify the exact operation introducing that final
   replacement. Do not equate the intermediate binding defect with a proven
   complete root cause of the final self-comparison.

Probe: `/tmp/inertia-quicksort-stage-probe.py`. Evidence logs:
`/tmp/inertia-quicksort-stage.log`, `/tmp/inertia-quicksort-passes.log`,
`/tmp/inertia-quicksort-owners.log`. Full JSON rows are large; parse only the
relevant owner, comparison and instruction fields instead of dumping logs.
The graph generation was 2026-08-27 with changed metadata for the inspected
paths; current source reads were used, not exhaustive graph claims.

## Next Bounded Repair

Follow-up trace identifies a concrete coordinate error in naming. At the
`_apply_preferred_stack_cvar_name_8616` call from direct MOV materialization,
requested and authoritative machine BP offsets are both +6, while the same
argument variable is stored at entry-SP +4. Its name changes from `arg_6` to
`local_6`, without changing that storage identity. `_stack_object_name` compares
the requested machine coordinate with raw argument offsets, missing the match.
This is a naming/coordinate contract defect, not evidence that Alias merged
BP+6 and BP-6. It is still not proven to explain the final arithmetic replacement.
Evidence: `/tmp/inertia-quicksort-names.log`, `QS_NAME` records.

- Reason: incorrect storage/value bindings can corrupt conditions while a
  later validation snapshot still reports stability.
- Investigation: instrument the individual Lowering consumers called by direct
  stack materialization, recording exact variable identity, signed BP offset,
  size and producer provenance before/after. Separately locate the final
  arithmetic-to-address substitution. Keep recovery attempts distinguishable.
- DoD: generic failing-before regression at the verified owning layer; preserve
  BP+6 versus BP-6 identity and distinct register versions; pass the unchanged
  QuickSort regression, strict C compilation, tail validation, required calls
  and partition-order behavior. Then run scoped Ruff/types and routine gates.
- Definition of Failure: sample/address/name-specific recovery, restoring the
  source expression in Rewrite, suppressing GCC diagnostics, accepting a
  misleading validation pass, or declaring closure from an intermediate AST.
