# Native Stack Anchor Provenance

## Reason And Ownership

Native SSA replaces a StackBaseOffset address with a reference to a stack
virtual variable. That reference alone does not prove whether its eventual
C variable uses entry-SP or machine-BP coordinates. Reinterpreting every
reference was rejected by four smoke regressions.

The frontend SSA adapter now publishes only an exact direct replacement:
StackBaseOffset -> Reference(stack VirtualVariable), with equal source and
replacement offsets. Adjusted replacements and other architectures are not
annotated. The IR contract carries the original offset in a primitive tag
that survives native codegen, plus a typed engine publication census.
Lowering consumes this explicit origin with complete, PROVEN frame evidence.
No variable name, source listing, rendered text or dummy register global is
used. Untagged references retain their existing coordinate rules.

## Evidence (2026-09-09)

- Before consumer integration: two new source-coordinate regressions fail;
  seven existing coordinate tests pass.
- After publication and consumption: 80 coordinate, publication/refusal and
  smoke tests pass in 18.57s under pytest -n 7, including the four cases that
  rejected blanket rebasing. Architecture scoping and idempotence are tested.
- Scoped Ruff --fix, MyPy and Pyright pass.
- Fresh byteops_unsigned with an isolated cache, using production publication
  and consumption, exits 0 and reports validation=passed. Its generated C has
  no EBP reference. GCC -O0 and -O2 compile and execute it to the expected
  0xC000 without any supplied runtime register globals. The observation script
  logs native AIL but does not inject the old diagnostic anchor hook.
- The fresh log records a later CLI AST mutation rollback after semantic drift;
  final whole-tail validation is clean across the one function. This is not
  evidence that every downstream CLI mutation is correct. Preserve the guard
  and investigate its offending mutation separately rather than suppressing it.
- The first quality-fast attempt stopped before pytest on two policy checks:
  the tag constant needed an annotation and the native method marker needed an
  explicit dynamic-boundary comment. Both were corrected.
- Quality-fast now exits 0: 3,116 tests pass (159.91s), configured checks and
  all three executable quality guards pass. Log:
  `/tmp/inertia-native-anchor-quality-fast.log`.
- Default pipeline exits 2: 3,116 unit tests pass (138.04s; lane 138.456s),
  QuickC passes (47.890s), MSC6 improves from 5/7 to 6/7 (64.175s).
  scalar_types_io now recompiles, links and executes with exit code 255.
  Its pick_ptr argument/assignment indirection warnings remain visible.
  function_pointers is the only failing example: unresolved `_inertia_esp`
  and `_inertia_ebp` at link time. Log:
  `/tmp/inertia-native-anchor-test-pipeline.log`; detailed mutable reports:
  `examples/build_msc6_tiny/report.json` and
  `angr_platforms/.cache/test_pipeline/summary.json`.
- This run also reports the existing multithreaded fork deprecation at
  `inertia_decompiler/fork_timeout.py:187`. SORTD InitBars and RunMenu tests
  took 61.97s and 60.67s. Keep these as follow-up measurements, not a controlled
  regression or speedup claim. No warning was suppressed or timeout reduced.
- Logs: `/tmp/inertia-native-anchor-{before,integrated,mypy,pyright}.log`;
  `/tmp/inertia-native-anchor-production-byteops.{c,log}`.

## Acceptance

Subsequent checkpoint: the [runtime PUSH carrier repair](p0-function-pointer-push-carrier.md)
resolves the remaining function_pointers linker failure. Its combined default
pipeline passes MSC6 7/7 and QuickC, plus 3,125 unit tests. The earlier 6/7
result above is retained as intermediate evidence, not current lane status.

DoD: provenance/refusal tests and existing coordinate/smoke tests pass; fresh
generated C retains behavior, calls and memory effects; validation and strict
recompilation pass; quality-fast and test-pipeline confirm the combined state.
Quality-fast and the subsequent combined default pipeline pass. Overall P0
and the plan are not complete; scalar pointer warnings and broader SORTD
acceptance remain open.

Definition of Failure: guess a coordinate from reference shape, reinterpret
untagged variables globally, translate incomplete frame evidence, suppress
validation failures, or supply fictitious runtime register state to compile.

Next: trace function_pointers' remaining register dependencies to their
earliest semantic owner; retain scalar_types_io pointer warnings as separate
typed-call debt. Do not call the 6/7 result a full-lane pass.
