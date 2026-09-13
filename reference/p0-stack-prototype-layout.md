# Stack Prototype Coordinate And Layout Preflight

## Reason And Ownership

Types/Lowering must consume the coordinate registry when reconciling prototypes.
Native `SimStackVariable.offset` can be an entry-SP coordinate, not a machine-BP
coordinate. A binary-only `__fimemset` trace showed entry-SP offset 2 registered
as BP+4, while reconciliation compared the raw 2 against BP-based evidence.

Width reconciliation, incoming-argument selection and generated argument names
now share the registry-resolved BP coordinate. Native variable offsets remain
unchanged. An accepted extent/name update refreshes its registry projection
while retaining entry-SP coordinates, producer and equivalent-variable metadata.
Storage may grow when the accepted owner grows; a narrower value type must not
shrink its physical ABI slot. A separate regression reproduced that distinction.

## Regression Found During Verification

The initial coordinate correction broke `_dos_loadProgram`. Its passing routine
regression caught failed validation and pointer/value parameter-class changes.
Disabling registry refresh did not fix it. A pointer-overwrite hypothesis was
also rejected: input tracing showed the argument types were already scalars.

The actual missing guard was layout preflight. Equal argument counts do not
prove matching offsets, and narrowing BP+4 can leave a BP+6 body read outside
every proposed parameter. Previously, reconciliation changed variable types
and sizes while still discovering the layout.

Reconciliation now computes proposed width facts first. Before mutation, it
checks exact offsets, non-overlap and coverage of decoded positive-BP accesses.
An available incoming layout is checked even when argument counts match.
Uncovered accesses refuse the transformation without changing argument storage
or prototypes. This is not guessed widening or recovery in Rewrite/CLI.

## Acceptance

- DoD: registry-backed offsets work for different entry-SP origins; width facts,
  names and registry extents agree; producer metadata survives; unmatched layouts
  and uncovered reads refuse before interface/storage mutation; value narrowing
  preserves the physical slot extent.
- Failure: raw entry-SP offsets are treated as BP offsets, equal counts conceal
  mismatched slots, narrowing leaves a decoded access unowned, or mutation occurs
  before a layout refusal.
- Regression suite: `test_x86_16_stack_prototype_wrapped_locals.py`, now included
  in the early Make contract gate, routine pipeline and test ownership mapping.

## Evidence

- Before: three registered-coordinate cases failed; separate tests reproduced
  equal-count layout acceptance and narrowing that orphaned a body read.
- Focused final semantic check: 95 passed, one failed in 26.35s. The remaining
  failure is full `__fimemset`; `_dos_loadProgram` again passed validation,
  generated-C compilation and its behavioral oracle.
- Final early gate: 254 passed. Routine pytest: 4,226 passed in 265.47s. All three
  pipeline lanes passed, including all seven MS C round trips.
- Scoped MyPy/Pyright and full architecture passed. Ruff ran with `--fix`;
  regression tests are clean, while 19 legacy findings remain in the two
  production modules. Global `quality-fast` remains red on lint debt; its
  39-module mypyc import smoke passed.

Correction: the 10.28s `__fimemset` run failed only its old helper-spelling
assertion. Its invalid byte arguments and uninitialized `local_5` incorrectly
received `validation=passed`. Entry-range collection had mistaken the physical
ABI slot width for the initialized C parameter value width.

Validation now uses the declared signature type, capped by the physical slot.
Missing or unknown value types provide no initialized range. Four padding cases
and the unknown-type case failed before repair; signature-type regressions also
failed before the collector was aligned with the renderer's authoritative type.
The final focused run passed 14 entry-range tests, including legitimate byte
reads from wider slots. The corpus recheck now exits nonzero at validation
(12 focused passes, one corpus failure in 24.71s), rather than falsely accepting
the generated function. Neither that function nor Step 9 is complete, and no
fresh full-suite total is claimed.
Next: trace its byte/word/far-pointer evidence through argument materialization;
do not repeat the rejected coordinate-only or pointer-overwrite hypotheses.

Logs: `/home/xor/.cache/prototype-{coordinates,registry,layout,orphan,preflight,pointer,loadprogram}*.log`.
Final slot checks: `prototype-slot-*.log`; corpus recheck:
`fimemset-after-prototype-preflight.log` in the same cache directory.

After the entry-value validation repair: 268 early contract checks passed,
4,226 routine tests passed in 246.26s, and all three pipeline lanes passed with
seven successful MS C compile/decompile/recompile/execute round trips.
The entry-range module and regressions are Ruff-clean; scoped MyPy/Pyright
and full architecture pass. Global `quality-fast` still fails on lint debt;
its 39-module mypyc import smoke passes. Logs: `entry-range-*.log`.
