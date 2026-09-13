# Return Address Classification Safety

## Scope And Root Cause

Step 9, Semantics. The branch-target and terminal-return decoders represented
`[BP+SI+disp]` and `[BP+DI+disp]` as fixed stack slots, discarding the index.
They also classified explicit non-SS BP accesses as stack storage and non-DS
direct accesses as ordinary globals. Their fixed-slot effect contracts cannot
represent those distinctions, so producing these effects was unsound.

## Correction

- Fixed BP slots require no index and default or explicit SS addressing.
- Direct globals require no base/index and default or explicit DS addressing.
- The same segment test applies to scalar memory operands in return arithmetic.
- Unsupported forms remain unclassified for these fixed-slot projections;
  their native instruction, IR memory effects and flags are not deleted.
- No source names, addresses, rendered C patterns or FPU recovery are involved.

## Verification

- Native indexed-load baseline: 2 failed, 1 passed in 8.34s.
- Native segment-override baseline: 4 failed, 6 passed in 8.31s.
- After correction: 65 native and return-decoder tests passed in 9.55s.
- Scoped Ruff, MyPy, Pyright and full architecture checks pass.
- Routine pipeline: 3,978 pytest tests passed in 202.08s; all seven MS C
  compile/decompile/recompile/run cases passed. No lane failed or timed out.
- Global quality still fails Ruff. The full repository suite was not rerun.

Logs use `/tmp/inertia-return-address-*`; fail-first logs use
`/tmp/inertia-return-index-before.log` and
`/tmp/inertia-return-segment-before.log`.

DoD for this correction: preserve native index/segment distinctions in both
return projections, retain supported default and explicit-default cases,
pass focused and routine regression gates, and keep unknown cases explicit.
Failure: substitute a guessed BP displacement/DS object, delete live effects,
or treat this focused repair as LIFE or whole-suite completion.
