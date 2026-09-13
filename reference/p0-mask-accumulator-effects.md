# Mask Accumulator Storage Effects

## Reason And Root Cause

Step 9 checkpoint, 2026-09-12, following the 08:45 native-tracker checkpoint;
recorded at 09:03. About 18 minutes elapsed including investigation, implementation,
behavior verification and gates; active and waiting time were not separated.

Correct native coordinates were necessary but insufficient for rel_i16.
`materialize_cfg_mask_accumulator_8616` replaced its entire structured body with
new accumulator statements, discarding unrelated SI/DI saves and restores.
The replacement had no storage-effect guard. The later GP materialization gate
correctly rejected classified facts whose save/restore projections disappeared.

This was not merely a lost instruction tag or a non-terminal AX spill.
The observed replacement tree contained only mask initialization, conditionals
and a return. The repair belongs at the Structuring replacement boundary,
not in GP Lowering or in a rule accepting absent register effects.

## Repair And Contract

The shared selector-projection owner now supplies
`mask_accumulator_has_unconsumed_effects_8616`. The mask reconstruction consumes
that guard before assigning a new body. Every storage-write obligation must
refer to the exact recovered mask variable object; equal names or offsets do
not suffice. Calls are not covered by this reconstruction and force refusal.
Other stack writes, runtime registers, globals and unknown lvalues retain the
original body. No existing GP materialization or Tail Validation gate is relaxed.

DoD: corruption controls fail before the guard and pass afterward, mask-only
reconstruction remains usable, rel_i16 retains SI/DI and all comparisons,
whole-tail validation passes, strict generated-C behavior passes, and the MS C
comparison fixture completes its compile/decompile/recompile/execute round trip.

Definition of failure: erase other effects to obtain a simpler body, accept
storage from equal spelling/offset alone, bypass missing GP consumption, move
recovery into Rewrite, or claim that this guard proves every mask condition.
The existing condition reconstruction remains a separate proof obligation.

## Verification

- Three storage-corruption controls failed before the repair; the mask-only
  control passed. Extended controls also cover calls and distinct variables at
  the same offset. Tests are enrolled in Make, the routine Python lane and
  changed-file ownership selection.
- The 254-test focused/enrollment run passes. After a nearby typed branch-reader
  extraction, 144 structuring tests pass. The final third-party container typing
  adjustment has 15 focused passes and clean Ruff/MyPy/Pyright for the projection
  owner. Legacy Ruff debt remains in the large return-chain module.
- Direct rel_i16 returns validation=passed and clean whole-tail validation.
  Its generated C retains SI/DI snapshots and all six signed comparisons.
- `gcc -std=c11 -Wall -Wextra -Werror -O2` compilation passes. Execution checks
  all 65,536 signed values for a against b in {-32768,-1,0,1,32767}: 327,680
  cases with correct comparison masks and unchanged full 32-bit ESI/EDI values.
- Routine pytest: 4,556 passed, the same three SORTD failures, seven warnings,
  201.98s. MS C compare16 and simple_control pass (2/7); five fixtures still fail.
  QuickC remains 3/4. Full architecture passes. Global quality-fast remains red
  on lint debt; the 39-module compiled import smoke passes.
- The routine run preceded the final type-only container annotation adjustment.
  No complete-suite refresh or Step 9 completion is claimed.

Artifacts under `/home/xor/.cache/`: `mask-effects-before.log`,
`mask-effects-enrolled.log`, `mask-effects-test-pipeline.log`,
`mask-effects-{ruff,pyright,mypy}-verified.log`, `rel-i16-mask-guard.c`,
`rel-i16-mask-guard.log`, and `check-rel-i16-mask.c` with its executable.

## Next

Classify the five remaining MS C failures from fresh evidence. Do not assume
they share this replacement defect. Keep the three SORTD storage/initialization
failures, QuickC args, stable full-suite acceptance and global quality gates
open as required by Step 9.
