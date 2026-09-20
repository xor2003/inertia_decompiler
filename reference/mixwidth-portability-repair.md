# Mixed-Width Portability Repair

This continues [the linked-fixture investigation](mixwidth-stability-probe.md).
It does not close the whole-corpus scan, Steps 10-12 or deferred parity features.

## Root Cause

The same generated program returned 255 under MS C and 3 under GCC/UBSan.
The failed check compares an equal negative 16-bit boundary against a signed
32-bit value. Its low-word comparison requires unsigned interpretation even
though the narrow argument also has signed uses.

Direct source and in-process evidence showed a temporal ownership error:

1. `condition_operand_views._operand_view` recognized the unsigned ConditionIR.
2. Both argument declarations were still unsigned at that moment. It removed
   the comparison's cast as an identity conversion.
3. Later argument refinement made `arg_8` signed. The bare comparison retained
   no record of its required unsigned view.
4. C integer promotions differed between the 16-bit MS C and 32-bit GCC int
   models, producing the wrong low-word comparison under GCC.

The first isolated probe used labels/types and produced a different, valid
signature. It was not representative of the failing worker. The second probe
used `--ignore-local-sidecar-hints --no-alternate-source-c`, an isolated cache
and verified in-process hooks. Its log records unsigned argument declarations
and uncast `ugt`/`ult` expressions before the final signed signature.
Artifacts: `.cache/mixwidth-operand-binary-probe.{c,log}`. The normal whole-file
debug run independently reproduced the uncast operands:
`.cache/mixwidth-batch-operands.{c,log}`. Graph tools were unavailable, so no
graph completeness is claimed.

## Repair And Evidence

Types/Lowering now retains the exact `CSemanticCast8616` comparison view even
when the current declaration happens to match. It does not modify the shared
declaration or recover semantics in Rewrite/export. Proven bounded masks and
constants retain their existing handling. Any future cosmetic cast elimination
must prove redundancy after all relevant declaration refinement has finished.

The compiled operand-ordering regression now includes later declaration
refinement. Four new cases failed before the patch; all 16 pass in 7.05 seconds.
The tests compile and execute 65,536 patterns per case across signed/unsigned
views, operand sides and 16/32-bit widths. The module was already in the routine
pipeline; explicit changed-file ownership was added. Ruff, mypy and types/docs
checks pass for the changed lowering module.

`.cache/mixwidth-msc6-view/report.json` reports validated two-function
decompilation, generated compilation/linking and MS C execution returning 255.
Decompilation took 16.63 seconds; no controlled performance claim is made.
The exact prepared C and runtime also compile under GCC C89 with UBSan and
return 255, without sanitizer diagnostics:

```sh
gcc -x c -std=c89 -O0 -fsanitize=undefined \
  .cache/mixwidth-msc6-view/DMIXW01.C \
  .cache/mixwidth-msc6-view/INERTIA.C -o .cache/mixwidth-host-view
.cache/mixwidth-host-view
```

DoD: both compiler executions retain all eight original checks and exit 255;
both generated functions validate; compiled regression rejects lost operand
views; focused checks and the routine pipeline pass, with lint limitations
explicit. Failure: changing the expected exit, dropping negative inputs,
globally retyping the signed argument, or relying on MS C alone.

The first broad audit found 6,112 passes and three failures, plus one failed
external construct (`loops_jumps`). Two unit assertions assumed bare operands;
they now retain their original branch/corruption obligations through the cast.
The real validation mismatch needed a comparison-only fix: typed condition
fingerprinting now uses the existing detached current-type identity projection.
It does not remove casts from the live AST or accept non-identity conversions.
All 95 focused smoke/storage/ordering tests pass in 14.31 seconds, and
`loops_jumps` recompiles and runs with exit 255 (17.00-second decompile attempt).

The final routine pipeline passed all three lanes:
6,115 main-lane tests (305.67 seconds), QuickC fixtures (33.809 seconds),
and all eight MS C tiny examples (107.540 seconds). Evidence:
`.cache/mixwidth-view-final-pipeline.log` and
`angr_platforms/.cache/test_pipeline/summary.json`. This is the routine selected
scope, not the whole repository test suite. `quality-fast` remains blocked by
global lint debt; changed lowering/validation types, docs and Ruff checks pass.

The final pipeline's `examples/build_msc6_tiny/mixwidth/DMIXW01.C` and
`INERTIA.C` also compile with GCC `-std=c89 -O2 -fsanitize=undefined` and
execute with exit 255, without compiler or sanitizer diagnostics.
The observed probe-to-final-gate interval on September 20 was
07:15:55 to 07:41:57 +0200 (26 minutes 2 seconds), including broad gate waits;
this is not a measurement of total active implementation time.
The linked GCC invocation is recorded but not yet a separate automatic lane;
the exhaustive compiled operand-refinement regression is automatic.
