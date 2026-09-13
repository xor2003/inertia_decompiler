# Return Jump Proof

Checkpoint: 2026-09-12. Step 9 remains open.

## Defect And Ownership

The shared branch-return scanner previously accepted a computed AX/DX value at
a jump without inspecting the destination. It also accepted an unfinished block
as a return. Both the Structuring consumer and the legacy compatibility consumer
could therefore accept an incomplete proof.

The scanner now publishes the value together with its pending jump destination.
That value is explicitly provisional until the shared return-chain consumer
proves the destination reaches a return while preserving AX/DX. Unresolved
jumps, incomplete blocks, clobbers, missing destinations, cycles and exhausted
depth budgets refuse recovery.

The existing preservation algorithm was extracted into
`structuring/return_path_preservation.py`. Both consumers share it; Semantics
still owns instruction preservation. The previous public wrapper and branch
target helper remain compatible. The new module has typed third-party boundary
views, is in the typing/architecture inventories, and is automatically included
in the production cache source manifest. No Rewrite recovery was added.

Reason: computing a value before a jump does not prove that it reaches return.

DoD: reject clobbered, missing, cyclic, unresolved and unfinished paths; preserve
valid single/multiple-jump returns; retain bounded traversal; cover the shared
consumer; pass focused type/architecture checks and preserve corpus results.

Definition of Failure: a provisional value becomes an accepted return without
tail proof, a supported preserving path regresses, or a guard is bypassed to
obtain cleaner output.

## Verification

- Controlled baseline with destination proof disabled: 7 failed / 3 passed,
  5.75s. The earlier initial run had an incomplete test fixture and is not proof.
- Final focused surface: 177 passed in 6.53s, pytest `-n 7`.
- Real-Capstone cases cover AX/EAX/DX clobbers, overwritten values, missing and
  cyclic tails, valid chained jumps, unresolved jumps and unterminated blocks.
- Positive legacy return-expression fixtures now include an explicit RET;
  dedicated incomplete-block refusals remain. All eight tests in that module
  are now enrolled in the Python routine runner; existing Make entries retained.
- Final routine lane: 4,435 passed / the same 3 SORTD failures in 208.11s.
- MS C tiny: 6/7 passed; FPTR remains failing. Scalar round trips remain green.
  QuickC remains failing. This is not the complete repository test collection.
- Scoped MyPy and final full architecture check pass. New module/test Ruff
  checks use `--fix`; existing lint debt remains in older modules.
  `quality-fast` remains lint-red; its 39-module mypyc smoke check passes.
- Final Makefile cleanup only removed duplicate test entries after the live
  pipeline ended. No runtime code changed after that pipeline.

Observed verification window: baseline ended at 04:12:04; final pipeline ended
at 04:28:03 +02:00, 15m59s including gate waits. Final architecture verification
followed the inventory cleanup. This is not total active engineering time.

## Next Work

The identified instruction-consumption and jump-completion gaps are addressed.
Return to the outstanding failures: FPTR caller/callee prototype dependencies,
three SORTD initialization regressions, and QuickC args. Global lint debt and
fresh full-suite/expanded acceptance remain necessary for Step 9 closure.

Logs: `/home/xor/.cache/branch-return-jump-*`.
