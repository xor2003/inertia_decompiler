# SetGear Condition Ownership

Checkpoint: 2026-09-13 11:52 +02:00. Step 9 remains open.

## Repairs And Acceptance

1. **Normalized condition ownership, at the Lowering boundary.** Alias correctly
   changed a JCC-bound `DEC AX` zero test into a comparison of the original
   argument with one. The transfer filter then dropped that condition because
   it interpreted historical `source=("test", "je")` provenance as the current
   operator. It now checks the normalized typed operator while preserving the
   original provenance. Reason: diagnostic history must not override a proven
   semantic representation. DoD: normalized JE/JNE comparisons and original
   zero tests retain exact decoded ownership; wrong polarity and wrong targets
   remain rejected. Failure: changing producer history to conceal the mismatch,
   accepting a mismatched branch, or losing a normalized condition. The live
   SetGear trace now retains all eight conditions with zero ownership failures.

2. **Executed arm entry, at Structuring.** The previous helper used the lowest
   block address anywhere in an AST subtree as its entry. In SetGear's backward
   dispatch this selected a later statement. Entry now comes from an explicitly
   tagged arm container or the first executed statement; unknown entry remains
   unknown. Subtree address inventories remain unchanged for membership and
   change-detection queries. Reason: binary address order is not execution order.
   DoD: backward-order arms and explicit containers work; operand-only/later
   tags cannot supply a missing entry. Failure: restoring minimum-address
   inference or assigning an unproven entry.

3. **Cloned return-arm orientation, at Structuring.** Two sole-return arms can
   share one epilogue statement origin. Their orientation now has a separate
   proof using the existing binary return-expression recovery for both branch
   successors. Both distinct recovered values must match the AST returns in
   exactly one orientation. Reason: a return-value definition is not arm-entry
   evidence. DoD: direct/inverted returns work; missing, identical or incorrect
   recovered values and statement prefixes refuse. Failure: using operand tags
   as entry evidence, accepting ambiguous values, or dropping body effects.

No frontend, Rewrite or CLI semantic recovery was added. Existing helper
ownership and the current traversal/storage validation gates remain intact.

## Evidence And Timing

All pytest runs used `PYTHON_JIT=1 PYTHONHASHSEED=0`, `-n 7`, short tracebacks
and duration reporting. The logs below are in `/home/xor/.cache/`.

- `step9-condition-owner-before.log`: 2 failed / 16 passed, 14.23s. Both new
  normalized-ownership cases failed before the repair.
- `step9-condition-owner-live.log`: 57 passed / 2 failed, 45.50s. Ownership
  was repaired, but SetGear and RunMenu still failed; this was not closure.
- `step9-arm-entry-before.log`: 2 failed / 2 passed, 7.10s. Execution-order
  and operand-origin refusal controls failed before the entry repair.
- `step9-arm-entry-live.log`: 62 passed / 1 failed, 39.47s. SetGear passed
  validation and its compiled behavioral oracle; RunMenu remained red.
- The first broad refresh exposed four additional failures: tagged empty-arm
  fixtures and a genuine Boolean-return validation regression. These were
  repaired, not suppressed. `step9-arm-container-live.log`: 41 passed / 1
  failed, 20.65s. Explicit containers alone did not repair cloned returns.
- `step9-binary-return-live.log`: all 60 focused checks passed in 20.00s,
  including SetGear, the Boolean-return smoke test, arm fixtures and ten
  direct/inverted return-proof controls.
- `step9-setgear-final-quality.log`: global Ruff remains red; promoted MyPy
  and the 39-module mypyc import smoke pass. Focused Ruff `check --fix` was
  run periodically. Legacy lint findings remain in touched large modules/tests;
  no global or changed-surface lint closure is claimed.
- `step9-setgear-final-pipeline.log`: 268 preliminary passes; **5,251 curated
  passes / 3 failures in 235.33s**. SetGear, LoadProgram and all four
  intermediate regressions pass. Remaining curated failures: InitBars,
  RunMenu and InBoxLng. QuickC remains 3/4 (`args`); MS C tiny remains 5/7
  (`simple_control`, `loops_jumps`). Lane wall times: 235.803s / 39.532s /
  153.359s. These are routine lanes, not the complete pytest collection.

The first SetGear diagnostic log completed at 11:17:20 +02:00 and the final
pipeline at 11:51:16 +02:00: an observed window of approximately 34 minutes,
including investigation and gate waits. Investigation began before that first
completion; exact active-work/start time was not instrumented. Do not convert
this window or warm-cache test times into an unsupported whole-goal ETA or
performance-improvement claim.

The regressions are enrolled in the routine Make/pipeline and ownership lists.
Step 9 still requires the remaining semantic failures, external round trips,
quality closure and a refreshed complete-suite audit.
