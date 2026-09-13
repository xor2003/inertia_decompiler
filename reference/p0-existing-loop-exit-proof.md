# Existing Loop Exit Proof

Checkpoint: 2026-09-13 11:15 +02:00. Step 9 remains open.

## Cause And Repair

Sidecar-free PercolateUp (`0x109e8`) retained its comparison and break, but
required condition `jcc=0x10a23`, block `0x10a02`, had no accepted CFG owner.
The original natural-loop classifier refused multiple exit targets. Those
targets were separate empty SSA jump connectors converging on one epilogue.
The older loop-break producer published no guard facts for this function.

Structuring now classifies a detached CFG view when physical-loop proof fails.
It uses the existing SSA transparency proof: only empty, refusal-free blocks
with agreeing SSA/CFG successors may be bypassed. Entry, headers and latches
retain their physical identities. Physical branch edges remain authoritative;
an explicit target projection connects them to logical loop exits. The strict
single-exit natural-loop contract is unchanged.

The focused existing-loop-exit owner binds an existing sole-break guard to one
typed condition, an already-proven enclosing loop header, and exact physical
successors. It orients the condition toward the proven exit and publishes the
shared condition-coverage ownership marker. It preserves the break body and
refuses composite/effectful predicates, ambiguous facts and mismatched edges.
Classified conditions that cannot be lowered fail early with the JCC address.
No semantic recovery was added to Rewrite or CLI.

The preceding negative-carrier repair preserves origin tags on a newly created
`Not` wrapper. Its regression passed, but that repair alone did not close the
live PercolateUp failure; do not count it as a separate function closure.

## Acceptance Evidence

- Before topology projection: 1 failed / 13 passed in 13.97s. The valid
  convergent-empty-exit case alone failed.
- After projection: 40 passed in 24.36s, including the isolated sidecar-free
  PercolateUp live regression. Missing SSA, effectful/refused connectors and
  disagreeing edges remain rejected; body and latch preservation are checked.
- PercolateUp reports `validation=passed` and clean whole-tail validation.
  Both swap calls survive. The recovered parent division, comparison, guarded
  pointer/value calls, update and break agree with `SORTDEMO.C`'s algorithm.
- The caller-cleanup regression now also compiles unchanged emitted C with
  `gcc -std=c11 -Wall -Wextra -Werror -fsyntax-only`. All 15 caller-cleanup
  tests passed in 8.75s afterward (warm live-function cache).
- New modules/tests are Ruff-clean. The module and regressions are enrolled in
  promoted typing, architecture/ownership inventories and routine test lists.
- `quality-fast` still fails on existing global Ruff debt. Promoted MyPy
  reports no errors; the 39-module mypyc smoke passes. No global quality
  closure is claimed.

All pytest runs used `PYTHON_JIT=1 PYTHONHASHSEED=0`, `-n 7` and duration
reporting. Logs are under `/home/xor/.cache/`: `step9-loop-projection-before`,
`step9-loop-projection-live`, `step9-loop-projection-quality`,
`step9-loop-projection-pipeline`, and `step9-percolateup-compile` (`.log`).
These measured gate times are not a measurement of total active development
time or an end-to-end performance improvement.

## Remaining Acceptance

The refreshed routine pipeline passed 268 preliminary tests, then **5,232
passed / 5 failed in 329.39s**. Remaining failures: InitBars, RunMenu, InBoxLng,
LoadProgram and SetGear. QuickC remains 3/4 (`args`); MS C tiny remains 5/7
(`simple_control`, `loops_jumps`). Lane wall times were 329.975s, 39.660s and
143.023s respectively. The final GCC assertion was added afterward and checked
with the 15-test focused run; the broad pipeline was not rerun for that
test-only strengthening.

DoD for this repair: exact exit ownership without discarded effects, focused
refusal controls, live validation and strict C compilation, plus routine
enrollment. Those focused obligations pass. Failure means relaxing physical
edge/SSA proof, losing calls or failing generated-C acceptance; none is an
acceptable shortcut to Step 9 closure.

Step 9 still requires the remaining semantic failures, external round trips,
quality debt and a refreshed complete-suite audit. The curated count is not
the complete pytest collection.
