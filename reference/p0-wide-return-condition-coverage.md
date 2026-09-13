# Wide Return Condition Coverage

Checkpoint: 2026-09-13 12:08 +02:00. Step 9 remains open.

## Reason And Correct Layer

InBoxLng's complete wide comparison/return graph was already recovered at
Structuring, with every input condition assigned to a proven wide pair and
every collapsed predicate visited. The replacement expression published a
private wide-predicate marker but omitted the shared condition-chain provenance
consumed by the traversal/condition coverage gate. Twelve required word-branch
identities consequently appeared missing after replacement.

The producer now calls the existing shared provenance binder after graph and
expression proof, before replacing the function body. Missing or duplicate JCC
identities produce a typed materialization failure while retaining the original
AST. The caller's existing classified-but-unmaterialized hard gate raises the
pipeline error. No new recovery or acceptance exception was added to validation,
Rewrite or CLI. Effects, wide-pair and return proofs remain prerequisites.

## DoD And Failure

DoD: publish every consumed JCC identity on the replacement; require complete
unique provenance before atomic publication; detect later provenance removal;
pass live tail validation, strict compilation and the signed-wide behavioral
oracle; enroll the regression in routine tests and ownership selection.

Failure: accept incomplete/duplicate identities, overwrite the original body
after failed publication, weaken the coverage gate, or change calls, memory,
return values or comparison meaning without proof. The tests explicitly cover
missing/duplicate identities, closed failure counters and a removed-provenance
mutation. Identity coverage is not itself proof of comparison semantics; the
existing graph, tail and compiled-behavior checks remain required.

## Verified Results

- Before repair: all three new controls failed in 5.95s
  (`/home/xor/.cache/step9-wide-coverage-before.log`).
- After repair: 12 focused tests passed in 16.05s, including the live InBoxLng
  regression, strict C compilation and signed-wide behavioral/mutation tests
  (`step9-wide-coverage-live.log`). No assertion or timeout was relaxed.
- New test/enrollment files pass Ruff `check --fix`. The touched producer still
  has two legacy Ruff findings: function complexity and an unnamed comparison
  constant. `quality-fast` remains red on global Ruff debt; promoted MyPy and
  the 39-module mypyc smoke pass (`step9-wide-coverage-quality.log`).
- Final routine pipeline: 268 preliminary passes, then **5,255 passed /
  2 failed in 242.29s**. Only InitBars and RunMenu remain in that curated lane.
  QuickC remains 3/4 (`args`); MS C tiny remains 5/7 (`simple_control`,
  `loops_jumps`). Lane wall times: 242.794s / 38.468s / 137.970s
  (`step9-wide-coverage-pipeline.log`). The strengthened failure-counter
  assertions were included in this broad run.

All pytest runs used `PYTHON_JIT=1 PYTHONHASHSEED=0`, `-n 7` and duration
reporting. The first diagnostic completed at 11:54:24 +02:00 and the final
pipeline at 12:08:00 +02:00: approximately 14 minutes including gate waits,
not measured active implementation time. No full-suite result or whole-goal
ETA is inferred from these routine/focused runs.

RunMenu was inspected separately and still lacks coverage for its switch
dispatch. Its complete switch proof has not been established by this work;
do not copy the wide-predicate publication onto a switch based only on missing
JCC tags. Step 9 retains all remaining semantic, external, quality and complete
suite acceptance obligations.
