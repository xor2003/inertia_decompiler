# DOS Unit Complexity Gate DoD

## Goal

Classify original DOS functions by solver/runtime-test difficulty before asking
Z3 larger questions.

The gate is conservative. A function is `simple_whole_function` only when it is
small, straight-line, returns normally, and has no control-flow or memory
features that would make a whole-function symbolic formula expensive.

## Required Behavior

1. `dosunit complexity` loads the original EXE through the x86-16 lifter and
   forces `project.factory.block(...).vex` before using instruction summaries.

2. The output schema is `dosunit.complexity.v1`.

3. Each function has typed metrics:
   - instruction and block counts
   - condition, branch, jump, call, interrupt, return counts
   - indirect-control count
   - explicit memory read/write counts
   - symbolic and segment-sensitive memory counts
   - flag read/write counts
   - partial-register count
   - variable-shift count
   - mul/div count
   - string-instruction count
   - loop-like and backward-branch counts

4. Each complex function reports blockers such as `conditions`, `calls`,
   `symbolic_memory`, `indirect_control`, `loops`, or `z3_risk_score`.

5. Risk points include instruction address and disassembly for visible reports
   and debugging.

6. `report-failures` renders complexity documents with summary counters,
   blockers, metrics, and risk-point disassembly.

7. A `simple_whole_function` emits exactly one `comparison_parts` item with
   `kind = "whole_function"`.

8. Complex or refused functions do not emit whole-function comparison parts.

## Verification

Run:

```bash
rtk pytest -q tools/dosunit/tests/test_dosunit_tool.py -k 'complexity'
rtk pytest -q tools/dosunit/tests/test_dosunit_tool.py
rtk python -m py_compile tools/dosunit/*.py dosunit.py
```

Smoke on F-15:

```bash
./dosunit.py complexity \
  --exe /home/xor/tmp/f15se2-re/bin/egame.exe \
  --functions /tmp/egame.original.functions.json \
  --max-simple-insns 16 \
  --simple-score-threshold 8 \
  --out /tmp/egame.complexity.json
```

## Non-Goals

This gate is not full VEX/AIL SSA-to-Z3 whole-function solving. It selects
functions where that later pass should be cheap enough. Edge vector generation
continues to use compact lifter-backed branch predicates and Z3 today.
