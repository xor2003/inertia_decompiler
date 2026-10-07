# Gate Inventory Coherence

## Reason and Ownership

The complete-suite audit found four failing gate/ownership tests. The static
Makefile reader stopped at the first `:=` block, ignoring `+=` target lists.
It falsely reported missing ALU tests and missed two duplicate Ruff entries.
The live DOS LoadProgram node was genuinely missing from QA_PYTEST_TARGETS.
An ownership assertion also predated the added generic annotation regression.

Extract literal Make word-list reading into `tools/dev/makefile_inventory.py`,
reducing the oversized architecture checker. Preserve assignment order,
replacement, conditional defaults, continuation lines, comments, and duplicates.
The reader does not execute Make or evaluate arbitrary Make expressions.
Tests compare supported literal forms against GNU Make itself.

The X86 quality implementation had already moved to reporting. Its admission
record incorrectly still claimed production wiring. Retain the X86-only
registry and classify that module as a compatibility wrapper; test production
imports of the actual reporting owner and identity of all four legacy exports.
This does not move semantics or change generated C.

## Definition of Done

- Make oracle cases pass for literal assignment, append, replacement, default,
  empty definitions, exact variable names, comments, and continuation lines.
- Appended duplicates/missing targets remain visible to architecture checks.
- Remove only duplicate inventory entries; enroll the real missing live test.
- Ownership requires the existing array test and its added typing regression.
- Quality shim identity, no-hidden-logic, and canonical production wiring pass.
- Routine checks include the inventory and quality wiring regressions. Keep
  layer-boundary tests grouped to share their existing immutable import scan.
- Pass scoped Ruff/MyPy, affected tests, and quality-hard; report global debt.

## Definition of Failure

Silencing architecture findings, dropping required tests, treating the shim as
a test-only implementation, reintroducing reporting into decompiler semantics,
or reporting incremental-cache diagnostic changes as fixes is failure. This
checkpoint cannot stand in for complete-suite or whole-SORTD acceptance.

## Evidence

- New Make tests before correction: 8 failed, 1 passed. GNU Make's expected
  outputs passed; the old static reader and appended-duplicate check failed.
- Corrected reader: all 9 cases passed in 1.68s. It exposed the real missing
  node and exactly two duplicate Ruff entries, which were corrected.
- Layer-boundary baseline: 2 failed, 12 passed in 19.49s. The module is a pure
  re-export of `inertia.cli.acceptance_scorecard`; the MSC6 builder and
  optimization guard import that canonical owner directly.
- Focused final gate tests before grouping: 455 passed in 39.66s, including all
  four failing gate/ownership nodes from the full audit and the new contracts.
- Scoped Ruff `check --fix` and MyPy for the reader, checker, and registry pass.
- `quality-dev` exits zero: 2,065 cases passed in 89.95s, one selected external
  case passed, and the CMP16/LOOPS/FPTR optimization guards passed.
- The grouped wiring test built its repository import index in 23.88s under
  the aggregate workload; other tests in the group reuse it. No controlled
  end-to-end performance improvement is claimed.
- Global quality-fast remains red. An incremental run showed 142 MyPy errors,
  but an immediate `make mypy ... --no-incremental` run confirms 146. The four
  temporarily absent errors were in untouched indexed-address inventory code;
  no typing improvement is claimed from that discrepancy.
- The existing multi-threaded `fork()` warning appeared during the live Swaps
  pointer-output regression. It is not suppressed or fixed by this checkpoint.
- `quality-hard` exits zero: the full architecture check passes, 2,065 tests
  pass in 89.14s, one external case passes, and all three executable optimization
  guards pass. Global typing remains red outside this changed-surface gate.

The complete-suite baseline remains 10,166 passed / 49 failed / 170 skipped;
four of those failures have focused closures, not a replacement full census.
Next semantic priority is RunMenu's flag/address compilation failure, followed
by missing initializers, duplicated calls, and lost/mismatched guards.

## Timing

Started 2026-09-07 about 13:53 +02:00; hard verification finished 14:11 +02:00.
Approximately 18 minutes elapsed, including repeated contract checks and
executable gate waits; this is wall time, not measured active coding time.
