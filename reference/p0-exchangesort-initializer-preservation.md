# ExchangeSort Initializer Preservation

## Status

2026-09-10: two causes of an uninitialized stack read are repaired. ExchangeSort
is **not accepted**: its unchanged end-to-end regression now fails whole-tail
validation on an outer-loop guard. Do not weaken that test or validator.

## Evidence And Correct Owners

The binary at `SORTDEMO.EXE:0x10b5b` initializes `[BP-6]` to zero before
the load at `0x10b66`. Source is an optional comparison oracle, not recovery
evidence. Structural stage traces isolated two independent mutations:

1. Structuring's pretest initializer placement required adjacency to the loop.
   It moved an already unconditional initializer past the intervening header
   load. `structuring/pretest_initializer_placement.py` now preserves an existing
   prefix placement, including nested unconditional sequences. Branch and loop
   bodies do not count as unconditional prefixes. The helper consumes existing
   classified assignment locations; it does not infer stack identity or values.
2. Call-argument replay subsequently deleted the initializer. Its legacy
   stack-probe artifact classifier permitted deletion of any `SimStackVariable`
   assignment absent from the current statement-list suffix. That suffix cannot
   prove memory deadness, especially across nested sequences and aliases.
   The compatibility bridge now refuses that deletion. Future positive deletion
   proof belongs to Alias/Lowering storage ownership, not postprocess. The existing
   `frame_carrier_liveness.py` contract deliberately excludes reused stack objects;
   applying its scalar proof to this memory lifetime would be incorrect.

This removes an unsafe semantic inference from the bridge; it does not add
replacement semantic recovery there. Existing proven scalar-carrier and typed
stack-probe metadata cleanup still pass their focused regressions.

## Verification

- Placement regression: three nesting cases failed before, nine tests passed
  after the placement repair.
- Stack-storage regression: all four nested/flat and observed/unobserved cases
  failed before, passed after. An absent direct read is not alias-deadness proof.
- Combined placement and stack-probe tests: **32 passed**, seven dependency
  warnings, 8.68 seconds, using `pytest -n 7`.
- ExchangeSort acceptance: **one failed**, 43.47 seconds including 35.49 seconds
  in the test call. The uninitialized read is gone; the new diagnostic is
  `loop-branch:missing-guard:jcc=0x101d:block=0x1013:body=0x1022:false=0x109e:matches=0`.
- Generated output now initializes `iRowCur` before `ax_6 = iRowCur` and retains
  the guarded minimum update, DrawTime, Swaps and SwapBars. This visual inspection
  is not semantic acceptance or a strict compilation success claim.
- Scoped production MyPy and Pyright pass; the new test's Pyright check passes.
  New helper/tests pass Ruff `check --fix`. Touched legacy owners retain 369
  clarity-rule findings, and ownership wiring retains one existing complexity
  finding. No suppressions or threshold changes were added.
- Both test files are admitted to the routine pipeline and ownership mapping;
  the new helper is admitted to the existing Make quality scopes.
- Final `make -k quality-fast test-pipeline PYTHON=./.venv/bin/python`:
  fast lane **3,476 passed** in 138.35 seconds; default lane **3,476 passed**
  in 118.46 seconds. These overlap; do not add them into a unique-test total.
  Startup architecture checks, three executable quality guards, QuickC and all
  seven MS C full round trips pass (`decompile_run=ok` for every example).
  The overall command exits 2 on the existing **6,322 Ruff findings** in the
  promoted scope. Full output is in `/tmp/inertia-exchangesort-gates.log`.
  The complete repository suite was not rerun; no green full-suite claim.

Temporary diagnostic logs: `/tmp/inertia-exchangesort-placement.log`,
`/tmp/inertia-exchangesort-prune.log`, `/tmp/inertia-probe-local-before.log`,
`/tmp/inertia-probe-local-after.log`, `/tmp/inertia-exchangesort-storage-fix.log`.
The durable evidence is the tests and this report, not retention of those logs.

## Remaining Task

**Reason:** the binary uses signed `jg` for the outer guard, while final C now
has `while (cRow > iRowCur)` with an unsigned-short local and no signed cast.
Determine whether condition projection, cast cleanup, or guard matching loses
the necessary identity/signedness. This is a lead, not a proven third root cause.

**Order:** trace the first loss in typed condition projections, add a failing
focused regression, repair the earliest responsible owner, then rerun the
unchanged function acceptance and routine/executable gates.

**DoD:** `validation=passed`, clean whole-tail validation, strict generated-C
compilation, correct loop/guard semantics and preserved calls/argument classes.
The original end-to-end shape assertions remain in force.

**Definition of Failure:** missing or unsigned machine-signed guards, suppressed
validation, deletion of live code, guessed range assumptions, or passing only
unit tests without the unchanged function acceptance.

## Timing Ledger

Local time (UTC+02), 2026-09-10:

- 09:23:43: deletion regression finished red (four failures).
- 09:24:05: combined focused verification finished green (32 tests).
- 09:25:02: function acceptance finished; remaining guard failure recorded.
- Full implementation effort includes earlier placement tracing; these timestamps
  are observed verification milestones, not a claim of total development time.
