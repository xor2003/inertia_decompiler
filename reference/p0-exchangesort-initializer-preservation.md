# ExchangeSort Initializer Preservation

## Status

2026-09-10: two causes of an uninitialized stack read and a subsequent required
cast deletion are repaired. The subsequent instruction-local reload correction
in `f37229fa1` also closes the outer-loop shape failure. The named ExchangeSort
acceptance now passes whole-tail validation, compilation and its loop/call
assertions. This does not establish full-suite or sidecar-free corpus acceptance.

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

## Required Conversion Follow-Up

The binary uses signed `jg` for the outer guard. Diagnostic guard matching
confirmed that the loop was in the correct CFG region, but the expected
unsigned-to-signed 16-bit semantic cast was absent from the final expression.
The validator was correct to refuse it; no validator changes were necessary.

Structural before/after tracing isolated `_simplify_structured_c_expressions`
in `inertia_decompiler/cli_c_ast_rewrites.py`. Its `_unwrap_c_casts` helper
unconditionally erased Lowering's `CSemanticCast8616` from binary operands.
Copy-alias rebuilding could also replace a semantic conversion with an ordinary
cast, discarding its class and metadata.

The legacy consumer now stops cosmetic unwrapping at required conversions,
except when Lowering's existing declaration-based proof establishes identity,
and copies existing cast nodes when replacing their inner expression. Semantic
ownership remains in Lowering; the CLI neither invents conversions nor guesses
signedness. This fixes consumption of an existing contract, not semantic recovery
in a later layer. The rule is also stated in the consumer's module header.

- Before: five new direct conversion/unwrapping regressions failed.
- After: seven focused tests pass in 10.95 seconds, including the previous
  expression-identity regression and a new copy-alias metadata regression.
- Unchanged ExchangeSort acceptance now passes CLI exit, `validation=passed`,
  clean whole-tail validation and CLI GCC checks. It fails later at the outer
  `for`-loop assertion; subsequent call/shape assertions are not claimed passed.
- Scoped MyPy and Pyright pass, new tests pass Ruff `check --fix`; the legacy
  consumer still has the same 99 clarity-rule findings. No lint exemptions added.
- The first broad follow-up exposed an InitMenu loop-shape regression: both
  lanes reported one failure and 3,481 passes. This was investigated, not ignored.

### Induction Matching Compatibility

Preserving casts exposed Structuring's bare-operand-only induction matcher:
`i = 0` remained immediately before `for (; (short)i < cszMenu; i += 1)`.
The focused `structuring/induction_comparisons.py` extraction now inspects
cast chains only to match existing storage identities, leaving the complete
condition object unchanged. This does not infer ranges, monotonicity or cast
redundancy. Computed/ambiguous operands still refuse. The larger canonical-loop
module shrank rather than gaining another matcher.

Four casted while/for cases failed before and pass after. Tests additionally
cover ambiguous/computed induction and a switch-case `continue` targeting its
enclosing loop. The latter guards the current native list-shaped case inventory;
typing exposed a legacy dictionary-only traversal, now using the existing AST
container iterator with explicit statement narrowing.

The InitMenu integration assertion still requires one complete initialized
`for` loop. It now also requires `(short)i` when the declaration is unsigned,
rather than demanding removal of the necessary conversion. Its other call,
compilation and behavior assertions remain intact. Unnecessary unsigned identity
casts are removed only with Lowering's emitted-declaration proof; missing proof
refuses, covered by two additional simplifier cases.

Final focused canonical-loop/simplifier/InitMenu run: **34 passed**, seven
dependency warnings, 37.99 seconds (InitMenu call 28.56 seconds). Scoped MyPy
and Pyright pass for the changed owners and wiring. New helper/tests pass Ruff;
legacy canonical-loop functions retain three clarity findings, ownership wiring
one, and the CLI owner 99.

### Final Follow-Up Gates

`PYTHON_JIT=1 PYTHONHASHSEED=0 make -k quality-fast test-pipeline PYTHON=./.venv/bin/python`
completed against stable source:

- Fast lane: **3,491 passed**, seven warnings, 145.42 seconds.
- Default lane: **3,491 passed**, seven warnings, 131.60 seconds.
- Startup architecture/context and ownership checks pass.
- Three executable quality guards and all seven MS C compile/decompile/recompile
  behavior checks pass, with `decompile_run=ok` for every example.
- Overall exit 2 remains due to **6,322 existing Ruff findings** in the promoted
  scope; no newly hidden diagnostics or relaxed lint thresholds.
- Separate final sort acceptance: QuickSort passes; ExchangeSort passes validation
  and CLI compilation but still fails the unchanged outer-loop shape assertion.
  Combined result: one passed, one failed in 43.58 seconds. Later ExchangeSort
  call/shape assertions were not reached and are not claimed passed.

Full logs: `/tmp/inertia-semantic-cast-final-gates.log` and
`/tmp/inertia-semantic-cast-sort-acceptance.log`. Routine lanes overlap and do not
replace the full-repository audit. No full-suite or complete P0 success is claimed.

Diagnostic logs: `/tmp/inertia-exchange-guard.log` and
`/tmp/inertia-exchange-cast.log`. Focused results:
`/tmp/inertia-semantic-cast-before.log`, `/tmp/inertia-semantic-cast-alias.log`,
`/tmp/inertia-exchange-cast-acceptance.log`.

## Instruction-Local Reload Correction

**Reason:** a resurrected register-copy assignment separated the initializer
from the outer loop. Existing liveness correctly removed the original header
carrier; later direct-stack reload replay selected a different, live SSA identity
from inside the loop body. A control statement's own instruction tag had been
combined with a recursive search of all descendant register reads.

**Correct owner:** Types/Lowering now selects only reads in the instruction-owning
statement's local expressions. Control statements contribute their condition,
not child bodies. The focused `register_reload_consumers.py` helper requires the
exact register width and an unambiguous existing variable/SSA identity; missing
or conflicting evidence refuses reconstruction. The recursive legacy selector
was removed from `real_mode_linear.py`. No DCE proof was relaxed and no semantic
recovery was added to Rewrite or CLI.

**Verification:** the new full-lowering body-identity regression failed before
the fix. Final reload ownership/idempotence and ExchangeSort acceptance passed
**26 tests**, seven dependency warnings, in **30.06 seconds**; the slowest test
was ExchangeSort at **21.68 seconds**. Tests cover body-versus-header ownership,
if/switch conditions, ambiguous SSA identities and byte/word/dword mismatches.
The inner-loop assertion now requires the signed conversion when its declaration
is unsigned, rather than demanding its unsafe removal; initializer, guard and
call requirements remain. Scoped MyPy and Pyright pass. The large lowering owner
retains 243 Ruff findings; the new helper and focused tests have none.

**Committed-source gates:** `PYTHON_JIT=1 PYTHONHASHSEED=0 make -k quality-fast
test-pipeline PYTHON=./.venv/bin/python` completed on `f37229fa1` with production
source unchanged (only these status documents were edited):

- Fast lane: **3,502 passed**, seven warnings, **158.24 seconds**.
- Default lane: **3,502 passed**, seven warnings, **145.05 seconds**.
- Startup architecture/context, ownership, 39-module compiled import smoke,
  three executable quality guards and seven MS C full round trips pass.
  Every MS C example reports `decompile_run=ok`.
- Overall exit **2**: the linter aggregate remains red, including **6,319**
  promoted-scope Ruff findings. No suppressions or threshold changes were added.
- Slowest fast-lane calls: sidecar-free RunMenu ESC preservation **66.38s**,
  InitMenu pause guard **65.27s**, sidecar-free InitBars stack array **62.90s**.

Full log: `/tmp/inertia-f37229fa1-gates.log`. These overlapping routine lanes
do not replace the complete repository audit. **Remaining verification:**
continue the full-repository failure audit and close the linter debt.

**DoD:** `validation=passed`, clean whole-tail validation, strict generated-C
compilation, correct loop/guard semantics and preserved calls/argument classes.
The end-to-end loop shape requirements remain in force, with required signed
conversions preserved.

**Definition of Failure:** missing or unsigned machine-signed guards, suppressed
validation, deletion of live code, guessed range assumptions, or passing only
unit tests without the unchanged function acceptance.

## Timing Ledger

Local time (UTC+02), 2026-09-10:

- 09:23:43: deletion regression finished red (four failures).
- 09:24:05: combined focused verification finished green (32 tests).
- 09:25:02: function acceptance finished; remaining guard failure recorded.
- 09:53:59: cast-preservation baseline finished (five new failures).
- 09:55:26: unchanged function regression reached the outer-loop shape assertion;
  validation and CLI compilation checks passed.
- 09:56:25: all seven simplifier regressions passed.
- 10:11:49: focused compatibility and InitMenu run passed (34 tests).
- 10:13:04: final QuickSort/ExchangeSort acceptance finished (one pass, one
  remaining shape failure).
- The observed investigation-to-function-check interval was 09:49:37-10:13:04
  (23 minutes 27 seconds), including diagnostics and the first broad gate.
  Final broad verification started at 10:13:22; its per-lane durations are above.
- Full implementation effort includes earlier placement tracing; these timestamps
  are observed verification milestones, not a claim of total development time.
- Reload regression log completed at 10:28:14; final focused acceptance log at
  10:35:58 (observed file timestamps, not implementation start/end times).
  The final test invocation took 30.06 seconds; exact active effort is unknown.
- Committed-source broad gate was observed terminal at 10:48:54. Per-lane test
  durations are recorded above; this timestamp is not a total-effort estimate.
