# Accepted Call Argument Shape Publication

## Reason And Layer

InitMenu's call at active-slice address `0x10e0` had three materialized C
arguments and a node summary with logical widths `(2, 2, 4)`, while the
authoritative callsite inventory still recorded `(2, 2, 2, 2)`. The physical
four word PUSHes and eight-byte cleanup were correct. Existing Lowering
already proved the adjacent DX:AX return pair; no new inference was needed.

The inventory update used a carry-forward helper designed for an empty logical
projection. It intentionally retained nonempty projections, including this
stale one. This prevented later consumers from relying on a coherent inventory.

`lowering/call_argument_shape_publication.py` now publishes the accepted typed
reconciliation across identical physical call facts. It delegates physical
identity and extent checking to the existing Lowering owner. The legacy calls
bridge invokes it without introducing new recovery rules. The startup
architecture guard admits this specific publication-only dependency explicitly.

## Acceptance

DoD: replace a stale nonempty projection only with its exact successful typed
reconciliation; preserve physical facts and original immutable objects; refuse
mismatched physical calls, failed reconciliation and borrowed evidence; remain
idempotent; keep generated C and validation unchanged; admit regressions to the
routine pipeline and pass scoped checks and fast/default gates.

Definition of failure: infer arguments from names or rendered text, transfer a
proof to another physical call, modify PUSH/cleanup evidence, accept a failed
reconciliation, weaken the architecture guard, or treat coherent metadata as
permission to delete stack state.

Eight new tests exercise publication, identity, idempotence and refusals. The
baseline failed the new stale-projection regression (one failed, seven passed);
the fix passes all eight plus 46 existing callsite prototype tests: 54 passed,
seven warnings, 8.25 seconds. Scoped Ruff `check --fix` and Pyright pass.
Scoped MyPy was reconfirmed with exit zero after the earlier process handle
expired; an empty old log alone was not treated as proof of successful exit.

## Live Evidence

All 18 observed InitMenu callsites now have matching node and inventory logical
widths. At `0x10e0`, both report `(2, 2, 4)` with three C arguments, four word
PUSHes and eight-byte cleanup. The existing exact return-pair classifier agrees.
The probe reports `validation=passed` and clean whole-tail validation.

Generated C remains byte-identical, SHA-256
`4a41e50d2e9dd5a85c438df8fee336b5c679ccfe28483c2677cacb87ca01ae3f`.
This fixes metadata coherence, not InitMenu's retained bookkeeping. Its known
acceptance failure remains open; no function-fix or full-suite claim is made.

Logs: `/tmp/inertia-argument-shape-publication-{before,after,live,pyright,mypy-confirm,gates}.log`.
The live validation record is timestamped 2026-09-10 04:47:32 CEST. Verification
resumed before the observed 04:52:27 CEST clock reading. The original step start
was not captured, so total implementation time is unknown rather than estimated.
Both `make quality-fast` and `make test-pipeline` exited zero, confirmed before
05:00:45 CEST. Each unit lane passed 3,321 tests with seven warnings: 134.54
seconds for fast and 124.04 seconds for default. All three executable quality
guards passed. Default QuickC took 45.765 seconds; all seven MS C tiny full
roundtrips passed with return code zero in a 61.120-second lane. The default
unit lane remains over its configured budget (124.471 seconds including lane
overhead). These are routine gates, not a full-repository audit.

The slowest fast tests were RunMenu Escape (53.00 seconds), InitBars stack-array
recovery (43.47 seconds), and indexed-address parity inventory (28.92 seconds).
No controlled performance improvement is claimed from these timings.

The subsequent focused acceptance rerun exited one: eight publication tests
passed and InitMenu failed the same unchanged bookkeeping assertion at
`test_x86_16_sortdemo_regressions.py:1653`. Total was 39.13 seconds, including
31.23 seconds for InitMenu, with seven dependency warnings. Final Ruff
`check --fix` and `git diff --check` passed. Completion of this bounded
publication checkpoint was observed at 05:01:48 CEST; the semantic function fix
and full plan remain incomplete.

## Next Semantic Obligation

The earlier bounded ownership observation associates 57 of 60 retained stack
arithmetic origins with one callsite PUSH or cleanup each. Three prologue
origins remain unowned. Neither unique ownership nor a matching logical shape
proves that an effect is dead. The next consumer must establish actual argument
consumption, complete live-use closure and path-correct stack behavior before
removing any effect. Preserve unknown cases and distinct CFG occurrences.
