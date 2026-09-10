# Switch Materialization Attempt Reporting

## Reason And Owner

RunMenu's live regression expected the last switch-materialization attempt to
be successful. A fresh isolated-cache observer instead recorded two successful
Structuring materializations followed by a pre-codegen `already_structured`
no-op. Each successful record had one attempt, one replacement, nine cases and
default target 4523. The CLI reported only the final record, losing the earlier
evidence in its diagnostic projection.

This is a CLI reporting defect, not a reason to change Structuring's idempotent
refusal. The diagnostic now includes `attempt_history`, in original order and
filtered to the current function. Existing top-level fields still describe the
latest attempt. Attempts are not summed and an earlier success cannot hide a
later refusal. Generated C and semantic ownership are unchanged.

## Acceptance

DoD: preserve both successful and refused records, function isolation, ordering,
latest-result semantics and original input records; RunMenu must still prove
nine materialized cases, the default target, segment-quality invariants and
clean tail validation. Admit regression coverage to routine gates.

Definition of failure: select the best historical outcome as the latest result,
double-count repeated materializations, mix functions, mutate source evidence,
fake a successful final attempt, or weaken semantic acceptance to make tests green.

Two unit cases failed before the fix with missing `attempt_history`; 17 existing
helper cases passed (5.64 seconds total). After the fix, 20 focused tests passed
in 42.21 seconds, including RunMenu (33.49 seconds call time). Both an idempotent
refusal and an ambiguous-default refusal remain visible after a prior success.
The tests are in the existing routine telemetry-support module.

Scoped Ruff `check --fix` and CLI MyPy pass. Scoped Pyright reports two errors
in unchanged CLI stack-local collection code: direct `cfunc` access on
`BaseStructuredCodeGenerator`. The touched test modules have no diagnostics.
This checkpoint does not claim global typing closure or full RunMenu acceptance.

`make quality-fast PYTHON=./.venv/bin/python` exited zero: 3,292 tests passed
with seven dependency warnings in 137.37 seconds, and all three executable
quality guards passed. The slowest tests were the sidecar-free RunMenu Escape
regression (55.79 seconds), InitBars stack-array regression (49.15 seconds),
and indexed-address parity inventory (35.36 seconds). Cache conditions were
not controlled for a performance comparison; no speedup is claimed.

The failing unit baseline completed at 03:46:35 CEST on 2026-09-10; focused
acceptance completed at 03:47:45; the broader gate's exit zero was observed
by 03:52 CEST. This is an observation window, not measured active coding time.

Logs: `/tmp/inertia-switch-history-{before,after,types,mypy,quality}.log`.
Full-repository tests and the default external pipeline were not rerun for
this reporting-only change. InitMenu stack-bookkeeping acceptance remains open.
