# CLI Output Contract Reconciliation

## Reason

Seven failures from the full-suite audit reproduced in the CLI reporting and
fallback group: seven failed, four passed in 14.97 seconds. They searched stdout
for diagnostics now intentionally emitted on stderr by `cli_output.py` and
the function-attempt reporting helper. This was not evidence of lost timeout
state or accepted invalid C.

## Correction And Ownership

Only tests changed. Diagnostic messages, attempt/validation status and assembly
listings are asserted on stderr. Generated-C and rejected-payload checks remain
on stdout. Added negative stdout checks for assembly text, the raw-segmented
access diagnostic and timeout messages guard against stream contamination.

The tests still require failure exit codes, refusal of late partial output,
preservation of timeout state, ordering of permitted partial output before
fallback, rejection of validation-failed payloads, and no reuse of a stale
project validation snapshot. No validator, fallback policy, timeout budget,
loader contract or production output behavior was relaxed.

## Acceptance

DoD: all originally selected cases plus adjacent parallel completion/order
tests pass with diagnostics checked on their intended stream. Definition of
Failure: checking only combined output, accepting invalid C, promoting a late
partial result or fabricating passed validation from stale state.

Final selected run: **13 passed**, 15 warnings, **19.13 seconds**, using
`PYTHON_JIT=1 PYTHONHASHSEED=0` and `pytest -n 7 --durations=10`.
Log: `/tmp/inertia-cli-contract-final.log`. Warnings include dependency
deprecation and existing multithreaded-fork warnings in fallback fixtures.

File-wide quality checks remain red: Ruff `check --fix` reports **174** findings
and Pyright **600** errors. No ignores or lint thresholds changed. Production
source is unchanged from the preceding broad gates; the full suite was not
rerun after these test corrections. The overall plan remains open.
