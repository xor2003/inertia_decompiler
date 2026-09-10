# DrawTime Acceptance Contract

## Evidence

Both sidecar-free DrawTime acceptance tests failed on `f37229fa1` only after
passing return status, Tail Validation and compilation checks. Output contains
`sub_10e70((unsigned short)arg_4 * 60, 75)` with `arg_4` already declared
`unsigned short`; the tests required absence of that identity conversion.

The assertions now permit that exact unsigned-short cast, not arbitrary casts
or expressions. The same parameter, multiplier 60, duration 75, wide delay
arguments, forwarded division result, required calls and forbidden artifacts
remain checked. No production code or semantic validator changed.

Reason: test correctness must not depend on removing a proven identity cast.
DoD: both original acceptance cases pass with every other obligation intact.
Definition of Failure: allowing a changed argument/value/width, dropping a call,
weakening validation, or claiming improved decompiler performance from a cache hit.

## Verification

- Before: two failed in 26.14 seconds; test calls 18.09/17.80 seconds.
- After: two passed, seven warnings, in 10.17 seconds using `pytest -n 7` with
  duration reporting and accepted-result cache reuse. Not a speedup measurement.
- Pyright: zero errors/warnings for both files. Ruff `check --fix`: 34 findings
  in the larger regression file, none in the positive-BP acceptance file.
- Logs: `/tmp/inertia-drawtime-current.log`, `/tmp/inertia-drawtime-after.log`.

The tests use different decompilation windows; their shared function alone does
not justify deleting either invocation. This is focused acceptance, not a new
full-suite count. The full audit and global lint/typing closure remain open.

## InsertionSort Follow-Up

Named and sidecar-free InsertionSort likewise passed validation/compilation but
failed stale `(char)` assignment expectations (two failed in 26.78 seconds).
Current output explicitly uses `signed char` and preserves `(short)iLength`
for the signed guard against an unsigned local declaration. The outer loop is
now an initialized `for`, consistent with `SORTDEMO.C`, not the earlier `while`.

The tests now require the explicit signed conversions and initialized outer
loop, while accepting the exact unsigned-short argument cast at DrawBar and
DrawTime calls. Aggregate field selection, guard-before-swap ordering, source
rebasing, whole-row copies, call counts and forbidden raw-memory artifacts are
still checked. Production code did not change.

DoD: both complete acceptance cases and the existing lost-break oracle pass.
Definition of Failure: removing the signed guard, accepting a whole-aggregate
scalar conversion, losing conditional exit, or moving a store before its guard.

Final acceptance: **two passed** in **10.22 seconds**, seven warnings, with
accepted-result cache reuse. The existing three source-contract tests, including
lost-conditional-break rejection, pass in **1.72 seconds**. Pyright is clean;
the large regression file retains 34 Ruff findings. Logs:
`/tmp/inertia-insertionsort-current.log`, `/tmp/inertia-insertionsort-after.log`,
`/tmp/inertia-insertionsort-oracles.log`. Broad/full-suite gates were not rerun
for these test-only corrections.
