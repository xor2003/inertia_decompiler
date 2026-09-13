# HeapSort Behavioral Acceptance

## Runtime Contract Refresh (2026-09-13)

The stable original-failure audit reproduced both live HeapSort failures at
link time. Generated C declares `inertia_esi` and `inertia_edi` as external
runtime state and saves/restores their low words while preserving upper words.
The observation harness supplied neither definition. This is a test-runtime
contract defect, not evidence that those generated operations can be deleted.

The harness now supplies both declared `unsigned long` objects, initializes
nonzero upper and varying lower words for every row-count case, and requires
exact register preservation after HeapSort. All existing call, pointer, row
count, and array-effect checks remain. Generated C is included unchanged.

DoD: both live cases pass their existing semantic validation and strict
compiled-behavior gates; valid controls pass and low/high-word corruption of
either register compiles but fails at runtime. Failure: accepting corruption,
weakening existing assertions, or changing generated C to satisfy the harness.

Verification: 18 passed in 2.45s under pytest `-n 7`, including four new
register-corruption controls. Both touched Python files pass Ruff `--fix`.
The mutation test module is already enrolled in Make and `test_pipeline.py`.
Logs: `/home/xor/.cache/step9-heapsort-runtime-harness.log` and
`/home/xor/.cache/step9-heapsort-runtime-controls.log`.
These are focused results, not a new complete-suite or routine-pipeline run.

## Historical Initial Oracle

## Reason And Contract

The current full audit includes two HeapSort failures caused by assertions
that require older rendered C. The named case rejects `(short)i` and the
sidecar-free case requires the descending-loop initializer before `for`.
`SORTDEMO.C` instead defines the behavior: ascending PercolateUp calls followed
by descending Swaps, SwapBars and PercolateDown calls, with exact arguments.

DoD: compile unchanged generated C with strict gcc warnings, verify ordered
calls and scalar/pointer arguments, retain tail-validation assertions, and
mutation-test the new oracle before admitting it to routine checks.
Definition of failure: accepting lost or reordered calls, changed loop bounds,
byte-truncated row counts, wrong pointers/arguments or unexpected array writes;
rewriting generated C to make the oracle pass; weakening validation.

## Change And Evidence

Test layer only; no decompiler semantic changes. The oracle includes generated
C unchanged and supplies observation stubs for the known fixture callees.
It checks counts 0 through 512, 1024 and 32767. The callbacks check every call
in order, scalar values and exact array addresses. Row count and array contents
must remain untouched by HeapSort itself; actual callee implementations are
outside this wrapper-level oracle's scope. Negative row counts and malformed
runtime state are not claimed covered. Existing numeric names remain valid.

Two equivalent loop layouts pass. Ten mutations cover up/down bounds, byte
truncation, extra/lost calls, scalar ordering, wrong pointers, wrong downward
arguments, call reordering and unexpected array writes. All mutations compile
and fail the runtime oracle; compiler errors are not counted as that evidence.
The new oracle tests are in Make's fast targets, the routine pipeline and the
ownership manifest. No existing tests were deleted or skipped.

Before: two real regressions failed in 19.35s.
After: the complete HeapSort module, mutation checks and ownership/pipeline
tests pass, 128 tests in 44.90s. Ruff passes for the new and modified test
modules and pipeline module. Helper MyPy and Pyright pass. The ownership
manifest retains one existing complexity finding in `validate_manifest_targets`.
The existing corpus test module shrank by 18 lines.

Evidence: `/tmp/inertia-heapsort-before.log`,
`/tmp/inertia-heapsort-wiring.log`, `/tmp/inertia-heapsort-ruff.log`,
`/tmp/inertia-heapsort-mypy.log`, `/tmp/inertia-heapsort-pyright.log`.
Work was observed around 18:30-18:36 CEST on 2026-09-10, approximately six
minutes including focused test execution; this is not a precision active-CPU
measurement. The full-suite total remains the prior measured 23 failures;
these two focused repairs do not establish a new full-suite result. P0,
BIOS strict compilation, global lint and full-suite runtime remain open.
