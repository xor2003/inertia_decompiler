# Typed Stack Declaration Snapshot

## Reason And Ownership

The CLI accessed `cfunc` on angr's generic structured-codegen base class,
producing two Pyright errors. Its inline candidate snapshot also rediscovered
argument identities once per variable. Existing native declaration metadata is
now copied by `snapshot_stack_local_candidates_8616` in `codegen_metadata.py`.
The CLI only transports that snapshot to its existing consumers.

This is metadata transport, not stack recovery. Candidate keys retain Python
object identity, values retain the exact native variable and declaration objects,
and arguments plus non-stack variables are excluded as before. The helper
requires a native CFunction root and fails clearly on incompatible generators.
Argument identities are collected once. No runtime speedup is claimed.

## Acceptance

DoD: preserve existing candidate contents and object identity, exclude arguments
and registers, avoid mutating native declaration metadata, reject incompatible
roots clearly, eliminate both CLI typing diagnostics without ignores or Any
substitutions, admit regression tests to routine gates, and preserve focused
runtime behavior.

Definition of failure: infer Alias identity, merge equal-looking stack slots,
delete stack effects, classify metadata as semantic proof, silently accept an
unsupported generator, or weaken InitMenu's existing acceptance test.

Four new tests failed before the helper existed (8.02 seconds), then passed.
The focused combined run was four passed and one failed, seven dependency
warnings, 50.13 seconds. InitMenu still fails the same unchanged bookkeeping
assertion (42.11 seconds call time), after its preceding required-call,
declaration and validation assertions pass. Its compiled behavior harness is
not reached; this is not an InitMenu semantic fix.

Scoped Ruff `check --fix`, MyPy and Pyright pass. Pyright now reports zero errors
and warnings for the CLI, metadata module and new tests. New cases are included
in Make's routine lists, the pipeline runner and ownership selection.
The combined `make quality-fast test-pipeline` gate exited zero. Fast passed
3,296 tests in 137.53 seconds with eight warnings; default passed 3,296 in
126.92 seconds pytest / 127.337 seconds lane with seven warnings. All three
executable quality guards passed, QuickC passed in 46.172 seconds, and all
seven MS C tiny roundtrips passed in 63.957 seconds, each with return code zero.
The default unit lane remains over budget. Fast's additional warning is the
already documented threaded-fork risk at `fork_timeout.py:187`; it was not
suppressed. No full-repository pass is claimed.

Logs: `/tmp/inertia-stack-snapshot-{before,after,pyright,mypy,gates}.log`.
The focused verification was observed complete by 04:05 CEST on 2026-09-10.
The broad gate log spans 04:05:06 to 04:13:12 (8m06s); terminal exit zero was
verified afterward. These anchors include gate waits, not total active effort.
