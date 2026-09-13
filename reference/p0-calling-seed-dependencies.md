# Calling-Convention Seed Dependencies

## Reason And Ownership

The CFG seed cache previously tracked local function state but not the callee
contracts or caller-result observations consumed by terminal-call return typing.
A caller initially inspected against a void callee could remain untyped after
the callee acquired a proven value return. The reduced baseline failed two
dependency-change tests while its unchanged-state control passed.

Analysis coordination now snapshots the caller, observed result-use verdict,
and the exact terminal callees inspected by Types/Lowering. Refused or missing
callee contracts remain dependencies. Detached prototype snapshots detect
in-place mutations. The collector publishes inspected target addresses before
type acceptance; the cache does not discover targets from names or rendered C.
No return recovery was added to Rewrite or CLI.

## Acceptance

DoD: changed consumed callee contracts and newly collected result-use evidence
revisit the caller; unchanged inputs and unrelated callees do not cause repeat
seeding; the MS C function-pointer example preserves its returned call and
passes compilation, execution and final tail validation.

Definition of failure: keying only on mutable object identity, omitting refused
dependencies, broad project rescans, fabricated return values, weakened source
contracts, or treating successful fallback as proof that the direct route works.

Focused verification: 43 passed in 6.14s, including prototype replacement,
in-place mutation, arriving result observation, unchanged-state reuse and an
uninspected-callee control. The existing seed-progress fixture now uses the
production evidence dataclass instead of an incomplete hand-built namespace.
The new tests are enrolled in both Make inventories and the Python pipeline.
The new owner is enrolled in typed/Ruff and architecture inventories.

Owner MyPy and the full architecture gate pass. Ruff ran with `--fix`; legacy
findings remain in larger touched modules. The broader MyPy invocation reports
`analysis_helpers.py:788` returning Any from the interrupt-name boundary; this
is outside the changed seeding function and remains unresolved, not suppressed.

Real FPTR round trip: all four functions rebuilt; source returned-call contract
passed; original/generated exit-code comparison passed (generated exit 255).
The final tail is clean, with one rejected earlier attempt retained in the
report. This used warm caches and is not a performance measurement.

## Remaining Work

Direct `select_and_apply` still rejects function-pointer/integer operations;
the successful result uses the fallback route. This checkpoint does not prove
sidecar-free direct acceptance, complete interprocedural fixed-point closure,
or invalidation of every other refinement's inputs. SORTD stack initialization,
QuickC and the complete-suite/quality acceptance remain open under Step 9.

The resumed verification window ended at 2026-09-12 04:44:50 +02:00. Its start
was not recorded reliably; no active-work duration is inferred. FPTR round-trip
wall time was 25.66s; focused pytest wall time is reported separately above.

Logs in `/home/xor/.cache/`: `seed-dependencies-before.log`,
`seed-dependencies-final-focused.log`, `seed-dependencies-owner-mypy.log`,
`seed-dependencies-architecture.log`, `seed-dependencies-fptr-roundtrip.log`.

## Regular Gates (Completed 04:51 +02:00)

- Traversal/storage prerequisite: 268 passed in 8.89s.
- Routine pytest: 4,440 passed, three failed in 207.44s. This is not the full
  repository collection. The failures remain sidecar-free InitBars, RunMenu
  escape preservation and InitMenu pause-zero flag handling. Their durations
  are 80.01s, 82.02s and 93.76s respectively.
- All seven MS C tiny compile/decompile/recompile/execute constructs pass;
  the external lane takes 63.629s, with seven workers.
- Ultra QuickC remains failed. Overall pipeline: one passed lane, two failed,
  none skipped or timed out.
- `quality-fast` stops at Ruff; its 39-module mypyc import smoke passes.
  Earlier standalone owner MyPy and full architecture checks also pass.

Logs: `seed-dependencies-quality-fast.log` and
`seed-dependencies-test-pipeline.log`. Only report/documentation edits followed
these gates; no semantic implementation changed during their execution.

The rejected direct FPTR payload restores EDI from `fn`, a function pointer,
instead of separate saved-register storage. The COD comparison oracle places
`fn` at BP-2, with DI/SI saved after the two-byte local allocation. That is
evidence for investigating coordinate/identity conflation, not yet proof of
which transformation introduced it. Never fix this with pointer-to-integer
casts or by deleting the register restore.

Follow-up: [worker storage investigation](p0-fptr-worker-storage-investigation.md)
reproduces the rejected candidate inside the actual forked worker and rules
out a simple pointer-coordinate lookup error. It does not fix that candidate.
