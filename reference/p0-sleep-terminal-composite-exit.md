# Sleep Terminal Composite Exit

## Implementation Checkpoint

The new `structuring/terminal_loop_exit_conditions.py` consumer now uses the
existing natural-loop owner and wide decision planner. It requires a direct
terminal, effect-free guard, the complete loop branch set, one exit, and
dominance of every comparison block and the latch by the decision root. It
does not move preceding statements or infer destinations from break tags.
The new bypass-root corruption failed before the dominance check and is now
refused. Canonical topology is collected once for both loop-exit consumers.

Three independent defects are corrected alongside this integration:

1. Compact wide predicates retain composite ownership from immutable branch
   provenance. Before the fix, the three-branch control failed while the
   one-branch control passed; a later scalar consumer could otherwise replace
   a whole wide comparison with its first half.
2. Legacy call-selector replay overwrote a proven wide capture's destination
   with AX. A worker-local mutation probe identified
   `_call_return_selector_assignment_statement_8616` as the first destructive
   consumer. It now consumes `is_scalar_ax_call_return_8616` from Lowering,
   shared with the existing switch-selector owner. Unknown and DX:AX returns
   cannot authorize scalar AX replacement. The architecture exception is
   explicitly veto-only, not permission for new semantic recovery in Rewrite.
3. Wide capture declarations were missing from the variable manager. Both
   capture forms failed a new declaration-publication assertion before the
   fix. Lowering now publishes the proven 32-bit type before refreshing C
   declarations, instead of letting regeneration narrow the temporary.

Focused verification: **191 passed, 11.01s**, including the five integration
regressions exposed and corrected during the first routine run. Scoped Ruff
(`--fix`) and MyPy pass for the new consumer and touched focused owners.
MyPy also passes for the two large integration modules. Their existing Ruff
debt remains: the scoped all-touched run reported 379 unresolved findings.
`quality-fast` remains globally lint-blocked; its 39-module mypyc compiled
import smoke passes. No diagnostics were suppressed.

**Sleep is not accepted yet.** Its most recent executable run has no
uninitialized-read failures and retains the wide clock-result definition, but
Tail Validation still reports
`branch-condition:invalid-fingerprint:jcc=0x10f58:matches=0`. The compact wide
predicate needs an explicit typed validation contract: the current validator
first tries to recreate the obsolete scalar ConditionIR surface, which can no
longer be lowered. Do not skip this error or treat branch-address provenance
alone as semantic equivalence. Carry the complete decision proof and exact
call/storage mapping through capture, then validate the final predicate and
its definition against that evidence, with corruption controls.

The existing live test remains unchanged. Its last combined run was
31 passed / 1 failed, 17.70s, with Sleep taking 8.12s. The first routine
pipeline run was 5 failed / 5,433 passed, 278.18s; all five failures were the
unconditional capture-commit integration bug, fixed in the 191-test batch.
That run's QuickC lane passed 4/4 (33.157s), and MS C tiny passed all seven
complete build/run/decompile/recompile/run fixtures (94.308s). The final routine
rerun after the integration and dominance corrections passed: 5,439 tests in
272.58s, QuickC in 39.850s, and MS C tiny in 115.246s. `make test-pipeline`
exited successfully. Startup architecture and test-ownership checks also pass.
These are not full-collection or Step 9 acceptance results. The final pipeline
log is `/tmp/step9-terminal-pipeline-final.log`.

Logs: `/tmp/step9-terminal-{before,entry-before,focused,types,quality,pipeline}.log`,
`/tmp/step9-capture-type-before.log`, and `/tmp/step9-capture.log`.
Implementation active time was not separately measured; durations above are
actual test/gate wall times, not an inferred implementation subtotal.

## Verified Baseline

Revision `cffd0bb43`, checked on 2026-09-18. The complete sidecar-free SORTD
gate accepts 15/20 functions. Sleep at `0x10f38` fails both that gate and its
existing focused regression (1 failed, 17.26s). This is not a whole-file-only
transport discrepancy. Validation reports four uninitialized register reads
and missing branch surfaces at `0x10f58`, `0x10f5d`, and `0x10f65`.

## Worker-Local Evidence

A read-only in-process probe used a private temporary decompilation cache,
`PYTHON_JIT=1 PYTHONHASHSEED=0`, `INERTIA_OTEL_PROFILE_IN_PROCESS=1`, and
`INERTIA_DIRECT_ADDR_FORCE_THREAD=1`. Hooks were observed inside analysis;
the process completed with exit 4, not a successful decompilation.

- The existing natural-loop owner proves header `0x10f52`, latch `0x10f6a`,
  and unique exit `0x10f6d`. Transparent connector proof remains SSA-backed.
- The first observed loop body is a clock-result assignment followed by an
  effect-free composite `if (...) break`. There is no following body statement.
- The guard carries all three typed identities on its first observed pass:
  `(0x10f58, 0x10f55)`, `(0x10f5d, 0x10f5d)`, `(0x10f65, 0x10f62)`.
- `plan_wide_call_condition_8616` already proves `sgt` for exit versus header.
  `build_proven_wide_call_condition_8616` returns a candidate. The probe does
  not insert it or commit a speculative call capture.
- On a later observed pass, the guard retains only the latter two identities.
  This confirms that first-pass provenance and subsequent replay must both be
  covered; a late text replacement is not a solution.

## Missing Integration

`structuring/existing_loop_exit_conditions.py` deliberately refuses composite
predicates. `structuring/composite_pretest_conditions.py` requires a leading
guard, so it cannot consume a guard following the clock assignment. Generic
single-branch inference correctly refuses to treat a break's source tag as a
destination. Preserve those safeguards.

The next implementation belongs in Structuring's existing loop-aware exit
path, using the proven natural-loop region, exact guard branch set, and wide
decision plan. Types/Lowering must retain ownership of wide storage and call
capture. Keep the clock evaluation at its current position. Do not promote
the predicate to a pretest header or infer an exit from the break's tag.

Reason: connect already-proven facts to their correct consumer without adding
a competing CFG, storage, or call-recovery implementation.

Definition of done:

- A terminal composite break has one proven enclosing loop and unique exit;
  all represented branch identities belong to the complete typed decision.
- Unknown, additional, ambiguous, effectful, nested-scope, or incomplete
  evidence refuses without changing the AST or committing call captures.
- The comparison consumes the wide result exactly once, preserves both clock
  calls and their positions, and remains coherent on repeated materialization.
- The unchanged live Sleep regression, strict C recompilation, independent
  deadline/clock-count oracle, corruption controls, and whole-tail validation
  pass; focused tests and routine gates show no regressions.

Definition of failure: guessed root or exit, deleting live scalar effects,
duplicated/moved calls, discarded branch provenance, weaker validation, or
accepting a focused result as full Step 9 completion.

Temporary diagnostic artifacts: `/tmp/step9-sleep-loop-probe.py`,
`/tmp/step9-sep18-loop.{c,log}`, `/tmp/step9-sep18-sleep-test.log`, and
`/tmp/step9-sep18-whole.{txt,json,log}`. The graph snapshot predates these
owners; affected source was read directly after coverage reported changed or
untracked metadata. The initial probe was read-only; implementation changes
and their still-open validation requirement are recorded above.
