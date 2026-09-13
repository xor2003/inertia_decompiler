# Terminal Stack Byte Views

Checkpoint: 2026-09-12, Step 9 remains open.

## Defect And Ownership

`scalar_types_io` / `rot_ui` loads one byte at BP+5 from its word argument at
BP+4. The legacy terminal-return callback rounded the load to two bytes and
created an uninitialized word local. ABI slot spacing is not machine-load width.

Types/Lowering now supplies contained argument views through its existing
storage-coordinate registry. Wrapper clones resolve through recorded storage
identity; matching offsets or names alone are insufficient. Successful prototype
reconciliation also replays the scalar subview consumer. Its word-owner support
refuses pointer reinterpretation, char-slot padding, ambiguous owners, writes,
and escaped addresses. Projection metadata describes the view, not its base read.

The legacy callback consumes contained projections and honors typed refusals.
Exact reads retain their existing argument surface and prototype binding.
The architecture exception documents this consumer-only dependency; recovery
remains in Lowering. Full migration of the legacy return scanner is still debt.

## Evidence

- Before the callback fix, the focused byte-load regression failed and real
  `rot_ui` failed generated-C initialization acceptance.
- The corrected CLI run exits zero, reports `validation=passed`, and reports
  clean whole-tail validation. Its return is `(a >> 8 >> 7) | (a << 1)`.
- Actual emitted C compiled with GCC `-std=c99 -Wall -Wextra -Werror` and passed
  all 65,536 input values while preserving ESI and EDI, including their high words.
- The example and both separate runtime harnesses now test high-bit rotate
  inputs. The final MS C round trip rebuilt all ten scalar functions, recompiled
  them, and executed successfully. The emitted harness contains the new checks.
- Final focused surface: 95 passed in 7.29s, using pytest `-n 7`.
- Early pipeline contracts: 268 passed in 8.87s.
- Final routine lane: 4,396 passed, 3 failed in 201.06s. This is not the complete
  repository collection. The remaining failures are SORTD InitBars, RunMenu,
  and InitMenu initialization/validation regressions.
- MS C tiny: 6/7 passed; function_pointers remains failing. QuickC remains red.
- Scoped MyPy and full architecture checks passed. `quality-fast` remains red
  on lint debt; its 39-module mypyc import smoke passed. Ruff ran with `--fix`;
  findings were retained rather than excluded.

Observed verification window: first failing test log completed at 03:28:25;
final pipeline log completed at 03:49:39 +02:00, elapsed 21m14s. This includes
investigation and gate waits, not a measured total of active engineering time.

## Rejected Expansion And Remaining Risk

An intermediate change also routed exact word reads through semantic casts.
That made `sub_ss` emit `return a` instead of `return a - b`. A controlled
in-process comparison reproduced the difference and confirmed the callbacks
executed. The broad exact-read change was removed; the final DOS round trip
passes the subtraction again.

This is an unresolved validation blind spot: the intermediate subtraction loss
was accepted by tail validation but rejected by the runtime gate. Do not expand
exact-read cast insertion without tracing and fixing the downstream loss and
its validation oracle. Existing execution gates must remain mandatory.

Follow-up: the demonstrated loss was traced to an unconsumed instruction in
branch-return recovery and is now prevented by a Structuring proof guard.
See [the subsequent checkpoint](p0-branch-return-consumption.md) for evidence
and remaining return-path validation risks.

Other Step 9 blockers remain: FPTR caller/callee return propagation and seed-cache
invalidation, the three SORTD failures, QuickC `args`, global lint debt, and a
fresh complete-suite/expanded acceptance audit. No Step 9 completion claim.

Logs: `/home/xor/.cache/terminal-byte-*`,
`/home/xor/.cache/rot-ui-typed-view.*`, and
`/home/xor/.cache/sub-ss-{legacy,current}-consumer.log`.
