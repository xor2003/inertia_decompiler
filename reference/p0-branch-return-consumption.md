# Branch Return Consumption Guard

Checkpoint: 2026-09-12. Step 9 remains open.

## Root Cause And Gate

An in-process mutation trace located the subtraction loss in the tagged-return
consumer, before Structuring's validation snapshot. Its branch-return scanner
consumed `mov ax,[bp+4]`, silently ignored `sub ax,[bp+6]`, and certified the
previous AX value. The complete native expression was replaced with that stale
value. Exact-read casts exposed this path; they did not cause the omitted effect.

Structuring now requires each instruction's effect to be consumed successfully
or proven to preserve return registers by the existing Semantics owner.
Unsupported operations and failed materializers refuse the candidate. The tagged
consumer records failed evidence and retains the original expression. No new
instruction recovery or Rewrite repair was added.

Reason: partial instruction coverage cannot prove a complete return value.
The check precedes mutation, so the invalid repair cannot become the baseline.

DoD: reject unconsumed writes and failed callbacks; accept preservation controls;
retain the tagged expression on refusal; show before/after failure evidence;
enroll tests routinely; verify execution, types, architecture and corpus results.

Definition of Failure: an unconsumed effect permits replacement of the complete
expression, valid preservation controls fail, or the check is bypassed to pass
compilation or validation.

## Evidence

- Before: 12 new regressions failed / 2 existing tests passed in 5.74s.
- Cases cover memory/register subtraction, implicit multiply outputs, AX/EAX,
  DX and byte-register writes, an unknown operation, and failed load/ALU/inc
  materializers. Four real-Capstone preservation controls pass as well.
- A consumer test verifies that failed proof retains the entire tagged expression.
- Final focused surface: 148 passed in 5.96s, pytest `-n 7`.
- With the formerly failing casts injected, real `sub_ss` retains `return a - b`;
  observed callback calls confirm execution. Its emitted C compiles with
  `-std=c99 -Wall -Wextra -Werror` and passes 327,680 subtraction/GP-preservation cases.
- Routine lane: 4,415 passed / the same 3 SORTD failures, 204.52s.
- MS C tiny: 6/7 passed, including scalar_types_io; FPTR and QuickC remain red.
- Scoped MyPy, full architecture and changed test/tooling Ruff pass. Ruff used
  `--fix`; large-module lint debt remains. `quality-fast` is lint-red, with its
  39-module mypyc import smoke passing. No complete-suite claim.

Observed verification window: 03:53:54 to 04:05:10 +02:00, 11m16s including
investigation and gate waits, not a measurement of total active engineering time.

## Remaining Work

This prevents the demonstrated corruption, not every validation blind spot.
Audit jump completion next: the existing scanner can return a recovered value at
a jump before examining its destination. A jump alone does not prove a completed
return path or preservation of the return registers.

Follow-up: the shared consumer now validates that destination before accepting
the provisional value. See [jump-completion evidence](p0-return-jump-proof.md).

Step 9 also retains FPTR prototype dependency invalidation, three SORTD
initialization failures, QuickC args, global lint debt, and fresh complete and
expanded acceptance audits. Do not close Step 9 from this checkpoint.

Logs: `/home/xor/.cache/branch-return-consumption-*`,
`/home/xor/.cache/sub-ss-return-mutations.log`, and
`/home/xor/.cache/sub-ss-guarded-casts.log`.
