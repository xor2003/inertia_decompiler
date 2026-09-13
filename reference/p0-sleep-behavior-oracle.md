# Sleep Acceptance Repair

Checkpoint: 2026-09-10, completed checks at 19:34 CEST. Individual measured
runs: baseline 17.18s, focused acceptance 9.75s, final wiring 19.05s. These
are test elapsed times, not a reconstructed total implementation duration.

## Reason And Owner

The existing Sleep regression rejected `(long)clock() > (long)goal` because
it required the literal `clock() > goal`. The source in `SORTDEMO.C` waits
while `goal >= clock()`. Signed comparison casts are not a semantic defect.
This repair belongs in test acceptance, not production lowering or Rewrite.

## Acceptance

DoD: unchanged generated C compiles under GCC C11 with `-Wall -Wextra
-Werror`, executes the source deadline contract, preserves existing validation
and shape guards, and the oracle rejects compilable semantic corruptions.

Definition of failure: weakened validation, generated-C editing to satisfy
the compiler, loss of signed/deadline behavior, or a corrupted implementation
passing the oracle. Host-long execution is not proof of 32-bit overflow.

The deterministic clock checks 50 combinations of negative and nonnegative
starts/waits, including values above 16 bits. All arithmetic stays within the
signed 32-bit domain. Exact clock-call counts distinguish strict versus
inclusive deadlines, missing/reversed loops, truncated goals, wrong deadline
arithmetic, extra calls and unsigned comparison. An in-harness call limit
rejects runaway loops without waiting for the subprocess timeout.

## Evidence

- Before: the real Sleep anchor test failed on its exact-text assertion.
- After: 19 focused tests passed in 9.75s, including seven independently
  compilable corruptions rejected by the execution oracle.
- Final: 131 tests passed in 19.05s, covering both real Sleep routes, oracle
  controls, stack-validation controls, ownership and pipeline wiring.
- Positive stack controls now accept equivalent independently regenerated
  initializers at BP offsets -4, 0 and +4; removed/changed values still fail.
- New helper, controls and touched pipeline/ownership files pass Ruff.
  The helper passes MyPy and Pyright. The legacy SORTDEMO regression module
  retains 34 Ruff findings; none were suppressed.
- Oracle tests are admitted to Make's routine checks, the test pipeline and
  ownership manifest. No production semantics changed in this follow-up.

The full-suite baseline remains 11,478 passed, 23 failed, 170 skipped. It was
not rerun or arithmetically updated from focused repairs. BIOS strict-C
unused locals and the remaining semantic/lint failures remain open.
