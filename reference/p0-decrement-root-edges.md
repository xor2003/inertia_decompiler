# Decrement Dispatch Root Edges

## Cause And Owner

Layer: Alias. The register-carrier normalizer already followed either unique
typed successor after a DEC condition, but seeded the first DEC only from a
root branch's fallthrough. The compiler's OR AX,AX / JNE dispatch continues on
the taken edge. A live worker trace showed one proven storage seed and zero
classified/materialized DEC conditions; the second comparison was rendered
against 1 instead of the accumulated threshold 2.

The seed now reuses the existing typed successor-selection proof. A unique
compatible taken or fallthrough successor is allowed; two compatible successors
refuse rather than choosing one. No mnemonic decoding, sample address, source
text, rendered-C repair, Rewrite change or new semantic layer was introduced.

## Acceptance

DoD: both root-edge orientations preserve the exact input storage and cumulative
thresholds through mixed signed JGE/JG and JNE conditions; ambiguous root edges
refuse; actual generated C preserves all switch results and saved register state;
MS C round trips and routine gates are rerun with honest remaining failures.

Definition of failure: selecting an ambiguous edge, losing accumulated value
versions, changing signed predicates, bypassing validation, losing saved-register
effects or leaving the simple_control execution result unequal to its original.

## Verification

- Work began approximately 06:19 +02:00 on 2026-09-12.
- Two new controls failed before repair: taken-edge signed-chain propagation
  and refusal of two compatible root successors.
- After repair: 64 Alias/condition-transfer tests passed in 6.55s. This regression
  module was already enrolled in both Make and the Python routine pipeline.
- switch_fold now succeeds on the direct path, with validation=passed and clean
  whole-tail validation. Its shared case-1/case-2 predicate is x <= 2.
- Strict GCC compilation (-O2 -Wall -Wextra -Werror) and execution cover all
  65,536 input bit patterns against the original source's switch semantics,
  checking full SI/DI runtime state preservation. Before: one failure, input 2
  produced 65533 instead of 22. After: zero failures.
- Scoped MyPy passes. Ruff check --fix reports existing complexity, Boolean-term
  and numeric-constant debt. quality-fast remains red on global lint debt; its
  39-module mypyc import smoke passes.

Routine acceptance: 268 early contracts pass, then 4,481 pytest tests pass with
the same three SORTD failures (InitBars, RunMenu, InitMenu) in 193.41s. This run
includes the newly enrolled selector-guard module and the new root-edge cases.
All seven MS C tiny examples pass decompilation, recompilation and execution;
simple_control now exits 255 like its original. QuickC remains 3/4, with args
failing. The whole pipeline is therefore still red.

Final focused verification after documentation corrections: 64 passed in 8.01s.
Full architecture passes, including the explicit Alias ownership header. The
header wording and carrier-seed documentation now describe either-edge selection.
The source file remains below 350 lines. Work finished approximately 06:35
+02:00, about 16 minutes including gates and before/after compiled-C execution.

The switch_fold root-edge defect is repaired; Step 9 remains open for the three
SORTD functions, QuickC args, global quality and stable complete-suite acceptance.

Logs: `/home/xor/.cache/dispatch-root-{before,after,mypy,ruff,switch,quality,pipeline}.log`.
Live typed-condition evidence: `/home/xor/.cache/switch-carrier-before.jsonl`.
Compiled oracle: `/home/xor/.cache/dispatch-root-oracle.c` and the before/after
executables alongside it. The source-controlled root-edge regressions and
existing simple_control round trip are the durable checks for this defect.
