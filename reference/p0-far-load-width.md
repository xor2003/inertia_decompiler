# Far-Load Memory Extent

## Reason And Ownership

Investigation of `__fimemset` found that Capstone underreports the memory
operands of LES/LDS/LSS/LFS/LGS. The installed version reports two bytes even
for an operand-size-overridden LES with a four-byte destination register.
The instruction-summary and fallback stack-width collectors copied that width.
This loses binary evidence needed to reject incomplete argument layouts.

`X86_16/decoded_memory_width.py` now owns normalization at the frontend boundary.
For a far-load source it derives the memory extent from the destination register
width plus the segment word: four bytes for a 16-bit offset, six for a 32-bit
offset. Ordinary operand widths pass through unchanged. Unknown far-load
destination widths yield no proven extent. No argument grouping, storage
identity or pointer type is inferred by this helper.

Both instruction-summary projection and fallback stack-width collection consume
this owner. Existing execution helpers already load offset and segment
separately; no lifter or byte-safe memory execution behavior was changed.

## Acceptance

- DoD: all five far loads expose their full memory extent for both operand
  widths and both decoding paths; ordinary accesses and LEA behavior remain
  unchanged. The new module participates in typing, Ruff and ownership gates.
- Failure: either decoding path loses the segment bytes, reports a guessed
  width, or adds pointer/argument recovery instead of publishing binary facts.
- Before: all ten summary-path binary regressions failed in 5.76s.
- After: 20 summary/fallback cases passed; the widening/argument-width group
  passed 50 tests. Routine pipeline: 4,246 passed in 260.28s, all three lanes
  passed, including seven MS C round trips. Early contracts: 268 passed.
- Final boundary/Make/ownership checks: 83 passed. Two stale ownership-test
  expectations were corrected without removing their assertions.
- Scoped MyPy/Pyright and full architecture pass. New helper/tests are
  Ruff-clean; consumers retain legacy findings. Global `quality-fast` remains
  red on lint debt; the 39-module mypyc import smoke passes.

## Remaining Failure

The fresh `__fimemset` regression still fails whole-tail validation with
uninitialized BP+5/BP+6/BP+7 subviews. This change is not a function fix or Step 9
completion. Next, trace the now-correct decoded extent through the argument
layout and subview materialization owners. Do not force widening from a debug
name, restore the false-positive validator, or patch generated C.

Logs: `/home/xor/.cache/far-load-width-*.log`.

## ABI Consumer Follow-Up

A binary-only in-process trace confirmed reconciliation receives the corrected
`{4: 4, 8: 2, 10: 2}` extent map. The remaining defect is not a stale width.
The separate ABI word collector still records only the first far-load word.
However, expanding that collector to every physical word was experimentally
rejected: its consumers synthesize C arguments without distinguishing live
value inputs from dead memory reads.

The routine compile/run regression `test_stack_word_return_compiles_and_preserves_both_bytes[les-saved-es]`
caught the added unused parameter: LES loads the segment and immediately
restores ES, while only the offset reaches the return. The candidate run had
4,259 passes and one failure in 258.42s. The expansion was removed, not its
regression test. Do not repeat it without liveness and logical-argument evidence.

Accepted independently: ABI stack-word classification now requires an exact
SS:BP address. ES/DS overrides and BP+SI/BP+DI must not become fixed stack inputs.
Four native decoded refusal cases failed before this repair and pass afterward.

- Reason: a BP base alone does not prove stack-space identity or a fixed offset.
- DoD: non-SS/indexed cases refuse; normal BP evidence and the LES return
  compile/run oracle pass; physical width is not promoted to argument arity.
- Failure: wrong-space/indexed memory becomes an SS argument, or dead far-load
  components create required C parameters without proof.
- Final verification: 47 focused checks; 268 early contracts; 4,250 routine
  tests in 270.07s; all three pipeline lanes and seven MS C round trips passed.
  Scoped MyPy/Pyright and full architecture pass. Global `quality-fast` remains
  red on lint debt; its 39-module mypyc smoke passes.
- Fresh `__fimemset`: still validation-failed at BP+5/BP+6/BP+7 (11.56s).
  Step 9 remains open. Next: trace live segment/offset value requirements and
  Alias-owned storage into argument materialization, keeping dead-input and
  live-string-store cases in the same focused acceptance set.

Logs: `/home/xor/.cache/fimemset-width-input-trace.log`, `far-load-abi-*.log`.

## Live-Segment Reduction (Open)

Latest subview follow-up: `wide_stack_argument_views.py` explicitly accepted
only word halves, refusing all byte views of a proven four-byte argument.
It now projects byte reads through the existing typed range helper. Writes,
address-taking and ambiguous owners remain refused. A separate regression
showed that the old word path rewrote address-taking into the address of an
expression; this is now refused too. All four byte positions compile and return
the expected values; the helper is Ruff/MyPy-clean and remains under 250 lines.

The focused run now has 32 passes / one corpus behavioral failure (13.89s).
`__fimemset` passes strict gcc and memory/return checks but fails saved ES/DI
preservation (oracle return code 3). This supersedes the uninitialized-local
failure below, not the outstanding acceptance obligations. Keep the runtime
emitted-variable gate on the plan: repairing this local does not close the
validator's previously demonstrated false-positive class.
Logs: `/home/xor/.cache/fim-byte-subview-{before,after,final}.log` and
`fim-reference-before.log`. Initial fixture-construction failures were corrected
before using the byte/refusal assertions as semantic evidence.

Broad verification: 4,280 routine passes / one saved-register failure in
193.68s, 268 early contract passes, other two pipeline lanes passed including
MS C round trips. Scoped Ruff/MyPy/Pyright and full architecture passed.
See `/home/xor/.cache/fim-byte-pipeline.log` and `fim-byte-architecture.log`.

Rejected diagnostic shortcut: monkeypatching callee-save pruning off in a fresh
binary-only probe executed six times and kept frame saves, but the final C still
had no register restores. Therefore removing that pruning alone is not a fix.
The probe still reported validation success. Trace earlier native output-state
loss and its absolute validation obligation; do not add an output-text repair.
Evidence: `/home/xor/.cache/fim-no-prune-probe.log`.

Follow-up (2026-09-11): the reduced live-segment function now passes final
semantic validation and compiled return-value checks. Its dead-segment control
still takes only one word argument. The earlier candidate lost evidence after
materialization because an unbound SimTypeShort raises on `.size`; resolving
against the actual architecture fixes this without treating slot padding as
initialized input. Logical Alias word owners, exact entry-version bytes, and
current AST reads are all required; adjacent bytes alone do not prove a word.

Caller reconciliation additionally exposed a mismatch between body grouping
`(4, 2, 2)` and four physical word pushes. It now permits groups of complete
source-order physical slots, never splits, missing coverage, or conflicting
explicit logical widths. Signed and unsigned SimTypeChar views now promote to
the full proven dword value, not just a larger storage slot. Grouping regression
failed before (1 failed / 3 passed); byte-promotion regression failed before
(2 failed / 4 passed). The combined focused run passed 37 tests and reached
the corpus test's obsolete helper-spelling assertion.

The replacement corpus oracle is deliberately stronger: strict gcc compilation,
zero/nonzero counts, both direction-flag states, full memory comparison, return,
and saved ES/DI preservation. Its correct implementation and four corrupted
controls behave as expected (5 passed). The actual corpus still fails compilation
on uninitialized `local_5`, despite validation=passed. This exposes an emitted
variable-binding gap after argument widening; initialized stack coordinates
alone cannot prove that a separate C local was assigned. No validation check
was relaxed. Function-fix acceptance and Step 9 are still open.

Logs: `/home/xor/.cache/live-word-{bound-arch,focused,pipeline,quality-fast}.log`,
`live-word-group-{before,after}.log`, `live-word-char-{before,after}.log`, and
`live-word-fim-behavior.log`. In-process COD probes confirmed the live-word
collector executes and the caller census is current, ruling out a stale cached
function as the explanation for the refusal.

Binary `55 8b ec 06 c4 7e 04 8c c0 07 5d c3` loads a far pointer,
copies the loaded ES into AX, restores ES, and returns AX. Unlike the existing
saved-ES/offset-return control, the segment input remains live through AX.

The typed AST trace retains byte reads at entry-SP offsets 4 and 5, correctly
projected by the coordinate registry to BP+6 and BP+7. Generated C nevertheless
returns uninitialized local bytes. Positive-BP planning starts from a contiguous
BP+4 prefix, while its separate word-access inventory lacks the far-load's high
word. This is the current investigation boundary, not a completed repair.

Added `test_live_les_segment_return_has_defined_input_bytes` alongside the
existing native compile/run controls. It checks final structured def-use rather
than prescribing separate-word versus packed-pointer arguments. Current focused
result: **one failed, two passed in 6.82s**; failures explicitly identify BP+6 and
BP+7. The earlier 4,250-pass pipeline predates this new failing regression.

- Reason: isolate the live high-word loss from REP loops and COD annotations.
- DoD: both live input bytes are defined, whole-tail validation passes, and the
  saved-ES dead-input compile/run control remains green; then recheck the full
  `__fimemset` function and routine pipeline.
- Failure: live bytes remain local/undefined, or fixing them invents a required
  argument for the dead-segment control. Raw physical reads alone remain
  insufficient proof of live C arguments.

Logs: `/home/xor/.cache/les-live-segment-defined-before.log`,
`les-live-segment-baseline.log`, and `les-live-candidates.log`.
