# Progress

Current objective: implement `reference/compiler-coverage-plan.md` —
correctness-first compiler coverage with evidence-driven semantic recovery.
Tagged start: `far-pointer-candidates-93c6b401`.

## Completed milestones

- Large-model far-frame argument base proven from terminal `retf` evidence
  (`argument_frame_base.py`, `SimCC8616MSClarge`); far `inc_one`
  `validation=passed` with its argument at machine `BP+6` (commit d3dc07573).
- AGENTS.md hard rule 16 (loud exceptions) added; both silent far-proof
  catch-alls removed; incomplete test mocks completed instead (d3dc07573).
- Far function pointers proven by call-operand width
  (`FunctionPointerParameterFact8616.pointer_width`,
  `SimTypeFarPointer16_8616`); materialization widens the proven slot and
  re-sites later arguments; far-CC survives clinic via
  `PrototypeSource.CCA_DECOMPILER` (commit 2a446ba04).
- Near-model regressions hold: `apply_twice`, `inc_one` `validation=passed`.

## Open work (far obligations, all still unadmitted)

- `apply_twice` far: fn slot and surface are correct (`(BP+6,4)/(BP+10,2)`),
  but body reads still bind to stale near-based merged variables and
  `value` renders as `unsigned long` with `>> 16` reads; validation still
  fails honestly.
- `fill_bytes`/`swap_ptrs`/`offset_copy` far-frame argument reads.
- Candidate manifest reruns for `large-far-pointer-001` and
  `large-far-function-001` once the above validate.

## Verification commands

- Focused regressions: `pytest angr_platforms/tests/...` (277 passing
  across the stack-prototype/GP-restore/CC/fn-pointer suites).
- Single function: `./.venv/bin/python decompile.py --no-alternate-source-c
  --timeout 60 --proc NAME --proc-kind {NEAR,FAR} <EXE>` in the retained
  `.cache/compiler-coverage/large-far-function-001/case-000` artifacts.
