# Argument Declaration Ownership

Step 9 checkpoint, 2026-09-12. The full step remains open.

## Cause And Correct Layer

Native `mset_pos` recovery correctly materialized two word arguments. Its body
referenced those exact variables, but angr's unified-local declaration map
retained a byte-sized key named `arg_6`. The entry under that stale key already
pointed to the canonical word argument. Rendering therefore redeclared a formal
parameter as a byte local, and the existing compiled-behavior test failed.

Types/Lowering owns this reconciliation. `stack_argument_identity.py` already
joined exact argument identities and removed their local declarations, but
checked only dictionary keys. `stack_declaration_identity.py` now also proves
member ownership: every well-formed declaration member must refer to the same
exact canonical formal variable. Matching names, overlapping byte ranges or
numeric offsets alone are not evidence.

A key still used by the body refuses removal. Body ownership includes both
physical variables and angr's unified declaration keys. An already canonical
formal does not need its obsolete local-declaration index. No C statement,
read, write, signature or call is deleted or reconstructed by this repair.
The two production modules remain below 350 lines.

## Regression And Acceptance Evidence

- Initial declaration regression: one failed / four passed. It distinguishes
  exact formal membership from a live key, other members, mixed membership and
  empty declarations. A malformed-entry refusal was added afterward.
- A further adversarial unified-key case failed before the body-owner guard:
  one failed / six passed in 19.99s. The guard now retains that live declaration.
- A related prototype test adapter lacked `statements`; it now supplies an
  empty C body, preserving its original argument/name assertions.
- The native `mset_pos` test compiles and executes recovered C. In addition to
  distinct input examples, it checks all 65,536 signed-word input values for
  both modulo outputs and the return value. It does not substitute original C
  for the decompiled body.
- Final five-module run: 43 passed in 44.84s using `PYTHON_JIT=1`, fixed hash
  seed, pytest `-n 7`, short tracebacks and duration reporting. MONOPRIN's string
  corpus behavior test passed in 23.58s; mset_pos took 4.01s.
- Real CLI: `./decompile.py cod/f14/MONOPRIN.COD --proc _mset_pos --timeout 60
  --no-alternate-source-c` exits zero with `validation=passed` and clean
  whole-tail validation. Its output passes `gcc -std=c11 -Wall -Wextra -Werror
  -fsyntax-only`. Adding the unified-key refusal leaves the generated C
  byte-identical: SHA-256
  `16a55b6ca88ddd286b96ea894049eadc897cdb1caefd271179e7b64f8663caaf`.
- Both argument-identity test modules are now in the routine pipeline. Make's
  test lists and the ownership manifest include the projected-argument module;
  the declaration and argument-identity owners have explicit test selection.
- Scoped MyPy passes for both production modules and pipeline/ownership code.
  Ruff --fix passes the declaration owner, mset_pos test and pipeline code.
  Legacy complexity/magic-value findings remain in the argument identity owner
  and older tests; no suppression was added. quality-fast remains red on broad
  lint debt, while the 39-module compiled import smoke passes.

## Broad Results And Open Work

The routine pipeline, before the final unified-key refusal, finished with exit
2: 268 preliminary passes (21.39s), then 4,632 passed / four failed (362.88s).
No production source or tests changed during that run. The failures were
SORTD InitBars, RunMenu, InitMenu, and MONOPRIN __fimemset. The latter reported
uncollected validation in the timeout20 lane; its later isolated pass does not
erase the broad failure. mset_pos and dos_loadProgram passed in the broad run.

QuickC remains 4/4 (80.433s). MS C remains 4/7 (186.154s), with loops_jumps,
function_pointers and pointer_memory still failing decompilation. Slowest
routine tests were RunMenu 151.02s, InitMenu 144.79s, InitBars 107.80s and
MONOPRIN __fimemset 62.29s. These are observations, not controlled speedups.

The final refusal has focused and CLI acceptance, not a refreshed whole
pipeline result. The complete repository collection and expanded gates remain
unrefreshed. Next: reproduce the MONOPRIN broad-lane failure without weakening
its validation, and continue the three SORTD / three MS C semantic blockers.

Logs: `/home/xor/.cache/msetpos-{declaration,unified}-{before,after,ruff}*.log`,
`msetpos-{pipeline,quality,contracts,final-contracts}.log`, and
`msetpos-{fixed,final}.{c,log}`. Diagnostic probes stay outside the repository.
Clock observations include 14:20:16, 14:30:32 and 14:32:38 +02:00; they include
gate waits and do not establish exclusive engineering effort or a finish ETA.
