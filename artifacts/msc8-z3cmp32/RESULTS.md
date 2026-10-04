# Verdict hardening (schema v2)

Two regressions reproduced the old behavior before the fix: a matched CFG could
report PASS with no passing block evidence, and constant relocation could hide a
changed scalar return while producing PASS/exit 0. Both are fixed.

- Complete identified records and consistent counters are required for PASS.
- Relocation-dependent equality is now `conditional`, counted separately, exit 2.
- The 25-test suite covers missing/duplicate/wrong/unknown/aborted evidence as well
  as real VEX/Z3 behavior and changed-code controls.
- Replaying all six saved backend reports retains all 43 unconditional proofs,
  including LINK's five. This is evidence replay, not a rerun of the full batch.
- Fresh selected LINK run: 5 passed, exit 0. Fresh CL `sub_1C96E`: 1 mismatch,
  exit 1. Fresh normalized C23216 `sub_593B0`: 1 conditional, exit 2.
- Current evidence: `results/verdict-v2-*`, `verdict-audit.json`, and
  `verdict-before.log` / `verdict-after.log` / `verdict-check.log`.

# Earlier full-batch baseline

The six-target batch compares current GCC-built ELF32 candidates to original PE32 binaries.
It uses the strict default EAX/EDX/ESP return contract, preserved state, and whole memory.
No global-address normalization was applied to the batch. Mismatches are untriaged proof failures, not confirmed C bugs.

| Target | Mapped | Proved | Mismatch | Refused |
|---|---:|---:|---:|---:|
| C13216 | 1008 | 9 | 15 | 984 |
| C1XX3216 | 2010 | 21 | 32 | 1957 |
| C23216 | 1298 | 7 | 6 | 1285 |
| C33216 | 589 | 1 | 3 | 585 |
| CL | 259 | 0 | 1 | 258 |
| LINK | 821 | 5 | 80 | 736 |
| **Total** | **5985** | **43** | **137** | **5805** |

Q23 was not included: it is Phar Lap, not PE32. Detailed per-function verdicts are in `results/batch/<target>/compare.json`.

## Requested examples

| Function | Binary | Current evidence |
|---|---|---|
| sub_27320 | C13216 | Proved against current ELF32; hash extraction agrees with tests/func/C13216.c |
| sub_4A8AC | C1XX3216 | Proved against current ELF32; signed 16-bit size helper agrees with tests/func/C1XX3216.c |
| sub_593B0 | C23216 | Proved conditionally under recorded symbol relocation against a separately built non-PIE candidate; nibble extraction agrees with tests/func/C23216.c |
| sub_26870 | C23216 | Refused: reachable calls; not a pure leaf over all inputs |
| sub_2B0F0 | C23216 | Refused: reachable calls |
| sub_1D216 | CL | Refused: explicit VEX division-exception edge in matched-CFG mode |

An additional C1XX3216 sub_4A964 matched-CFG trial fails strict block-state comparison (EDX internally and EAX at returns). No decompiled C was changed.

## Controls and validation

- Relocated synthetic cyclic CFG passes by block induction; a dec-to-inc mutation fails.
- Hash-mask mutation, CCall operand mutation, stack-pop mutation, partial-register preservation, unsupported control flow, floating-point refusal, and scoped patch restoration are regression-tested.
- Original PE32 versus itself: sub_593B0 passes. sub_26870 and sub_2B0F0 remain refused at calls. This validates the PE candidate path, not the future self-hosted build.
- Focused pytest: 13 passed (36.61 s); Ruff including complexity rules: passed; Pyright: 0 errors. Detailed results are in local logs.
- All seven existing *_ftest.exe runtime attempts ended with SIGSYS (signal 31); zero checks were observed. The claimed earlier 205 passing checks were not reverified.
- quality-dev and quality-hard stop at pre-existing repository Ruff/type failures outside this adapter. The combined quality command stopped before quality-fast. A separate global linters run also failed on existing Ruff/type debt and a mypy internal error. No full green gate or decompiler improvement is claimed.

## Reproduction

Use README.md commands. `nonpie-build-command.txt` and `nonpie-build.log` record the isolated GCC build, which writes only C23216-nonpie.exe here. The rebuild source tree and its out/ binaries were not changed.

The original PoC baseline is in .cache/z3cmp32/baseline under vextest: both lowerings refused and its comparison summary was zero, yet its exit status was 0. The new driver retains every requested obligation and exits 2 for an incomplete run.

MSC-built candidate binaries do not exist yet; testing them remains pending. Callee composition, different-shape CFG equivalence, division-exception semantics and general pointer relocation remain open.
