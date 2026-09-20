# Ruff Policy

The shared `pyproject.toml` is authoritative for direct Ruff and Make checks.
This September 19, 2026 review prioritizes correctness, durable contracts and
readability rather than making the repository appear green.

## Retained

- Undefined names, unused imports/locals, invalid expressions and suspicious
  constructs: Pyflakes, pycodestyle and Bugbear checks.
- Mandatory annotations (`ANN`) and missing/empty documentation (`D1`, `D419`).
  Useful explanations, Layer/Responsibility and the project's type/doc ratchet
  remain mandatory. Existing per-file legacy exceptions are unchanged.
- Complexity above 10 (`C901`) and more than five Boolean terms (`PLR0916`).
  These expose hard-to-review logic, not merely typography. Prefer meaningful
  helpers and named predicates, not artificial fragmentation to satisfy a score.
- Logging, redundant/ambiguous constructs, supported Python idioms, imports,
  and the other existing bug/simplification checks. Cheap automatic cleanup
  remains useful; only safe fixes are enabled by normal Make invocations.
- Dictionary iteration checks such as `PERF102`: iterating unused key/value
  pairs obscures intent; use keys or values when that is all the code needs.

## Removed Noise

- `PLR2004`: blanket literal-comparison complaints. Sampled findings include
  8/16/32-bit widths, masks, opcodes and explicit test data. Name meaningful
  limits and repeated domain constants by review, not every numeric literal.
- Docstring punctuation, blank lines, section layout and repeated argument
  descriptions. Missing/empty docs still fail; prose must explain the contract.
- `SIM108`, `SIM110` (including former SIM111), `PERF401`, `PERF403`: mandatory conversion to
  ternaries, any/all or comprehensions. Use them when clearer or measurably
  faster; an explicit branch/loop is not itself a defect.

No complexity threshold, safety/type rule, file scope or test selection was
weakened to erase remaining debt. No blanket `noqa` was added. Ruff cannot prove
semantic correctness, comment quality or sufficient tests; architecture,
validation, typing and behavioral gates remain separate obligations.

## Evidence

Before changes, direct repository discovery (`ruff check --no-fix`, JSON)
reported 7,866 findings: PLR2004 5,657; C901 2,005; PLR0916 193; PERF102 11.
The raw local audit is `.cache/ruff-policy-before.json`. This scope is Ruff's
normal discovered files, not the Makefile's curated promoted-file list.
Removing numeric-literal noise does not mean those locations were repaired.

After review: 2,209 findings remain (C901 2,005; PLR0916 193; PERF102 11),
a 71.9% reduction in reported findings, not a 71.9% reduction in code defects.
The curated `make ruff` scope remains red with 2,053 findings (C901 1,858;
PLR0916 193; PERF102 2). Its smaller scope is not the whole-repository audit.

Ruff removed 144 obsolete rule-suppression comments in 57 files. The fix preview
was checked against the resulting files, and every changed line differs only
by its trailing `noqa` comment; no executable code was rewritten. Existing
concurrent edits were preserved. Local evidence: `.cache/ruff-policy-after.json`,
`.cache/ruff-policy-fix-preview.log` and `.cache/ruff-policy-make.log`.

Regression tests in `test_make_linter_inputs.py` execute the real global config
and prove safety, annotations, missing/empty docs and complexity still fail,
while readable numeric comparisons and explicit loops remain allowed. The
existing routine pipeline already includes this test module.
Final focused run: 10 passed in 4.11s with `PYTHON_JIT=1` and `pytest -n 7`.
Direct `ruff check --fix` and Make's `ruff-files` both pass for the test module;
`git diff --check` passes. A full semantic pipeline was not rerun for this
configuration/test/documentation and comment-only change.
