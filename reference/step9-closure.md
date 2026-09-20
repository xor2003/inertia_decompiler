# Step 9 Closure Ledger

Bounded Step 9 is complete on September 19, 2026 under the user-approved
[acceptance contract](step9-acceptance-contract.md). Stop after this step.
Unrelated work remains in [the backlog](post-step9-backlog.md); it is not done.

## Source And Artifact Identity

- Declared SORTD MZ image: 26,432 bytes, SHA256
  `09e3ce9746b96ebc2fdefd73f34cdf63c1be6acf6c2736c8fc89db595f2ce798`.
- Production manifest: 1,051 files, digest
  `0e6d25693be5c59bbf8d65eedf920e6405b4723ce9162fb2b9aa3ab17840368c`.
  Rechecked after final acceptance; this is not a whole-worktree commit hash.
- Saved C: `SORTD.default-check.dec`, SHA256
  `9c82793b3e08d400ccfef813f15faf8019c80b4d75717a7d94e97583a2b8a897`.
- Worktree is based on `37fc06c52925a335dac3597c6b5c5edb9e945a58` with
  uncommitted changes. These results do not describe that commit alone.

## Requirement Audit

1. Whole-binary semantics: the exact frozen 20-address inventory emits C;
   all 20 validate. Selected/queued/attempted/decompiled and every evidence
   counter are 20; failures, empty output, timeouts, tracebacks and violations
   are zero. See [acceptance JSON](step9-sortd-acceptance.json).
2. Compilation and behavior: explicit C compilation returns zero with zero
   errors and zero warnings; see [compiler JSON](step9-sortd-compilation.json).
   Generated behavior passes for 19 functions, excluding main. RunMenu's
   executed regression and deliberate call/ESC/argument corruption controls
   are included in the passing routine pipeline. No warning suppression was
   needed; reviewed warnings are permitted by the user's clarified policy.
3. Comparison: the [current semantic review](step9-current-comparison.md)
   covers all 20 bodies. All 20 saved-C line links were checked against function
   definitions. Historical Ghidra/Reko evidence and missing peer functions are
   labeled; peer/source information is not semantic recovery input.
4. Final source-stable gates: the results below are terminal, not pending jobs.
   Existing unrelated quality failures are disclosed rather than waived as green.

## Gate Results

All Python runs use `PYTHON_JIT=1` and the project venv; pytest uses `-n 7`.

| Gate | Observed result | Evidence |
| --- | --- | --- |
| Focused changed-owner regressions | 229 passed, 7 warnings, 16.94s | `.cache/step9-final-focused.log` |
| Scoped Ruff/MyPy/type/doc checks | exit 0 | `.cache/step9-final-scoped-linters.log` |
| `make mypy` | exit 0 | `.cache/step9-final-mypy.log` |
| Architecture and test ownership | exit 0 | `.cache/step9-final-architecture.log` |
| `make quality-fast` | exit 2, existing global Ruff debt; not green | `.cache/step9-final-quality-fast.log` |
| `make quality-hard` | exit 2 at Ruff; later sequential gates not claimed run | `.cache/step9-final-quality-hard.log` |
| `make test-pipeline` prerequisites | 268 passed, 7 warnings, 10.74s | `.cache/step9-final-pipeline.log` |
| Routine pipeline lane | 5,861 passed, 7 warnings, 352.04s | same log |
| QuickC external lane | 4 fixtures pass, 42.704s | pipeline summary JSON |
| MS C tiny full round trips | all 7 pass, 135.881s | pipeline summary JSON |
| Whole SORTD gate | exit 0, 20/20 | `.cache/step9-final-sortd.{json,txt,log}` |
| Generated translation unit | exit 0, 0 errors, 0 warnings | `.cache/step9-final-compilation.json` |
| Generated behavior | exit 0, 19 functions | `.cache/step9-final-behavior/` |

Pipeline summary: `angr_platforms/.cache/test_pipeline/summary.json`, written
22:55:33 +02:00; selected 3, passed 3, failed/skipped/timed_out 0. Seven MS C
constructs are compare16, simple_control, loops_jumps, storage_classes,
function_pointers, pointer_memory and scalar_types_io; each records build,
original execution, decompilation, recompilation and generated execution passing.
Do not sum overlapping focused/prerequisite/routine tests as unique coverage.
The routine lane exceeds its configured 30-second budget; no speed claim is made.
Its slowest test is RunMenu's sidecar-free ESC regression at 86.95s.

Whole SORTD started 22:44:13; pipeline ran approximately 22:46:31-22:55:33
(9m02s including prerequisites and external lanes). These are observed run
windows, not an invented total development effort estimate.

## Reproduction And Limits

Run `make test-pipeline PYTHON=./.venv/bin/python` and the quality commands
above with `PYTHON_JIT=1`. Whole SORTD used `PYTHONHASHSEED=0` and:

```sh
.venv/bin/python scripts/check_sortd_sidecar_free.py --source-binary SORTD.EXE \
  --transcript-out .cache/step9-final-sortd.txt \
  --report-out .cache/step9-final-sortd.json \
  --function-c-dir .cache/step9-final-sortd-functions
.venv/bin/python scripts/check_generated_translation_unit.py \
  --function-c-dir .cache/step9-final-sortd-functions \
  --output .cache/step9-final-combined.c --report-out .cache/step9-final-compilation.json
.venv/bin/python scripts/check_sortd_generated_sort_core.py \
  --transcript .cache/step9-final-sortd.txt \
  --function-c-dir .cache/step9-final-sortd-functions \
  --build-dir .cache/step9-final-behavior
```

This is not proof of all-path linked DOS equivalence, a green full pytest
collection, or a fresh Ghidra/Reko run. Global Ruff and separately documented
full-suite failures remain open. Codebase-memory MCP transport was unavailable;
source inspection was used, with no index-completeness claim. Temporary logs
may be cleaned; the saved C, JSON reports and this ledger retain the checkpoint.
