# Full-Suite Audit After BIOS Repair

## Verified Result

Command: `PYTHON_JIT=1 PYTHONHASHSEED=0 make pytest-all PYTHON=./.venv/bin/python PARALLEL_JOBS=7`.

- **11,750 passed, 21 failed, 170 skipped**; 11,941 expected and observed.
- Execution: **1,180.89s (19m 41s)**, excluding inventory collection.
- No missing, unexpected or duplicate node IDs or outcomes.
- Source remained stable: SHA256
  `8e2ead8660391cb6a59149241e4b5ee5d8acbe24b0162e894028b234bc7600cd`.
- Peak RSS: 1,781,488 KiB; no breach of the 2 GiB limit.
- Machine report: `.cache/pytest/partitioned-summary.json`.
- Full log: `/tmp/inertia-full-suite-post-bios.log`.

This supersedes the 11,618/26/170 baseline, not the full project goal. The
routine pipeline separately passed 3,898 tests and all seven MS C tiny round
trips. Global Ruff still fails `quality-fast`; touched-owner MyPy/Pyright and
architecture checks pass. No test was removed, skipped or relaxed for this audit.

The runner also records 49 outcome regressions against its retained accepted
history: 21 failures and 28 skips. That history is not the preceding failed
audit, and does not establish which code change caused each regression.
Missing CMP16 binary coverage accounts for 14 skips; other common reasons
include missing IMOD/ISOD/IHOD/IHOT COD fixtures. Skips remain uncovered work,
not passes, even when the seven separately built tiny examples pass.

## Remaining Failures

All paths below are under `angr_platforms/tests/`. Exact parameterized node IDs
and complete failure details are retained in the machine report.

| Module | Failing cases | Count |
| --- | --- | ---: |
| `test_x86_16_cli.py` | DrawRadarAlt, SetGear, TIDShowRange, small-COD Ready5 | 4 |
| `test_x86_16_cod_regressions.py` | loadprog, overlay function-address bindings | 2 |
| `test_x86_16_cod_samples.py` | `f14_mset_pos` | 1 |
| `test_x86_16_life_decompile_regressions.py` | pause_screen | 1 |
| `test_x86_16_sortd_indexed_aggregate_regression.py` | sidecar-free indexed aggregate load/store | 1 |
| `test_x86_16_sortdemo_regressions.py` | DrawBar, InitBars, DrawFrame, ReInitBars, BubbleSort, two HeapSort cases, main, QuickSort, typed-switch RunMenu, SwapBars | 11 |
| `test_x86_16_string_corpus_anchors.py` | MONOPRIN fimemset | 1 |

Failure observations are not yet complete causal diagnoses:

- LIFE pause_screen raises `PipelineHardError`: unresolved stack locals in
  final C. Preserve this guard and repair the upstream stack projection.
- RunMenu typed-switch coverage reports four unresolved runtime segment helpers.
- TIDShowRange reports rejected DCE validation and restoration; investigate
  the rejected transformation, not suppression of its verdict.
- DrawRadarAlt still takes the timeout path. Its failure also includes a
  hard-coded timeout-message expectation. Fixing that text check alone would
  not establish successful decompilation.
- Several failures are exact spelling/shape/name checks: SetGear `else if`,
  HeapSort's casted array index, ReInitBars' local name, anonymous callees,
  indexed-aggregate assignment spelling and fimemset helper syntax.
  These require comparison against semantic oracles before calling them stale.
- InitBars' missing `fSound = 1` anchor and QuickSort's partition-size comparison
  require checking actual effects and conditions, not merely accepting new text.

## Repair Order

1. **Close hard semantic failures at their owners.** Start with LIFE stack
   leakage and RunMenu segment projection, then TIDShowRange and COD overlay.
   Reason: these can block or invalidate generated C, beyond cosmetic quality.
   DoD: before/after focused regressions, correct upstream evidence, clean tail
   validation, strict unchanged-C compilation and preserved required effects.
   Failure: bypass a hard guard, hide an unresolved helper, guess a value, or
   move recovery into Rewrite/CLI.
2. **Audit exact-text failures with executable contracts.** Reuse the existing
   mset_pos and sort behavior oracles where their scope actually matches;
   otherwise add small strict-C harnesses and corruption controls.
   Reason: reject real regressions without coupling tests to harmless casts,
   temporary names or equivalent control-flow spelling.
   DoD: each replacement proves the same required calls, argument classes,
   returns and memory effects and rejects relevant corrupted output.
   Failure: broaden a regex or remove an assertion without equivalent coverage.
3. **Resolve measured slow decompilation and repeated expensive test work.**
   Reason: full execution is still far above the accepted 335-398s range.
   DoD: profile current failing/slow functions, preserve validation, prove
   coverage before deduplicating, and measure the complete suite afterward.
   Failure: shorten timeouts to hide failures, delete distinct obligations,
   exceed the memory limit, or count a microbenchmark as end-to-end progress.
4. **Clear global lint while preserving mandatory types and documentation.**
   Reason: green tests alone do not satisfy the requested quality gate.
   DoD: shared Ruff configuration and Make gates pass without exclusions or
   weakened thresholds; touched non-test code retains typed, documented owners.
   Failure: ignore warnings, strip types/docs or disable rules to obtain green.
5. **Repeat the complete acceptance audit.**
   Reason: focused fixes cannot establish a repository-wide green baseline.
   DoD: full inventory reconciliation, zero failed tests, explicit skip review,
   all seven MS C round trips, and passing quality gates on a stable source tree.
   Failure: infer totals by subtraction or substitute a curated subset.

## Slowest Tests

| Test | Seconds |
| --- | ---: |
| CLI TIDShowRange | 88.64 |
| COD openfilewrapper direct forwarding | 84.09 |
| InitBars far-pointer setup | 68.91 |
| QuickSort pivot/swaps/recursive calls | 40.17 |
| RunMenu typed-switch artifacts | 37.98 |
| RunMenu default direct path | 36.77 |
| COD loadprog | 33.85 |
| Sidecar-free SORTD Quicksort | 29.40 |

The heavy scheduling wave consumed 1,160.81s with at most two simultaneous
workers; the full runner was configured for seven workers but retained a
conservative heavy-worker limit under the memory contract. Scheduling and
repeated setup need measurement before raising parallelism. This run alone
does not prove that increasing workers is safe or sufficient.
