# Test Overlap Review: 2026-09-10

## Measured Pilot

Actually ran `/home/xor/pytest_deduplicate/pytest_deduplicate.py` against
`test_x86_16_vex_bit_source.py` and `test_x86_16_direction_flag_execution.py`,
with application scope `angr_platforms/angr_platforms/X86_16`, branch coverage
and call-phase comparisons. Installed coverage 7.16.0 and pytest-cov 7.1.0
in the existing venv using uv; no project dependency files were changed.

- Seven-worker pytest-cov run: 48 passed in 13.68 seconds. Import was rejected:
  workers did not provide test-body exclusions or tracing-core metadata.
  This is not usable overlap evidence; the integration cause is uninvestigated.
- Supported serial context collector: 48 passed in 26.72 seconds;
  analyzer elapsed 27.03 seconds, exit 0, no analyzer errors.
- 42 review findings: 10 identical-coverage groups, 30 containment findings,
  two combined-coverage findings. These are not 42 removable tests.
- No tests removed from this pilot. Width, selected-bit position, operand order, instruction
  and initial DF state can protect different semantics despite matching arcs.
  Stability and sampled mutation checks have not been run.

Temporary evidence: `/tmp/inertia-deduplicate-direction-serial.json`, matching
`.html` and `.log`. The rejected parallel manifest is
`/tmp/inertia-deduplicate-direction-outcomes.json`.
This bounded pilot does not profile or deduplicate the full suite.

## Expensive-Test Inspection

In `angr_platforms/tests/test_x86_16_cod_regressions.py`, the three
`_openFileWrapper` cases use the same `_run_cod_proc` command and default
timeout. Their latest full-audit durations total 315.86 test-seconds, not
necessarily wall-clock seconds saved. All invoke a subprocess, whose internal
Python coverage is not established by this pilot.

The recoverability, forwarding and declaration checks have distinct assertions.
Prefer sharing an immutable decompilation result over deleting obligations.
The helper-signature test accepts `anchors` but never checks them: investigate
and restore its intended obligation instead of treating a weak pass as proof.
Several checks also accept partial/failed decompilation and then return early;
their passing count is not evidence that the semantic assertions ran.

### Manually Reviewed Consolidation

Deleted these two redundant parameterized executions from
`test_x86_16_cod_regressions.py`:

- `test_cod_regression_targets_are_recoverable[EGAME2.COD-_openFileWrapper-20]`
- `test_cod_known_helper_signatures_are_declared[EGAME2.COD-_openFileWrapper-anchors2]`

Retained `test_cod_openfilewrapper_direct_forwarding` now enforces the union
of their existing assertions from one identical CLI invocation:

- Original status/partial-result classification is unchanged.
- Function discovery marker is mandatory even for accepted partial output.
- Successful output must contain path/mode and reject empty decompilation,
  missing types and all three previously forbidden forwarding artifacts.

Eight cheap corrupted-output tests independently verify these obligations and
one invocation per case. They mock only this test's subprocess helper, not the
production pipeline. They do not prove actual decompiler correctness; the
retained integration test still runs the real command. No unused `anchors`
expectation is claimed as coverage that existed before consolidation.
This removes two expensive executions, not merely a coverage-based guess.

The same review then removed six further repeated invocations: four remaining
recoverability cases (BIOS clear-key-flags, DOS get-free-space, load-overlay and
get-return-code), and two declaration cases (get-free-space and load-overlay).
Their existing obligations now run in the corresponding dedicated behavior
regressions. `scripts/pytest_inventory_review.py` maps all eight retired node IDs
to their replacements. The unused signature-anchor data was removed with the
redundant function; it was never asserted and is not claimed as preserved proof.

Verification:

- Open-file integration plus eight negative guard cases: 9 passed, 7 warnings
  in 43.23 seconds; real decompilation call 33.55 seconds.
- Four remaining retained integrations: 4 passed, 7 warnings in 19.42 seconds;
  slowest call get-free-space 10.08 seconds.
- Eight removed launches totaled 220.05 test-seconds in the previous full audit.
  Cache/load conditions differ, so no controlled end-to-end speedup is claimed.
- Eight new cheap negative cases replace eight expensive repeated cases in the
  collection count; reducing runtime, not artificially shrinking counts, is
  the purpose. The cheap cases are admitted to Make and the routine pipeline.
- Retirement/profile and negative-guard gate: 14 passed in 14.10 seconds.
  Scoped Ruff `check --fix`, MyPy, Pyright and `git diff --check` pass.
  The full suite has not been rerun after consolidation.

### Faster Tests That Do Not Supersede Integration

The small `test_cockpit_cod_module_proves_tidshowrange_result_is_unused` proves
caller-return liveness and its evidence census, not the generated body, call
counts, argument expressions or whole-tail validation. The SetGear caller test
similarly checks result/argument evidence, not branch and state-store output.
They do not supersede the slow CLI tests, which remain necessary and currently
expose failures. Tail-validation record tests use synthetic summaries rather
than executing those functions.

RunMenu's two slow source-assisted/default tests also differ: one enables typed
switch artifacts and alternate source, while the other explicitly forbids
alternate source. The stripped sidecar-free test is a third distinct contract.
Do not consolidate these into one altered execution configuration.

## Ordered Work

1. **Validate parallel collection.** Reason: serial instrumentation of the
   entire suite would be expensive. DoD: a small seven-worker run imports with
   complete call contexts, worker metadata and bound outcome/source hashes.
   Definition of Failure: missing worker coverage or accepting an incomplete
   manifest. Status: open; supported serial pilot complete.
2. **Share expensive equivalent setup.** Reason: three repeated subprocess
   invocations dominate the inspected group. DoD: verify environment, timeout,
   cache and isolation equivalence; run decompilation once per compatible group,
   retain all assertions, test the invocation count, and measure uninstrumented
   before/after timing. Definition of Failure: hiding an isolation regression,
   weakened assertions, or treating separate xdist-worker caches as one run.
   Status: the openFileWrapper group is consolidated with all existing checks;
   controlled whole-suite timing remains open.
3. **Review overlap by behavioral obligation.** Reason: equal arcs do not prove
   equal fault detection. DoD: map candidates to requirements and assertions;
   use bounded stability/fault checks where useful; document each retain,
   combine or removal decision. Definition of Failure: deleting width/flag/
   boundary cases merely because coverage matches. Status: pilot evidence only.
4. **Re-audit the whole suite.** Reason: local savings are not suite closure.
   DoD: all collected nodes accounted for, zero unexpected failures, justified
   skips, unchanged semantic gates, and full-suite runtime at most 398 seconds
   on the documented host/cache configuration (300 seconds remains preferred).
   Definition of Failure: omitted tests, suppressed diagnostics, weaker
   validation, or using instrumented timings as production speedup evidence.
   Status: open; latest full baseline remains 11326 passed, 40 failed,
   170 skipped in 1326.65 seconds.
