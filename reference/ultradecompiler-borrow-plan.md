# UltraDecompiler QuickC Follow-Up Plan

## Context

The first UltraDecompiler borrowing pass established the boundaries:

- UltraDecompiler is a fixture and edge-case source, not an architecture source.
- DOS execution must use `/home/xor/kvikdos/kvikdos`, not DOSBox-X.
- Inertia keeps its existing OMF/PAT reader, function matcher, compiler/flag
  detector, and evidence-based decompiler pipeline.
- Semantic recovery still belongs in the earliest correct Inertia layer. Do not
  add rendered-C or CLI text repair.

The next useful work is to make the borrowed QuickC examples produce stronger
decompiler signal, not only compile/run signal.

## Goals

### 1. Add Decompile Checks For QuickC Fixtures

The `ultra-quickc-fixtures` lane currently proves that selected borrowed QuickC
sources compile, link, and run through `kvikdos`. Extend it so the generated
`.EXE` or `.OBJ` files are also passed through Inertia decompilation.

Requirements:

- Decompile at least one non-trivial function from each selected fixture.
- Assert generated C exists and the function does not silently disappear.
- Record decompile stdout/stderr, return code, selected function names, and
  validation status when available.
- Prefer focused function decompilation over whole-program sweeps when runtime
  would be too slow.
- If tail validation is available for a fixture/function, require
  `validation=passed`; if not, record the exact reason it is unavailable.

Non-goals:

- Do not require byte-identical C.
- Do not accept prettified output as success without decompiler evidence.
- Do not use source comments, compiler names, or fixture names as semantic
  proof.

DoD:

- The QuickC fixture runner invokes Inertia decompilation for selected generated
  `.EXE` or `.OBJ` artifacts.
- The emitted fixture report contains a structured `decompile` section with
  command, stdout/stderr, return code, target functions, generated-C presence,
  and validation status or validation-unavailable reason.
- A focused test proves a missing target function or empty generated C marks the
  fixture failed.
- At least one real borrowed QuickC fixture passes compile, link, run, and
  decompile checks through `kvikdos`.

### 2. Expand The QuickC Fixture Selection

Move beyond `hello.c` and `add.c` with a curated, deterministic subset from
`borrow/UltraDecompiler/QuickC/PROGRAMS`.

Initial candidates:

- `args.c` for argc/argv and string pointer flow.
- `fptr.c` or `fncp.c` for function pointer/callsite behavior.
- `switch.c` for control-flow structuring.
- `st.c` or another struct-oriented fixture if it compiles cleanly.
- One loop-heavy fixture such as `forlp.c`, `whcnt.c`, or `whsum.c`.

Current fast-lane default: `hello`, `add`, `whsum`, and `args`. `switch` is
tracked as an explicit excluded fixture until its decompile result is
deterministic under the fast-lane timeout.

Selection rules:

- Each fixture must have explicit expected run behavior: exit code and stable
  stdout substring, or a documented reason why stdout is intentionally not
  checked.
- Failing fixtures are excluded with an explicit reason or represented as
  xfail-style evidence. No silent skips.
- Fixture metadata must include source path, toolchain root, compiler, linker,
  library, compile flags, link flags, memory model, run args, expected exit
  behavior, and expected decompile target functions.
- Keep the default set small enough for `tools/dev/test_pipeline.py --tier fast`.

DoD:

- The default selected fixture set contains at least three borrowed QuickC
  programs and is not limited to `hello.c` and `add.c`.
- Each selected fixture has structured metadata for source path, run
  expectations, compile/link flags, memory model, run args, and decompile
  target functions.
- Any candidate excluded from the default set has an explicit reason recorded in
  code or test data.
- `./.venv/bin/python tools/dev/test_pipeline.py --tier fast` still completes
  within the expected lane budgets in the prepared workspace.

### 3. Feed QuickC Outputs Into Compiler Matcher Tests

Use the generated QuickC `.OBJ`, `.EXE`, and `.MAP` outputs as real inputs for
the existing compiler/memory-model/flag detection pipeline.

Requirements:

- Add a focused test or pipeline step that runs the current compiler matcher on
  at least one generated QuickC fixture.
- Assert structured compiler-family evidence identifies Microsoft QuickC or the
  local equivalent classification.
- Assert memory-model and flag evidence is represented structurally, not parsed
  from rendered prose.
- Preserve the existing neural/compiler-flag detector; use QuickC fixtures as
  additional evidence, not as a replacement detector.
- If classifier confidence is below the acceptance threshold, record the raw
  features and expected gap rather than forcing a guessed result.

Non-goals:

- Do not make library/runtime symbol names proof for stack recovery, argument
  values, types, or validation success.
- Do not add corpus-specific allowlists that bypass the normal matcher.

DoD:

- A generated QuickC artifact from the fixture lane is passed into the existing
  compiler matcher or report path in an automated test.
- The test asserts structured family evidence for Microsoft QuickC or the
  repository's existing equivalent classification.
- Memory-model and flag evidence are asserted through structured fields or typed
  result objects, not prose parsing.
- Low-confidence matcher output is represented as an explicit evidence gap with
  raw features preserved, not converted into a guessed pass.
- Existing non-QuickC compiler matcher tests still pass.

### 4. Tighten Callsite Stats Reporting

Callsite materialization now has structured evidence counters and a hard gate
for classified facts with zero materialization. Make those counters visible in
normal decompiler diagnostics so failures are actionable from CLI output and
pipeline reports.

Requirements:

- Surface callsite evidence counters in the decompile profile/report path:
  `raw_fact_count`, `normalized_fact_count`, `classified_fact_count`,
  `materialized_count`, and `failure_count`.
- Include call-target and call-argument subcounts when available.
- Preserve structured fields internally; text rendering is only presentation.
- Add tests proving the report consumes structured stats from
  `CallsiteMaterializationStats`, not regex output from rendered C.
- Keep the hard gate: if classified facts exist and nothing materializes, the
  pipeline fails.

Non-goals:

- Do not add late call argument repair in postprocess or CLI output.
- Do not hide incomplete materialization by lowering severity or changing
  validation wording.

DoD:

- Normal decompile profile/report output includes structured callsite evidence
  counters: `raw_fact_count`, `normalized_fact_count`,
  `classified_fact_count`, `materialized_count`, and `failure_count`.
- Call-target and call-argument subcounts are present when
  `CallsiteMaterializationStats` provides them.
- Tests build a synthetic `CallsiteMaterializationStats` object and prove the
  report consumes that object directly.
- A classified-with-zero-materialized case still raises the existing hard
  pipeline error.
- No test relies on regex over rendered C to prove callsite reporting.

### 5. Run The Required Default Pipeline Gate

The new QuickC lane must work with the normal curated decompiler pipeline, not
only as an isolated command.

Required command:

```bash
./.venv/bin/python tools/dev/test_pipeline.py --tier default --require-external
```

Requirements:

- The default tier includes `unit-focused`, `ultra-quickc-fixtures`, and
  `msc6-tiny-full-pipeline`.
- `--require-external` turns missing `kvikdos`, QuickC, or MSC6 dependencies
  into failures, not skips.
- The summary JSON records all selected lanes, child commands, statuses,
  elapsed time, budgets, and failure reasons.
- This command is the final integration gate for the follow-up plan.

DoD:

- `tools/dev/test_pipeline.py --tier default --require-external` selects exactly
  the expected normal lanes, including `ultra-quickc-fixtures`.
- Missing `kvikdos`, QuickC, or MSC6 dependencies fail under
  `--require-external`; tests cover that behavior.
- A successful run writes summary JSON with selected lane count, pass/fail/skip
  counts, child command details, statuses, elapsed times, budgets, and failure
  reasons.
- The required command passes in the prepared workspace after all other plan
  items are complete.
- The gate does not introduce or require DOSBox-X.

## Delivery Order

1. Extend QuickC fixture metadata with expected decompile targets and richer
   selected fixtures.
2. Add decompile execution to the QuickC fixture importer or a closely related
   pipeline helper.
3. Add focused tests for QuickC decompile report structure and failure handling.
4. Add compiler matcher coverage for generated QuickC outputs.
5. Surface callsite materialization counters in decompile profile/report output.
6. Run focused checks, changed-file checks, architecture check, and the required
   default pipeline gate with external dependencies required.

## Definition Of Done

### QuickC Decompile Checks

- At least one selected QuickC fixture is decompiled through Inertia in an
  automated test or pipeline lane.
- Each decompiled fixture records target function names, decompile command,
  stdout/stderr, return code, generated C presence, and validation status or a
  structured reason validation is unavailable.
- A function disappearing silently is a failure.
- Any accepted semantic improvement has focused before/after evidence.

### Fixture Expansion

- The selected fixture set includes more than `hello.c` and `add.c`.
- Every selected fixture has explicit run expectations and decompile targets.
- Failing or unsupported fixtures are represented with explicit skip/xfail
  reasons.
- `tools/dev/test_pipeline.py --tier fast` remains practical.

### Compiler Matcher Coverage

- Generated QuickC outputs are fed into the existing compiler matcher path.
- Tests assert structured family/flag/memory-model evidence.
- Low-confidence or missing classifications are reported as evidence gaps, not
  guessed successes.

### Callsite Reporting

- Decompiler reports expose structured callsite evidence counters.
- Tests prove the report reads structured stats, not rendered-C text.
- Classified-with-zero-materialized facts still hard-fail.

### Pipeline Acceptance

- `make architecture-check PYTHON=./.venv/bin/python` passes.
- Changed-file checks pass with
  `make check-files PYTHON=./.venv/bin/python FILES="..."`.
- `./.venv/bin/python tools/dev/test_pipeline.py --tier default --require-external`
  passes in the prepared workspace.
- No new DOSBox-X dependency is introduced.
- No new semantic recovery is added to rewrite/postprocess compatibility files.
