# Agent Execution Rules

These are mandatory supplemental execution rules referenced by `AGENTS.md`.
They do not relax its architecture or function-fix acceptance contract.

### Regression Tests And Local Gates

- When an issue is reproducible and worth preventing, add a focused regression
  at the responsible layer. Demonstrate failure before the fix and success
  afterward; include relevant boundary and refusal cases. Reuse existing coverage
  rather than duplicating expensive tests without a distinct obligation.
- Test required behavior, not incidental formatting. Replace a brittle assertion
  only with evidence-backed equivalent or stronger coverage; use compiled-C
  behavioral checks when useful. Prove important oracles reject corrupted cases.
- Admit important new regressions to the appropriate routine pipeline. Document
  genuinely slow or external-only coverage and why it is not in the fast lane.
- Add general gates when a demonstrated failure class justifies their runtime
  and maintenance cost. Require an owning layer, clear diagnostics, valid and
  deliberately corrupted controls, and routine-pipeline enrollment. Never treat
  machine-storage validity as proof of emitted-C variable initialization.
- Introduce valuable gates proactively; separate approval is not required.
  Prefer extending an existing gate over adding a duplicate. Check invariants
  at the earliest boundary with sufficient evidence, and report the function,
  stage, violated invariant and relevant typed evidence. Measure added runtime;
  keep cheap checks in the normal path and expensive checks in an explicit
  test lane without weakening mandatory semantic validation.
- Run linters periodically on changed files, not just at the end. Use the project
  venv, global tool configuration, and `ruff check --fix`; retain mandatory types
  and docs for touched non-test code. Do not expand into unrelated cleanup.
- Add linters or enable additional checks when they reliably prevent observed
  defects. Keep configuration shared between direct invocations and Make, test
  enforcement, and report existing debt without hiding or weakening findings.
- Use `PYTHON_JIT=1` and nice 10 for Python commands. Run pytest with up to six
  workers, short tracebacks, and duration reporting so the slowest tests are
  visible on every run. The user-authorized aggregate test limit is independent
  of linter and decompiler pools; concurrent pytest jobs share those six slots.
  Partitioned suites use at most six concurrent serial pytest processes;
  retain their lower heavy/exclusive limits instead of nesting xdist pools.
  The small `decompiler-contracts` precheck caps its pool at two (one for a
  serial request); measured interpreter startup outweighed six-worker gains.
  The wall-budgeted comparator admission stage defaults to two workers (one
  for a serial request), while `PYTEST_WORKERS=6` still governs later suites.
  `COMPARATOR_PYTEST_WORKERS` explicitly overrides this independent pool.
  This avoids observed contention-induced refusals; proof budgets never increase.
  `test-pipeline-fast` waits for contracts and then fail-fast comparator
  admission before launching the broad suite, including under parallel Make.
  Every standalone pipeline tier also runs `binary-budgeted` before the unit
  pool. This phase caps transitive-call proofs at two workers (one when
  requested); six concurrent copies reproduced deadline refusals. Keep these
  controls out of the broad unit inventory, without raising proof timeouts.
  The unit and relational lanes print failed node IDs, phases and existing
  tracebacks immediately through `scripts.pytest_live_failures`; final pytest
  summaries and exit codes remain authoritative. Its subprocess integration
  checks run serially to avoid nesting an xdist pool inside the six-worker pool.
  Use `make ... PYTEST_WORKERS=6` to select six workers in both Make's focused
  tests and the curated pipeline, or pass `scripts/test_pipeline.py
  --pytest-workers 6` directly. The pipeline accepts 1-6 and defaults to three;
  `--msc6-workers` controls external compiler constructs, not pytest workers.
- Pass the selected project interpreter to Pyright, for example
  `.venv/bin/pyright --pythonpath .venv/bin/python`; the executable's location
  alone does not ensure it resolves dependencies from that environment.
- Prefer the existing parallel Make linter targets. Avoid overlapping broad test
  gates or concurrent tools writing the same mutable cache.
- Batch related test nodes in one pytest invocation. Start a fresh interpreter
  per case only when its isolation contract requires it; repeated native imports
  have cost about 20 seconds per otherwise trivial case in this workspace.
- Finish source-writing linters and native builds before provenance-sensitive
  comparator tests. Keep semantic sources and generated artifacts frozen until
  those tests finish: even a comment edit can intentionally invalidate a proof.
  Preserve a rejected run's evidence, then rerun on the stable tree; do not
  relax freshness checks or increase proof budgets to mask the race. Use fewer
  test workers when shared-host contention consumes wall-clock proof budgets.
- Avoid adding to files already over 350 lines where practical. Extract a focused
  owner when warranted, but do not turn a small fix into a size-only refactor.

### KVM Test Requirements

SSA/Z3 comparison, VEX lifting, static IR/Alias analysis, Unicorn replay and
host GCC tests do not require KVM. Mark every test that executes a KVM-backed
DOS runner with `@pytest.mark.requires_kvm`, including indirect compiler
execution through decompiler CLI recompilation validation. Use function-level
marks in mixed modules; mocked runners and missing-tool controls remain static.
The collection hook probes KVM only for marked tests and records unavailable
access as skipped evidence. A skip is not native acceptance. Run the static
subset with `-m "not requires_kvm"` and native execution with `-m requires_kvm`;
keep both in the applicable acceptance run.

### Linter Cadence

Use explicit owned paths, not the entire shared dirty tree. A development
iteration is a coherent edit plus its focused regression, not each keystroke.

| When | Checks |
| --- | --- |
| Python edit iteration | `make lint-iteration FILES="path.py test_path.py"`: Ruff autofix, then the type/doc/owned-access ratchet. Includes new and unpromoted files. Run the relevant focused regression. |
| Completed implementation or changed interfaces | Scoped MyPy (`mypy-files`); inspect skipped-file notices and check new owners directly with shared configuration. Add scoped Pyright for inference, third-party boundaries, or its existing diagnostics; disable watch mode. |
| CLI or layer-boundary import changes | Run `architecture-check-fast` before native or xdist tests; scoped lint/type checks do not validate the architecture import policy. |
| Compiled Python/Cython changes | Applicable mypyc/Cython build and smoke tests after source stabilizes, before proof tests. No rebuild for unrelated Python or documentation edits. |
| Module removal, moves, import/entry-point changes | Basta unused-file scan; Vulture for dead-code changes. These need repository context, not a per-edit loop. |
| Complexity refactors | Scoped Lizard when its metric is relevant; Ruff already checks configured complexity rules every iteration. |
| Documentation-only edits | Review links/content and applicable context checks; no Python linters or compiler smoke. |
| Semantic integration / PR checkpoint | Existing `quality-dev`, `quality-fast`, `quality-hard` and pipeline obligations still apply at their documented checkpoints. Repository-wide typing/dead-code/complexity scans remain integration checks. |

Example (Python processes inherit nice 10 and the configured JIT setting):

```sh
rtk proxy nice -n 10 make lint-iteration PYTHON=./.venv/bin/python FILES="tools/dosunit/owner.py angr_platforms/tests/test_owner.py"
```

Do not run broad MyPy, Pyright, mypyc, Vulture, Basta, or Lizard after every
small edit. Do not rerun an unchanged successful check merely to report it;
rerun when its inputs or dependencies change, a failure remains, or an
integration gate requires it. Finish Ruff autofixes before parallel read-only
checks and freeze semantic sources before proof tests. Keep full diagnostics
in logs; report scope, exit status, counts and actionable failures only.
`lint-iteration` is an inner-loop check, not semantic or full-plan acceptance.

### Clear Code

- Prefer descriptive domain names and straightforward control flow. Code should
  communicate intent without requiring readers to reconstruct the algorithm.
- Add comments where they explain non-obvious reasoning, invariants, constraints,
  or proof obligations. Explain why, not obvious assignments; keep comments
  accurate when changing the implementation. Docstrings remain mandatory.
- Extract meaningful magic values into named, typed constants at their owning
  layer, especially repeated values and domain limits. Do not replace every
  obvious zero or one with a name or introduce configuration without a need.
- Split complex conditions into meaningfully named Boolean variables or focused
  predicates before using them. Preserve short-circuit evaluation, evaluation
  order, side effects, and guards against invalid accesses.
- Extract focused helpers when they clarify a coherent operation or remove real
  duplication. Do not create wrappers or meaningless names merely to satisfy a
  complexity threshold. Apply improvements to touched code, not unrelated files.
- The shared Ruff configuration enforces `C901` (complexity above 10) and
  `PLR0916` (more than five Boolean terms in an if condition), alongside bug,
  type and missing/empty docstring checks. `PLR0916` requires preview mode;
  preview-only rules require explicit selection. Direct Ruff and Make
  invocations must use this same configuration.
- Do not enforce docstring punctuation/layout or blanket numeric-constant
  extraction (`PLR2004`). Register widths, masks and test expectations often
  read better literally; name meaningful domain limits when that adds clarity.
  Explicit branches/loops are allowed instead of forced ternaries, any/all or
  comprehensions. See [the Ruff policy](ruff-policy.md) for rationale and scope.
- These checks are guardrails, not proof of clarity: review comment usefulness,
  descriptive names, constants outside comparisons, and complex expressions the
  rules do not cover. Do not silence findings with blanket exclusions or weaken
  thresholds. Record legacy violations honestly and fix them as files are touched.

### Measured Performance Work

- Optimize code or tests on demand when measurements show a meaningful execution
  or development bottleneck. Correctness remains first; optimization need not
  wait for every other plan step to finish.
- Profile current HEAD before selecting work. Preserve accepted optimizations and
  consult rejected experiments before repeating them. Consider mypyc only for a
  measured residual Python hotspot, with controlled end-to-end evidence.
- Record cache state, worker count, timing conditions, before/after results and
  semantic acceptance. A faster microbenchmark or fewer scans is not an
  end-to-end improvement. Keep plan-specific gain thresholds and memory limits.
- For in-process diagnostic hooks, first prove they execute in the analysis
  worker. Parent counters do not observe forked/clean-worker state. Direct-address
  probes may require both `INERTIA_OTEL_PROFILE_IN_PROCESS=1` and
  `INERTIA_DIRECT_ADDR_FORCE_THREAD=1`; these are diagnostic settings, not defaults.
- For stack sampling, match the existing worker: use
  `INERTIA_FORK_STACK_DUMP_SEC` for fork children and
  `INERTIA_THREAD_STACK_DUMP_SEC` for daemon threads. Verify actual samples;
  an empty log from the wrong switch is not evidence of an idle worker.
  Prefer the matching sampler over changing worker mode for observation.
- Also verify that a diagnostic run did not return a cached function. For a
  bounded in-process probe, use a temporary cache namespace/directory instead of
  deleting shared caches; confirm actual stage observations before interpreting
  an empty counter as absence of behavior.
- Worker stdout/stderr may be captured and discarded on timeout. Write bounded
  diagnostic events to a dedicated file and verify them there; missing console
  hook messages do not establish that a stage was not executed.
- Remove or consolidate tests only after proving duplication, supersession or
  obsolete requirements. Do not reduce coverage, suppress diagnostics, shorten
  timeouts indiscriminately, or hide failures to improve timings.

### Selective Delegation

- Keep agents off the critical path once a reviewable patch and focused results
  exist. Check long tasks at a 15–20 minute checkpoint; if only harness cleanup
  or reporting remains, preserve the patch and take over that bounded work.
  Verify process identity and terminal status when interrupting. A checkpoint
  is not a timeout-based restart, and never waives review or required checks.
- Give workers existing fixtures and one minimal reproducer. Prefer ordinary
  pytest tests to a new standalone diagnostic framework; avoid spending a
  handoff cycle refactoring temporary report scripts to satisfy production
  lint rules. Production code and permanent tests retain their required gates.
- Before changing a shared IR contract, identify its value, address and proof
  consumers and coordinate their updates together; producer-only success is
  not a complete implementation of that contract.
- Integrate a coherent reviewed slice before starting another expansion of it.
  Batch its final focused checks on stable sources. Keep repeated evidence
  refreshes and full gates for changes that invalidate their inputs or for the
  actual integration checkpoint; do not substitute more staging for delivery.
- Agents may be started on demand, not automatically for every step. Prefer one
  bounded independent task initially; add workers only when expected wall-time
  savings justify their token and coordination cost. Do not delegate the next
  blocking action and then idle while waiting for it.
- Use a lower-cost capable model for bounded test/tooling work and stronger
  reasoning for semantic ownership or difficult root causes when the delegation
  tool exposes model selection. Never claim model control that is unavailable.
- Follow the graph/coverage handoff requirements in `AGENTS.md` and
  [reference/devin-handoff.md](devin-handoff.md). Supply exact
  ownership, current evidence, accepted/rejected experiments, deliverables,
  verification expectations and a stop condition; do not copy unnecessary history.
- Avoid overlapping edits, duplicate investigation, repeated broad profiling and
  concurrent broad gates. Tell agents to preserve others' changes. Review their
  evidence and patches before integration, and close agents when no longer needed.

### Token-Efficient Command Output

- View saved logs with `rtk proxy nice -n 10 env PYTHON_JIT=1 .venv/bin/python scripts/compact_paths.py --legend < run.log`. One pass abbreviates all supported paths: `X16/`, `TEST/`, `DU/`, `REF/`, `SCRIPTS/`, and repository-root `./`. These are display aliases, not filesystem paths. Keep full raw logs and use canonical paths in commands, links and proof receipts; never feed compact output into machine validation.

- Keep Make's quiet recipe mode enabled; use `make Q=` only when the expanded command itself is needed for diagnosis.
- Keep `RUFF_OUTPUT_FLAGS`, `MYPY_OUTPUT_FLAGS`, `PYRIGHT_OUTPUT_FLAGS`, `PYTEST_OUTPUT_FLAGS`, and `LIZARD_OUTPUT_FLAGS` compact by default; override one explicitly only when deeper diagnostics are needed.
- Prefer tool-native compact modes that preserve findings: Ruff quiet/concise, MyPy plain/no-color/no-summary, Pyright warning-level, pytest short-traceback/no-header, and Lizard warnings-only. Never use Ruff silent, pytest no-summary/warning suppression, Vulture confidence filtering, or similar flags that hide actionable diagnostics.
- For broad gates, retain complete stdout/stderr in a temporary log and report only the exit status, pass/fail/skip counts, failure tracebacks, and slowest tests.
- Capture both streams with `set -o pipefail; tool 2>&1 | tee file.log | tail -n 40`, or redirect both to the log and inspect it afterward. Preserve the producer's exit status. Do not pipe a required long-running command into `head`: its early exit can terminate the producer through SIGPIPE. Use `head` only on an already saved log. Inspect existing logs instead of rerunning a command merely to recover omitted output.
- On success, do not load the full log. On failure, search or tail only the relevant failure section before widening the read. Parse JSON/JSONL reports for the required fields rather than dumping large profile records.
- Prefer scoped `git diff --stat`, changed-path filters, and narrow file ranges over dumping the shared worktree or large inventories.
- Output reduction must never suppress diagnostics, skip checks, weaken gates, or replace exact test evidence. Optimize noisy test/tool output when encountered without concealing actionable information.
- For fail-fast batched checks, report which batches actually ran; the first failing batch's count is not a repository total. Use `CI=1 make pyright-all PYRIGHT_WATCH=0` for the configured whole-scope audit, state its scope, and separate static diagnostics from failing pytest counts.

### Progress And Checkpoints

- Record plan-step start, end and elapsed time from actual observations; distinguish
  active work, waiting and overlapping agent time. Do not invent timestamps.
- Give progress percentages only with a stated denominator and verified completed
  acceptance items. State uncertainty in estimates instead of repeating an
  unsupported finish time. Focused passing tests are not a green full suite.
- At a user-authorized commit/push checkpoint, include requested concurrent work,
  preserve other edits, exclude temporary artifacts, and verify push completion.
  A checkpoint is not whole-goal completion; record unresolved failures explicitly.

### Context / Compaction Handoff

For shorter displayed paths, use `scripts/compact_paths.py` on saved logs;
`--legend` explains the aliases (see also Token-Efficient Command Output).
Keep canonical paths in commands, source, raw logs and proof receipts. Do not
rename modules just to shorten a report.

Before compaction, create a minimal handoff for the next agent.

Keep only:

- current objective
- non-obvious settled decisions/invariants
- current state
- next 3–6 actions
- active blockers/risks
- files needed for those actions

Do not retain information that can be cheaply rediscovered from the repo.

Delete:

- investigation/history/rejected approaches
- completed commands, logs, tool output
- line numbers and Makefile locations
- constructor/signature details unless currently blocking
- completed test-case inventories
- unrelated/future defects
- duplicated information already in PLAN/PROGRESS
- long path repetitions

Use path aliases when useful.

Completed work: one line per logical milestone.

Relevant files: maximum 8 entries.

Hard limit: 500 words. If the draft exceeds 500 words, rewrite it before compaction.

For every retained fact ask:
"Would the next agent likely make a wrong implementation decision without this?"
If not, omit it.

Do not preserve commands or exact locations solely to save the next agent a grep/search.
