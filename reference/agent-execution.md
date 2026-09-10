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
- Run linters periodically on changed files, not just at the end. Use the project
  venv, global tool configuration, and `ruff check --fix`; retain mandatory types
  and docs for touched non-test code. Do not expand into unrelated cleanup.
- Use `PYTHON_JIT=1` for Python commands. Run pytest with `-n 7`, short tracebacks,
  and duration reporting so the slowest tests are visible on every run.
- Pass the selected project interpreter to Pyright, for example
  `.venv/bin/pyright --pythonpath .venv/bin/python`; the executable's location
  alone does not ensure it resolves dependencies from that environment.
- Prefer the existing parallel Make linter targets. Avoid overlapping broad test
  gates or concurrent tools writing the same mutable cache.
- Avoid adding to files already over 350 lines where practical. Extract a focused
  owner when warranted, but do not turn a small fix into a size-only refactor.

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
- The shared Ruff configuration enforces `C901` (complexity above 10), `PLR0916`
  (more than five Boolean terms in an if condition), and `PLR2004` (unnamed numeric
  comparison values), alongside existing simplification, type and docstring
  rules. `PLR0916` requires preview mode; preview-only rules require explicit
  selection. Direct Ruff and Make invocations must use this same configuration.
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
- Also verify that a diagnostic run did not return a cached function. For a
  bounded in-process probe, use a temporary cache namespace/directory instead of
  deleting shared caches; confirm actual stage observations before interpreting
  an empty counter as absence of behavior.
- Remove or consolidate tests only after proving duplication, supersession or
  obsolete requirements. Do not reduce coverage, suppress diagnostics, shorten
  timeouts indiscriminately, or hide failures to improve timings.

### Selective Delegation

- Agents may be started on demand, not automatically for every step. Prefer one
  bounded independent task initially; add workers only when expected wall-time
  savings justify their token and coordination cost. Do not delegate the next
  blocking action and then idle while waiting for it.
- Use a lower-cost capable model for bounded test/tooling work and stronger
  reasoning for semantic ownership or difficult root causes when the delegation
  tool exposes model selection. Never claim model control that is unavailable.
- Follow the graph/coverage handoff requirements in `AGENTS.md`. Supply exact
  ownership, current evidence, accepted/rejected experiments, deliverables,
  verification expectations and a stop condition; do not copy unnecessary history.
- Avoid overlapping edits, duplicate investigation, repeated broad profiling and
  concurrent broad gates. Tell agents to preserve others' changes. Review their
  evidence and patches before integration, and close agents when no longer needed.

### Token-Efficient Command Output

- Keep Make's quiet recipe mode enabled; use `make Q=` only when the expanded command itself is needed for diagnosis.
- Keep `RUFF_OUTPUT_FLAGS`, `MYPY_OUTPUT_FLAGS`, `PYRIGHT_OUTPUT_FLAGS`, `PYTEST_OUTPUT_FLAGS`, and `LIZARD_OUTPUT_FLAGS` compact by default; override one explicitly only when deeper diagnostics are needed.
- Prefer tool-native compact modes that preserve findings: Ruff quiet/concise, MyPy plain/no-color/no-summary, Pyright warning-level, pytest short-traceback/no-header, and Lizard warnings-only. Never use Ruff silent, pytest no-summary/warning suppression, Vulture confidence filtering, or similar flags that hide actionable diagnostics.
- For broad gates, retain complete stdout/stderr in a temporary log and report only the exit status, pass/fail/skip counts, failure tracebacks, and slowest tests.
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
