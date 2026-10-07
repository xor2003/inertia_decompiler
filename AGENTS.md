# Inertia Decompiler

## Mission

Correctness first. Evidence-driven C. No guessing. Readable only when proven.

## Priority order

1. All functions must decompile to generated C (no crashes, no silent disappear)
2. Tail validation must pass (`validation=passed` = semantic equivalence)
3. Generated C must be recompilable (portable-flat gcc → MS C DOS)

Readability, names, structs, arrays: P1/P2 unless required for above.

## Core pipeline (DO NOT BREAK)

```text
IR → Alias → Widening → Types → Structuring → Rewrite
```

Semantics must be introduced as early as possible, never in rewrite.

Core model: all reasoning on `Value` (data), `Address` (memory segment+offset),
`Condition` (branch meaning).

## Layer ownership

- `frontend`: architecture, control coordinates, MZ/NE loaders, interrupt contracts,
  DOS SimOS, VEX lifter, sidecars, adapters and native-backend verification in
  `inertia/frontend/x86_16/`
- `IR`: `inertia/ir/`
- `semantics`: `inertia/semantics/`
- `alias`: `inertia/alias/`
- `widening`: `inertia/widening/`
- `traits/summaries/confidence`: their owning `inertia/` layer (see `reference/project-map.md`)
- `types/lowering/object recovery`: `inertia/lowering/`
- `structuring`: `inertia/structuring/`
- `rewrite/cleanup`: `inertia/postprocess/`
- `tail validation`: `inertia/validation/`
- `CLI/fallback/reporting`: `inertia/cli/`

Semantic recovery → the owning `inertia/` layer. Cleanup-only → `inertia/postprocess/`. Import canonical owners directly; do not recreate historical forwarding files.

## Hard rules

1. **Solve at correct layer** — alias in alias, types in types, never in rewrite
2. **Alias-first** — storage identity from alias only, widening after alias proof
3. **Segmented memory** — SS/DS/ES are distinct spaces. `Address(space=SS, offset=...)` not `(seg<<4)+offset`
4. **Stack → Variable** — `SS:BP+offset` → `local_*`/`arg_*`. Not stack[x], not raw pointer arithmetic
5. **Explicit conditions** — `if (x < y)` not `if (tmp_14)` or `if (flags & ...)`
6. **No text-based recovery** — only IR, CFG, alias, typed structures. No regex on asm or rendered C.
7. **Rewrite boundary** — cleanup/naming/formatting only. No alias/type/semantic recovery, no call-argument/signature/body repair.
8. **Validation is truth** — compare register effects, memory writes, return values, control flow. No hiding `changed`/`uncollected`.
9. **No guessing** — insufficient evidence → honest ugly output.
10. **Determinism** — same input → same output.
11. **Typed status/state, not text matching** — for any new work, represent statuses/verdicts with enums or structured fields instead of string matching/parsing.
12. **Dot access for owned contracts** — use `obj.field` for owned/internal dataclasses, enums, state, and pipeline contracts. Avoid getattr/setattr; use `getattr`/`setattr` only at dynamic third-party/angr/codegen/plugin boundaries with a clear reason. Existing avoidable dynamic attribute access is cleanup debt and should be removed when touching nearby code.
13. **Docstrings and types ratchet** — types are mandatory for non-test code: every new or touched non-test module must state `Layer:` and `Responsibility:`, and every new/touched function, method, dataclass, enum, and pipeline contract must keep explicit type annotations and useful docstrings on public owned definitions. Do not strip docs/types to silence tools; legacy missing docs/types are cleanup debt and must be fixed when touching nearby code.
14. **Behavior must outlive its implementation** — important behavior must be recoverable from typed contracts, tests, and documentation, not exist only as an implicit peculiarity of the current code. When changing or replacing a module, preserve its required behavior in those durable sources before relying on a new implementation.
15. **Keep all projections coherent** — after changing one concept, update every owned representation of it so IR, typed contracts, consumers, diagnostics, documentation, and tests describe the same behavior. One concept has one authoritative owner; other layers consume or derive from that owner rather than creating competing truths.
16. **Loud exceptions** — never swallow exceptions broadly. `except Exception:` that silently substitutes a default (e.g. "proof failed → near") masks real defects and is forbidden. Catch only the specific exception types that name the boundary condition being handled; when a surface genuinely cannot produce evidence, return the typed non-result (`complete=False`, `UNKNOWN_REFUSE`, empty evidence) so the pipeline records "no proof" instead of guessing. An exception that survives to the user must carry its cause. If a test mock cannot satisfy a production call, fix the mock — do not add a catch-all in production to accommodate it.

If a fix makes output prettier without improving underlying semantics, it is wrong.

## Agent execution rules

DO: push semantics earlier, prefer generic typed effects, make register/segment/flag/condition/memory impact explicit, track liveness across branches/loops/calls, prefer static recovery with runtime only as refinement.

DON'T: build recovery around compiler/library names, assume nice frames/conventions/loops, leave semantics in raw VEX tmps, treat timeout fallback as final architecture, solve live flag/segment/loop state in rewrite, use text-pattern recovery over rendered asm/C, depend on runtime traces as sole semantics source.

Sidecars/COD/debug listings are optional evidence only. They may provide labels, function bounds, and names, but must not be required for argument values, types, control-flow semantics, stack recovery, memory modeling, or validation success. The decompiler must work from binary IR/CFG/alias/typed effects for general 16-bit segmented binaries.

## Anti-patterns (never, unless explicitly marked temporary rescue)

- sample-specific address hacks, symbol-name hacks as proof, shape-only widening
- binary/function-specific C postprocess fixes, missing-argument fill-ins, signature rewrites, or whole-body replacements
- flatten-segment-for-convenience, guessed structs/arrays/helpers
- rewrite-stage semantic repairs, silent fallback as success
- `if "...substring..." in asm_text`, regex over assembly lines
- name-based helper substitution as recovered semantics
- corpus-specific allowlists, address-specific helper substitution
- avoidable `getattr`/`setattr` on owned Inertia objects instead of explicit dot access
- removing docstrings or type annotations to pass checks instead of improving the owned contract
- `except Exception:` catch-alls that silently substitute defaults, or widening production catches to accommodate incomplete test mocks

## Execution discipline

Every semantic improvement needs closed evidence loop: `raw_fact_count`, `normalized_fact_count`, `classified_fact_count`, `materialized_count`, `failure_count`. If `classified > 0` and `materialized == 0`, pipeline must fail.

### Persistent startup contract (do not relax)

- Inertia is an **evidence-based decompiler in every layer**.
- DCE is allowed only when evidence is collected and consumed (not guessed).
- Unknown classification means **refuse and keep code**, never delete.
- Passing gcc by deleting semantically live code is a hard failure.

### Function-fix acceptance contract (mandatory)

- For every function being fixed, run a focused function regression before and after changes.
- If original C/COD source exists, compare output shape and call semantics against source:
  required calls must survive with correct argument classes (value vs pointer).
- Do not mark a function “fixed” unless:
  1) `validation=passed`,
  2) no semantic call loss,
  3) output is closer to original C than previous baseline.
- Any DCE candidate without full evidence is `UNKNOWN_REFUSE` and must be kept.

## Review checklist

1. What layer? Why earliest correct layer?
2. What invariant does it fix? What test proves it?
3. What corpus result improved? What might regress?
4. Architectural or temporary rescue? If temporary, what replaces it?

## Improving code

- Fast iteration per coherent Python edit on explicit owned paths:
  `rtk proxy nice -n 10 make lint-iteration PYTHON=./.venv/bin/python FILES="owned.py test_owned.py"`
  (Ruff + type/doc/access ratchet), then the focused regression. Scoped
  MyPy/Pyright/Basta/Vulture/Lizard, Cython builds, broad scans and repeat-check policy:
  [Linter cadence](reference/agent-execution.md#linter-cadence). Documentation-only edits need no Python lint.
- Run Python/pytest at nice 10 with `PYTHON_JIT=1`; share at most six test workers; retain
  full logs and report scope, exit status, counts and actionable failures.
- Mandatory guidance: read and follow
  [reference/agent-execution.md](reference/agent-execution.md) at startup and after compaction
  (regression, performance, delegation, token-output, progress, compaction-handoff rules). This file
  remains the canonical architecture and acceptance contract; `CLAUDE.md` supplements and never overrides either file.
- Regular local gate: `make quality-fast PYTHON=./.venv/bin/python`.
  `make test-pipeline PYTHON=./.venv/bin/python` before claiming semantic decompiler improvements.
  `make test-pipeline-expanded PYTHON=./.venv/bin/python` for broad slow audits.
  Hard gate before PR/incremental work: `make quality-hard PYTHON=./.venv/bin/python`; linters-only: `make linters-hard PYTHON=./.venv/bin/python`.
  Changed surface: `make quality-dev PYTHON=./.venv/bin/python`; typing debt: `make linters PYTHON=./.venv/bin/python`.
- Read `reference/project-map.md`, then the task's component README. Use
  `tools/dev/agent_test_focus.py --files <paths> --context --json --json-only`
  to locate owners, interfaces and focused tests. For decompiler, lifter or proof changes also read
  `reference/decompiler-map.md`, `reference/agent-rules.md`, `reference/real-mode-edge-policy.md` and
  `reference/frontend-backend-migration-policy.md`. `reference/agent-rules.md` provides supplemental
  glossary and long-running-agent guidance. Independent tools need their domain guides when crossing those boundaries; root invariants always apply.
- Devin delegation (user-authorized only): baseline, sandbox boundary, launch, prompt template and
  parent review: [reference/devin-handoff.md](reference/devin-handoff.md). Compaction handoff spec: [agent-execution.md](reference/agent-execution.md#context--compaction-handoff).
