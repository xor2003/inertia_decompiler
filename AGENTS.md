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

## Core model

All reasoning on: `Value` (data), `Address` (memory segment+offset), `Condition` (branch meaning).

## Layer ownership

- `frontend`: `angr_platforms/angr_platforms/X86_16/` (arch, loader, lift, SimOS, sidecar)
- `IR`: `X86_16/ir/`
- `semantics`: `X86_16/semantics/`
- `alias`: `X86_16/alias/`
- `widening`: `X86_16/widening/`
- `traits/summaries/confidence`: `X86_16/*.py`
- `types/lowering/object recovery`: `X86_16/lowering/` + `type_*.py`
- `structuring`: `X86_16/structuring/` + `decompiler_structuring_stage.py`
- `rewrite/cleanup`: `X86_16/postprocess/` + `decompiler_postprocess_stage.py`
- `tail validation`: `X86_16/tail_validation*.py`, `validation_*.py`
- `CLI/fallback/reporting`: `inertia_decompiler/`

Semantic recovery → `X86_16/`. Cleanup-only → `postprocess/`. Do not add to root compatibility files (`alias_model.py`, `alias_domains.py`, etc.).

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

### Mandatory execution guidance

Read and follow [reference/agent-execution.md](reference/agent-execution.md)
at startup and after compaction. It owns the detailed regression-test,
performance, selective-delegation, token-efficient-output, and progress-reporting
rules. This file remains the canonical architecture and acceptance contract.
`CLAUDE.md` is the agent entry file: its context-efficiency rules supplement
this contract, and on any conflict this contract and
[reference/agent-execution.md](reference/agent-execution.md) win.

Regular local gate: `make quality-fast PYTHON=./.venv/bin/python`.
`make test-pipeline PYTHON=./.venv/bin/python` before claiming semantic decompiler improvements.
`make test-pipeline-expanded PYTHON=./.venv/bin/python` for broad slow audits.
Hard development gate before PR/incremental work: `make quality-hard PYTHON=./.venv/bin/python`.
For a narrower local loop with only linters: `make linters-hard PYTHON=./.venv/bin/python`.

For the changed surface, run `make quality-dev PYTHON=./.venv/bin/python`.
For global typing debt accounting, run `make linters PYTHON=./.venv/bin/python`.
Read `reference/project-map.md`, `reference/decompiler-map.md`, `reference/agent-rules.md`, `reference/real-mode-edge-policy.md`, and `reference/frontend-backend-migration-policy.md`.
This includes the Supplemental glossary and long-running-agent guidance.

## Context / compaction

Context / compaction

Before compaction, create a minimal handoff for the next agent.

Keep only:

current objective
non-obvious settled decisions/invariants
current state
next 3–6 actions
active blockers/risks
files needed for those actions

Do not retain information that can be cheaply rediscovered from the repo.

Delete:

investigation/history/rejected approaches
completed commands, logs, tool output
line numbers and Makefile locations
constructor/signature details unless currently blocking
completed test-case inventories
unrelated/future defects
duplicated information already in PLAN/PROGRESS
long path repetitions

Use path aliases when useful.

Completed work: one line per logical milestone.

Relevant files: maximum 8 entries.

Hard limit: 500 words. If the draft exceeds 500 words, rewrite it before compaction.

For every retained fact ask:
"Would the next agent likely make a wrong implementation decision without this?"
If not, omit it.

Do not preserve commands or exact locations solely to save the next agent a grep/search.

