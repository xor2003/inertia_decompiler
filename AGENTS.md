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

### Fast iteration checks

Detailed policy: [Linter cadence](reference/agent-execution.md#linter-cadence).

- Check explicit owned paths, not the shared dirty tree. Each coherent Python edit:
  `rtk proxy nice -n 10 make lint-iteration PYTHON=./.venv/bin/python FILES="owned.py test_owned.py"`
  (Ruff + type/doc/access ratchet), then the focused regression.
- Completed implementation/interface changes: scoped MyPy; add Pyright for
  inference, third-party boundaries, or existing Pyright diagnostics.
- Cython/mypyc changes: relevant build and smoke tests before proof tests.
- File/import/entry-point moves or removals: Basta; dead-code changes: Vulture;
  complexity refactors: scoped Lizard. Documentation-only edits need no Python lint.
- Keep broad linters and required quality/pipeline gates at integration checkpoints.
  Do not run repository-wide MyPy, Pyright, Vulture, Basta, or Lizard per edit.
  Repeat successful checks only when inputs/dependencies change or a required gate
  calls for them. Finish autofixes and freeze semantic sources before proof runs.
- Run Python/pytest at nice 10 with `PYTHON_JIT=1`; share at most six test workers.
  Retain full logs; report scope, exit status, counts and actionable failures.
  Read saved logs instead of rerunning checks just to recover output.

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

### Devin batch handoff (only when the user authorizes delegation)

Standing user preference for this compiler-coverage plan: use Devin for suitable
bounded work to reduce Codex token usage, with parent review before acceptance.

Use Devin for independent, bounded tasks with disjoint file ownership; keep the
parent responsible for integration, evidence review, and acceptance. Do not hand
it the whole compiler-coverage plan or let two workers edit the same files.
Before launch, record the current baseline and write a task-specific prompt
under ignored `.cache/devin-prompts/`. Start each CLI process with
`ulimit -v 4194304` (KiB: 4 GiB), use a separate batch invocation per task,
and retain its output/session ID.

Writable staging/type-check overlays must use private regular-file copies.
Never copy or write staged replacements through symlinks or hardlinks to shared
source: that mutates production before review. Verify destination paths and
link identity before creating an overlay; retain exact pre-run source hashes.

Do not stash, reset, or check out shared source to obtain a baseline. Compare
the saved pre-run sources in an isolated process; clean HEAD is not the dirty
pre-run baseline. If a failure cannot be classified within one bounded baseline
attempt, report it as unresolved and hand it back instead of expanding the task.

In this workspace, after verifying the outer sandbox described below, the
current CLI pattern is:

```sh
devin_repo=/home/xor/vextest
ulimit -v 4194304
rtk proxy "$devin_repo/.venv/bin/python" \
  "$devin_repo/scripts/workspace_sandbox.py" -- \
  env XDG_CONFIG_HOME="$devin_repo/.cache/devin-config" \
  XDG_DATA_HOME="$devin_repo/.cache/devin-data" \
  XDG_STATE_HOME="$devin_repo/.cache/devin-state" \
  XDG_CACHE_HOME="$devin_repo/.cache/devin-cache" \
  TMPDIR="$devin_repo/.cache" \
  devin --config /home/xor/.config/devin/config.json --model swe-2-high \
  --permission-mode dangerous --respect-workspace-trust false \
  --prompt-file "$devin_repo/.cache/devin-prompts/TASK.md" -p
```

In a restricted Codex workspace where Devin's default user-state directory is
not writable, point `XDG_CONFIG_HOME`, `XDG_DATA_HOME`, `XDG_STATE_HOME`,
`XDG_CACHE_HOME`, and `TMPDIR` at ignored directories under this repository's
`.cache/`. Preserve the authenticated data root when resuming; a fresh data
root is not automatically logged in. Keep CLI
credentials private (mode 0600); never paste them into prompts or commit them.
Use `--permission-mode dangerous --respect-workspace-trust false` for unattended
batch runs **only after verifying an outer filesystem sandbox limits writes to
this working directory**. Without that boundary, use restricted permissions;
do not treat the flag as authorization for host-wide access.

The explicit Bubblewrap boundary above is verified locally: host mounts are
read-only, this repository's bind mount is writable, and the child inherits
the 4 GiB address-space limit. Private `/proc` and `/dev` permit normal process
and device setup without exposing writable host directories. Omitting
`--dev /dev` makes this CLI's ACP child fail when opening `/dev/null`.
For a job that executes DOS tools or recompilation validation, add
`--with-kvm` before the launcher's `--`. The launcher opens the host device in
Python, verifies both path and opened descriptor are character10:232/API12,
and retains FD33 across the private `/dev` setup. The corresponding scoped
`--dev-bind /proc/self/fd/33 /dev/kvm` was independently checked with child
API12, rootRO/repoRW and4GiB. Direct pathname and shell-FD attempts did not
preserve that device in this restricted environment; do not substitute them
without the exact identity/API check. Missing KVM fails loudly: do not expose
other host devices or remove the read-only-host boundary. A run without the
required device is environment-limited, not comparable decompiler acceptance.
Static-only staging tasks use the default launcher, which exposes no host KVM.
If Bubblewrap is unavailable, do not silently remove the boundary. Session-lock
PIDs inside a PID namespace are not host PIDs: identify the owned process tree
and check `NSpid` before using a lock for liveness or sending a signal.

Copy and fill this handoff prompt for each job:

```text
You are one worker in /home/xor/vextest; other agents are editing concurrently.
Read AGENTS.md and its required startup references. Preserve all existing edits.
Goal slice: <one concrete acceptance obligation and current baseline>.
Ownership: edit only <exact files>; do not edit other files, docs, or artifacts.
Evidence: <graph project/generation/tier, checked paths and coverage caveats,
          exact source or binary facts already established, unresolved question>.
Implementation: fix the earliest correct layer; use typed evidence and fail
closed. No COD/source/name/rendered-C semantic proof or sample-specific hacks.
Validation: show a focused red regression, the green result, and scoped lint/type
checks. Do not run broad gates, round trips, commit, or publish a claim of
validation=passed; the parent coordinates those checks after review.
Handoff: report changed files, invariant, test commands/results, evidence counts,
and remaining refusals or blockers. Do not revert anyone else's work.
```

After Devin exits, the parent must review its report and compare every owned
file against the recorded pre-run baseline. Identify Devin's exact delta in the
shared dirty tree; reject unrelated edits, unsupported proof claims, semantic
repairs in rewrite, and any weakened validation or refusal gate. Independently
read the changed code and tests, reproduce the focused red/green result, and
check the binary-derived evidence and failure counts. Then rerun relevant
focused checks on the final shared tree and project gates at the semantic
checkpoint. If Devin made no patch, verify its diagnostic claims before using
them. A Devin answer or passing unit test alone is not decompiler acceptance;
only the parent may claim a function fixed after the required tail validation,
call-semantics check, output-shape comparison, and applicable round trip.

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
