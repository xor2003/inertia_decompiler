# Decompiler Map

This is the short map for agents. `AGENTS.md` is the canonical rulebook;
`reference/agent-rules.md` is supplemental glossary and long-running-agent
guidance. This file exists so the correct layer is visible before editing.

## Core Order

```text
IR -> Alias -> Widening -> Types -> Structuring -> Rewrite
```

Semantic facts move left to right.  Do not introduce new semantics in rewrite.
If a late pass proves a fact, migrate that proof to the owning earlier layer and
leave the late pass as a temporary consumer only.

## Layer Owners

| Layer | Owner paths | Owns |
| --- | --- | --- |
| Frontend | `inertia/frontend/x86_16/` | arch, loaders, VEX lifter, SimOS, instruction facts |
| IR | `inertia/ir/` | typed `Value`, `Address`, `Condition`, instruction facts |
| Semantics | `inertia/semantics/` | instruction effects, flags, branch meaning |
| Alias | `inertia/alias/` | storage identity, stack/global alias proof |
| Widening | `inertia/widening/` | proven byte/word/pointer joins after alias |
| Types and Lowering | `inertia/lowering/` | stack/global object materialization, callsite facts, segmented memory lowering |
| Structuring | `inertia/structuring/` | CFG shape, loops, switches, structured condition lowering |
| Rewrite/Postprocess | `inertia/postprocess/` | formatting, cleanup, validation-gated compatibility consumers |
| Validation | `inertia/validation/` | semantic equivalence checks and honest failure reporting |
| CLI | `inertia/cli/` | orchestration, fallback choice, reports, timeouts |

Per-module evidence, ownership, and consumer facts for each layer live in
[`decompiler-evidence-owners.md`](decompiler-evidence-owners.md); consult that
guide for the relevant semantic consumers before editing.

## Never Fix Here

- Do not add semantic recovery to `decompiler_postprocess_jcc.py`.
- Do not add call argument/signature/body repair to postprocess or CLI.
- Do not add stack identity, global identity, or type recovery to rewrite.
- Import and extend canonical layer owners directly. Historical root compatibility
  shims have been removed; do not recreate them.
- Do not recover semantics from rendered C, assembly text, or regex matches.

## Compatibility Debt

Existing `inertia/postprocess/decompiler_postprocess_*.py` owners retain guarded
legacy cross-layer edges during relocation; new recovery belongs in its semantic layer.
Their headers say what they may consume and where their debt must move.  The
current debt is also visible through:

- `inertia/postprocess/decompiler_postprocess_inventory.py`
- `reference/layer-module-status.md`
- `reference/decompiler-fix-plan.md`

Adding a new semantic-looking postprocess pass must also update the inventory,
evidence counters, owner layer, and tests.  Unknown proof means keep the ugly
code and let validation report the missing fact.

## Gate Tiers

Run the fast tier while editing and before handing off ordinary decompiler
changes. The fast tier is unit-focused only; external compiler/decompiler smoke
lanes belong to the default and expanded tiers:

```bash
make check-files PYTHON=./.venv/bin/python FILES="path/to/file.py path/to/test.py"
make quality-fast PYTHON=./.venv/bin/python
make test-pipeline-fast PYTHON=./.venv/bin/python
```

Run the default tier before claiming a semantic decompiler improvement:

```bash
make test-pipeline PYTHON=./.venv/bin/python
```

Run the expanded tier for broad architecture/status audits and slower SORTDEMO
or corpus work:

```bash
make test-pipeline-expanded PYTHON=./.venv/bin/python
```

`make architecture-check PYTHON=./.venv/bin/python` is the ratchet for future
agents. It checks postprocess guard headers, protected import exceptions,
canonical CLI imports, runtime guard entrypoints, documentation
markers, ownership manifests, and docs/types/dot-access ratchets. If it fails,
either move the work to the correct layer or explicitly update the architecture
allowlist with a documented migration reason and regression.

## Function Fix DoD
A fixed function needs all of:

- focused before/after regression evidence;
- `validation=passed`;
- no semantic call loss;
- output closer to original C/COD source when source exists;
- MS C tiny/full pipeline coverage when the case is represented there.

Passing recompilation by deleting live code is a failure, not a fix.
