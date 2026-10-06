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
| Frontend | `angr_platforms/angr_platforms/X86_16/`, `angr_platforms/angr_platforms/X86_16/lift_86_16.py` | arch, loader/lift hooks, instruction facts |
| IR | `X86_16/ir/` | typed `Value`, `Address`, `Condition`, instruction facts |
| Semantics | `X86_16/semantics/` | instruction effects, flags, branch meaning |
| Alias | `X86_16/alias/` | storage identity, stack/global alias proof |
| Widening | `X86_16/widening/` | proven byte/word/pointer joins after alias |
| Types and Lowering | `X86_16/lowering/`, `type_*.py` | stack/global object materialization, callsite facts, segmented memory lowering |
| Structuring | `X86_16/structuring/`, `decompiler_structuring_stage.py` | CFG shape, loops, switches, structured condition lowering |
| Rewrite/Postprocess | `X86_16/postprocess/`, `decompiler_postprocess_*.py`, `decompiler_postprocess_stage.py` | formatting, cleanup, validation-gated compatibility consumers |
| Validation | `X86_16/tail_validation*.py`, `validation_*.py` | semantic equivalence checks and honest failure reporting |
| CLI | `inertia_decompiler/` | orchestration, fallback choice, reports, timeouts |

Per-module evidence, ownership, and consumer facts for each layer live in
[`decompiler-evidence-owners.md`](decompiler-evidence-owners.md); consult that
guide for the relevant semantic consumers before editing.

## Never Fix Here

- Do not add semantic recovery to `decompiler_postprocess_jcc.py`.
- Do not add call argument/signature/body repair to postprocess or CLI.
- Do not add stack identity, global identity, or type recovery to rewrite.
- Do not add behavior to root compatibility shims such as `alias_model.py` and
  `alias_domains.py`.
- Do not recover semantics from rendered C, assembly text, or regex matches.

## Compatibility Debt

Root `decompiler_postprocess_*.py` files are guarded compatibility bridges.
Their headers say what they may consume and where their debt must move.  The
current debt is also visible through:

- `angr_platforms/angr_platforms/X86_16/decompiler_postprocess_inventory.py`
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
agents. It checks postprocess guard headers, protected import exceptions, root
compatibility shims, CLI imports, runtime guard entrypoints, documentation
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
