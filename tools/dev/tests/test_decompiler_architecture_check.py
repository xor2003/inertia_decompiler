from __future__ import annotations

import ast
import os
import subprocess
import sys
from pathlib import Path

import pytest

import inertia.cli.architecture_runtime_guard as architecture_runtime_guard
import inertia.cli.cli as cli
import inertia.cli.cli_core as cli_core
import tools.dev.check_changed_non_test_types as check_changed_non_test_types
import tools.dev.check_decompiler_architecture as arch_check
import tools.dev.test_ownership_manifest as test_ownership_manifest


def _write_minimal_tree(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "angr_platforms" / "angr_platforms" / "X86_16"
    root.mkdir(parents=True)
    (root / "decompiler_postprocess_jcc.py").write_text(
        '"""Legacy JCC cleanup bridge.\n\nDo not add fresh semantic decoding here.\n"""\n'
        "from __future__ import annotations\n",
        encoding="utf-8",
    )
    (root / "alias_model.py").write_text(
        '"""Layer: Compatibility shim.\n\n'
        "Responsibility: preserve flat import surface during alias package migration.\n"
        "Dynamic boundary: compatibility re-export only; canonical alias.alias_model owns\n"
        "the literal public API.\n"
        "Forbidden: semantic ownership; import canonical alias.alias_model only.\n"
        '"""\n'
        "from __future__ import annotations\n"
        "from inertia.alias.alias_model import *  # noqa: F403\n",
        encoding="utf-8",
    )
    (root / "alias_domains.py").write_text(
        '"""Layer: Compatibility shim.\n\n'
        "Responsibility: preserve flat alias_domains import surface during alias package migration.\n"
        "Dynamic boundary: compatibility re-export only; canonical alias.domains owns\n"
        "the literal public API.\n"
        "Forbidden: semantic ownership; import canonical alias.domains only.\n"
        '"""\n'
        "from __future__ import annotations\n"
        "from inertia.alias.domains import *  # noqa: F403\n",
        encoding="utf-8",
    )
    (root / "alias_state.py").write_text(
        '"""Layer: Compatibility shim.\n\n'
        "Responsibility: preserve flat alias_state import surface during alias package migration.\n"
        "Dynamic boundary: compatibility re-export only; canonical alias.state owns\n"
        "the literal public API.\n"
        "Forbidden: semantic ownership; import canonical alias.state only.\n"
        '"""\n'
        "from __future__ import annotations\n"
        "from inertia.alias.state import *  # noqa: F403\n",
        encoding="utf-8",
    )
    (root / "alias_transfer.py").write_text(
        '"""Layer: Compatibility shim.\n\n'
        "Responsibility: preserve flat alias_transfer import surface during alias package migration.\n"
        "Dynamic boundary: compatibility re-export only; canonical alias.transfer owns\n"
        "the literal public API.\n"
        "Forbidden: semantic ownership; import canonical alias.transfer only.\n"
        '"""\n'
        "from __future__ import annotations\n"
        "from inertia.alias.transfer import *  # noqa: F403\n",
        encoding="utf-8",
    )
    (root / "condition_ir.py").write_text(
        '"""Layer: Compatibility shim.\n\n'
        "Responsibility: preserve flat condition_ir imports during IR package migration.\n"
        "Dynamic boundary: compatibility re-export only; canonical ir.condition_ir owns\n"
        "the literal public API.\n"
        "Forbidden: semantic ownership; import canonical ir.condition_ir only.\n"
        '"""\n'
        "from __future__ import annotations\n"
        "from inertia.ir.condition_ir import *  # noqa: F403\n",
        encoding="utf-8",
    )
    (root / "widening_alias.py").write_text(
        '"""Layer: Compatibility shim.\n\n'
        "Responsibility: preserve flat widening_alias import surface during widening package migration.\n"
        "Dynamic boundary: compatibility re-export only; canonical widening.register_widening\n"
        "owns the literal public API.\n"
        "Forbidden: semantic ownership; import canonical widening.register_widening only.\n"
        '"""\n'
        "from __future__ import annotations\n"
        "from inertia.widening.register_widening import *  # noqa: F403\n",
        encoding="utf-8",
    )
    cli = tmp_path / "inertia" / "cli" / "cli_decompilation.py"
    cli.parent.mkdir(parents=True)
    cli.write_text(
        '"""CLI boundary; must not become the owner of decompiler semantics.\n\n'
        "Layer: CLI/fallback/reporting.\n"
        '"""\n'
        "from __future__ import annotations\n",
        encoding="utf-8",
    )
    _write_project_awareness_docs(tmp_path)
    return root, cli


def _write_project_awareness_docs(tmp_path: Path) -> None:
    (tmp_path / "AGENTS.md").write_text(
        "Read reference/project-map.md and reference/decompiler-map.md.\n"
        "Dot access for owned contracts.\n"
        "avoidable `getattr`/`setattr`.\n"
        "use `getattr`/`setattr` only at dynamic third-party/angr/codegen/plugin boundaries with a clear reason.\n"
        "Existing avoidable dynamic attribute access is cleanup debt and should be removed when touching nearby code.\n"
        "Docstrings and types ratchet.\n"
        "every new or touched non-test module must state `Layer:` and `Responsibility:`.\n"
        "legacy missing docs/types are cleanup debt.\n"
        "Regular local gate: `make quality-fast PYTHON=./.venv/bin/python`.\n"
        "Use `make test-pipeline PYTHON=./.venv/bin/python` before claiming semantic decompiler improvements.\n"
        "Use `make test-pipeline-expanded PYTHON=./.venv/bin/python` for broad slow audits.\n"
        "Supplemental glossary and long-running-agent guidance.\n",
        encoding="utf-8",
    )
    reference = tmp_path / "reference"
    reference.mkdir(exist_ok=True)
    (reference / "agent-rules.md").write_text(
        "AGENTS.md contains the mandatory agent rules and canonical architecture contract.\n"
        "This file intentionally does not restate those rules.\n",
        encoding="utf-8",
    )
    (reference / "project-map.md").write_text(
        "\n".join(
            (
                "inertia/frontend/x86_16",
                "inertia/cli/",
                "dosunit.py",
                "tools/signatures/signature_catalog.py",
                "tools/dev/test_pipeline.py",
                "binary-budgeted",
                "tools/compiler_toolchain/build_msc6_examples.py",
                "examples/msc6_constructs/",
                "reference/dosunit-execution-spec.md",
                "make architecture-check",
                "make agent-context-check",
                "make test-ownership-check",
                "make check-files",
                "changed-file module/doc/type/dot-access ratchet",
                "architecture/context guards, ownership-manifest validation, and owned tests",
                "legacy `Responsibility:` header debt explicitly",
                "remove entries from those lists as soon as the owning module docstring is fixed",
                "requires every X86_16 and inertia_decompiler module to be in the promoted typed/ruff gates or explicit promotion debt",
                "Full-promotion debt files stay out of `QA_TYPED_FILES` and `QA_RUFF_TARGETS`",
                "Ownership-manifest tests are fast-only",
                "make quality-fast",
                "make test-pipeline-fast",
                "proof budgets stay unchanged",
                "make test-pipeline",
                "make test-pipeline-expanded",
                "libdosbox",
                ".understand-anything/config.json",
                "--no-auto-update",
            )
        ),
        encoding="utf-8",
    )
    (reference / "decompiler-map.md").write_text(
        "\n".join(
            (
                "IR -> Alias -> Widening -> Types -> Structuring -> Rewrite",
                "AGENTS.md` is the canonical rulebook",
                "reference/agent-rules.md` is supplemental glossary",
                "make quality-fast PYTHON=./.venv/bin/python",
                "make test-pipeline-fast PYTHON=./.venv/bin/python",
                "make test-pipeline PYTHON=./.venv/bin/python",
                "make test-pipeline-expanded PYTHON=./.venv/bin/python",
                "fast tier",
                "unit-focused only",
                "default tier",
                "expanded tier",
                "runtime guard entrypoints",
                "docs/types/dot-access ratchets",
            )
        ),
        encoding="utf-8",
    )
    (tmp_path / "SORTDEMO_HANDOFF.md").write_text("SORTDEMO handoff.\n", encoding="utf-8")
    for filename in (
        "dosunit-execution-spec.md",
        "telemetry.md",
        "layer-module-status.md",
        "decompiler-fix-plan.md",
    ):
        (reference / filename).write_text(f"# {filename}\n", encoding="utf-8")
    config = tmp_path / ".understand-anything" / "config.json"
    config.parent.mkdir(exist_ok=True)
    config.write_text('{"autoUpdate": false}\n', encoding="utf-8")


def test_project_awareness_fixture_matches_agent_doc_contract(tmp_path):
    _write_project_awareness_docs(tmp_path)

    violations = arch_check._check_project_awareness_docs(tmp_path)

    assert not any(item.rule.startswith("agent-doc") for item in violations)


def _fast_skip_policy_source() -> str:
    return (
        "FAST_PYTEST_SKIP_CALLS = frozenset((\n"
        '    "pytest.mark.skip",\n'
        '    "pytest.mark.skipif",\n'
        '    "pytest.mark.xfail",\n'
        '    "pytest.skip",\n'
        '    "pytest.xfail",\n'
        "))\n"
    )


@pytest.mark.repository_contract
def test_current_decompiler_architecture_contract_is_clean():
    assert arch_check.check_decompiler_architecture() == ()


def test_annotation_debt_ratchet_accepts_exact_baseline_and_rejects_equal_count_move(tmp_path, monkeypatch):
    module = tmp_path / "inertia" / "cli" / "legacy.py"
    module.parent.mkdir(parents=True)
    module.write_text(
        "from __future__ import annotations\n\n"
        "def outer(value):\n"
        "    def inner(item):\n"
        "        return item\n"
        "    return inner(value)\n",
        encoding="utf-8",
    )
    slots = arch_check._annotation_debt_slots(arch_check._parse_python(module))
    relative_path = "inertia/cli/legacy.py"
    monkeypatch.setattr(arch_check, "_DECOMPILER_ANNOTATION_ROOTS", ("inertia/cli",))
    monkeypatch.setattr(
        arch_check,
        "_DECOMPILER_ANNOTATION_DEBT_BASELINE",
        {relative_path: (len(slots), arch_check._annotation_debt_fingerprint(slots))},
    )

    assert arch_check._check_decompiler_annotation_debt(tmp_path) == ()

    module.write_text(
        "from __future__ import annotations\n\n"
        "def outer(value):\n"
        "    def moved(other_item):\n"
        "        return other_item\n"
        "    return moved(value)\n",
        encoding="utf-8",
    )

    violations = arch_check._check_decompiler_annotation_debt(tmp_path)

    assert any(item.rule == "decompiler-annotation-debt-changed" for item in violations)


def test_annotation_debt_ratchet_rejects_untracked_debt(tmp_path, monkeypatch):
    module = tmp_path / "inertia" / "cli" / "new_debt.py"
    module.parent.mkdir(parents=True)
    module.write_text("def helper(value):\n    return value\n", encoding="utf-8")
    monkeypatch.setattr(arch_check, "_DECOMPILER_ANNOTATION_ROOTS", ("inertia/cli",))
    monkeypatch.setattr(arch_check, "_DECOMPILER_ANNOTATION_DEBT_BASELINE", {})

    violations = arch_check._check_decompiler_annotation_debt(tmp_path)

    assert any(item.rule == "decompiler-annotation-debt-new" for item in violations)


def test_annotation_debt_tracks_nested_definitions_in_statement_bodies(tmp_path):
    module = tmp_path / "nested.py"
    module.write_text(
        "if True:\n"
        "    class Owner:\n"
        "        async def method(self, value):\n"
        "            def nested(item):\n"
        "                return item\n"
        "            return nested(value)\n",
        encoding="utf-8",
    )

    slots = arch_check._annotation_debt_slots(arch_check._parse_python(module))

    assert slots == (
        "Owner.method.nested:item",
        "Owner.method.nested:return",
        "Owner.method:return",
        "Owner.method:value",
    )


def test_annotation_debt_ratchet_rejects_stale_entry_after_cleanup(tmp_path, monkeypatch):
    module = tmp_path / "inertia" / "cli" / "cleaned.py"
    module.parent.mkdir(parents=True)
    module.write_text("def helper(value: object) -> object:\n    return value\n", encoding="utf-8")
    monkeypatch.setattr(arch_check, "_DECOMPILER_ANNOTATION_ROOTS", ("inertia/cli",))
    monkeypatch.setattr(
        arch_check,
        "_DECOMPILER_ANNOTATION_DEBT_BASELINE",
        {"inertia/cli/cleaned.py": (2, "obsolete")},
    )

    violations = arch_check._check_decompiler_annotation_debt(tmp_path)

    assert any(item.rule == "decompiler-annotation-debt-stale" for item in violations)


def test_architecture_check_parse_cache_reuses_and_invalidates_changed_file(tmp_path):
    path = tmp_path / "sample.py"
    path.write_text("from __future__ import annotations\nVALUE = 1\n", encoding="utf-8")
    arch_check._PYTHON_AST_CACHE.clear()

    first = arch_check._parse_python(path)
    second = arch_check._parse_python(path)

    assert second is first

    path.write_text("from __future__ import annotations\nVALUE = 100\n", encoding="utf-8")
    third = arch_check._parse_python(path)

    assert third is not first


def test_architecture_check_text_cache_reuses_and_invalidates_changed_file(tmp_path):
    path = tmp_path / "sample.txt"
    path.write_text("alpha\n", encoding="utf-8")
    arch_check._TEXT_CACHE.clear()

    first = arch_check._read_text_if_present(path)
    second = arch_check._read_text_if_present(path)

    assert second is first

    path.write_text("alpha beta\n", encoding="utf-8")
    third = arch_check._read_text_if_present(path)

    assert third == "alpha beta\n"
    assert third is not first


def test_architecture_check_rejects_duplicate_architecture_table_keys(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    scripts = tmp_path / "tools" / "dev"
    scripts.mkdir(parents=True, exist_ok=True)
    (scripts / "check_decompiler_architecture.py").write_text(
        '"""Static architecture guard.\n\n'
        "Layer: Tooling/gates.\n"
        "Responsibility: enforce architecture.\n"
        '"""\n'
        "from __future__ import annotations\n\n"
        "_SEMANTIC_LAYER_OWNERSHIP_MARKERS = {\n"
        '    "lowering": ("Layer: Types/Lowering",),\n'
        '    "lowering": ("Layer: Types/Lowering", "Responsibility:"),\n'
        "}\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "architecture-table-duplicate-key"
        and item.path == "tools/dev/check_decompiler_architecture.py"
        and "_SEMANTIC_LAYER_OWNERSHIP_MARKERS" in item.detail
        and "'lowering'" in item.detail
        for item in violations
    )


def test_architecture_check_rejects_duplicate_architecture_allowlist_keys(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    scripts = tmp_path / "tools" / "dev"
    scripts.mkdir(parents=True, exist_ok=True)
    (scripts / "check_decompiler_architecture.py").write_text(
        '"""Static architecture guard.\n\n'
        "Layer: Tooling/gates.\n"
        "Responsibility: enforce architecture.\n"
        '"""\n'
        "from __future__ import annotations\n\n"
        "_POSTPROCESS_LEGACY_IMPORT_ALLOWLIST = {\n"
        '    "decompiler_postprocess_calls.py": frozenset({".cod_extract"}),\n'
        '    "decompiler_postprocess_calls.py": frozenset({".lowering.real_mode_linear"}),\n'
        "}\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "architecture-table-duplicate-key"
        and item.path == "tools/dev/check_decompiler_architecture.py"
        and "_POSTPROCESS_LEGACY_IMPORT_ALLOWLIST" in item.detail
        and "'decompiler_postprocess_calls.py'" in item.detail
        for item in violations
    )


def test_architecture_check_rejects_duplicate_required_ownership_test_keys(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    scripts = tmp_path / "tools" / "dev"
    scripts.mkdir(parents=True, exist_ok=True)
    (scripts / "check_decompiler_architecture.py").write_text(
        '"""Static architecture guard.\n\n'
        "Layer: Tooling/gates.\n"
        "Responsibility: enforce architecture.\n"
        '"""\n'
        "from __future__ import annotations\n\n"
        "_OWNERSHIP_MANIFEST_REQUIRED_TESTS = {\n"
        '    "pipeline-architecture-final-emission-guard": ("test_a.py",),\n'
        '    "pipeline-architecture-final-emission-guard": ("test_b.py",),\n'
        "}\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "architecture-table-duplicate-key"
        and item.path == "tools/dev/check_decompiler_architecture.py"
        and "_OWNERSHIP_MANIFEST_REQUIRED_TESTS" in item.detail
        and "'pipeline-architecture-final-emission-guard'" in item.detail
        for item in violations
    )


def test_architecture_check_rejects_orphan_required_ownership_test_owner(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    scripts = tmp_path / "tools" / "dev"
    scripts.mkdir(parents=True, exist_ok=True)
    (scripts / "check_decompiler_architecture.py").write_text(
        '"""Static architecture guard.\n\n'
        "Layer: Tooling/gates.\n"
        "Responsibility: enforce architecture.\n"
        '"""\n'
        "from __future__ import annotations\n\n"
        "_OWNERSHIP_MANIFEST_REQUIRED_RULES = {\n"
        '    "pipeline-architecture-final-emission-guard": ("pipeline/architecture_guard.py",),\n'
        "}\n"
        "_OWNERSHIP_MANIFEST_REQUIRED_TESTS = {\n"
        '    "orphan-owner": ("angr_platforms/tests/test_orphan.py",),\n'
        "}\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "architecture-required-test-owner"
        and item.path == "tools/dev/check_decompiler_architecture.py"
        and "'orphan-owner'" in item.detail
        for item in violations
    )


def test_architecture_check_rejects_stale_required_ownership_rule_source(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    scripts = tmp_path / "tools" / "dev"
    scripts.mkdir(parents=True, exist_ok=True)
    (scripts / "check_decompiler_architecture.py").write_text(
        '"""Static architecture guard.\n\n'
        "Layer: Tooling/gates.\n"
        "Responsibility: enforce architecture.\n"
        '"""\n'
        "from __future__ import annotations\n\n"
        "_OWNERSHIP_MANIFEST_REQUIRED_RULES = {\n"
        '    "pipeline-architecture-final-emission-guard": ("pipeline/missing_guard.py",),\n'
        "}\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "architecture-required-rule-source"
        and item.path == "tools/dev/check_decompiler_architecture.py"
        and "pipeline/missing_guard.py" in item.detail
        for item in violations
    )


def test_architecture_check_rejects_missing_required_ownership_test_target(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    scripts = tmp_path / "tools" / "dev"
    scripts.mkdir(parents=True, exist_ok=True)
    (scripts / "check_decompiler_architecture.py").write_text(
        '"""Static architecture guard.\n\n'
        "Layer: Tooling/gates.\n"
        "Responsibility: enforce architecture.\n"
        '"""\n'
        "from __future__ import annotations\n\n"
        "_OWNERSHIP_MANIFEST_REQUIRED_RULES = {\n"
        '    "pipeline-architecture-final-emission-guard": ("pipeline/architecture_guard.py",),\n'
        "}\n"
        "_OWNERSHIP_MANIFEST_REQUIRED_TESTS = {\n"
        '    "pipeline-architecture-final-emission-guard": ("angr_platforms/tests/test_missing_guard.py",),\n'
        "}\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "architecture-required-test-target"
        and "test_missing_guard.py" in item.detail
        for item in violations
    )


def test_architecture_check_rejects_missing_required_ownership_test_node(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    scripts = tmp_path / "tools" / "dev"
    scripts.mkdir(parents=True, exist_ok=True)
    test_path = tmp_path / "angr_platforms" / "tests" / "test_guard_contract.py"
    test_path.parent.mkdir(parents=True, exist_ok=True)
    test_path.write_text(
        "from __future__ import annotations\n\n"
        "def test_existing_guard_contract():\n"
        "    assert True\n",
        encoding="utf-8",
    )
    (scripts / "check_decompiler_architecture.py").write_text(
        '"""Static architecture guard.\n\n'
        "Layer: Tooling/gates.\n"
        "Responsibility: enforce architecture.\n"
        '"""\n'
        "from __future__ import annotations\n\n"
        "_OWNERSHIP_MANIFEST_REQUIRED_RULES = {\n"
        '    "pipeline-architecture-final-emission-guard": ("pipeline/architecture_guard.py",),\n'
        "}\n"
        "_OWNERSHIP_MANIFEST_REQUIRED_TESTS = {\n"
        '    "pipeline-architecture-final-emission-guard": ('
        '"angr_platforms/tests/test_guard_contract.py::test_missing_guard_contract",),\n'
        "}\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "architecture-required-test-target"
        and "test_missing_guard_contract" in item.detail
        for item in violations
    )


def test_architecture_check_rejects_slow_required_ownership_test_target(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    scripts = tmp_path / "tools" / "dev"
    scripts.mkdir(parents=True, exist_ok=True)
    slow_test = tmp_path / "angr_platforms" / "tests" / "test_x86_16_sortdemo_regressions.py"
    slow_test.parent.mkdir(parents=True, exist_ok=True)
    slow_test.write_text(
        "from __future__ import annotations\n\n"
        "def test_sortdemo_regression_contract():\n"
        "    assert True\n",
        encoding="utf-8",
    )
    (scripts / "check_decompiler_architecture.py").write_text(
        '"""Static architecture guard.\n\n'
        "Layer: Tooling/gates.\n"
        "Responsibility: enforce architecture.\n"
        '"""\n'
        "from __future__ import annotations\n\n"
        "_OWNERSHIP_MANIFEST_REQUIRED_RULES = {\n"
        '    "pipeline-architecture-final-emission-guard": ("pipeline/architecture_guard.py",),\n'
        "}\n"
        "_OWNERSHIP_MANIFEST_REQUIRED_TESTS = {\n"
        '    "pipeline-architecture-final-emission-guard": ('
        '"tests/cli/test_x86_16_sortdemo_regressions.py",),\n'
        "}\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "architecture-required-test-fast-target"
        and "test_x86_16_sortdemo_regressions.py" in item.detail
        for item in violations
    )


def test_architecture_check_rejects_skip_xfail_in_required_ownership_test_target(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    scripts = tmp_path / "tools" / "dev"
    scripts.mkdir(parents=True, exist_ok=True)
    (scripts / "test_ownership_manifest.py").write_text(
        '"""Focused ownership manifest."""\n'
        "from __future__ import annotations\n\n"
        f"{_fast_skip_policy_source()}\n",
        encoding="utf-8",
    )
    fast_test = tmp_path / "angr_platforms" / "tests" / "test_guard_contract.py"
    fast_test.parent.mkdir(parents=True, exist_ok=True)
    fast_test.write_text(
        "from __future__ import annotations\n\n"
        "import pytest\n\n"
        "def test_guard_contract():\n"
        "    pytest.xfail('not mandatory yet')\n",
        encoding="utf-8",
    )
    (scripts / "check_decompiler_architecture.py").write_text(
        '"""Static architecture guard.\n\n'
        "Layer: Tooling/gates.\n"
        "Responsibility: enforce architecture.\n"
        '"""\n'
        "from __future__ import annotations\n\n"
        "_OWNERSHIP_MANIFEST_REQUIRED_RULES = {\n"
        '    "pipeline-architecture-final-emission-guard": ("pipeline/architecture_guard.py",),\n'
        "}\n"
        "_OWNERSHIP_MANIFEST_REQUIRED_TESTS = {\n"
        '    "pipeline-architecture-final-emission-guard": ('
        '"angr_platforms/tests/test_guard_contract.py::test_guard_contract",),\n'
        "}\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "architecture-required-test-skip-xfail"
        and item.path == "angr_platforms/tests/test_guard_contract.py"
        and "test_guard_contract" in item.detail
        for item in violations
    )


def test_architecture_check_rejects_duplicate_architecture_frozenset_values(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    scripts = tmp_path / "tools" / "dev"
    scripts.mkdir(parents=True, exist_ok=True)
    (scripts / "check_decompiler_architecture.py").write_text(
        '"""Static architecture guard.\n\n'
        "Layer: Tooling/gates.\n"
        "Responsibility: enforce architecture.\n"
        '"""\n'
        "from __future__ import annotations\n\n"
        "_LEGACY_SCRIPT_RESPONSIBILITY_DEBT = frozenset({\n"
        '    "tools/dev/build_tools/signatures/signature_catalog/py.py",\n'
        '    "tools/dev/build_tools/signatures/signature_catalog/py.py",\n'
        "})\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "architecture-table-duplicate-value"
        and item.path == "tools/dev/check_decompiler_architecture.py"
        and "_LEGACY_SCRIPT_RESPONSIBILITY_DEBT" in item.detail
        and "build_tools/signatures/signature_catalog/py.py" in item.detail
        for item in violations
    )


def test_architecture_check_rejects_weak_ownership_header_marker_contract(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    scripts = tmp_path / "tools" / "dev"
    scripts.mkdir(parents=True, exist_ok=True)
    (scripts / "check_decompiler_architecture.py").write_text(
        '"""Static architecture guard.\n\n'
        "Layer: Tooling/gates.\n"
        "Responsibility: enforce architecture.\n"
        '"""\n'
        "from __future__ import annotations\n\n"
        "_HELPER_BOUNDARY_HEADER_MARKERS = {\n"
        '    "addressing_helpers.py": ("Layer: Helper boundary", "Responsibility: decode addresses"),\n'
        "}\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "architecture-header-marker-contract"
        and item.path == "tools/dev/check_decompiler_architecture.py"
        and "_HELPER_BOUNDARY_HEADER_MARKERS" in item.detail
        and "addressing_helpers.py" in item.detail
        for item in violations
    )


def test_architecture_check_rejects_misordered_ownership_header_marker_contract(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    scripts = tmp_path / "tools" / "dev"
    scripts.mkdir(parents=True, exist_ok=True)
    (scripts / "check_decompiler_architecture.py").write_text(
        '"""Static architecture guard.\n\n'
        "Layer: Tooling/gates.\n"
        "Responsibility: enforce architecture.\n"
        '"""\n'
        "from __future__ import annotations\n\n"
        "_HELPER_BOUNDARY_HEADER_MARKERS = {\n"
        '    "addressing_helpers.py": ("decode addresses", "Layer: Helper boundary", "no flattening"),\n'
        "}\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "architecture-header-marker-contract"
        and "must start with Layer" in item.detail
        for item in violations
    )


def test_architecture_check_rejects_forced_corpus_template_body(tmp_path):
    cli = tmp_path / "cli_decompilation.py"
    cli.write_text(
        "from __future__ import annotations\n"
        "def _forced_corpus_templates_enabled() -> bool:\n"
        "    return False\n\n"
        "def _forced_function_template(function_name, binary_path=None, api_style=None):\n"
        "    if function_name == '_main':\n"
        "        return 'int _main(void) { return 0; }'\n"
        "    return None\n",
        encoding="utf-8",
    )
    entrypoint = tmp_path / "decompile.py"
    entrypoint.write_text("from __future__ import annotations\n", encoding="utf-8")

    violations = arch_check._check_forced_corpus_templates_inert(cli, entrypoint)

    assert any(item.rule == "forced-corpus-template-fallback" for item in violations)


def test_architecture_check_rejects_default_enabled_forced_corpus_templates(tmp_path):
    cli = tmp_path / "cli_decompilation.py"
    cli.write_text(
        "from __future__ import annotations\n"
        "def _forced_corpus_templates_enabled() -> bool:\n"
        "    return False\n\n"
        "def _forced_function_template(function_name, binary_path=None, api_style=None):\n"
        "    return None\n",
        encoding="utf-8",
    )
    entrypoint = tmp_path / "decompile.py"
    entrypoint.write_text(
        "from __future__ import annotations\n"
        "import os\n"
        "os.environ.setdefault('INERTIA_ENABLE_FORCED_CORPUS_TEMPLATES', '1')\n",
        encoding="utf-8",
    )

    violations = arch_check._check_forced_corpus_templates_inert(cli, entrypoint)

    assert any(item.rule == "forced-corpus-template-fallback" for item in violations)


def test_architecture_check_rejects_cli_acceptance_source_sidecar_import(tmp_path):
    cli = tmp_path / "cli_core.py"
    cli.write_text(
        "from __future__ import annotations\n"
        "from inertia.cli.source_sidecar import render_local_source_sidecar_function\n\n"
        "def _validated_generated_c_acceptance_8616():\n"
        "    return None\n",
        encoding="utf-8",
    )

    violations = arch_check._check_cli_acceptance_not_source_evidence_gated(cli)

    assert any(item.rule == "cli-source-evidence-acceptance-gate" for item in violations)


def test_architecture_check_rejects_cli_decompilation_source_sidecar_renderer_import(tmp_path):
    cli = tmp_path / "cli_decompilation.py"
    cli.write_text(
        "from __future__ import annotations\n"
        "from inertia.cli.source_sidecar import render_local_source_sidecar_function\n",
        encoding="utf-8",
    )

    violations = arch_check._check_cli_not_source_backed_quality_gated(cli)

    assert any(item.rule == "cli-source-backed-quality-gate" for item in violations)


def test_architecture_check_rejects_cli_acceptance_source_evidence_helper_definition(tmp_path):
    cli = tmp_path / "cli_core.py"
    cli.write_text(
        "from __future__ import annotations\n\n"
        "def _with_source_evidence_comments_8616(binary_path, function_name, payload, *, enabled):\n"
        "    return payload\n\n"
        "def _source_evidence_payload_for_function_8616(*, binary_path, function_name, payload):\n"
        "    return payload\n\n"
        "def _validated_generated_c_acceptance_8616():\n"
        "    return None\n",
        encoding="utf-8",
    )

    violations = arch_check._check_cli_acceptance_not_source_evidence_gated(cli)

    assert any(item.rule == "cli-source-evidence-acceptance-gate" for item in violations)


def test_architecture_check_rejects_new_postprocess_protected_import(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    (root / "decompiler_postprocess_new.py").write_text(
        '"""New bridge.\n\nDo not add new recovery logic here.\n"""\n'
        "from __future__ import annotations\n"
        "from inertia.semantics.alias_query import query_alias\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "postprocess-protected-import" for item in violations)


def test_architecture_check_admits_typed_lowering_consumers_only_from_stage(tmp_path):
    root, _cli = _write_minimal_tree(tmp_path)
    (root / "decompiler_postprocess_stage.py").write_text(
        '"""Decompiler postprocess orchestrator; do not make it a semantics layer."""\n'
        "from __future__ import annotations\n"
        "from .lowering.condition_argument_types import apply_condition_argument_types_8616\n"
        "from .lowering.stack_aggregate_objects import decay_stack_aggregate_call_arguments_8616\n",
        encoding="utf-8",
    )

    violations = arch_check._check_postprocess_imports(root)

    assert not any(item.rule == "postprocess-protected-import" for item in violations)


def test_architecture_check_rejects_semantic_layer_postprocess_import(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    lowering = root / "lowering"
    lowering.mkdir(parents=True)
    (lowering / "bad_stack_lowering.py").write_text(
        "from __future__ import annotations\n"
        "from ..decompiler_postprocess_utils import _iter_c_nodes_deep_8616\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "semantic-layer-postprocess-import" for item in violations)


def test_architecture_check_rejects_root_semantic_helper_postprocess_import(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    (root / "callsite_stack_metadata.py").write_text(
        "from __future__ import annotations\n"
        "from .decompiler_postprocess_utils import _iter_c_nodes_deep_8616\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "semantic-layer-postprocess-import" for item in violations)


def test_architecture_check_rejects_type_array_matching_postprocess_import(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    (root / "type_array_matching.py").write_text(
        "from __future__ import annotations\n"
        "from .decompiler_postprocess_utils import _safe_assign_cfunc_statements_8616\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "semantic-layer-postprocess-import" for item in violations)


def test_architecture_check_requires_guard_header_for_new_postprocess_module(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    (root / "decompiler_postprocess_new.py").write_text(
        '"""Too vague."""\nfrom __future__ import annotations\n',
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "postprocess-header" for item in violations)


def test_architecture_check_requires_guard_header_for_root_postprocess_bridge(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    (root / "decompiler_postprocess.py").write_text(
        '"""Too vague."""\nfrom __future__ import annotations\n',
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "postprocess-header" for item in violations)


def test_architecture_check_rejects_postprocess_source_text_recovery(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    (root / "decompiler_postprocess_source_text.py").write_text(
        '"""Source text bridge.\n\n'
        "Allowed work: report-only compatibility diagnostics.\n"
        "Forbidden work: semantic recovery from source text.\n"
        "Owning layer: CLI/reporting only.\n"
        '"""\n'
        "from __future__ import annotations\n"
        "def recover(metadata):\n"
        "    return tuple(metadata.source_lines)\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "postprocess-source-text-recovery" for item in violations)


def test_architecture_check_rejects_behavior_in_root_compatibility_shim(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    with (root / "alias_model.py").open("a", encoding="utf-8") as stream:
        stream.write("\ndef recover_alias():\n    return None\n")

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "compat-shim-behavior" for item in violations)


def test_architecture_check_requires_root_compatibility_shim_header(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    (root / "condition_ir.py").write_text(
        "from __future__ import annotations\n"
        "from .ir import condition_ir as _condition_ir\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "compat-shim-header" for item in violations)


def test_architecture_check_admits_cli_lowering_owned_wrapper_identity(tmp_path):
    """CLI may consume representation identity without owning pointer recovery."""
    root, cli = _write_minimal_tree(tmp_path)
    cli.write_text(
        '"""CLI boundary; must not become the owner of decompiler semantics."""\n'
        "from __future__ import annotations\n"
        "from inertia.lowering.near_pointer_argument_values import "
        "is_near_pointer_argument_helper_call_8616\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert not any(item.rule == "cli-x86-16-import" for item in violations)


def test_architecture_check_rejects_unadmitted_cli_x86_16_import(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    cli.write_text(
        '"""CLI boundary; must not become the owner of decompiler semantics."""\n'
        "from __future__ import annotations\n"
        "from inertia.semantics.condition_recovery import build_typed_condition_from_cmp_pair_8616\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "cli-x86-16-import" for item in violations)


@pytest.mark.parametrize(
    ("body", "forbidden_call"),
    (
        (
            "from inertia.postprocess.decompiler_postprocess_calls import "
            "prune_consumed_segmented_stack_byte_arg_stores_8616\n"
            "def run(project: object, codegen: object) -> bool:\n"
            "    return prune_consumed_segmented_stack_byte_arg_stores_8616(project, codegen)\n",
            "prune_consumed_segmented_stack_byte_arg_stores_8616",
        ),
        (
            "import inertia.postprocess.decompiler_postprocess_calls as calls\n"
            "def run(project: object, codegen: object) -> bool:\n"
            "    return calls.prune_consumed_segmented_stack_byte_arg_stores_8616(project, codegen)\n",
            "prune_consumed_segmented_stack_byte_arg_stores_8616",
        ),
        (
            "from inertia.structuring.decompiler_structuring_stage import "
            "run_structuring_condition_cleanup_8616\n"
            "def run(project: object, codegen: object) -> bool:\n"
            "    return run_structuring_condition_cleanup_8616(project, codegen, 0x1000)\n",
            "run_structuring_condition_cleanup_8616",
        ),
    ),
)
def test_architecture_check_rejects_cli_semantic_mutation(
    tmp_path: Path,
    body: str,
    forbidden_call: str,
) -> None:
    """Keep semantic AST mutation inside the validated X86_16 pipeline."""
    root, cli = _write_minimal_tree(tmp_path)
    cli.write_text(
        '"""CLI boundary; must not become the owner of decompiler semantics."""\n'
        "from __future__ import annotations\n"
        f"{body}",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "cli-semantic-mutation" and forbidden_call in item.detail
        for item in violations
    )


def test_architecture_check_rejects_cli_c_text_semantic_recovery(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    cleanup = tmp_path / "inertia" / "cli" / "c_text_cleanup.py"
    cleanup.write_text(
        "from __future__ import annotations\n"
        "def _synthesize_ellipsis_word_borrow_arithmetic(c_text: str) -> str:\n"
        "    return c_text\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "cli-c-text-semantic-recovery" for item in violations)


def test_architecture_check_rejects_cli_c_text_void_object_type_repair(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    cleanup = tmp_path / "inertia" / "cli" / "c_text_cleanup.py"
    cleanup.write_text(
        "from __future__ import annotations\n"
        "def _rewrite_invalid_void_object_decls(c_text: str) -> str:\n"
        "    return c_text\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "cli-c-text-semantic-recovery" for item in violations)


def test_architecture_check_rejects_active_cod_source_rewrite_stage(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    (root / "cod_source_rewrites.py").write_text(
        "from __future__ import annotations\n"
        "def rewrite_cod_source_stage(c_text, metadata):\n"
        "    return '\\n'.join(metadata.source_lines)\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "cod-source-rewrite-active" for item in violations)


def test_architecture_check_rejects_source_annotation_prototype_materialization(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    (root / "annotations.py").write_text(
        "from __future__ import annotations\n"
        "def _apply_source_prototype_annotations_8616(project, func_addr, func, source_lines):\n"
        "    annotate_function(project, func_addr, c_decl='void f(void);')\n"
        "    return True\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "source-annotation-semantic-materialization" for item in violations)


def test_architecture_check_rejects_cod_stack_alias_annotation_materialization(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    (root / "annotations.py").write_text(
        "from __future__ import annotations\n"
        "def _source_decl_from_cod_source_lines(source_lines, function_name=None):\n"
        "    return None\n"
        "def _source_decl_from_cod_source_lines_cached_8616(source_lines, function_name=None):\n"
        "    return None\n"
        "def _source_args_from_cod_source_lines(source_lines, func_name):\n"
        "    return None\n"
        "def _apply_known_helper_signatures(project, cod_metadata=None):\n"
        "    return False\n"
        "def _apply_source_prototype_annotations_8616(project, func_addr, func, source_lines):\n"
        "    return False\n"
        "def _source_function_pointer_local_types_8616(project, source_lines):\n"
        "    return {}\n"
        "def apply_x86_16_metadata_annotations(project, *, func_addr=None, cod_metadata=None):\n"
        "    stack_aliases = getattr(cod_metadata, 'stack_aliases', {})\n"
        "    if stack_aliases:\n"
        "        annotate_function(project, func_addr, bp_stack_vars=stack_aliases)\n"
        "    return False\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "source-annotation-semantic-materialization" for item in violations)


def test_architecture_check_rejects_lowering_cod_global_name_recovery(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    lowering = root / "lowering"
    lowering.mkdir(parents=True)
    (lowering / "bad_global_names.py").write_text(
        "from __future__ import annotations\n"
        "def recover_name(cod_metadata):\n"
        "    return tuple(cod_metadata.global_names)\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "lowering-cod-name-evidence" for item in violations)


def test_architecture_check_requires_alias_ownership_headers(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    alias = root / "alias"
    alias.mkdir(parents=True)
    (alias / "transfer.py").write_text(
        '"""Alias transfer functions without the mandatory ownership contract."""\n'
        "from __future__ import annotations\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "semantic-layer-ownership-header" for item in violations)


def test_architecture_check_requires_widening_ownership_headers(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    widening = root / "widening"
    widening.mkdir(parents=True)
    (widening / "stack_widening.py").write_text(
        '"""Widening pass without the mandatory ownership contract."""\n'
        "from __future__ import annotations\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "semantic-layer-ownership-header" for item in violations)


def test_architecture_check_requires_widening_responsibility_header(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    widening = root / "widening"
    widening.mkdir(parents=True)
    (widening / "stack_widening.py").write_text(
        '"""Stack widening pass.\n\n'
        "Layer: Widening.\n"
        "Consumes alias-proven storage identity before joining values.\n"
        "Do not join values from rendered text, cosmetic shape, postprocess, or CLI/reporting evidence.\n"
        '"""\n'
        "from __future__ import annotations\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "semantic-layer-ownership-header" and "Responsibility:" in item.detail
        for item in violations
    )


def test_architecture_check_requires_semantics_ownership_headers(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    semantics = root / "semantics"
    semantics.mkdir(parents=True)
    (semantics / "flag_semantics.py").write_text(
        '"""Flag helpers without the mandatory ownership contract."""\n'
        "from __future__ import annotations\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "semantic-layer-ownership-header" for item in violations)


def test_architecture_check_requires_pipeline_ownership_headers(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    pipeline = root / "pipeline"
    pipeline.mkdir(parents=True)
    (pipeline / "invariants.py").write_text(
        '"""Pipeline invariants without the mandatory ownership contract."""\n'
        "from __future__ import annotations\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "semantic-layer-ownership-header" for item in violations)


@pytest.mark.parametrize("extra_body", ["", "def hidden_logic():\n    return 1\n"])
def test_layer_alias_cannot_hide_additional_implementation(tmp_path, extra_body):
    root, _ = _write_minimal_tree(tmp_path)
    legacy = root / "ir"
    legacy.mkdir(parents=True)
    canonical = tmp_path / "inertia" / "ir"
    canonical.mkdir(parents=True)
    owner = canonical / "evidence.py"
    markers = arch_check._SEMANTIC_LAYER_OWNERSHIP_MARKERS["ir"]
    owner.write_text('"""' + "\n".join(markers) + '\n"""\n')
    shim = legacy / "evidence.py"
    shim.write_text(
        '"""Layer: compatibility. Responsibility: preserve import identity."""\n'
        'from __future__ import annotations\nimport sys\n'
        'from inertia.ir import evidence as _owner\nsys.modules[__name__] = _owner\n'
        + extra_body
    )
    violations = arch_check._check_semantic_layer_ownership_headers(root)
    assert bool(violations) == bool(extra_body)
    owner.write_text('"""Layer: IR."""\n')
    assert arch_check._check_semantic_layer_ownership_headers(root)


def test_architecture_check_requires_owned_lane_dot_access(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    pipeline = root / "pipeline"
    pipeline.mkdir(parents=True)
    (pipeline / "contracts.py").write_text(
        '"""Layer: Pipeline governance.\n\n'
        "Owns runtime ordering, invariant checks, hard failures, and final emission gates.\n"
        "Do not recover semantic facts or perform IR, alias, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here.\n"
        '"""\n'
        "from __future__ import annotations\n\n"
        "def check(stack_lane):\n"
        "    return getattr(stack_lane, 'raw', 0)\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "owned-lane-dot-access" for item in violations)


def test_architecture_check_requires_pipeline_invariant_alias_dot_access(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    pipeline = root / "pipeline"
    pipeline.mkdir(parents=True)
    (pipeline / "invariants.py").write_text(
        '"""Layer: Pipeline governance.\n\n'
        "Owns runtime ordering, invariant checks, hard failures, and final emission gates.\n"
        "Do not recover semantic facts or perform IR, alias, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here.\n"
        '"""\n'
        "from __future__ import annotations\n\n"
        "def _check_stack_slots_materialized(codegen, report):\n"
        "    for fact in codegen.facts:\n"
        "        identity_val = fact.identity[1]\n"
        "        return getattr(identity_val, 'offset', None)\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "pipeline-invariants-alias-dot-access" for item in violations)


def test_architecture_check_rejects_getattr_on_typed_owned_contract(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    ir = root / "ir"
    ir.mkdir(parents=True)
    (ir / "core.py").write_text(
        '"""Layer: IR.\n\n'
        "Owns typed Value, Address, Condition, instruction facts, and lossless normalization.\n"
        "Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here.\n"
        '"""\n'
        "from __future__ import annotations\n\n"
        "from dataclasses import dataclass\n\n"
        "@dataclass(frozen=True, slots=True)\n"
        "class Address:\n"
        "    space: str\n"
        "    offset: int\n\n"
        "def render(address: Address) -> int:\n"
        "    return getattr(address, 'offset', 0)\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "owned-contract-dot-access" for item in violations)


def test_owned_contract_field_collection_uses_module_level_dataclasses(tmp_path):
    root = tmp_path / "X86_16"
    root.mkdir(parents=True)
    (root / "contracts.py").write_text(
        "from __future__ import annotations\n\n"
        "from dataclasses import dataclass\n\n"
        "@dataclass(frozen=True, slots=True)\n"
        "class Address:\n"
        "    space: str\n"
        "    offset: int\n\n"
        "def factory() -> object:\n"
        "    @dataclass\n"
        "    class LocalOnly:\n"
        "        hidden: int\n"
        "    return LocalOnly(1)\n",
        encoding="utf-8",
    )

    fields = arch_check._collect_owned_dataclass_fields(root)

    assert fields["Address"] == frozenset({"space", "offset"})
    assert "LocalOnly" not in fields


def test_architecture_check_rejects_getattr_on_typed_owned_protocol(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    ir = root / "ir"
    ir.mkdir(parents=True)
    (ir / "core.py").write_text(
        '"""Layer: IR.\n\n'
        "Owns typed Value, Address, Condition, instruction facts, and lossless normalization.\n"
        "Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here.\n"
        '"""\n'
        "from __future__ import annotations\n\n"
        "from typing import Protocol\n\n"
        "class AddressCarrier(Protocol):\n"
        "    offset: int\n\n"
        "def render(address: AddressCarrier) -> int:\n"
        "    return getattr(address, 'offset', 0)\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "owned-contract-dot-access" for item in violations)


def test_architecture_check_rejects_getattr_on_isinstance_narrowed_owned_contract(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    ir = root / "ir"
    ir.mkdir(parents=True)
    (ir / "core.py").write_text(
        '"""Layer: IR.\n\n'
        "Owns typed Value, Address, Condition, instruction facts, and lossless normalization.\n"
        "Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here.\n"
        '"""\n'
        "from __future__ import annotations\n\n"
        "from dataclasses import dataclass\n\n"
        "@dataclass(frozen=True, slots=True)\n"
        "class Address:\n"
        "    space: str\n"
        "    offset: int\n\n"
        "def render(value: object) -> int | None:\n"
        "    if isinstance(value, Address):\n"
        "        return getattr(value, 'offset', None)\n"
        "    return None\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "owned-contract-dot-access" for item in violations)


def test_architecture_check_rejects_setattr_on_constructed_owned_contract(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    pipeline = root / "pipeline"
    pipeline.mkdir(parents=True)
    (pipeline / "contracts.py").write_text(
        '"""Layer: Pipeline governance.\n\n'
        "Owns runtime ordering, invariant checks, hard failures, and final emission gates.\n"
        "Do not recover semantic facts or perform IR, alias, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here.\n"
        '"""\n'
        "from __future__ import annotations\n\n"
        "from dataclasses import dataclass\n\n"
        "@dataclass(slots=True)\n"
        "class SemanticLaneState:\n"
        "    raw: int = 0\n\n"
        "def check() -> None:\n"
        "    lane = SemanticLaneState()\n"
        "    setattr(lane, 'raw', 1)\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "owned-contract-dot-access" for item in violations)


def test_architecture_check_allows_dynamic_attr_on_untyped_external_object(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    ir = root / "ir"
    ir.mkdir(parents=True)
    (ir / "core.py").write_text(
        '"""Layer: IR.\n\n'
        "Owns typed Value, Address, Condition, instruction facts, and lossless normalization.\n"
        "Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here.\n"
        '"""\n'
        "from __future__ import annotations\n\n"
        "from dataclasses import dataclass\n\n"
        "@dataclass(frozen=True, slots=True)\n"
        "class Address:\n"
        "    space: str\n"
        "    offset: int\n\n"
        "def render(external) -> object:\n"
        "    return getattr(external, 'offset', None)\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert not any(item.rule == "owned-contract-dot-access" for item in violations)


def test_architecture_check_requires_grouped_graph_iraddress_dot_access(tmp_path):
    grouped = tmp_path / "structuring_grouped_graph_builder.py"
    grouped.write_text(
        "from __future__ import annotations\n"
        "def _scan_typed_ir_block_8616(block):\n"
        "    for arg in block.args:\n"
        "        return getattr(arg, 'status', None)\n"
        "    return None\n",
        encoding="utf-8",
    )

    violations = arch_check._check_grouped_graph_ir_address_dot_access(grouped)

    assert any(item.rule == "grouped-graph-iraddress-dot-access" for item in violations)


def test_architecture_check_requires_type_equivalence_typed_ir_dot_access(tmp_path):
    type_equivalence = tmp_path / "type_equivalence_classes.py"
    type_equivalence.write_text(
        "from __future__ import annotations\n"
        "def _typed_ir_summary_from_codegen(codegen):\n"
        "    for atom in codegen.atoms:\n"
        "        return getattr(atom, 'segment_origin', None)\n"
        "    return None\n",
        encoding="utf-8",
    )

    violations = arch_check._check_type_equivalence_typed_ir_dot_access(type_equivalence)

    assert any(item.rule == "type-equivalence-typed-ir-dot-access" for item in violations)


def test_architecture_check_requires_type_equivalence_owned_artifact_dot_access(tmp_path):
    type_equivalence = tmp_path / "type_equivalence_classes.py"
    type_equivalence.write_text(
        "from __future__ import annotations\n"
        "def _typed_ir_equivalence_from_codegen(codegen):\n"
        "    artifact = codegen.artifact\n"
        "    return getattr(artifact, 'blocks', ())\n",
        encoding="utf-8",
    )

    violations = arch_check._check_type_equivalence_typed_ir_dot_access(type_equivalence)

    assert any(item.rule == "type-equivalence-typed-ir-dot-access" for item in violations)


def test_architecture_check_requires_type_array_matching_iraddress_dot_access(tmp_path):
    array_matching = tmp_path / "type_array_matching.py"
    array_matching.write_text(
        "from __future__ import annotations\n"
        "def _typed_ir_array_candidates(codegen):\n"
        "    for atom in codegen.atoms:\n"
        "        return getattr(atom, 'base', ())\n"
        "    return None\n",
        encoding="utf-8",
    )

    violations = arch_check._check_type_array_matching_typed_ir_dot_access(array_matching)

    assert any(item.rule == "type-array-matching-iraddress-dot-access" for item in violations)


def test_architecture_check_requires_type_array_matching_owned_artifact_dot_access(tmp_path):
    array_matching = tmp_path / "type_array_matching.py"
    array_matching.write_text(
        "from __future__ import annotations\n"
        "def _typed_ir_array_candidates(codegen):\n"
        "    artifact = codegen.artifact\n"
        "    return getattr(artifact, 'blocks', ())\n",
        encoding="utf-8",
    )

    violations = arch_check._check_type_array_matching_typed_ir_dot_access(array_matching)

    assert any(item.rule == "type-array-matching-iraddress-dot-access" for item in violations)


def test_architecture_check_requires_type_array_induction_summary_dot_access(tmp_path):
    array_matching = tmp_path / "type_array_matching.py"
    array_matching.write_text(
        "from __future__ import annotations\n"
        "def _profile_induction_match_8616(codegen, loop_var):\n"
        "    for summary in codegen.summaries:\n"
        "        return getattr(summary, 'index_key', None)\n"
        "    return None\n",
        encoding="utf-8",
    )

    violations = arch_check._check_type_array_matching_induction_summary_dot_access(array_matching)

    assert any(
        item.rule == "type-array-induction-summary-dot-access" and "InductionSummary" in item.detail
        for item in violations
    )


def test_architecture_check_requires_type_array_matching_string_record_dot_access(tmp_path):
    array_matching = tmp_path / "type_array_matching.py"
    array_matching.write_text(
        "from __future__ import annotations\n"
        "def _typed_string_array_candidates(codegen):\n"
        "    for record in codegen.records:\n"
        "        return getattr(record, 'source', None)\n"
        "    return None\n",
        encoding="utf-8",
    )

    violations = arch_check._check_type_array_matching_typed_ir_dot_access(array_matching)

    assert any(item.rule == "type-array-matching-iraddress-dot-access" for item in violations)


def test_architecture_check_requires_type_structure_merging_typed_ir_dot_access(tmp_path):
    structure_merging = tmp_path / "type_structure_merging.py"
    structure_merging.write_text(
        "from __future__ import annotations\n"
        "def _typed_ir_struct_candidates(codegen):\n"
        "    for block in codegen.blocks:\n"
        "        return getattr(block, 'instrs', ())\n"
        "    return None\n",
        encoding="utf-8",
    )

    violations = arch_check._check_type_structure_merging_typed_ir_dot_access(structure_merging)

    assert any(item.rule == "type-structure-merging-typed-ir-dot-access" for item in violations)


def test_architecture_check_requires_structuring_alias_failure_dot_access(tmp_path):
    structuring = tmp_path / "decompiler_structuring_stage.py"
    structuring.write_text(
        "from __future__ import annotations\n"
        "def _assert_alias_complete_8616(codegen):\n"
        "    for fact in codegen.facts:\n"
        "        return getattr(fact, 'space', None)\n"
        "    return None\n",
        encoding="utf-8",
    )

    violations = arch_check._check_structuring_alias_failure_dot_access(structuring)

    assert any(item.rule == "structuring-alias-failure-dot-access" for item in violations)


def test_architecture_check_requires_stack_lowering_binding_dot_access(tmp_path):
    lowering = tmp_path / "stack_lowering_from_facts.py"
    lowering.write_text(
        "from __future__ import annotations\n"
        "def lower_stack_accesses_from_alias_facts_8616(codegen, alias_facts):\n"
        "    bindings = codegen.bindings\n"
        "    for binding in bindings:\n"
        "        return getattr(binding, 'bp_offset', None)\n"
        "    return None\n",
        encoding="utf-8",
    )

    violations = arch_check._check_stack_lowering_binding_dot_access(lowering)

    assert any(item.rule == "stack-lowering-binding-dot-access" for item in violations)


def test_architecture_check_requires_stack_lowering_fact_identity_dot_access(tmp_path):
    lowering = tmp_path / "stack_lowering_from_facts.py"
    lowering.write_text(
        "from __future__ import annotations\n"
        "def build_stack_variable_bindings_from_alias_facts_8616(alias_facts):\n"
        "    for fact in alias_facts:\n"
        "        return getattr(fact, 'identity', None)\n"
        "    return None\n",
        encoding="utf-8",
    )

    violations = arch_check._check_stack_lowering_binding_dot_access(lowering)

    assert any(
        item.rule == "stack-lowering-binding-dot-access" and "fact.identity" in item.detail
        for item in violations
    )


def test_architecture_check_requires_fact_transfer_alias_fact_dot_access(tmp_path):
    transfer = tmp_path / "fact_transfer.py"
    transfer.write_text(
        "from __future__ import annotations\n"
        "def transfer_semantic_alias_facts_to_codegen_8616(project, codegen):\n"
        "    for fact in codegen.facts:\n"
        "        return getattr(fact, 'identity', None)\n"
        "    return None\n",
        encoding="utf-8",
    )

    violations = arch_check._check_fact_transfer_alias_fact_dot_access(transfer)

    assert any(
        item.rule == "fact-transfer-alias-fact-dot-access" and "fact.identity" in item.detail
        for item in violations
    )


def test_architecture_check_rejects_address_keyed_global_semantic_evidence(tmp_path) -> None:
    evidence_cache = tmp_path / "evidence_cache.py"
    evidence_cache.write_text(
        "_accesses_by_block = {}\n"
        "def migrate_block_accesses_to_function(block_addr: int, function_addr: int) -> int:\n"
        "    return 0\n",
        encoding="utf-8",
    )

    violations = arch_check._check_semantic_evidence_context_ownership(evidence_cache)

    assert {item.rule for item in violations} == {"semantic-evidence-context-ownership"}


def test_architecture_check_requires_stack_lowering_result_typed_status(tmp_path):
    lowering = tmp_path / "stack_lowering_from_facts.py"
    lowering.write_text(
        "from __future__ import annotations\n"
        "def lower_stack_accesses_from_alias_facts_8616(codegen, alias_facts):\n"
        "    return StackLoweringResult(status='ok', failures=[])\n",
        encoding="utf-8",
    )

    violations = arch_check._check_stack_lowering_result_typed_status(lowering)

    assert any(item.rule == "stack-lowering-result-typed-status" for item in violations)


def test_architecture_check_requires_stack_prototype_narrowed_field_dot_access(tmp_path):
    lowering = tmp_path / "stack_prototype_materialization.py"
    lowering.write_text(
        "from __future__ import annotations\n"
        "def stack_offset(variable):\n"
        "    return getattr(variable, 'offset', None)\n",
        encoding="utf-8",
    )

    violations = arch_check._check_stack_prototype_narrowed_fields_use_dot(lowering)

    assert any(
        item.rule == "stack-prototype-narrowed-field-dot-access" and "variable.offset" in item.detail
        for item in violations
    )


def test_architecture_check_requires_stack_c_ast_narrowed_field_dot_access(tmp_path):
    lowering = tmp_path / "stack_c_ast_matching.py"
    lowering.write_text(
        "from __future__ import annotations\n"
        "def assignment_lhs(stmt):\n"
        "    return getattr(stmt, 'lhs', None)\n",
        encoding="utf-8",
    )

    violations = arch_check._check_stack_c_ast_narrowed_fields_use_dot(lowering)

    assert any(
        item.rule == "stack-c-ast-narrowed-field-dot-access" and "stmt.lhs" in item.detail
        for item in violations
    )


def test_architecture_check_requires_calling_convention_owned_seed_dot_access(tmp_path):
    compatibility = tmp_path / "calling_convention_compat.py"
    compatibility.write_text(
        "from __future__ import annotations\n"
        "def target(seed):\n"
        "    return getattr(seed, 'target_addr', None)\n",
        encoding="utf-8",
    )

    violations = arch_check._check_calling_convention_owned_seed_fields_use_dot(compatibility)

    assert any(
        item.rule == "calling-convention-owned-seed-dot-access" and "seed.target_addr" in item.detail
        for item in violations
    )


def test_architecture_check_requires_c_ast_utils_dot_access_after_narrowing(tmp_path):
    utility = tmp_path / "c_ast_utils.py"
    utility.write_text(
        "from __future__ import annotations\n"
        "def variable(node):\n"
        "    if isinstance(node, CVariable):\n"
        "        return getattr(node, 'variable', None)\n"
        "    return None\n",
        encoding="utf-8",
    )

    violations = arch_check._check_c_ast_utils_narrowed_fields_use_dot(utility)

    assert any(
        item.rule == "c-ast-utils-narrowed-field-dot-access"
        and "node.variable" in item.detail
        and "CVariable narrowing" in item.detail
        for item in violations
    )


def test_architecture_check_requires_cli_dead_local_dot_access_after_narrowing(tmp_path):
    pruner = tmp_path / "cli_dead_local_prune.py"
    pruner.write_text(
        "from __future__ import annotations\n"
        "def assignment_rhs(node):\n"
        "    if isinstance(node, structured_c.CAssignment):\n"
        "        return getattr(node, 'rhs', None)\n"
        "    return None\n",
        encoding="utf-8",
    )

    violations = arch_check._check_cli_dead_local_narrowed_fields_use_dot(pruner)

    assert any(
        item.rule == "cli-dead-local-narrowed-field-dot-access"
        and "node.rhs" in item.detail
        and "structured_c.CAssignment narrowing" in item.detail
        for item in violations
    )


def test_architecture_check_requires_lifter_operand_size_dot_access(tmp_path):
    lifter = tmp_path / "lift_86_16.py"
    lifter.write_text(
        "from __future__ import annotations\n"
        "def operand_size(operand):\n"
        "    return getattr(operand, 'size', None)\n",
        encoding="utf-8",
    )

    violations = arch_check._check_lifter_operand_size_uses_dot(lifter)

    assert any(
        item.rule == "lifter-operand-size-dot-access" and "operand.size" in item.detail
        for item in violations
    )


def test_architecture_check_requires_structuring_codegen_dot_access_after_guard(tmp_path):
    structuring = tmp_path / "structuring_codegen.py"
    structuring.write_text(
        "from __future__ import annotations\n"
        "def statements(node):\n"
        "    if not isinstance(node, structured_c.CStatements):\n"
        "        return ()\n"
        "    return getattr(node, 'statements', ())\n",
        encoding="utf-8",
    )

    violations = arch_check._check_structuring_codegen_narrowed_fields_use_dot(structuring)

    assert any(
        item.rule == "structuring-codegen-narrowed-field-dot-access"
        and "node.statements" in item.detail
        and "structured_c.CStatements guard" in item.detail
        for item in violations
    )


def test_architecture_check_requires_postprocess_simplify_narrowed_field_dot_access(tmp_path):
    simplify = tmp_path / "decompiler_postprocess_simplify.py"
    simplify.write_text(
        "from __future__ import annotations\n"
        "def binary_lhs(expr):\n"
        "    return getattr(expr, 'lhs', None)\n",
        encoding="utf-8",
    )

    violations = arch_check._check_postprocess_simplify_narrowed_fields_use_dot(simplify)

    assert any(
        item.rule == "postprocess-simplify-narrowed-field-dot-access" and "expr.lhs" in item.detail
        for item in violations
    )


def test_architecture_check_requires_postprocess_simplify_dot_access_after_narrowing(tmp_path):
    simplify = tmp_path / "decompiler_postprocess_simplify.py"
    simplify.write_text(
        "from __future__ import annotations\n"
        "def assignment_rhs(node):\n"
        "    if isinstance(node, CAssignment):\n"
        "        return getattr(node, 'rhs', None)\n"
        "    return None\n",
        encoding="utf-8",
    )

    violations = arch_check._check_postprocess_simplify_narrowed_fields_use_dot(simplify)

    assert any(
        item.rule == "postprocess-simplify-narrowed-field-dot-access"
        and "node.rhs" in item.detail
        and "CAssignment narrowing" in item.detail
        for item in violations
    )


def test_architecture_check_requires_postprocess_simplify_dot_access_after_guard(tmp_path):
    simplify = tmp_path / "decompiler_postprocess_simplify.py"
    simplify.write_text(
        "from __future__ import annotations\n"
        "def call_args(node):\n"
        "    if not isinstance(node, CFunctionCall):\n"
        "        return None\n"
        "    return getattr(node, 'args', None)\n",
        encoding="utf-8",
    )

    violations = arch_check._check_postprocess_simplify_narrowed_fields_use_dot(simplify)

    assert any(
        item.rule == "postprocess-simplify-narrowed-field-dot-access"
        and "node.args" in item.detail
        and "CFunctionCall guard" in item.detail
        for item in violations
    )


def test_architecture_check_requires_postprocess_calls_narrowed_field_dot_access(tmp_path):
    calls = tmp_path / "decompiler_postprocess_calls.py"
    calls.write_text(
        "from __future__ import annotations\n"
        "def binary_lhs(expr):\n"
        "    if isinstance(expr, CBinaryOp):\n"
        "        return getattr(expr, 'lhs', None)\n"
        "    return None\n",
        encoding="utf-8",
    )

    violations = arch_check._check_postprocess_calls_narrowed_fields_use_dot(calls)

    assert any(
        item.rule == "postprocess-calls-narrowed-field-dot-access" and "expr.lhs" in item.detail
        for item in violations
    )


def test_architecture_check_requires_dot_access_after_terminating_type_guard(tmp_path):
    calls = tmp_path / "decompiler_postprocess_calls.py"
    calls.write_text(
        "from __future__ import annotations\n"
        "def stack_offset(variable):\n"
        "    if not isinstance(variable, SimStackVariable):\n"
        "        return None\n"
        "    return getattr(variable, 'offset', None)\n",
        encoding="utf-8",
    )

    violations = arch_check._check_postprocess_calls_narrowed_fields_use_dot(calls)

    assert any(
        item.rule == "postprocess-calls-narrowed-field-dot-access" and "variable.offset" in item.detail
        for item in violations
    )


def test_architecture_check_requires_real_mode_narrowed_field_dot_access(tmp_path):
    lowering = tmp_path / "real_mode_linear.py"
    lowering.write_text(
        "from __future__ import annotations\n"
        "def memory_address(variable):\n"
        "    if isinstance(variable, SimMemoryVariable):\n"
        "        return getattr(variable, 'addr', None)\n"
        "    return None\n",
        encoding="utf-8",
    )

    violations = arch_check._check_real_mode_linear_narrowed_fields_use_dot(lowering)

    assert any(
        item.rule == "real-mode-linear-narrowed-field-dot-access" and "variable.addr" in item.detail
        for item in violations
    )


def test_architecture_check_requires_real_mode_dot_access_after_type_guard(tmp_path):
    lowering = tmp_path / "real_mode_linear.py"
    lowering.write_text(
        "from __future__ import annotations\n"
        "def register_offset(variable):\n"
        "    if not isinstance(variable, SimRegisterVariable):\n"
        "        return None\n"
        "    return getattr(variable, 'reg', None)\n",
        encoding="utf-8",
    )

    violations = arch_check._check_real_mode_linear_narrowed_fields_use_dot(lowering)

    assert any(
        item.rule == "real-mode-linear-narrowed-field-dot-access" and "variable.reg" in item.detail
        for item in violations
    )


def test_architecture_check_requires_postprocess_narrowed_field_dot_access(tmp_path):
    postprocess = tmp_path / "decompiler_postprocess.py"
    postprocess.write_text(
        "from __future__ import annotations\n"
        "def return_value(node):\n"
        "    if isinstance(node, CReturn):\n"
        "        return getattr(node, 'retval', None)\n"
        "    return None\n",
        encoding="utf-8",
    )

    violations = arch_check._check_postprocess_narrowed_fields_use_dot(postprocess)

    assert any(
        item.rule == "postprocess-narrowed-field-dot-access" and "node.retval" in item.detail
        for item in violations
    )


def test_architecture_check_requires_postprocess_dot_access_after_type_guard(tmp_path):
    postprocess = tmp_path / "decompiler_postprocess.py"
    postprocess.write_text(
        "from __future__ import annotations\n"
        "def stack_offset(variable):\n"
        "    if not isinstance(variable, SimStackVariable):\n"
        "        return None\n"
        "    return getattr(variable, 'offset', None)\n",
        encoding="utf-8",
    )

    violations = arch_check._check_postprocess_narrowed_fields_use_dot(postprocess)

    assert any(
        item.rule == "postprocess-narrowed-field-dot-access" and "variable.offset" in item.detail
        for item in violations
    )


def test_architecture_check_requires_cli_c_ast_narrowed_field_dot_access(tmp_path):
    rewrites = tmp_path / "cli_c_ast_rewrites.py"
    rewrites.write_text(
        "from __future__ import annotations\n"
        "def binary_type(node):\n"
        "    if isinstance(node, structured_c.CBinaryOp):\n"
        "        return getattr(node, 'type', None)\n"
        "    return None\n",
        encoding="utf-8",
    )

    violations = arch_check._check_cli_c_ast_rewrites_narrowed_fields_use_dot(rewrites)

    assert any(
        item.rule == "cli-c-ast-rewrites-narrowed-field-dot-access" and "node.type" in item.detail
        for item in violations
    )


def test_architecture_check_requires_cli_c_ast_dot_access_after_type_guard(tmp_path):
    rewrites = tmp_path / "cli_c_ast_rewrites.py"
    rewrites.write_text(
        "from __future__ import annotations\n"
        "def register_offset(variable):\n"
        "    if not isinstance(variable, SimRegisterVariable):\n"
        "        return None\n"
        "    return getattr(variable, 'reg', None)\n",
        encoding="utf-8",
    )

    violations = arch_check._check_cli_c_ast_rewrites_narrowed_fields_use_dot(rewrites)

    assert any(
        item.rule == "cli-c-ast-rewrites-narrowed-field-dot-access" and "variable.reg" in item.detail
        for item in violations
    )


def test_architecture_check_requires_postprocess_jcc_narrowed_field_dot_access(tmp_path):
    jcc = tmp_path / "decompiler_postprocess_jcc.py"
    jcc.write_text(
        "from __future__ import annotations\n"
        "def cast_expr(node):\n"
        "    if isinstance(node, CTypeCast):\n"
        "        return getattr(node, 'expr', None)\n"
        "    return None\n",
        encoding="utf-8",
    )

    violations = arch_check._check_postprocess_jcc_narrowed_fields_use_dot(jcc)

    assert any(
        item.rule == "postprocess-jcc-narrowed-field-dot-access" and "node.expr" in item.detail
        for item in violations
    )


def test_architecture_check_requires_postprocess_jcc_dot_access_after_type_guard(tmp_path):
    jcc = tmp_path / "decompiler_postprocess_jcc.py"
    jcc.write_text(
        "from __future__ import annotations\n"
        "def stack_offset(variable):\n"
        "    if not isinstance(variable, SimStackVariable):\n"
        "        return None\n"
        "    return getattr(variable, 'offset', None)\n",
        encoding="utf-8",
    )

    violations = arch_check._check_postprocess_jcc_narrowed_fields_use_dot(jcc)

    assert any(
        item.rule == "postprocess-jcc-narrowed-field-dot-access" and "variable.offset" in item.detail
        for item in violations
    )


def test_architecture_check_requires_postprocess_stage_narrowed_field_dot_access(tmp_path):
    stage = tmp_path / "decompiler_postprocess_stage.py"
    stage.write_text(
        "from __future__ import annotations\n"
        "def constant_value(node):\n"
        "    if isinstance(node, CConstant):\n"
        "        return getattr(node, 'value', None)\n"
        "    return None\n",
        encoding="utf-8",
    )

    violations = arch_check._check_postprocess_stage_narrowed_fields_use_dot(stage)

    assert any(
        item.rule == "postprocess-stage-narrowed-field-dot-access" and "node.value" in item.detail
        for item in violations
    )


def test_architecture_check_requires_postprocess_stage_dot_access_after_type_guard(tmp_path):
    stage = tmp_path / "decompiler_postprocess_stage.py"
    stage.write_text(
        "from __future__ import annotations\n"
        "def call_target(node):\n"
        "    if not isinstance(node, CFunctionCall):\n"
        "        return None\n"
        "    return getattr(node, 'callee_target', None)\n",
        encoding="utf-8",
    )

    violations = arch_check._check_postprocess_stage_narrowed_fields_use_dot(stage)

    assert any(
        item.rule == "postprocess-stage-narrowed-field-dot-access" and "node.callee_target" in item.detail
        for item in violations
    )


def test_architecture_check_requires_tail_validation_narrowed_field_dot_access(tmp_path):
    validation = tmp_path / "tail_validation.py"
    validation.write_text(
        "from __future__ import annotations\n"
        "def loop_body(node):\n"
        "    if isinstance(node, CWhileLoop):\n"
        "        return getattr(node, 'body', None)\n"
        "    return None\n",
        encoding="utf-8",
    )

    violations = arch_check._check_tail_validation_narrowed_fields_use_dot(validation)

    assert any(
        item.rule == "tail-validation-narrowed-field-dot-access" and "node.body" in item.detail
        for item in violations
    )


def test_architecture_check_requires_loop_body_repair_tuple_narrowed_dot_access(tmp_path):
    repair = tmp_path / "loop_body_repair.py"
    repair.write_text(
        "from __future__ import annotations\n"
        "def loop_body(node):\n"
        "    if isinstance(node, (CForLoop, CWhileLoop, CDoWhileLoop)):\n"
        "        return getattr(node, 'body', None)\n"
        "    return None\n",
        encoding="utf-8",
    )

    violations = arch_check._check_loop_body_repair_narrowed_fields_use_dot(repair)

    assert any(
        item.rule == "loop-body-repair-narrowed-field-dot-access" and "node.body" in item.detail
        for item in violations
    )


def test_architecture_check_requires_loop_body_repair_dot_access_after_type_guard(tmp_path):
    repair = tmp_path / "loop_body_repair.py"
    repair.write_text(
        "from __future__ import annotations\n"
        "def statements(node):\n"
        "    if not isinstance(node, CStatements):\n"
        "        return ()\n"
        "    return getattr(node, 'statements', ())\n",
        encoding="utf-8",
    )

    violations = arch_check._check_loop_body_repair_narrowed_fields_use_dot(repair)

    assert any(
        item.rule == "loop-body-repair-narrowed-field-dot-access" and "node.statements" in item.detail
        for item in violations
    )


def test_architecture_check_requires_stack_lowering_impl_narrowed_field_dot_access(tmp_path):
    lowering = tmp_path / "stack_lowering_impl.py"
    lowering.write_text(
        "from __future__ import annotations\n"
        "def indexed_variable(node):\n"
        "    if isinstance(node, structured_c.CIndexedVariable):\n"
        "        return getattr(node, 'variable', None)\n"
        "    return None\n",
        encoding="utf-8",
    )

    violations = arch_check._check_stack_lowering_impl_narrowed_fields_use_dot(lowering)

    assert any(
        item.rule == "stack-lowering-impl-narrowed-field-dot-access" and "node.variable" in item.detail
        for item in violations
    )


def test_architecture_check_requires_stack_lowering_impl_dot_access_after_type_guard(tmp_path):
    lowering = tmp_path / "stack_lowering_impl.py"
    lowering.write_text(
        "from __future__ import annotations\n"
        "def stack_offset(variable):\n"
        "    if not isinstance(variable, SimStackVariable):\n"
        "        return None\n"
        "    return getattr(variable, 'offset', None)\n",
        encoding="utf-8",
    )

    violations = arch_check._check_stack_lowering_impl_narrowed_fields_use_dot(lowering)

    assert any(
        item.rule == "stack-lowering-impl-narrowed-field-dot-access" and "variable.offset" in item.detail
        for item in violations
    )


def test_architecture_check_requires_return_chains_narrowed_field_dot_access(tmp_path):
    chains = tmp_path / "return_chains.py"
    chains.write_text(
        "from __future__ import annotations\n"
        "def return_value(node):\n"
        "    if isinstance(node, CReturn):\n"
        "        return getattr(node, 'retval', None)\n"
        "    return None\n",
        encoding="utf-8",
    )

    violations = arch_check._check_return_chains_narrowed_fields_use_dot(chains)

    assert any(
        item.rule == "return-chains-narrowed-field-dot-access" and "node.retval" in item.detail
        for item in violations
    )


def test_architecture_check_requires_return_chains_dot_access_after_type_guard(tmp_path):
    chains = tmp_path / "return_chains.py"
    chains.write_text(
        "from __future__ import annotations\n"
        "def statements(node):\n"
        "    if not isinstance(node, CStatements):\n"
        "        return ()\n"
        "    return getattr(node, 'statements', ())\n",
        encoding="utf-8",
    )

    violations = arch_check._check_return_chains_narrowed_fields_use_dot(chains)

    assert any(
        item.rule == "return-chains-narrowed-field-dot-access" and "node.statements" in item.detail
        for item in violations
    )


def test_architecture_check_requires_return_compat_narrowed_field_dot_access(tmp_path):
    compat = tmp_path / "decompiler_return_compat.py"
    compat.write_text(
        "from __future__ import annotations\n"
        "def register_offset(expr):\n"
        "    if isinstance(expr, ailment.Expr.Register):\n"
        "        return getattr(expr, 'reg_offset', None)\n"
        "    return None\n",
        encoding="utf-8",
    )

    violations = arch_check._check_return_compat_narrowed_fields_use_dot(compat)

    assert any(
        item.rule == "return-compat-narrowed-field-dot-access" and "expr.reg_offset" in item.detail
        for item in violations
    )


def test_architecture_check_requires_return_compat_dot_access_after_type_guard(tmp_path):
    compat = tmp_path / "decompiler_return_compat.py"
    compat.write_text(
        "from __future__ import annotations\n"
        "def assignment_source(stmt):\n"
        "    if not isinstance(stmt, ailment.Stmt.Assignment):\n"
        "        return None\n"
        "    return getattr(stmt, 'src', None)\n",
        encoding="utf-8",
    )

    violations = arch_check._check_return_compat_narrowed_fields_use_dot(compat)

    assert any(
        item.rule == "return-compat-narrowed-field-dot-access" and "stmt.src" in item.detail
        for item in violations
    )


def test_architecture_check_requires_segmented_global_narrowed_field_dot_access(tmp_path):
    lowering = tmp_path / "segmented_global_loads.py"
    lowering.write_text(
        "from __future__ import annotations\n"
        "def call_target(node):\n"
        "    if isinstance(node, CFunctionCall):\n"
        "        return getattr(node, 'callee_target', None)\n"
        "    return None\n",
        encoding="utf-8",
    )

    violations = arch_check._check_segmented_global_loads_narrowed_fields_use_dot(lowering)

    assert any(
        item.rule == "segmented-global-loads-narrowed-field-dot-access" and "node.callee_target" in item.detail
        for item in violations
    )


def test_architecture_check_requires_segmented_global_dot_access_after_type_guard(tmp_path):
    lowering = tmp_path / "segmented_global_loads.py"
    lowering.write_text(
        "from __future__ import annotations\n"
        "def stack_offset(variable):\n"
        "    if not isinstance(variable, SimStackVariable):\n"
        "        return None\n"
        "    return getattr(variable, 'offset', None)\n",
        encoding="utf-8",
    )

    violations = arch_check._check_segmented_global_loads_narrowed_fields_use_dot(lowering)

    assert any(
        item.rule == "segmented-global-loads-narrowed-field-dot-access" and "variable.offset" in item.detail
        for item in violations
    )


def test_architecture_check_requires_structuring_stage_narrowed_field_dot_access(tmp_path):
    stage = tmp_path / "decompiler_structuring_stage.py"
    stage.write_text(
        "from __future__ import annotations\n"
        "def binary_lhs(node):\n"
        "    if isinstance(node, CBinaryOp):\n"
        "        return getattr(node, 'lhs', None)\n"
        "    return None\n",
        encoding="utf-8",
    )

    violations = arch_check._check_structuring_stage_narrowed_fields_use_dot(stage)

    assert any(
        item.rule == "structuring-stage-narrowed-field-dot-access" and "node.lhs" in item.detail
        for item in violations
    )


def test_architecture_check_requires_cli_decompilation_narrowed_field_dot_access(tmp_path):
    cli = tmp_path / "cli_decompilation.py"
    cli.write_text(
        "from __future__ import annotations\n"
        "def unary_operand(node):\n"
        "    if isinstance(node, structured_c.CUnaryOp):\n"
        "        return getattr(node, 'operand', None)\n"
        "    return None\n",
        encoding="utf-8",
    )

    violations = arch_check._check_cli_decompilation_narrowed_fields_use_dot(cli)

    assert any(
        item.rule == "cli-decompilation-narrowed-field-dot-access" and "node.operand" in item.detail
        for item in violations
    )


def test_architecture_check_requires_cli_decompilation_dot_access_after_type_guard(tmp_path):
    cli = tmp_path / "cli_decompilation.py"
    cli.write_text(
        "from __future__ import annotations\n"
        "def call_target(node):\n"
        "    if not isinstance(node, structured_c.CFunctionCall):\n"
        "        return None\n"
        "    return getattr(node, 'callee_target', None)\n",
        encoding="utf-8",
    )

    violations = arch_check._check_cli_decompilation_narrowed_fields_use_dot(cli)

    assert any(
        item.rule == "cli-decompilation-narrowed-field-dot-access" and "node.callee_target" in item.detail
        for item in violations
    )


def test_architecture_check_requires_postprocess_optimization_narrowed_dot_access(tmp_path):
    optimization = tmp_path / "dead_setup.py"
    optimization.write_text(
        "from __future__ import annotations\n"
        "def binary_lhs(node):\n"
        "    if isinstance(node, CBinaryOp):\n"
        "        return getattr(node, 'lhs', None)\n"
        "    return None\n",
        encoding="utf-8",
    )

    violations = arch_check._check_postprocess_optimization_narrowed_fields_use_dot(optimization)

    assert any(
        item.rule == "postprocess-optimization-narrowed-field-dot-access" and "node.lhs" in item.detail
        for item in violations
    )


def test_architecture_check_requires_postprocess_optimization_dot_access_after_guard(tmp_path):
    optimization = tmp_path / "trivial_copy.py"
    optimization.write_text(
        "from __future__ import annotations\n"
        "def stack_offset(variable):\n"
        "    if not isinstance(variable, SimStackVariable):\n"
        "        return None\n"
        "    return getattr(variable, 'offset', None)\n",
        encoding="utf-8",
    )

    violations = arch_check._check_postprocess_optimization_narrowed_fields_use_dot(optimization)

    assert any(
        item.rule == "postprocess-optimization-narrowed-field-dot-access" and "variable.offset" in item.detail
        for item in violations
    )


def test_architecture_check_requires_stack_lowering_impl_binding_dot_access(tmp_path):
    lowering = tmp_path / "stack_lowering_impl.py"
    lowering.write_text(
        "from __future__ import annotations\n"
        "def _sole_bound_stack_cvar_8616(codegen, resolve_stack_cvar_at_offset):\n"
        "    binding = codegen.bindings[0]\n"
        "    return getattr(binding, 'size', None)\n",
        encoding="utf-8",
    )

    violations = arch_check._check_stack_lowering_impl_binding_dot_access(lowering)

    assert any(item.rule == "stack-lowering-impl-binding-dot-access" for item in violations)


def test_architecture_check_requires_stack_lowering_impl_alias_fact_dot_access(tmp_path):
    lowering = tmp_path / "stack_lowering_impl.py"
    lowering.write_text(
        "from __future__ import annotations\n"
        "def _typed_alias_fact_bp_offsets_8616(facts):\n"
        "    for fact in facts:\n"
        "        return getattr(fact, 'identity', None)\n"
        "    return set()\n",
        encoding="utf-8",
    )

    violations = arch_check._check_stack_lowering_impl_alias_fact_dot_access(lowering)

    assert any(
        item.rule == "stack-lowering-impl-alias-fact-dot-access" and "AliasStorageFacts" in item.detail
        for item in violations
    )


def test_architecture_check_requires_tail_validation_binding_dot_access(tmp_path):
    fingerprint = tmp_path / "tail_validation_fingerprint.py"
    fingerprint.write_text(
        "from __future__ import annotations\n"
        "def _materialized_local_map_8616(codegen):\n"
        "    for binding in codegen.bindings:\n"
        "        return getattr(binding, 'var_name', None)\n"
        "    return None\n",
        encoding="utf-8",
    )

    violations = arch_check._check_tail_validation_binding_dot_access(fingerprint)

    assert any(
        item.rule == "tail-validation-binding-dot-access" and "StackVariableBinding" in item.detail
        for item in violations
    )


def test_architecture_check_requires_tail_validation_callsite_summary_dot_access(tmp_path):
    tail_validation = tmp_path / "tail_validation.py"
    tail_validation.write_text(
        "from __future__ import annotations\n"
        "def _call_summary_target_addr_8616(project, summary):\n"
        "    return getattr(summary, 'target_addr', None)\n",
        encoding="utf-8",
    )

    violations = arch_check._check_tail_validation_callsite_summary_dot_access(tail_validation)

    assert any(
        item.rule == "tail-validation-callsite-summary-dot-access" and "CallsiteSummary8616" in item.detail
        for item in violations
    )


def test_architecture_check_requires_call_recovery_summary_dot_access(tmp_path):
    calls = tmp_path / "decompiler_postprocess_calls.py"
    calls.write_text(
        "from __future__ import annotations\n"
        "def _summary_looks_loop_carried_arg_8616(summary):\n"
        "    return getattr(summary, 'push_arg_sources', ())\n",
        encoding="utf-8",
    )

    violations = arch_check._check_call_recovery_summary_dot_access(calls)

    assert any(
        item.rule == "call-recovery-summary-dot-access" and "CallsiteSummary8616" in item.detail
        for item in violations
    )


def test_architecture_check_requires_real_mode_linear_binding_dot_access(tmp_path):
    lowering = tmp_path / "real_mode_linear.py"
    lowering.write_text(
        "from __future__ import annotations\n"
        "def _known_bp_stack_offsets_8616(codegen):\n"
        "    for binding in codegen.bindings:\n"
        "        return getattr(binding, 'bp_offset', None)\n"
        "    return None\n",
        encoding="utf-8",
    )

    violations = arch_check._check_stack_lowering_impl_binding_dot_access(lowering)

    assert any(item.rule == "stack-lowering-impl-binding-dot-access" for item in violations)


def test_architecture_check_requires_real_mode_alias_fact_dot_access(tmp_path):
    lowering = tmp_path / "real_mode_linear.py"
    lowering.write_text(
        "from __future__ import annotations\n"
        "def _known_bp_stack_offsets_8616(codegen):\n"
        "    for fact in codegen.facts:\n"
        "        return getattr(fact, 'identity', None)\n"
        "    return None\n",
        encoding="utf-8",
    )

    violations = arch_check._check_real_mode_alias_fact_dot_access(lowering)

    assert any(item.rule == "real-mode-alias-fact-dot-access" for item in violations)


def test_architecture_check_requires_real_mode_stack_probe_fact_dot_access(tmp_path):
    lowering = tmp_path / "real_mode_linear.py"
    lowering.write_text(
        "from __future__ import annotations\n"
        "def _ss_probe_enabled_8616(codegen):\n"
        "    for fact in codegen.facts:\n"
        "        return getattr(fact, 'segment_space', None) == 'ss'\n"
        "    return False\n",
        encoding="utf-8",
    )

    violations = arch_check._check_real_mode_stack_probe_fact_dot_access(lowering)

    assert any(
        item.rule == "real-mode-stack-probe-fact-dot-access" and "TypedStackProbeReturnFact8616" in item.detail
        for item in violations
    )


def test_architecture_check_requires_stack_probe_summary_dot_access(tmp_path):
    lowering = tmp_path / "stack_probe_return_facts.py"
    lowering.write_text(
        "from __future__ import annotations\n"
        "def build_typed_stack_probe_return_facts_8616(codegen):\n"
        "    for summary in codegen.summaries.values():\n"
        "        return getattr(summary, 'helper_return_state', None) == 'stack_address'\n"
        "    return False\n",
        encoding="utf-8",
    )

    violations = arch_check._check_stack_probe_return_summary_dot_access(lowering)

    assert any(
        item.rule == "stack-probe-return-summary-dot-access" and "CallsiteSummary8616" in item.detail
        for item in violations
    )


def test_architecture_check_requires_ss_bp_substitution_binding_dot_access(tmp_path):
    lowering = tmp_path / "ss_bp_substitution.py"
    lowering.write_text(
        "from __future__ import annotations\n"
        "def substitute_ss_bp_dereferences_with_variables(c_text, bindings):\n"
        "    for b in bindings:\n"
        "        return getattr(b, 'name', None)\n"
        "    return c_text\n",
        encoding="utf-8",
    )

    violations = arch_check._check_ss_bp_substitution_binding_dot_access(lowering)

    assert any(item.rule == "ss-bp-substitution-binding-dot-access" for item in violations)


def test_architecture_check_requires_ss_bp_substitution_typed_bindings(tmp_path):
    lowering = tmp_path / "ss_bp_substitution.py"
    lowering.write_text(
        "from __future__ import annotations\n"
        "from typing import Sequence\n"
        "def substitute_ss_bp_dereferences_with_variables(c_text: str, bindings: Sequence[object]) -> str:\n"
        "    return c_text\n",
        encoding="utf-8",
    )

    violations = arch_check._check_ss_bp_substitution_binding_dot_access(lowering)

    assert any(item.rule == "ss-bp-substitution-typed-bindings" for item in violations)


def test_architecture_check_requires_callsite_materialization_stats_dot_access(tmp_path):
    metadata = tmp_path / "callsite_stack_metadata.py"
    metadata.write_text(
        "from __future__ import annotations\n"
        "def _callsite_materialization_complete_8616(codegen):\n"
        "    stats = codegen.stats\n"
        "    return getattr(stats, 'call_arg_materialized_count', 0)\n",
        encoding="utf-8",
    )

    violations = arch_check._check_callsite_materialization_stats_dot_access(metadata)

    assert any(item.rule == "callsite-materialization-stats-dot-access" for item in violations)


def test_architecture_check_requires_callsite_stack_summary_dot_access(tmp_path):
    metadata = tmp_path / "callsite_stack_metadata.py"
    metadata.write_text(
        "from __future__ import annotations\n"
        "def prune_materialized_callsite_segment_metadata_8616(project, codegen):\n"
        "    for summary in codegen.summaries.values():\n"
        "        return getattr(summary, 'stack_probe_helper', False)\n"
        "    return False\n",
        encoding="utf-8",
    )

    violations = arch_check._check_callsite_stack_summary_dot_access(metadata)

    assert any(
        item.rule == "callsite-stack-summary-dot-access" and "CallsiteSummary8616" in item.detail
        for item in violations
    )


def test_architecture_check_requires_postprocess_calls_summary_dot_access(tmp_path):
    calls = tmp_path / "decompiler_postprocess_calls.py"
    calls.write_text(
        "from __future__ import annotations\n"
        "def _call_node_matches_summary_8616(project, node, summary):\n"
        "    return getattr(summary, 'target_addr', None)\n",
        encoding="utf-8",
    )

    violations = arch_check._check_postprocess_calls_summary_dot_access(calls)

    assert any(
        item.rule == "postprocess-calls-summary-dot-access" and "CallsiteSummary8616" in item.detail
        for item in violations
    )


def test_architecture_check_requires_postprocess_stack_identity_dot_access(tmp_path):
    postprocess = tmp_path / "decompiler_postprocess.py"
    postprocess.write_text(
        "from __future__ import annotations\n"
        "def _prune_return_address_stack_arguments_8616(project, codegen):\n"
        "    def _return_address_stack_offset(variable):\n"
        "        identity = _stack_slot_identity_for_variable(variable)\n"
        "        return getattr(identity, 'offset', None)\n",
        encoding="utf-8",
    )

    violations = arch_check._check_postprocess_stack_identity_dot_access(postprocess)

    assert any(
        item.rule == "postprocess-stack-identity-dot-access" and "_StackSlotIdentity" in item.detail
        for item in violations
    )


def test_architecture_check_requires_structuring_diagnostics_stats_dot_access(tmp_path):
    diagnostics = tmp_path / "structuring_diagnostics.py"
    diagnostics.write_text(
        "from __future__ import annotations\n"
        "def suggest_recovery_hints(stats):\n"
        "    return getattr(stats, 'iterations', 0)\n",
        encoding="utf-8",
    )

    violations = arch_check._check_structuring_diagnostics_stats_dot_access(diagnostics)

    assert any(item.rule == "structuring-diagnostics-stats-dot-access" for item in violations)


def test_architecture_check_requires_return_chain_codegen_metadata_dot_access(tmp_path):
    return_chains = tmp_path / "return_chains.py"
    return_chains.write_text(
        "from __future__ import annotations\n"
        "def return_chain_expected_counts_8616(codegen):\n"
        "    return getattr(codegen, '_inertia_return_chain_flattened_8616', False)\n"
        "def root_matches_flattened_return_chain_8616(codegen):\n"
        "    return getattr(codegen, 'cfunc', None)\n",
        encoding="utf-8",
    )

    violations = arch_check._check_return_chain_codegen_metadata_dot_access(return_chains)

    assert any(
        item.rule == "return-chain-codegen-metadata-dot-access"
        and "codegen._inertia_return_chain_flattened_8616" in item.detail
        for item in violations
    )
    assert any(
        item.rule == "return-chain-codegen-metadata-dot-access" and "codegen.cfunc" in item.detail
        for item in violations
    )


def test_architecture_check_requires_segmented_global_materializer_codegen_dot_access(tmp_path):
    lowering = tmp_path / "segmented_global_loads.py"
    lowering.write_text(
        "from __future__ import annotations\n"
        "def materialize_named_segmented_global_loads_8616(project, codegen, synthetic_globals):\n"
        "    return getattr(codegen, 'cfunc', None)\n",
        encoding="utf-8",
    )

    violations = arch_check._check_segmented_global_materializer_codegen_dot_access(lowering)

    assert any(
        item.rule == "segmented-global-materializer-codegen-dot-access"
        and "codegen.cfunc" in item.detail
        for item in violations
    )


def test_architecture_check_requires_segmented_global_codegen_boundary_helpers(tmp_path):
    lowering = tmp_path / "segmented_global_loads.py"
    lowering.write_text(
        "from __future__ import annotations\n"
        "def _codegen_cfunc_optional_8616(codegen):\n"
        "    return getattr(codegen, 'cfunc', None)\n"
        "def _register_name_for_dword_half_8616(codegen, expr):\n"
        "    return getattr(codegen, 'project', None)\n",
        encoding="utf-8",
    )

    violations = arch_check._check_segmented_global_codegen_boundary_helpers(lowering)

    assert any(
        item.rule == "segmented-global-codegen-boundary-helper"
        and "_codegen_project_optional_8616" in item.detail
        for item in violations
    )


def test_architecture_check_requires_postprocess_package_ownership_headers(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    postprocess = root / "postprocess"
    postprocess.mkdir(parents=True)
    (postprocess / "value_flow.py").write_text(
        '"""Value-flow cleanup without the mandatory ownership contract."""\n'
        "from __future__ import annotations\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "semantic-layer-ownership-header" for item in violations)


def test_architecture_check_requires_postprocess_responsibility_header(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    postprocess = root / "postprocess"
    postprocess.mkdir(parents=True)
    (postprocess / "value_flow.py").write_text(
        '"""Layer: Rewrite/Postprocess cleanup.\n\n'
        "Consumes already-proven IR, alias, widening, typed, and structuring facts.\n"
        "Do not recover new semantics, storage identity, types, call signatures, control flow, "
        "or facts from rendered text, COD, source, or CLI/reporting evidence here.\n"
        '"""\n'
        "from __future__ import annotations\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "semantic-layer-ownership-header" and "Responsibility:" in item.detail
        for item in violations
    )


def test_architecture_check_requires_structuring_ownership_headers(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    structuring = root / "structuring"
    structuring.mkdir(parents=True)
    (structuring / "loop_recovery.py").write_text(
        '"""Loop recovery without the mandatory ownership contract."""\n'
        "from __future__ import annotations\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "semantic-layer-ownership-header" for item in violations)


def test_architecture_check_requires_lowering_package_ownership_headers(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    lowering = root / "lowering"
    lowering.mkdir(parents=True)
    (lowering / "stack_lowering.py").write_text(
        '"""Stack lowering without the mandatory ownership contract."""\n'
        "from __future__ import annotations\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "semantic-layer-ownership-header" for item in violations)


def test_architecture_check_requires_lowering_responsibility_header(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    lowering = root / "lowering"
    lowering.mkdir(parents=True)
    (lowering / "stack_lowering.py").write_text(
        '"""Layer: Types/Lowering.\n\n'
        "Consumes alias, widening, and typed facts.\n"
        "Do not recover semantics from COD, source, assembly, or rendered C text.\n"
        '"""\n'
        "from __future__ import annotations\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "semantic-layer-ownership-header" and "Responsibility:" in item.detail
        for item in violations
    )


def test_architecture_check_requires_ir_ownership_headers(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    ir = root / "ir"
    ir.mkdir(parents=True)
    (ir / "core.py").write_text(
        '"""IR core without the mandatory ownership contract."""\n'
        "from __future__ import annotations\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "semantic-layer-ownership-header" for item in violations)


def test_architecture_check_requires_analysis_ownership_headers(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    analysis = root / "analysis"
    analysis.mkdir(parents=True)
    (analysis / "alias.py").write_text(
        '"""Analysis helper without the mandatory ownership contract."""\n'
        "from __future__ import annotations\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "semantic-layer-ownership-header" for item in violations)


def test_architecture_check_rejects_vague_analysis_ownership_header(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    analysis = root / "analysis"
    analysis.mkdir(parents=True)
    (analysis / "alias.py").write_text(
        '"""Layer: Analysis.\n\n'
        "Responsibility: analyze aliases.\n"
        "Forbidden: bad alias proof.\n"
        '"""\n'
        "from __future__ import annotations\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "semantic-layer-ownership-header"
        and "rendered text as alias proof" in item.detail
        for item in violations
    )


def test_architecture_check_rejects_vague_analysis_package_ownership_header(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    analysis = root / "analysis"
    analysis.mkdir(parents=True)
    (analysis / "__init__.py").write_text(
        '"""Layer: Analysis.\n\n'
        "Responsibility: analyze things.\n"
        "Forbidden: bad proof.\n"
        '"""\n'
        "from __future__ import annotations\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "semantic-layer-ownership-header"
        and item.path == "inertia/ir/analysis/__init__.py"
        and "derived read-only analysis artifacts" in item.detail
        for item in violations
    )


def test_architecture_check_requires_nested_postprocess_ownership_headers(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    optimization = root / "postprocess" / "optimization"
    optimization.mkdir(parents=True)
    (optimization / "const_prop.py").write_text(
        '"""Optimization pass without the mandatory ownership contract."""\n'
        "from __future__ import annotations\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "semantic-layer-ownership-header" for item in violations)


def test_architecture_check_requires_validation_package_ownership_headers(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    validation = root / "validation"
    validation.mkdir(parents=True)
    (validation / "canonicalize.py").write_text(
        '"""Validation helper without the mandatory ownership contract."""\n'
        "from __future__ import annotations\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "semantic-layer-ownership-header" for item in violations)


def test_architecture_check_rejects_vague_validation_package_ownership_header(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    validation = root / "validation"
    validation.mkdir(parents=True)
    (validation / "__init__.py").write_text(
        '"""Layer: Validation.\n\n'
        "Responsibility: validate things.\n"
        "Forbidden: bad validation.\n"
        '"""\n'
        "from __future__ import annotations\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "semantic-layer-ownership-header"
        and item.path == "inertia/validation/__init__.py"
        and "canonical equivalence checking" in item.detail
        for item in violations
    )


def test_architecture_check_requires_lowering_ownership_header(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    lowering = root / "lowering"
    lowering.mkdir(parents=True)
    (lowering / "global_declarations.py").write_text(
        '"""Register globals without the required ownership contract."""\n'
        "from __future__ import annotations\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "lowering-module-ownership-header" for item in violations)


def test_architecture_check_requires_validation_ownership_headers(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    (root / "tail_validation_routing.py").write_text(
        '"""Validation routing without the mandatory ownership contract."""\n'
        "from __future__ import annotations\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "validation-ownership-header" for item in violations)


def test_architecture_check_rejects_vague_validation_ownership_header(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    (root / "tail_validation_routing.py").write_text(
        '"""Layer: Tail Validation.\n\n'
        "Responsibility: route things.\n"
        "Forbidden: bad validation.\n"
        '"""\n'
        "from __future__ import annotations\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "validation-ownership-header"
        and "treating routing as proof" in item.detail
        for item in violations
    )


def test_architecture_check_requires_recompilable_ownership_headers(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    (root / "recompilable_checks.py").write_text(
        '"""Generated C checks without the mandatory ownership contract."""\n'
        "from __future__ import annotations\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "recompilable-ownership-header" for item in violations)


def test_architecture_check_rejects_vague_recompilable_ownership_header(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    (root / "recompilable_checks.py").write_text(
        '"""Layer: Recompilable output.\n\n'
        "Responsibility: check C.\n"
        "Forbidden: bad repair.\n"
        '"""\n'
        "from __future__ import annotations\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "recompilable-ownership-header"
        and "without changing recovered semantics" in item.detail
        for item in violations
    )


def test_architecture_check_requires_root_structuring_ownership_headers(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    (root / "structuring_ir_hints.py").write_text(
        '"""IR hints without the mandatory ownership contract."""\n'
        "from __future__ import annotations\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "root-structuring-ownership-header" for item in violations)


def test_architecture_check_rejects_vague_root_structuring_ownership_header(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    (root / "structuring_ir_hints.py").write_text(
        '"""Layer: Structuring.\n\n'
        "Responsibility: expose hints.\n"
        "Forbidden: bad recovery.\n"
        '"""\n'
        "from __future__ import annotations\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "root-structuring-ownership-header"
        and "changing structuring verdicts" in item.detail
        for item in violations
    )


def test_architecture_check_requires_optional_evidence_ownership_headers(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    (root / "cod_extract.py").write_text(
        '"""COD parser without the mandatory ownership contract."""\n'
        "from __future__ import annotations\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "optional-evidence-ownership-header" for item in violations)


def test_architecture_check_rejects_vague_optional_evidence_ownership_header(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    (root / "cod_extract.py").write_text(
        '"""Layer: Optional evidence/reporting.\n\n'
        "Responsibility: parse COD files.\n"
        "Forbidden: bad semantic recovery.\n"
        '"""\n'
        "from __future__ import annotations\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "optional-evidence-ownership-header"
        and "using COD text as required proof" in item.detail
        for item in violations
    )


def test_architecture_check_requires_recovery_reporting_ownership_headers(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    (root / "recovery_confidence.py").write_text(
        '"""Recovery confidence without the mandatory ownership contract."""\n'
        "from __future__ import annotations\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "recovery-reporting-ownership-header" for item in violations)


def test_architecture_check_rejects_vague_recovery_reporting_ownership_header(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    (root / "recovery_confidence.py").write_text(
        '"""Layer: Recovery/reporting.\n\n'
        "Responsibility: report confidence.\n"
        "Forbidden: bad recovery.\n"
        '"""\n'
        "from __future__ import annotations\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "recovery-reporting-ownership-header"
        and "creating proof, hiding assumptions" in item.detail
        for item in violations
    )


def test_architecture_check_requires_frontend_runtime_ownership_headers(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    (root / "arch_86_16.py").write_text(
        '"""Frontend arch without the mandatory ownership contract."""\n'
        "from __future__ import annotations\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "frontend-runtime-ownership-header" for item in violations)


def test_architecture_check_rejects_vague_frontend_runtime_ownership_header(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    (root / "arch_86_16.py").write_text(
        '"""Layer: Frontend/runtime.\n\n'
        "Responsibility: define architecture bits.\n"
        "Forbidden: bad recovery.\n"
        '"""\n'
        "from __future__ import annotations\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "frontend-runtime-ownership-header"
        and "alias/type ownership" in item.detail
        for item in violations
    )


def test_architecture_check_requires_recovery_metadata_ownership_headers(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    (root / "callsite_summary.py").write_text(
        '"""Callsite summaries without the mandatory ownership contract."""\n'
        "from __future__ import annotations\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "recovery-metadata-ownership-header" for item in violations)


def test_architecture_check_rejects_vague_recovery_metadata_ownership_header(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    (root / "callsite_summary.py").write_text(
        '"""Layer: Recovery metadata.\n\n'
        "Responsibility: summarize things.\n"
        "Forbidden: bad things.\n"
        '"""\n'
        "from __future__ import annotations\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "recovery-metadata-ownership-header"
        and "deriving call semantics from source/COD text" in item.detail
        for item in violations
    )


def test_architecture_check_requires_helper_boundary_ownership_headers(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    (root / "addressing_helpers.py").write_text(
        '"""Address helpers without the mandatory ownership contract."""\n'
        "from __future__ import annotations\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "helper-boundary-ownership-header" for item in violations)


def test_architecture_check_rejects_vague_helper_boundary_ownership_header(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    (root / "addressing_helpers.py").write_text(
        '"""Layer: Helper boundary.\n\n'
        "Responsibility: decode addresses.\n"
        "Forbidden: bad address handling.\n"
        '"""\n'
        "from __future__ import annotations\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "helper-boundary-ownership-header"
        and "flattening SS/DS/ES into semantic storage identity" in item.detail
        for item in violations
    )


def test_architecture_check_requires_type_helper_boundary_ownership_headers(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    (root / "type_array_matching.py").write_text(
        '"""Array expression matching for an obsolete numbered phase."""\n'
        "from __future__ import annotations\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "helper-boundary-ownership-header" for item in violations)


def test_architecture_check_requires_root_module_docstrings(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    (root / "new_root_helper.py").write_text(
        "from __future__ import annotations\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "root-module-docstring" for item in violations)


def test_architecture_check_requires_x86_16_module_layer_headers(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    (root / "new_root_helper.py").write_text(
        '"""Documented helper without an ownership layer."""\n'
        "from __future__ import annotations\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "x86-16-module-layer-header" and item.path.endswith("new_root_helper.py")
        for item in violations
    )


def test_architecture_check_requires_root_contract_responsibility_headers(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    (tmp_path / "Makefile").write_text("", encoding="utf-8")
    (tmp_path / "tools/signatures/signature_catalog/py.py").write_text(
        '"""Optional signature catalog.\n\nLayer: Optional evidence/reporting.\n"""\n'
        "from __future__ import annotations\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "root-contract-layer-header"
        and "tools/signatures/signature_catalog/py.py" in item.path
        and "Responsibility:" in item.detail
        for item in violations
    )


def test_architecture_check_rejects_new_script_without_responsibility_header(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    (tmp_path / "Makefile").write_text("", encoding="utf-8")
    scripts = tmp_path / "tools" / "dev"
    scripts.mkdir(parents=True, exist_ok=True)
    (scripts / "new_gate.py").write_text(
        '"""New gate script.\n\nLayer: Tooling/gates.\n"""\n'
        "from __future__ import annotations\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "script-module-docstring"
        and item.path == "tools/dev/new_gate.py"
        and "Responsibility:" in item.detail
        for item in violations
    )


def test_architecture_check_has_no_legacy_script_responsibility_debt():
    assert frozenset() == arch_check._LEGACY_SCRIPT_RESPONSIBILITY_DEBT


def test_architecture_check_rejects_new_inertia_module_without_responsibility_header(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    (tmp_path / "Makefile").write_text("", encoding="utf-8")
    package = tmp_path / "inertia" / "cli"
    package.mkdir(parents=True, exist_ok=True)
    (package / "new_report.py").write_text(
        '"""New reporting helper.\n\nLayer: CLI/fallback/reporting.\n"""\n'
        "from __future__ import annotations\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "inertia-module-docstring"
        and item.path == "inertia/cli/new_report.py"
        and "Responsibility:" in item.detail
        for item in violations
    )


def test_architecture_check_has_no_legacy_inertia_responsibility_debt():
    assert frozenset() == arch_check._LEGACY_INERTIA_RESPONSIBILITY_DEBT


def test_architecture_check_rejects_gate_docstring_marker_without_responsibility(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    scripts = tmp_path / "tools" / "dev"
    scripts.mkdir(parents=True, exist_ok=True)
    (scripts / "check_decompiler_architecture.py").write_text(
        '"""Static architecture guard.\n\n'
        "Layer: Tooling/gates.\n"
        "Responsibility: enforce architecture.\n"
        '"""\n'
        "from __future__ import annotations\n\n"
        "_GATE_SCRIPT_DOCSTRING_MARKERS = {\n"
        '    "tools/dev/test_pipeline.py": ("Layer: Tooling/gates",),\n'
        "}\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "architecture-docstring-marker-contract"
        and "_GATE_SCRIPT_DOCSTRING_MARKERS" in item.detail
        and "test_pipeline.py" in item.detail
        for item in violations
    )


def test_architecture_check_rejects_cli_responsibility_marker_without_prefix(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    scripts = tmp_path / "tools" / "dev"
    scripts.mkdir(parents=True, exist_ok=True)
    (scripts / "check_decompiler_architecture.py").write_text(
        '"""Static architecture guard.\n\n'
        "Layer: Tooling/gates.\n"
        "Responsibility: enforce architecture.\n"
        '"""\n'
        "from __future__ import annotations\n\n"
        "_CLI_BOUNDARY_RESPONSIBILITY_MARKERS = {\n"
        '    "inertia/cli/cli.py": "expose the CLI entrypoint",\n'
        "}\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "architecture-docstring-marker-contract"
        and "_CLI_BOUNDARY_RESPONSIBILITY_MARKERS" in item.detail
        and "inertia/cli/cli.py" in item.detail
        for item in violations
    )


def test_architecture_check_rejects_cod_raw_listing_semantic_evidence(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    lowering = root / "lowering"
    lowering.mkdir(exist_ok=True)
    (lowering / "segmented_global_loads.py").write_text(
        "from __future__ import annotations\n"
        "def recover_name(cod_metadata):\n"
        "    return tuple(getattr(cod_metadata, 'cod_raw_entries', ()))\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "cod-raw-text-semantic-evidence" for item in violations)


def test_architecture_check_rejects_default_on_source_call_floor(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    (root / "decompiler_postprocess_calls.py").write_text(
        '"""Call cleanup bridge.\n\nDo not add new source-text recovery here.\n"""\n'
        "from __future__ import annotations\n"
        "def _source_call_floor_enabled_8616():\n"
        "    return env_value in {'1', 'true', 'yes', 'on'}\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "source-call-floor-default" for item in violations)


def test_architecture_check_rejects_cod_call_name_source_evidence(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    (root / "decompiler_postprocess_calls.py").write_text(
        '"""Call cleanup bridge.\n\nDo not add new source-text recovery here.\n"""\n'
        "from __future__ import annotations\n"
        "def _source_call_floor_enabled_8616():\n"
        "    return False\n"
        "def _cod_source_call_names_8616(project, func_addr):\n"
        "    return tuple(project.metadata.call_names)\n"
        "def _cod_source_call_names_for_symbol_8616(project, symbol_name):\n"
        "    return ()\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "cod-call-name-source-evidence" for item in violations)


def test_architecture_check_rejects_source_prototype_arg_width_recovery(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    (root / "decompiler_postprocess_calls.py").write_text(
        '"""Call cleanup bridge.\n\nDo not add new source-text recovery here.\n"""\n'
        "from __future__ import annotations\n"
        "def _source_call_floor_enabled_8616():\n"
        "    return env_value in {'1', 'true', 'yes', 'on'}\n"
        "def _source_prototype_arg_widths_8616(project, symbol_name):\n"
        "    text = project._inertia_lst_metadata.cod_path.read_text()\n"
        "    return _prototype_arg_widths_8616(text)\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "source-prototype-width-recovery" for item in violations)


def test_architecture_check_rejects_source_call_arg_semantic_recovery(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    (root / "decompiler_postprocess_calls.py").write_text(
        '"""Call cleanup bridge.\n\nDo not add new source-text recovery here.\n"""\n'
        "from __future__ import annotations\n"
        "def _source_call_floor_enabled_8616():\n"
        "    return env_value in {'1', 'true', 'yes', 'on'}\n"
        "def _align_cod_call_names_8616(project, codegen):\n"
        "    return _source_call_floor_enabled_8616()\n"
        "def _source_call_arg_semantic_kind_8616(project, callee, arg_index):\n"
        "    text = project._inertia_lst_metadata.cod_path.read_text()\n"
        "    return _source_arg_kind_from_part_8616(text)\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "source-call-arg-semantic-recovery" for item in violations)


def test_architecture_check_rejects_cod_call_sources_text_evidence(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    (root / "decompiler_postprocess_calls.py").write_text(
        '"""Call cleanup bridge.\n\nDo not add new source-text recovery here.\n"""\n'
        "from __future__ import annotations\n"
        "def _source_call_floor_enabled_8616():\n"
        "    return env_value in {'1', 'true', 'yes', 'on'}\n"
        "def _cod_source_call_names_8616(project, func_addr):\n"
        "    return tuple(name for name, _line in project.metadata.call_sources)\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "cod-call-source-text-evidence" for item in violations)


def test_architecture_check_rejects_default_on_cod_call_name_alignment(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    (root / "decompiler_postprocess_calls.py").write_text(
        '"""Call cleanup bridge.\n\nDo not add new source-text recovery here.\n"""\n'
        "from __future__ import annotations\n"
        "def _source_call_floor_enabled_8616():\n"
        "    return env_value in {'1', 'true', 'yes', 'on'}\n"
        "def _align_cod_call_names_8616(project, codegen):\n"
        "    return bool(project.metadata.call_names)\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "cod-call-name-alignment-default" for item in violations)


def test_architecture_check_rejects_cli_fallback_source_body_recovery(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    fallback = tmp_path / "inertia" / "cli" / "cli_fallback_decompilation.py"
    fallback.write_text(
        "from __future__ import annotations\n"
        "from inertia.cli.cli_c_text_postprocess import _render_cod_source_function_text\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "cli-fallback-source-body-recovery" for item in violations)


def test_architecture_check_rejects_cli_decompilation_source_body_helper(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    decompilation = tmp_path / "inertia" / "cli" / "cli_decompilation.py"
    decompilation.write_text(
        "from __future__ import annotations\n"
        "def _render_cod_comment_source_fallback(binary_path, function_name):\n"
        "    return None\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "cli-fallback-source-body-recovery" for item in violations)


def test_architecture_check_rejects_cli_c_text_source_body_helper(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    text_postprocess = tmp_path / "inertia" / "cli" / "cli_c_text_postprocess.py"
    text_postprocess.write_text(
        "from __future__ import annotations\n"
        "def _restore_collapsed_cod_source_function_text(c_text, function, metadata):\n"
        "    return c_text\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "cli-fallback-source-body-recovery" for item in violations)


def test_architecture_check_rejects_cli_source_prototype_sync(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    cli.write_text(
        '"""CLI boundary; must not become the owner of decompiler semantics."""\n'
        "from __future__ import annotations\n"
        "def sync(source, function):\n"
        "    source_prototype = getattr(source, 'prototype', None)\n"
        "    if source_prototype is not None:\n"
        "        function.prototype = source_prototype\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "cli-fallback-source-body-recovery" for item in violations)


def test_architecture_check_rejects_cli_c_text_source_assignment_rewrite(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    text_postprocess = tmp_path / "inertia" / "cli" / "cli_c_text_postprocess.py"
    text_postprocess.write_text(
        "from __future__ import annotations\n"
        "def _rewrite_source_backed_assignments_8616(text, metadata):\n"
        "    return text\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "cli-fallback-source-body-recovery" for item in violations)


def test_architecture_check_rejects_cli_c_text_source_decl_header_rewrite(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    text_postprocess = tmp_path / "inertia" / "cli" / "cli_c_text_postprocess.py"
    text_postprocess.write_text(
        "from __future__ import annotations\n"
        "def _apply_source_decl_to_header_8616(lines, **kwargs):\n"
        "    return True\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "cli-fallback-source-body-recovery" for item in violations)


def test_architecture_check_rejects_cli_source_header_recovery_callsite(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    text_postprocess = tmp_path / "inertia" / "cli" / "cli_c_text_postprocess.py"
    text_postprocess.write_text(
        "from __future__ import annotations\n"
        "def _materialize_annotated_cod_declarations_text(c_text, metadata):\n"
        "    return _source_function_prototype_decls_from_cod_source_lines(metadata.source_lines)\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "cli-source-header-recovery" for item in violations)


def test_architecture_check_rejects_cli_source_evidence_acceptance_gate(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    core = tmp_path / "inertia" / "cli" / "cli_core.py"
    core.write_text(
        "from __future__ import annotations\n"
        "def _validated_generated_c_acceptance_8616(payload):\n"
        "    return _missing_expected_calls_from_embedded_evidence_8616(payload)\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "cli-source-evidence-acceptance-gate" for item in violations)


def test_architecture_check_rejects_cli_source_backed_quality_gate(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    core = tmp_path / "inertia" / "cli" / "cli_core.py"
    core.write_text(
        "from __future__ import annotations\n"
        "def _function_work_cache_lookup(payload):\n"
        "    return assess_source_backed_c_text(payload)\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "cli-source-backed-quality-gate" for item in violations)


def test_architecture_check_rejects_cli_source_evidence_gate_definition(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    core = tmp_path / "inertia" / "cli" / "cli_core.py"
    core.write_text(
        "from __future__ import annotations\n"
        "def _missing_expected_return_values_from_embedded_evidence_8616(payload):\n"
        "    return []\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "cli-source-backed-quality-gate" for item in violations)


def test_architecture_check_rejects_cli_decompilation_source_backed_quality_import(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    decompilation = tmp_path / "inertia" / "cli" / "cli_decompilation.py"
    decompilation.write_text(
        "from __future__ import annotations\n"
        "from inertia.cli.decompilation_quality import assess_source_backed_c_text\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "cli-source-backed-quality-gate" for item in violations)


def test_architecture_check_rejects_cli_decompilation_cod_call_sources_gate(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    decompilation = tmp_path / "inertia" / "cli" / "cli_decompilation.py"
    decompilation.write_text(
        "from __future__ import annotations\n"
        "def _expected_source_call_arity_counter_8616(metadata):\n"
        "    return tuple(metadata.call_sources)\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "cli-source-backed-quality-gate" for item in violations)


def test_architecture_check_rejects_cli_cod_stack_alias_candidate_ranking(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    decompilation = tmp_path / "inertia" / "cli" / "cli_decompilation.py"
    decompilation.write_text(
        "from __future__ import annotations\n"
        "def _cod_signature_and_stack_alias_score_8616(rendered_text, function, cod_metadata):\n"
        "    return len(cod_metadata.stack_aliases)\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "cli-source-backed-quality-gate" for item in violations)


def test_architecture_check_rejects_cli_cod_global_name_candidate_ranking(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    decompilation = tmp_path / "inertia" / "cli" / "cli_decompilation.py"
    decompilation.write_text(
        "from __future__ import annotations\n"
        "def _candidate_expected_global_names_8616(cod_metadata, synthetic_globals):\n"
        "    return tuple(cod_metadata.global_names)\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "cli-source-backed-quality-gate" for item in violations)


def test_architecture_check_rejects_cli_decompilation_source_sidecar_return_type_import(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    decompilation = tmp_path / "inertia" / "cli" / "cli_decompilation.py"
    decompilation.write_text(
        "from __future__ import annotations\n"
        "from inertia.cli.source_sidecar import collect_local_source_sidecar_return_types\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "cli-source-backed-quality-gate" for item in violations)


def test_architecture_check_rejects_cod_call_name_index_rewrite(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    text_postprocess = tmp_path / "inertia" / "cli" / "cli_c_text_postprocess.py"
    text_postprocess.write_text(
        "from __future__ import annotations\n"
        "def _finalize_cod_annotation_text_8616(c_text, metadata):\n"
        "    return c_text.replace('CallReturn();', metadata.call_names[0] + '();')\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "cli-source-header-recovery" for item in violations)


def test_architecture_check_rejects_cli_ast_cod_callee_call_name_order(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    ast_rewrites = tmp_path / "inertia" / "cli" / "cli_c_ast_rewrites.py"
    ast_rewrites.write_text(
        "from __future__ import annotations\n"
        "def _attach_cod_callee_names(project, codegen, cod_metadata):\n"
        "    for name in cod_metadata.call_names:\n"
        "        pass\n"
        "    return False\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "cli-ast-cod-callee-name-recovery" for item in violations)


def test_architecture_check_rejects_cli_running_cod_callee_name_recovery(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    cli.write_text(
        '"""CLI boundary; must not become the owner of decompiler semantics."""\n'
        "from __future__ import annotations\n"
        "def run(project, codegen, metadata):\n"
        "    return _attach_cod_callee_names(project, codegen, metadata)\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "cli-ast-cod-callee-name-recovery" for item in violations)


def test_architecture_check_rejects_cli_cod_call_name_stub_recovery(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    cli.write_text(
        '"""CLI boundary; must not become the owner of decompiler semantics."""\n'
        "from __future__ import annotations\n"
        "def _register_direct_call_target_function_stubs(project, function, cod_metadata=None):\n"
        "    return tuple(cod_metadata.call_names)\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "cli-cod-call-name-stub-recovery" for item in violations)


def test_architecture_check_rejects_cli_cod_call_name_helper_declarations(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    helper = tmp_path / "inertia" / "cli" / "cli_helper_modeling.py"
    helper.write_text(
        "from __future__ import annotations\n"
        "def _known_helper_declarations(cod_metadata, *, preferred_known_helper_signature_decl):\n"
        "    return [preferred_known_helper_signature_decl(name) for name in cod_metadata.call_names]\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "cli-cod-call-name-helper-decls" for item in violations)


def test_architecture_check_rejects_cli_cod_call_name_prototype_recovery(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    postprocess = tmp_path / "inertia" / "cli" / "cli_c_text_postprocess.py"
    postprocess.write_text(
        "from __future__ import annotations\n"
        "def _collect_missing_annotated_cod_declarations(metadata):\n"
        "    return [f'int {name}();' for name in metadata.call_names]\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "cli-cod-call-name-prototype-recovery" for item in violations)


def test_architecture_check_rejects_cli_text_missing_call_prototype_recovery(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    postprocess = tmp_path / "inertia" / "cli" / "cli_c_text_postprocess.py"
    postprocess.write_text(
        "from __future__ import annotations\n"
        "def _materialize_missing_direct_call_prototypes_text(c_text):\n"
        "    return 'int missing();\\n' + c_text\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "cli-text-prototype-recovery" for item in violations)


def test_architecture_check_rejects_cli_ast_cod_stack_alias_variable_rename(tmp_path):
    ast_rewrites = tmp_path / "inertia" / "cli" / "cli_c_ast_rewrites.py"
    ast_rewrites.parent.mkdir(parents=True)
    ast_rewrites.write_text(
        "from __future__ import annotations\n"
        "def _attach_cod_variable_names(codegen, cod_metadata):\n"
        "    return bool(cod_metadata.stack_aliases)\n",
        encoding="utf-8",
    )
    text_postprocess = tmp_path / "inertia" / "cli" / "cli_c_text_postprocess.py"
    text_postprocess.write_text(
        "from __future__ import annotations\n"
        "def _collapse_annotated_stack_aliases_text(c_text):\n"
        "    return c_text\n",
        encoding="utf-8",
    )

    violations = arch_check._check_cli_cod_stack_alias_rewrites_inert(ast_rewrites, text_postprocess)

    assert any(item.rule == "cli-cod-stack-alias-rewrite" for item in violations)


def test_architecture_check_rejects_cli_text_cod_stack_alias_collapse(tmp_path):
    ast_rewrites = tmp_path / "inertia" / "cli" / "cli_c_ast_rewrites.py"
    ast_rewrites.parent.mkdir(parents=True)
    ast_rewrites.write_text(
        "from __future__ import annotations\n"
        "def _attach_cod_variable_names(codegen, cod_metadata):\n"
        "    return False\n",
        encoding="utf-8",
    )
    text_postprocess = tmp_path / "inertia" / "cli" / "cli_c_text_postprocess.py"
    text_postprocess.write_text(
        "from __future__ import annotations\n"
        "def _collapse_annotated_stack_aliases_text(c_text):\n"
        "    return c_text.replace('arg_1', 'cod_alias')\n",
        encoding="utf-8",
    )

    violations = arch_check._check_cli_cod_stack_alias_rewrites_inert(ast_rewrites, text_postprocess)

    assert any(item.rule == "cli-cod-stack-alias-rewrite" for item in violations)


def test_architecture_check_rejects_cli_text_cod_proc_annotation(tmp_path):
    ast_rewrites = tmp_path / "inertia" / "cli" / "cli_c_ast_rewrites.py"
    ast_rewrites.parent.mkdir(parents=True)
    ast_rewrites.write_text(
        "from __future__ import annotations\n"
        "def _attach_cod_variable_names(codegen, cod_metadata):\n"
        "    return False\n",
        encoding="utf-8",
    )
    text_postprocess = tmp_path / "inertia" / "cli" / "cli_c_text_postprocess.py"
    text_postprocess.write_text(
        "from __future__ import annotations\n"
        "def _collapse_annotated_stack_aliases_text(c_text):\n"
        "    return c_text\n"
        "def _annotate_cod_proc_output(c_text, function, metadata, *, codegen=None):\n"
        "    return '/* COD annotations */\\n' + c_text\n",
        encoding="utf-8",
    )

    violations = arch_check._check_cli_cod_stack_alias_rewrites_inert(ast_rewrites, text_postprocess)

    assert any(item.rule == "cli-cod-stack-alias-rewrite" for item in violations)


def test_architecture_check_rejects_cli_text_cod_global_name_declaration(tmp_path):
    ast_rewrites = tmp_path / "inertia" / "cli" / "cli_c_ast_rewrites.py"
    ast_rewrites.parent.mkdir(parents=True)
    ast_rewrites.write_text(
        "from __future__ import annotations\n"
        "def _attach_cod_variable_names(codegen, cod_metadata):\n"
        "    return False\n",
        encoding="utf-8",
    )
    text_postprocess = tmp_path / "inertia" / "cli" / "cli_c_text_postprocess.py"
    text_postprocess.write_text(
        "from __future__ import annotations\n"
        "def _collapse_annotated_stack_aliases_text(c_text):\n"
        "    return c_text\n"
        "def _materialize_missing_synthetic_global_declarations_text(c_text, metadata=None, synthetic_globals=None):\n"
        "    return tuple(metadata.global_names)\n",
        encoding="utf-8",
    )

    violations = arch_check._check_cli_cod_stack_alias_rewrites_inert(ast_rewrites, text_postprocess)

    assert any(item.rule == "cli-cod-stack-alias-rewrite" for item in violations)


def test_architecture_check_rejects_postprocess_source_return_shape_helper(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    postprocess = root / "decompiler_postprocess.py"
    postprocess.write_text(
        "from __future__ import annotations\n"
        "def _source_return_shape_8616(source_return_lines):\n"
        "    return 'wide_fp' if source_return_lines else None\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "postprocess-source-return-shape" for item in violations)


def test_architecture_check_rejects_postprocess_source_sidecar_return_type_import(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    postprocess = root / "decompiler_postprocess.py"
    postprocess.write_text(
        "from __future__ import annotations\n"
        "from inertia.cli.source_sidecar import collect_local_source_sidecar_return_types\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "postprocess-source-return-shape" for item in violations)


def test_architecture_check_rejects_postprocess_cod_source_annotation_attachment(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    postprocess = root / "decompiler_postprocess.py"
    postprocess.write_text(
        "from __future__ import annotations\n"
        "def _source_annotation_lines_8616(func):\n"
        "    return ()\n"
        "def _merge_source_annotations_if_missing_8616(target_func, source_func):\n"
        "    return False\n"
        "def _attach_project_cod_source_annotations_if_missing_8616(project, func_addr, func):\n"
        "    metadata = project._inertia_cod_metadata_by_func_addr_8616.get(func_addr)\n"
        "    return bool(metadata.source_lines)\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "postprocess-source-return-shape" for item in violations)


def test_architecture_check_rejects_postprocess_cod_stack_alias_evidence(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    dce_path = root / "postprocess" / "optimization" / "dce.py"
    dce_path.parent.mkdir(parents=True)
    dce_path.write_text(
        "from __future__ import annotations\n"
        "def protect(metadata):\n"
        "    return tuple(metadata.stack_aliases)\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "postprocess-cod-stack-alias-evidence" for item in violations)


def test_architecture_check_rejects_validation_source_backed_call_shape(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    validation = root / "validation_semantics.py"
    validation.write_text(
        "from __future__ import annotations\n"
        "def _validate_source_backed_call_shape_8616(report, callee, args):\n"
        "    return None\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "validation-source-sample-call-shape" for item in violations)


def test_architecture_check_rejects_tail_validation_source_decl_return_evidence(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    tail_validation = root / "tail_validation.py"
    tail_validation.write_text(
        "from __future__ import annotations\n"
        "from .annotations import _source_decl_from_cod_source_lines\n"
        "def check(lines):\n"
        "    return _source_decl_from_cod_source_lines(lines, 'f')\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "tail-validation-source-decl-return-evidence" for item in violations)


def test_architecture_check_rejects_tail_validation_cod_call_fingerprints(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    fingerprint = root / "tail_validation_fingerprint.py"
    fingerprint.write_text(
        "from __future__ import annotations\n"
        "from .decompiler_postprocess_calls import _cod_metadata_for_function_8616\n"
        "def build(project, addr):\n"
        "    return _cod_metadata_for_function_8616(project, addr).call_names\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "tail-validation-cod-call-fingerprint" for item in violations)


def test_architecture_check_rejects_recompilable_source_evidence_builder(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    source_evidence = root / "recompilable_source_evidence.py"
    source_evidence.write_text(
        "from __future__ import annotations\n"
        "def build_recompilable_source_evidence_text(case):\n"
        "    return 'int source_backed(void) { return 0; }'\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "recompilable-source-evidence-fallback" for item in violations)


def test_architecture_check_rejects_recompilable_cli_bridge_source_fallback(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    bridge = root / "recompilable_cli_bridge.py"
    bridge.write_text(
        "from __future__ import annotations\n"
        "from .recompilable_source_evidence import load_or_build_recompilable_source_evidence\n"
        "def run(case):\n"
        "    return 'shape_ok_evidence'\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "recompilable-source-evidence-fallback" for item in violations)


def test_architecture_check_requires_project_map_markers(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    project_map = tmp_path / "reference" / "project-map.md"
    project_map.write_text("angr_platforms/angr_platforms/X86_16\n", encoding="utf-8")

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "project-map-marker" for item in violations)


def test_architecture_check_requires_project_map_ratchet_marker(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    project_map = tmp_path / "reference" / "project-map.md"
    project_map.write_text(
        "\n".join(
            (
                "angr_platforms/angr_platforms/X86_16",
                "inertia/cli/",
                "dosunit.py",
                "tools/signatures/signature_catalog/py.py",
                "tools/dev/test_pipeline.py",
                "binary-budgeted",
                "tools/dev/build_msc6_examples.py",
                "examples/msc6_constructs/",
                "reference/dosunit-execution-spec.md",
                "make architecture-check",
                "make agent-context-check",
                "make test-ownership-check",
                "make check-files",
                "make quality-fast",
                "make test-pipeline-fast",
                "proof budgets stay unchanged",
                "make test-pipeline",
                "make test-pipeline-expanded",
                "libdosbox",
                ".understand-anything/config.json",
                "--no-auto-update",
            )
        ),
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "project-map-marker"
        and (
            "changed-file module/doc/type/dot-access ratchet" in item.detail
            or "architecture/context guards, ownership-manifest validation, and owned tests" in item.detail
            or "Ownership-manifest tests are fast-only" in item.detail
        )
        for item in violations
    )


def test_architecture_check_requires_project_map_promotion_debt_marker(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    project_map = tmp_path / "reference" / "project-map.md"
    project_map.write_text(
        "\n".join(
            marker
            for marker in arch_check._PROJECT_MAP_MARKERS
            if "promoted typed/ruff gates or explicit promotion debt" not in marker
        ),
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "project-map-marker"
        and "promoted typed/ruff gates or explicit promotion debt" in item.detail
        for item in violations
    )


def test_architecture_check_requires_project_map_full_promotion_debt_gate_marker(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    project_map = tmp_path / "reference" / "project-map.md"
    project_map.write_text(
        "\n".join(
            marker
            for marker in arch_check._PROJECT_MAP_MARKERS
            if "Full-promotion debt files stay out of `QA_TYPED_FILES`" not in marker
        ),
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "project-map-marker"
        and "Full-promotion debt files stay out of `QA_TYPED_FILES`" in item.detail
        for item in violations
    )


def test_architecture_check_rejects_project_map_duplicate_rulebook_heading(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    project_map = tmp_path / "reference" / "project-map.md"
    project_map.write_text(
        f"{project_map.read_text(encoding='utf-8')}\n## Hard rules\n1. Alias-first.\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "project-map-duplicate-rulebook" and "## Hard rules" in item.detail
        for item in violations
    )


def test_architecture_check_rejects_project_map_duplicate_agent_execution_rules(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    project_map = tmp_path / "reference" / "project-map.md"
    project_map.write_text(
        f"{project_map.read_text(encoding='utf-8')}\n## Agent execution rules\nDO: push semantics earlier.\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "project-map-duplicate-rulebook" and "## Agent execution rules" in item.detail
        for item in violations
    )


def test_architecture_check_rejects_project_map_duplicate_improving_code_section(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    project_map = tmp_path / "reference" / "project-map.md"
    project_map.write_text(
        f"{project_map.read_text(encoding='utf-8')}\n## Improving code\nRun quality-fast regularly.\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "project-map-duplicate-rulebook" and "## Improving code" in item.detail
        for item in violations
    )


def test_architecture_check_rejects_project_map_duplicate_reference_files_section(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    project_map = tmp_path / "reference" / "project-map.md"
    project_map.write_text(
        f"{project_map.read_text(encoding='utf-8')}\n## Reference files\nRead the maps before editing.\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "project-map-duplicate-rulebook" and "## Reference files" in item.detail
        for item in violations
    )


def test_architecture_check_rejects_oversized_project_map(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    project_map = tmp_path / "reference" / "project-map.md"
    current_lines = len(project_map.read_text(encoding="utf-8").splitlines())
    filler_count = arch_check._PROJECT_MAP_MAX_LINES - current_lines + 1
    filler = "\n".join(f"extra project detail {index}" for index in range(filler_count))
    project_map.write_text(f"{project_map.read_text(encoding='utf-8')}\n{filler}\n", encoding="utf-8")

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "project-map-too-large" for item in violations)


def test_architecture_check_requires_decompiler_map_tier_markers(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    decompiler_map = tmp_path / "reference" / "decompiler-map.md"
    decompiler_map.write_text("IR -> Alias -> Widening -> Types -> Structuring -> Rewrite\n", encoding="utf-8")

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "decompiler-map-marker" for item in violations)


def test_architecture_check_rejects_oversized_decompiler_map(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    decompiler_map = tmp_path / "reference" / "decompiler-map.md"
    current_lines = len(decompiler_map.read_text(encoding="utf-8").splitlines())
    filler_count = arch_check._DECOMPILER_MAP_MAX_LINES - current_lines + 1
    filler = "\n".join(f"extra decompiler detail {index}" for index in range(filler_count))
    decompiler_map.write_text(f"{decompiler_map.read_text(encoding='utf-8')}\n{filler}\n", encoding="utf-8")

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "decompiler-map-too-large" for item in violations)


def test_architecture_check_requires_active_reference_paths(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    (tmp_path / "reference" / "layer-module-status.md").unlink()

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "active-reference-missing" and item.path == "reference/layer-module-status.md"
        for item in violations
    )


def test_architecture_check_rejects_decompiler_map_two_rulebooks(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    decompiler_map = tmp_path / "reference" / "decompiler-map.md"
    decompiler_map.write_text(
        "\n".join(
            (
                "This is the short map for agents. The detailed rulebook is `AGENTS.md` and `reference/agent-rules.md`.",
                "IR -> Alias -> Widening -> Types -> Structuring -> Rewrite",
                "AGENTS.md` is the canonical rulebook",
                "reference/agent-rules.md` is supplemental glossary",
                "make quality-fast PYTHON=./.venv/bin/python",
                "make test-pipeline-fast PYTHON=./.venv/bin/python",
                "make test-pipeline PYTHON=./.venv/bin/python",
                "make test-pipeline-expanded PYTHON=./.venv/bin/python",
                "fast tier",
                "unit-focused only",
                "default tier",
                "expanded tier",
                "runtime guard entrypoints",
                "docs/types/dot-access ratchets",
            )
        ),
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "decompiler-map-duplicate-rulebook" for item in violations)


def test_architecture_check_rejects_decompiler_map_duplicate_rulebook_heading(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    decompiler_map = tmp_path / "reference" / "decompiler-map.md"
    decompiler_map.write_text(
        f"{decompiler_map.read_text(encoding='utf-8')}\n## Mission\nCorrectness first.\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "decompiler-map-duplicate-rulebook" and "## Mission" in item.detail
        for item in violations
    )


def test_architecture_check_rejects_decompiler_map_duplicate_layer_ownership(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    decompiler_map = tmp_path / "reference" / "decompiler-map.md"
    decompiler_map.write_text(
        f"{decompiler_map.read_text(encoding='utf-8')}\n## Layer ownership\n- alias owns alias proof.\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "decompiler-map-duplicate-rulebook" and "## Layer ownership" in item.detail
        for item in violations
    )


def test_architecture_check_rejects_decompiler_map_duplicate_reference_files_section(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    decompiler_map = tmp_path / "reference" / "decompiler-map.md"
    decompiler_map.write_text(
        f"{decompiler_map.read_text(encoding='utf-8')}\n## Reference files\nRead project-map first.\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "decompiler-map-duplicate-rulebook" and "## Reference files" in item.detail
        for item in violations
    )


def test_architecture_check_requires_decompiler_map_architecture_ratchet_scope(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    decompiler_map = tmp_path / "reference" / "decompiler-map.md"
    decompiler_map.write_text(
        "\n".join(
            (
                "IR -> Alias -> Widening -> Types -> Structuring -> Rewrite",
                "make quality-fast PYTHON=./.venv/bin/python",
                "make test-pipeline-fast PYTHON=./.venv/bin/python",
                "make test-pipeline PYTHON=./.venv/bin/python",
                "make test-pipeline-expanded PYTHON=./.venv/bin/python",
                "fast tier",
                "unit-focused only",
                "default tier",
                "expanded tier",
            )
        ),
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "decompiler-map-marker"
        and ("runtime guard entrypoints" in item.detail or "docs/types/dot-access ratchets" in item.detail)
        for item in violations
    )


def test_architecture_check_requires_agents_dot_access_guidance(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    (tmp_path / "AGENTS.md").write_text(
        "Read reference/project-map.md and reference/decompiler-map.md.\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "agent-doc-marker" for item in violations)


def test_architecture_check_requires_agents_docstrings_and_types_guidance(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    (tmp_path / "AGENTS.md").write_text(
        "Read reference/project-map.md and reference/decompiler-map.md.\n"
        "Dot access for owned contracts.\n"
        "avoidable `getattr`/`setattr`.\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "agent-doc-marker" for item in violations)


def test_architecture_check_requires_agents_dynamic_attr_boundary_guidance(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    (tmp_path / "AGENTS.md").write_text(
        "Read reference/project-map.md and reference/decompiler-map.md.\n"
        "Dot access for owned contracts.\n"
        "avoidable `getattr`/`setattr`.\n"
        "Docstrings and types ratchet.\n"
        "every new or touched non-test module must state `Layer:` and `Responsibility:`.\n"
        "legacy missing docs/types are cleanup debt.\n"
        "Regular local gate: `make quality-fast PYTHON=./.venv/bin/python`.\n"
        "Supplemental glossary and long-running-agent guidance.\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "agent-doc-marker" and "dynamic third-party/angr/codegen/plugin boundaries" in item.detail
        for item in violations
    )


def test_architecture_check_requires_agents_dynamic_attr_cleanup_debt_guidance(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    (tmp_path / "AGENTS.md").write_text(
        "Read reference/project-map.md and reference/decompiler-map.md.\n"
        "Dot access for owned contracts.\n"
        "avoidable `getattr`/`setattr`.\n"
        "use `getattr`/`setattr` only at dynamic third-party/angr/codegen/plugin boundaries with a clear reason.\n"
        "Docstrings and types ratchet.\n"
        "every new or touched non-test module must state `Layer:` and `Responsibility:`.\n"
        "legacy missing docs/types are cleanup debt.\n"
        "Regular local gate: `make quality-fast PYTHON=./.venv/bin/python`.\n"
        "Supplemental glossary and long-running-agent guidance.\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "agent-doc-marker"
        and "Existing avoidable dynamic attribute access is cleanup debt" in item.detail
        for item in violations
    )


def test_architecture_check_requires_agents_module_layer_responsibility_guidance(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    (tmp_path / "AGENTS.md").write_text(
        "Read reference/project-map.md and reference/decompiler-map.md.\n"
        "Dot access for owned contracts.\n"
        "avoidable `getattr`/`setattr`.\n"
        "use `getattr`/`setattr` only at dynamic third-party/angr/codegen/plugin boundaries with a clear reason.\n"
        "Existing avoidable dynamic attribute access is cleanup debt and should be removed when touching nearby code.\n"
        "Docstrings and types ratchet.\n"
        "legacy missing docs/types are cleanup debt.\n"
        "Regular local gate: `make quality-fast PYTHON=./.venv/bin/python`.\n"
        "Supplemental glossary and long-running-agent guidance.\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "agent-doc-marker"
        and 'every new or touched non-test module must state `Layer:` and `Responsibility:`' in item.detail
        for item in violations
    )


def test_architecture_check_requires_agents_fast_gate_guidance(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    (tmp_path / "AGENTS.md").write_text(
        "Read reference/project-map.md and reference/decompiler-map.md.\n"
        "Dot access for owned contracts.\n"
        "avoidable `getattr`/`setattr`.\n"
        "Docstrings and types ratchet.\n"
        "legacy missing docs/types are cleanup debt.\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "agent-doc-marker" for item in violations)


def test_architecture_check_requires_agents_default_and_expanded_gate_guidance(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    (tmp_path / "AGENTS.md").write_text(
        "Read reference/project-map.md and reference/decompiler-map.md.\n"
        "Dot access for owned contracts.\n"
        "avoidable `getattr`/`setattr`.\n"
        "use `getattr`/`setattr` only at dynamic third-party/angr/codegen/plugin boundaries with a clear reason.\n"
        "Existing avoidable dynamic attribute access is cleanup debt and should be removed when touching nearby code.\n"
        "Docstrings and types ratchet.\n"
        "every new or touched non-test module must state `Layer:` and `Responsibility:`.\n"
        "legacy missing docs/types are cleanup debt.\n"
        "Regular local gate: `make quality-fast PYTHON=./.venv/bin/python`.\n"
        "Supplemental glossary and long-running-agent guidance.\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "agent-doc-marker" and "test-pipeline PYTHON" in item.detail for item in violations)
    assert any(
        item.rule == "agent-doc-marker" and "test-pipeline-expanded PYTHON" in item.detail for item in violations
    )


def test_architecture_check_rejects_agents_agent_rules_as_execution_details(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    agents_path = tmp_path / "AGENTS.md"
    agents_path.write_text(
        f"{agents_path.read_text(encoding='utf-8')}\n"
        "Agent execution details -> reference/agent-rules.md\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "agent-doc-duplicate-rulebook" for item in violations)


def test_architecture_check_rejects_agents_reference_glossary_section(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    agents_path = tmp_path / "AGENTS.md"
    agents_path.write_text(
        f"{agents_path.read_text(encoding='utf-8')}\n## Glossary\nSemantic honesty: fail explicitly.\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "agent-doc-duplicate-rulebook" and "## Glossary" in item.detail
        for item in violations
    )


def test_architecture_check_rejects_agents_reference_resume_section(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    agents_path = tmp_path / "AGENTS.md"
    agents_path.write_text(
        f"{agents_path.read_text(encoding='utf-8')}\n## Resume Loop\nUse codex_resume_loop.py.\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "agent-doc-duplicate-rulebook" and "## Resume Loop" in item.detail
        for item in violations
    )


def test_architecture_check_rejects_agents_reference_diagnostics_section(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    agents_path = tmp_path / "AGENTS.md"
    agents_path.write_text(
        f"{agents_path.read_text(encoding='utf-8')}\n## Diagnostics And Profiling\nUse compact telemetry.\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "agent-doc-duplicate-rulebook" and "## Diagnostics And Profiling" in item.detail
        for item in violations
    )


def test_architecture_check_rejects_duplicate_agents_golden_rules(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    agents_path = tmp_path / "AGENTS.md"
    agents_path.write_text(
        f"{agents_path.read_text(encoding='utf-8')}\n## Golden rules\n1. Semantics early, not late\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "agent-doc-duplicate-rulebook" for item in violations)


def test_architecture_check_rejects_oversized_agents_md(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    agents_path = tmp_path / "AGENTS.md"
    current_lines = len(agents_path.read_text(encoding="utf-8").splitlines())
    filler_count = arch_check._AGENTS_MAX_LINES - current_lines + 1
    filler = "\n".join(f"extra detail {index}" for index in range(filler_count))
    agents_path.write_text(f"{agents_path.read_text(encoding='utf-8')}\n{filler}\n", encoding="utf-8")

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "agent-doc-too-large" for item in violations)


def test_architecture_check_requires_promoted_typed_file_docstrings(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    (tmp_path / "Makefile").write_text("pyright:\n\tpython -m pyright\n", encoding="utf-8")
    (tmp_path / "monkeytype_config.py").write_text(
        "from __future__ import annotations\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "promoted-typed-file-docstring" for item in violations)


def test_architecture_check_requires_promoted_typed_file_layer_marker(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    (tmp_path / "Makefile").write_text("pyright:\n\tpython -m pyright\n", encoding="utf-8")
    (tmp_path / "monkeytype_config.py").write_text(
        '"""MonkeyType configuration.\n\nResponsibility: configure traces.\n"""\n\n'
        "from __future__ import annotations\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "promoted-typed-file-docstring" and "Layer:" in item.detail for item in violations
    )


def test_architecture_check_requires_promoted_typed_file_responsibility_marker(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    (tmp_path / "Makefile").write_text("pyright:\n\tpython -m pyright\n", encoding="utf-8")
    (tmp_path / "monkeytype_config.py").write_text(
        '"""MonkeyType configuration.\n\nLayer: Tooling/gates.\n"""\n\n'
        "from __future__ import annotations\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "promoted-typed-file-docstring" and "Responsibility:" in item.detail
        for item in violations
    )


def test_architecture_check_requires_promoted_typed_future_annotations(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    (tmp_path / "Makefile").write_text("pyright:\n\tpython -m pyright\n", encoding="utf-8")
    (tmp_path / "monkeytype_config.py").write_text(
        '"""MonkeyType configuration."""\n\n'
        "def public_filter() -> bool:\n"
        '    """Return whether a value should be traced."""\n'
        "    return True\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "promoted-typed-future-annotations" for item in violations)


def test_architecture_check_requires_promoted_typed_public_assignment_annotations(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    (tmp_path / "Makefile").write_text("pyright:\n\tpython -m pyright\n", encoding="utf-8")
    (tmp_path / "monkeytype_config.py").write_text(
        '"""MonkeyType configuration."""\n'
        "from __future__ import annotations\n\n"
        "CONFIG = object()\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "promoted-typed-public-assignment-annotation" for item in violations)


def test_architecture_check_requires_promoted_typed_public_definition_docstrings(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    (tmp_path / "Makefile").write_text("pyright:\n\tpython -m pyright\n", encoding="utf-8")
    (tmp_path / "monkeytype_config.py").write_text(
        '"""MonkeyType configuration."""\n'
        "from __future__ import annotations\n\n"
        "def public_filter() -> bool:\n"
        "    return True\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "promoted-typed-public-docstring" for item in violations)


def test_architecture_check_requires_promoted_typed_public_function_annotations(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    (tmp_path / "Makefile").write_text("pyright:\n\tpython -m pyright\n", encoding="utf-8")
    (tmp_path / "monkeytype_config.py").write_text(
        '"""MonkeyType configuration."""\n'
        "from __future__ import annotations\n\n"
        "def public_filter(value):\n"
        '    """Return whether a value should be traced."""\n'
        "    return bool(value)\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "promoted-typed-public-annotations" for item in violations)


def test_architecture_check_requires_promoted_dataclass_field_annotations(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    (tmp_path / "Makefile").write_text("pyright:\n\tpython -m pyright\n", encoding="utf-8")
    (tmp_path / "monkeytype_config.py").write_text(
        '"""MonkeyType configuration."""\n'
        "from __future__ import annotations\n\n"
        "from dataclasses import dataclass\n\n"
        "@dataclass\n"
        "class PublicContract:\n"
        '    """Typed public contract."""\n'
        "    value = 1\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "promoted-typed-dataclass-field-annotation" for item in violations)


def test_architecture_check_requires_promoted_enum_string_values(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    (tmp_path / "Makefile").write_text("pyright:\n\tpython -m pyright\n", encoding="utf-8")
    (tmp_path / "monkeytype_config.py").write_text(
        '"""MonkeyType configuration."""\n'
        "from __future__ import annotations\n\n"
        "from enum import Enum, auto\n\n"
        "class PublicStatus(str, Enum):\n"
        '    """Typed status contract."""\n'
        "    READY = auto()\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "promoted-typed-enum-string-value" for item in violations)


def test_architecture_check_rejects_promoted_typed_computed_dunder_all(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    (tmp_path / "Makefile").write_text("pyright:\n\tpython -m pyright\n", encoding="utf-8")
    (tmp_path / "monkeytype_config.py").write_text(
        '"""MonkeyType configuration."""\n'
        "from __future__ import annotations\n\n"
        "_EXPORTS = ('public_filter',)\n"
        "__all__ = tuple(_EXPORTS)\n\n"
        "def public_filter() -> bool:\n"
        '    """Return whether a value should be traced."""\n'
        "    return True\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "promoted-typed-file-literal-dunder-all" for item in violations)


def test_architecture_check_rejects_promoted_typed_file_dynamic_attr(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    (tmp_path / "Makefile").write_text("pyright:\n\tpython -m pyright\n", encoding="utf-8")
    scripts = tmp_path / "tools" / "dev"
    scripts.mkdir(parents=True, exist_ok=True)
    (scripts / "check_changed_non_test_types.py").write_text(
        '"""Changed-file type ratchet."""\n'
        "from __future__ import annotations\n\n"
        "def dynamic_line(node: object) -> int:\n"
        '    """Return a line using forbidden dynamic attribute access."""\n'
        "    return int(getattr(node, 'lineno', 0))\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "promoted-typed-file-dynamic-attr" for item in violations)


def test_dynamic_attr_boundary_terms_match_changed_file_ratchet():
    assert arch_check._DYNAMIC_ATTR_BOUNDARY_TERMS == check_changed_non_test_types._DYNAMIC_ATTR_BOUNDARY_TERMS


def test_fast_pytest_skip_calls_come_from_ownership_manifest():
    assert arch_check._fast_pytest_skip_calls() == test_ownership_manifest.FAST_PYTEST_SKIP_CALLS


def test_architecture_check_rejects_dynamic_attr_boundary_term_drift(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    scripts = tmp_path / "tools" / "dev"
    scripts.mkdir(parents=True, exist_ok=True)
    (scripts / "check_decompiler_architecture.py").write_text(
        '"""Static architecture guard.\n\n'
        "Layer: Tooling/gates.\n"
        "Responsibility: enforce architecture.\n"
        '"""\n'
        "from __future__ import annotations\n\n"
        '_DYNAMIC_ATTR_BOUNDARY_TERMS = frozenset(("third-party", "plugin"))\n',
        encoding="utf-8",
    )
    (scripts / "check_changed_non_test_types.py").write_text(
        '"""Changed-file type ratchet.\n\n'
        "Layer: Tooling/gates.\n"
        "Responsibility: enforce changed-file docstring, type annotation, and dot-access ratchets.\n"
        '"""\n'
        "from __future__ import annotations\n\n"
        '_DYNAMIC_ATTR_BOUNDARY_TERMS = frozenset(("third-party", "plugin", "angr"))\n',
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "dynamic-attr-boundary-term-drift"
        and item.path == "tools/dev/check_decompiler_architecture.py"
        for item in violations
    )


def test_architecture_check_allows_promoted_typed_file_documented_dynamic_boundary(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    (tmp_path / "Makefile").write_text("pyright:\n\tpython -m pyright\n", encoding="utf-8")
    scripts = tmp_path / "tools" / "dev"
    scripts.mkdir(parents=True, exist_ok=True)
    (scripts / "check_changed_non_test_types.py").write_text(
        '"""Changed-file type ratchet.\n\n'
        "Layer: Tooling/gates.\n"
        "Responsibility: enforce changed-file docstring, type annotation, and dot-access ratchets.\n"
        '"""\n'
        "from __future__ import annotations\n\n"
        "def plugin_field(plugin: object, field_name: str) -> object:\n"
        '    """Return a dynamically named plugin value."""\n'
        "    # dynamic plugin boundary: field names come from a third-party registry.\n"
        "    return getattr(plugin, field_name)\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert not any(
        item.rule == "promoted-typed-file-dynamic-attr"
        and item.path == "tools/dev/check_changed_non_test_types.py"
        for item in violations
    )


def test_architecture_check_rejects_promoted_typed_file_dynamic_non_boundary_comment(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    (tmp_path / "Makefile").write_text("pyright:\n\tpython -m pyright\n", encoding="utf-8")
    scripts = tmp_path / "tools" / "dev"
    scripts.mkdir(parents=True, exist_ok=True)
    (scripts / "check_changed_non_test_types.py").write_text(
        '"""Changed-file type ratchet.\n\n'
        "Layer: Tooling/gates.\n"
        "Responsibility: enforce changed-file docstring, type annotation, and dot-access ratchets.\n"
        '"""\n'
        "from __future__ import annotations\n\n"
        "def plugin_field(plugin: object, field_name: str) -> object:\n"
        '    """Return a dynamically named plugin value."""\n'
        "    # dynamic plugin field names come from a third-party registry.\n"
        "    return getattr(plugin, field_name)\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "promoted-typed-file-dynamic-attr"
        and item.path == "tools/dev/check_changed_non_test_types.py"
        and "getattr" in item.detail
        for item in violations
    )


def test_architecture_check_allows_promoted_typed_file_docstring_dynamic_boundary(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    (tmp_path / "Makefile").write_text("pyright:\n\tpython -m pyright\n", encoding="utf-8")
    scripts = tmp_path / "tools" / "dev"
    scripts.mkdir(parents=True, exist_ok=True)
    (scripts / "check_changed_non_test_types.py").write_text(
        '"""Changed-file type ratchet.\n\n'
        "Layer: Tooling/gates.\n"
        "Responsibility: enforce changed-file docstring, type annotation, and dot-access ratchets.\n"
        '"""\n'
        "from __future__ import annotations\n\n"
        "def plugin_field(plugin: object, field_name: str) -> object:\n"
        '    """Return a dynamic plugin boundary value from a third-party registry."""\n'
        "    return getattr(plugin, field_name)\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert not any(
        item.rule == "promoted-typed-file-dynamic-attr"
        and item.path == "tools/dev/check_changed_non_test_types.py"
        for item in violations
    )


def test_module_dynamic_boundary_docstring_short_circuits_scope_walk(monkeypatch):
    tree = ast.parse(
        '"""Dynamic angr/codegen boundary for compatibility objects."""\n'
        "value = getattr(codegen, 'value', None)\n"
    )

    def fail_walk(_tree):
        raise AssertionError("module boundary contract should short-circuit AST walking")

    monkeypatch.setattr(arch_check, "_walk_ast", fail_walk)

    assert arch_check._dynamic_attr_docstring_has_boundary_reason(tree, 2)


def test_architecture_check_rejects_promoted_typed_file_dynamic_non_boundary_docstring(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    (tmp_path / "Makefile").write_text("pyright:\n\tpython -m pyright\n", encoding="utf-8")
    scripts = tmp_path / "tools" / "dev"
    scripts.mkdir(parents=True, exist_ok=True)
    (scripts / "check_changed_non_test_types.py").write_text(
        '"""Changed-file type ratchet.\n\n'
        "Layer: Tooling/gates.\n"
        "Responsibility: enforce changed-file docstring, type annotation, and dot-access ratchets.\n"
        '"""\n'
        "from __future__ import annotations\n\n"
        "def plugin_field(plugin: object, field_name: str) -> object:\n"
        '    """Return a dynamic plugin value from a third-party registry."""\n'
        "    return getattr(plugin, field_name)\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "promoted-typed-file-dynamic-attr"
        and item.path == "tools/dev/check_changed_non_test_types.py"
        and "getattr" in item.detail
        for item in violations
    )


def test_architecture_check_allows_promoted_typed_file_documented_builtins_dynamic_boundary(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    (tmp_path / "Makefile").write_text("pyright:\n\tpython -m pyright\n", encoding="utf-8")
    scripts = tmp_path / "tools" / "dev"
    scripts.mkdir(parents=True, exist_ok=True)
    (scripts / "check_changed_non_test_types.py").write_text(
        '"""Changed-file type ratchet.\n\n'
        "Layer: Tooling/gates.\n"
        "Responsibility: enforce changed-file docstring, type annotation, and dot-access ratchets.\n"
        '"""\n'
        "from __future__ import annotations\n\n"
        "import builtins\n\n"
        "def plugin_field(plugin: object, field_name: str) -> object:\n"
        '    """Return a dynamic plugin boundary value from a third-party registry."""\n'
        "    return builtins.getattr(plugin, field_name)\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert not any(
        item.rule == "promoted-typed-file-dynamic-attr"
        and item.path == "tools/dev/check_changed_non_test_types.py"
        for item in violations
    )


def test_architecture_check_rejects_promoted_typed_file_undocumented_builtins_dynamic_boundary(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    (tmp_path / "Makefile").write_text("pyright:\n\tpython -m pyright\n", encoding="utf-8")
    scripts = tmp_path / "tools" / "dev"
    scripts.mkdir(parents=True, exist_ok=True)
    (scripts / "check_changed_non_test_types.py").write_text(
        '"""Changed-file type ratchet.\n\n'
        "Layer: Tooling/gates.\n"
        "Responsibility: enforce changed-file docstring, type annotation, and dot-access ratchets.\n"
        '"""\n'
        "from __future__ import annotations\n\n"
        "import builtins\n\n"
        "def plugin_field(plugin: object, field_name: str) -> object:\n"
        '    """Return a plugin value."""\n'
        "    return builtins.getattr(plugin, field_name)\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "promoted-typed-file-dynamic-attr"
        and item.path == "tools/dev/check_changed_non_test_types.py"
        and "builtins.getattr" in item.detail
        for item in violations
    )


def test_architecture_check_rejects_promoted_typed_file_detached_dynamic_boundary(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    (tmp_path / "Makefile").write_text("pyright:\n\tpython -m pyright\n", encoding="utf-8")
    scripts = tmp_path / "tools" / "dev"
    scripts.mkdir(parents=True, exist_ok=True)
    (scripts / "check_changed_non_test_types.py").write_text(
        '"""Changed-file type ratchet.\n\n'
        "Layer: Tooling/gates.\n"
        "Responsibility: enforce changed-file docstring, type annotation, and dot-access ratchets.\n"
        '"""\n'
        "from __future__ import annotations\n\n"
        "def plugin_field(plugin: object, field_name: str) -> object:\n"
        '    """Return a dynamically named plugin value."""\n'
        "    # dynamic plugin boundary: field names come from a third-party registry.\n"
        "    value: object = plugin\n"
        "    return getattr(value, field_name)\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "promoted-typed-file-dynamic-attr"
        and item.path == "tools/dev/check_changed_non_test_types.py"
        and "line 12" in item.detail
        and "getattr" in item.detail
        for item in violations
    )


def test_architecture_check_rejects_promoted_typed_file_setattr_without_boundary(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    (tmp_path / "Makefile").write_text("pyright:\n\tpython -m pyright\n", encoding="utf-8")
    scripts = tmp_path / "tools" / "dev"
    scripts.mkdir(parents=True, exist_ok=True)
    (scripts / "check_changed_non_test_types.py").write_text(
        '"""Changed-file type ratchet.\n\n'
        "Layer: Tooling/gates.\n"
        "Responsibility: enforce changed-file docstring, type annotation, and dot-access ratchets.\n"
        '"""\n'
        "from __future__ import annotations\n\n"
        "def plugin_field(plugin: object, field_name: str) -> None:\n"
        '    """Set a dynamically named plugin value."""\n'
        "    setattr(plugin, field_name, 1)\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "promoted-typed-file-dynamic-attr"
        and item.path == "tools/dev/check_changed_non_test_types.py"
        for item in violations
    )


def test_architecture_check_allows_promoted_typed_file_documented_setattr_boundary(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    (tmp_path / "Makefile").write_text("pyright:\n\tpython -m pyright\n", encoding="utf-8")
    scripts = tmp_path / "tools" / "dev"
    scripts.mkdir(parents=True, exist_ok=True)
    (scripts / "check_changed_non_test_types.py").write_text(
        '"""Changed-file type ratchet.\n\n'
        "Layer: Tooling/gates.\n"
        "Responsibility: enforce changed-file docstring, type annotation, and dot-access ratchets.\n"
        '"""\n'
        "from __future__ import annotations\n\n"
        "def plugin_field(plugin: object, field_name: str) -> None:\n"
        '    """Set a dynamically named plugin value."""\n'
        "    # dynamic plugin boundary: field names come from a third-party registry.\n"
        "    setattr(plugin, field_name, 1)\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert not any(
        item.rule == "promoted-typed-file-dynamic-attr"
        and item.path == "tools/dev/check_changed_non_test_types.py"
        for item in violations
    )


def test_architecture_check_rejects_promoted_typed_file_documented_static_setattr(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    (tmp_path / "Makefile").write_text("pyright:\n\tpython -m pyright\n", encoding="utf-8")
    scripts = tmp_path / "tools" / "dev"
    scripts.mkdir(parents=True, exist_ok=True)
    (scripts / "check_changed_non_test_types.py").write_text(
        '"""Changed-file type ratchet.\n\n'
        "Layer: Tooling/gates.\n"
        "Responsibility: enforce changed-file docstring, type annotation, and dot-access ratchets.\n"
        '"""\n'
        "from __future__ import annotations\n\n"
        "def set_cache(plugin: object) -> None:\n"
        '    """Set a plugin cache field through a dynamic plugin boundary."""\n'
        "    setattr(plugin, '_cache', 1)\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "promoted-typed-file-static-setattr"
        and item.path == "tools/dev/check_changed_non_test_types.py"
        and "'_cache'" in item.detail
        for item in violations
    )


def test_architecture_check_requires_gate_script_docstrings(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    (tmp_path / "Makefile").write_text("architecture-check:\n\tpython tools/dev/check_decompiler_architecture.py\n", encoding="utf-8")
    scripts = tmp_path / "tools" / "dev"
    scripts.mkdir(parents=True, exist_ok=True)
    (scripts / "check_decompiler_architecture.py").write_text(
        "from __future__ import annotations\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "gate-script-docstring" for item in violations)


def test_architecture_check_requires_gate_script_responsibility_markers(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    (tmp_path / "Makefile").write_text("architecture-check:\n\tpython tools/dev/check_decompiler_architecture.py\n", encoding="utf-8")
    scripts = tmp_path / "tools" / "dev"
    scripts.mkdir(parents=True, exist_ok=True)
    (scripts / "check_decompiler_architecture.py").write_text(
        '"""Static architecture guard.\n\nLayer: Tooling/gates.\n"""\n'
        "from __future__ import annotations\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "gate-script-docstring" and "Responsibility:" in item.detail for item in violations
    )


def test_architecture_check_requires_changed_type_ratchet_responsibility_marker(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    (tmp_path / "Makefile").write_text("architecture-check:\n\tpython tools/dev/check_decompiler_architecture.py\n", encoding="utf-8")
    scripts = tmp_path / "tools" / "dev"
    scripts.mkdir(parents=True, exist_ok=True)
    (scripts / "check_changed_non_test_types.py").write_text(
        '"""Changed-file ratchet.\n\nLayer: Tooling/gates.\n"""\n'
        "from __future__ import annotations\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "gate-script-docstring"
        and item.path == "tools/dev/check_changed_non_test_types.py"
        and "Responsibility:" in item.detail
        for item in violations
    )


def test_architecture_check_requires_cli_boundary_docstrings(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    (tmp_path / "Makefile").write_text("architecture-check:\n\tpython tools/dev/check_decompiler_architecture.py\n", encoding="utf-8")
    cli_core = tmp_path / "inertia" / "cli" / "cli_core.py"
    cli_core.write_text(
        "from __future__ import annotations\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "cli-boundary-docstring" for item in violations)


def test_architecture_check_rejects_vague_cli_boundary_docstring(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    (tmp_path / "Makefile").write_text("architecture-check:\n\tpython tools/dev/check_decompiler_architecture.py\n", encoding="utf-8")
    cli_core = tmp_path / "inertia" / "cli" / "cli_core.py"
    cli_core.write_text(
        '"""Layer: CLI/fallback/reporting.\n\n'
        "Responsibility: keep CLI code separate.\n\n"
        "Forbidden: owning decompiler semantics, source-backed recovery, or postprocess semantic repair.\n"
        '"""\n'
        "from __future__ import annotations\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "cli-boundary-docstring"
        and item.path == "inertia/cli/cli_core.py"
        and "orchestrate commands, fallback lanes, diagnostics, and output policy" in item.detail
        for item in violations
    )


def test_architecture_check_requires_inertia_module_docstrings(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    (tmp_path / "Makefile").write_text("architecture-check:\n\tpython tools/dev/check_decompiler_architecture.py\n", encoding="utf-8")
    module = tmp_path / "inertia" / "cli" / "runtime_support.py"
    module.write_text(
        "from __future__ import annotations\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "inertia-module-docstring" for item in violations)


def test_architecture_check_requires_inertia_module_layer_headers(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    module = tmp_path / "inertia" / "cli" / "runtime_support.py"
    module.write_text(
        '"""Documented CLI helper without a layer marker."""\n'
        "from __future__ import annotations\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "inertia-module-layer-header" and item.path.endswith("inertia/cli/runtime_support.py")
        for item in violations
    )


def test_architecture_check_requires_script_module_docstrings(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    (tmp_path / "Makefile").write_text("architecture-check:\n\tpython tools/dev/check_decompiler_architecture.py\n", encoding="utf-8")
    scripts = tmp_path / "tools" / "dev"
    scripts.mkdir(parents=True, exist_ok=True)
    (scripts / "build_tools/signatures/signature_catalog/py.py").write_text(
        "from __future__ import annotations\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "script-module-docstring" for item in violations)


def test_architecture_check_requires_script_module_layer_headers(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    scripts = tmp_path / "tools" / "dev"
    scripts.mkdir(parents=True, exist_ok=True)
    (scripts / "build_tools/signatures/signature_catalog/py.py").write_text(
        '"""Documented tool without a layer marker."""\n'
        "from __future__ import annotations\n",
        encoding="utf-8",
    )
    tests_dir = scripts / "tests"
    tests_dir.mkdir()
    (tests_dir / "test_private.py").write_text(
        '"""Private test helper without a production layer marker."""\n',
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "script-module-layer-header" and item.path.endswith("tools/dev/build_tools/signatures/signature_catalog/py.py")
        for item in violations
    )
    assert not any(
        item.rule == "script-module-layer-header" and "tools/dev/tests/" in item.path
        for item in violations
    )


def test_architecture_check_requires_root_contract_docstrings(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    (tmp_path / "Makefile").write_text("architecture-check:\n\tpython tools/dev/check_decompiler_architecture.py\n", encoding="utf-8")
    (tmp_path / "tools/signatures/signature_catalog/py.py").write_text(
        "from __future__ import annotations\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "root-contract-docstring" for item in violations)


def test_architecture_check_requires_root_contract_layer_headers(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    (tmp_path / "Makefile").write_text("architecture-check:\n\tpython tools/dev/check_decompiler_architecture.py\n", encoding="utf-8")
    (tmp_path / "tools/signatures/signature_catalog/py.py").write_text(
        '"""Documented root contract without a layer marker."""\n'
        "from __future__ import annotations\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "root-contract-layer-header" and item.path == "tools/signatures/signature_catalog/py.py"
        for item in violations
    )


def test_architecture_check_requires_makefile_gate_markers(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    (tmp_path / "Makefile").write_text(
        "check-files: linters-files pytest-files\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "makefile-gate-marker" for item in violations)


def test_architecture_check_requires_quality_fast_type_ratchet(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    (tmp_path / "Makefile").write_text(
        "\n".join(
            (
                "QA_TYPED_FILES := \\",
                "\tmonkeytype_config.py",
                "QA_CHANGED_TYPED_FILES := $(filter $(QA_TYPED_FILES),$(PY_CHANGED_FILES))",
                "check-files: linters-files architecture-check-fast agent-context-check test-ownership-check pytest-files",
                "\t$(PYTHON) tools/dev/check_changed_non_test_types.py $(TYPE_RATCHET_SELECTED_FILES)",
                "quality-fast: linters decompiler-check-fast",
                "decompiler-check: architecture-check agent-context-check test-ownership-check pytest test-pipeline",
                "decompiler-check-fast: architecture-check-fast agent-context-check test-ownership-check component-catalog-check test-pipeline-fast",
                "decompiler-check-expanded: architecture-check agent-context-check test-ownership-check pytest test-pipeline-expanded",
                "test-pipeline-fast:",
                "\t$(PYTHON) tools/dev/test_pipeline.py --tier fast --require-external",
                "test-pipeline-expanded:",
                "\t$(PYTHON) tools/dev/test_pipeline.py --tier expanded --require-external",
            )
        ),
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "makefile-gate-marker" and "type-ratchet-changed" in item.detail
        for item in violations
    )


def test_architecture_check_requires_focused_ruff_promotion_filter(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    (tmp_path / "Makefile").write_text(
        "\n".join(
            (
                "QA_TYPED_FILES := \\",
                "\tmonkeytype_config.py",
                "QA_RUFF_TARGETS := \\",
                "\tmonkeytype_config.py",
                "QA_CHANGED_TYPED_FILES := $(filter $(QA_TYPED_FILES),$(PY_CHANGED_FILES))",
                "TYPE_RATCHET_SELECTED_FILES := $(PY_FILES)",
                "check-files: linters-files architecture-check-fast agent-context-check test-ownership-check pytest-files",
                "\t$(PYTHON) tools/dev/check_changed_non_test_types.py $(TYPE_RATCHET_SELECTED_FILES)",
                "quality: linters type-ratchet-changed decompiler-check",
                "quality-fast: linters type-ratchet-changed decompiler-check-fast",
                "type-ratchet-changed:",
                "\t$(PYTHON) tools/dev/check_changed_non_test_types.py $(QA_CHANGED_TYPED_FILES)",
                "decompiler-check: architecture-check agent-context-check test-ownership-check pytest test-pipeline",
                "decompiler-check-fast: architecture-check-fast agent-context-check test-ownership-check component-catalog-check test-pipeline-fast",
                "decompiler-check-expanded: architecture-check agent-context-check test-ownership-check pytest test-pipeline-expanded",
                "test-pipeline:",
                "\t$(PYTHON) tools/dev/test_pipeline.py --require-external",
                "test-pipeline-fast:",
                "\t$(PYTHON) tools/dev/test_pipeline.py --tier fast --require-external",
                "test-pipeline-expanded:",
                "\t$(PYTHON) tools/dev/test_pipeline.py --tier expanded --require-external",
            )
        ),
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "makefile-gate-marker" and "RUFF_SELECTED_FILES" in item.detail
        for item in violations
    )


def test_architecture_check_requires_quality_type_ratchet(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    (tmp_path / "Makefile").write_text(
        "\n".join(
            (
                "QA_TYPED_FILES := \\",
                "\tmonkeytype_config.py",
                "QA_CHANGED_TYPED_FILES := $(filter $(QA_TYPED_FILES),$(PY_CHANGED_FILES))",
                "TYPE_RATCHET_SELECTED_FILES := $(PY_FILES)",
                "check-files: linters-files architecture-check-fast agent-context-check test-ownership-check pytest-files",
                "\t$(PYTHON) tools/dev/check_changed_non_test_types.py $(TYPE_RATCHET_SELECTED_FILES)",
                "quality: linters decompiler-check",
                "quality-fast: linters type-ratchet-changed decompiler-check-fast",
                "type-ratchet-changed:",
                "\t$(PYTHON) tools/dev/check_changed_non_test_types.py $(QA_CHANGED_TYPED_FILES)",
                "decompiler-check: architecture-check agent-context-check test-ownership-check pytest test-pipeline",
                "decompiler-check-fast: architecture-check-fast agent-context-check test-ownership-check component-catalog-check test-pipeline-fast",
                "decompiler-check-expanded: architecture-check agent-context-check test-ownership-check pytest test-pipeline-expanded",
                "test-pipeline:",
                "\t$(PYTHON) tools/dev/test_pipeline.py --require-external",
                "test-pipeline-fast:",
                "\t$(PYTHON) tools/dev/test_pipeline.py --tier fast --require-external",
                "test-pipeline-expanded:",
                "\t$(PYTHON) tools/dev/test_pipeline.py --tier expanded --require-external",
            )
        ),
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "makefile-gate-marker"
        and "quality: linters type-ratchet-changed decompiler-check" in item.detail
        for item in violations
    )


def test_architecture_check_requires_check_all_project_guards(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    (tmp_path / "Makefile").write_text(
        "\n".join(
            (
                "QA_TYPED_FILES := \\",
                "\tmonkeytype_config.py",
                "QA_CHANGED_TYPED_FILES := $(filter $(QA_TYPED_FILES),$(PY_CHANGED_FILES))",
                "TYPE_RATCHET_SELECTED_FILES := $(PY_FILES)",
                "check-files: linters-files architecture-check-fast agent-context-check test-ownership-check pytest-files",
                "check-all: ruff-all pyright-all architecture-check agent-context-check test-ownership-check pytest-all",
                "\t$(PYTHON) tools/dev/check_changed_non_test_types.py $(TYPE_RATCHET_SELECTED_FILES)",
                "quality: linters type-ratchet-changed decompiler-check",
                "quality-fast: linters type-ratchet-changed decompiler-check-fast",
                "type-ratchet-changed:",
                "\t$(PYTHON) tools/dev/check_changed_non_test_types.py $(QA_CHANGED_TYPED_FILES)",
                "decompiler-check: architecture-check agent-context-check test-ownership-check pytest test-pipeline",
                "decompiler-check-fast: architecture-check-fast agent-context-check test-ownership-check component-catalog-check test-pipeline-fast",
                "decompiler-check-expanded: architecture-check agent-context-check test-ownership-check pytest test-pipeline-expanded",
                "test-pipeline:",
                "\t$(PYTHON) tools/dev/test_pipeline.py --require-external",
                "test-pipeline-fast:",
                "\t$(PYTHON) tools/dev/test_pipeline.py --tier fast --require-external",
                "test-pipeline-expanded:",
                "\t$(PYTHON) tools/dev/test_pipeline.py --tier expanded --require-external",
            )
        ),
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "makefile-gate-marker"
        and "check-all: ruff-all pyright-all type-ratchet-changed architecture-check agent-context-check test-ownership-check pytest-all"
        in item.detail
        for item in violations
    )


def test_architecture_check_requires_changed_type_ratchet_command(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    (tmp_path / "Makefile").write_text(
        "\n".join(
            (
                "QA_TYPED_FILES := \\",
                "\tmonkeytype_config.py",
                "QA_CHANGED_TYPED_FILES := $(filter $(QA_TYPED_FILES),$(PY_CHANGED_FILES))",
                "check-files: linters-files architecture-check-fast agent-context-check test-ownership-check pytest-files",
                "\t$(PYTHON) tools/dev/check_changed_non_test_types.py $(TYPE_RATCHET_SELECTED_FILES)",
                "quality-fast: linters type-ratchet-changed decompiler-check-fast",
                "type-ratchet-changed:",
                "\t@echo skipped",
                "decompiler-check: architecture-check agent-context-check test-ownership-check pytest test-pipeline",
                "decompiler-check-fast: architecture-check-fast agent-context-check test-ownership-check component-catalog-check test-pipeline-fast",
                "decompiler-check-expanded: architecture-check agent-context-check test-ownership-check pytest test-pipeline-expanded",
                "test-pipeline-fast:",
                "\t$(PYTHON) tools/dev/test_pipeline.py --tier fast --require-external",
                "test-pipeline-expanded:",
                "\t$(PYTHON) tools/dev/test_pipeline.py --tier expanded --require-external",
            )
        ),
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "makefile-gate-marker"
        and "tools/dev/check_changed_non_test_types.py $(QA_CHANGED_TYPED_FILES)" in item.detail
        for item in violations
    )


def test_architecture_check_requires_default_test_pipeline_command(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    (tmp_path / "Makefile").write_text(
        "\n".join(
            (
                "QA_TYPED_FILES := \\",
                "\tmonkeytype_config.py",
                "QA_CHANGED_TYPED_FILES := $(filter $(QA_TYPED_FILES),$(PY_CHANGED_FILES))",
                "check-files: linters-files architecture-check-fast agent-context-check test-ownership-check pytest-files",
                "\t$(PYTHON) tools/dev/check_changed_non_test_types.py $(TYPE_RATCHET_SELECTED_FILES)",
                "quality-fast: linters type-ratchet-changed decompiler-check-fast",
                "type-ratchet-changed:",
                "\t$(PYTHON) tools/dev/check_changed_non_test_types.py $(QA_CHANGED_TYPED_FILES)",
                "decompiler-check: architecture-check agent-context-check test-ownership-check pytest test-pipeline",
                "decompiler-check-fast: architecture-check-fast agent-context-check test-ownership-check component-catalog-check test-pipeline-fast",
                "decompiler-check-expanded: architecture-check agent-context-check test-ownership-check pytest test-pipeline-expanded",
                "test-pipeline-fast:",
                "\t$(PYTHON) tools/dev/test_pipeline.py --tier fast --require-external",
                "test-pipeline-expanded:",
                "\t$(PYTHON) tools/dev/test_pipeline.py --tier expanded --require-external",
            )
        ),
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "makefile-gate-marker"
        and "$(PYTHON) tools/dev/test_pipeline.py --require-external" in item.detail
        for item in violations
    )


def test_architecture_check_requires_promoted_typed_files_in_makefile(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    (tmp_path / "Makefile").write_text(
        "\n".join(
            (
                "QA_TYPED_FILES := \\",
                "\tmonkeytype_config.py",
                "QA_CHANGED_TYPED_FILES := $(filter $(QA_TYPED_FILES),$(PY_CHANGED_FILES))",
                "check-files: linters-files architecture-check-fast agent-context-check test-ownership-check pytest-files",
                "\t$(PYTHON) tools/dev/check_changed_non_test_types.py $(TYPE_RATCHET_SELECTED_FILES)",
                "quality-fast: linters type-ratchet-changed decompiler-check-fast",
                "type-ratchet-changed:",
                "\t$(PYTHON) tools/dev/check_changed_non_test_types.py $(QA_CHANGED_TYPED_FILES)",
                "decompiler-check: architecture-check agent-context-check test-ownership-check pytest test-pipeline",
                "decompiler-check-fast: architecture-check-fast agent-context-check test-ownership-check component-catalog-check test-pipeline-fast",
                "decompiler-check-expanded: architecture-check agent-context-check test-ownership-check pytest test-pipeline-expanded",
                "test-pipeline-fast:",
                "\t$(PYTHON) tools/dev/test_pipeline.py --tier fast --require-external",
                "test-pipeline-expanded:",
                "\t$(PYTHON) tools/dev/test_pipeline.py --tier expanded --require-external",
            )
        ),
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "makefile-promoted-typed-file" for item in violations)


def test_architecture_check_requires_pipeline_contracts_in_promoted_typed_makefile_set(tmp_path):
    missing_file = "inertia/pipeline/contracts.py"
    makefile_text = "\n".join(
        (
            *arch_check._MAKEFILE_MARKERS,
            *(filename for filename in arch_check._PROMOTED_TYPED_FILES if filename != missing_file),
        )
    )
    (tmp_path / "Makefile").write_text(makefile_text, encoding="utf-8")

    violations = arch_check._check_makefile_gate_targets(tmp_path)

    assert any(
        item.rule == "makefile-promoted-typed-file" and missing_file in item.detail
        for item in violations
    )


def test_architecture_check_requires_pipeline_contracts_in_promoted_ruff_makefile_set(tmp_path):
    missing_file = "inertia/pipeline/contracts.py"

    def makefile_variable_lines(filenames: tuple[str, ...]) -> tuple[str, ...]:
        """Return Makefile continuation lines for a synthetic variable."""

        return tuple(f"\t{filename}" + (" \\" if index + 1 < len(filenames) else "") for index, filename in enumerate(filenames))

    typed_lines = makefile_variable_lines(arch_check._PROMOTED_TYPED_FILES)
    ruff_files = tuple(filename for filename in arch_check._PROMOTED_TYPED_FILES if filename != missing_file)
    ruff_lines = makefile_variable_lines(ruff_files)
    makefile_text = "\n".join(
        (
            *arch_check._MAKEFILE_MARKERS,
            "QA_TYPED_FILES := \\",
            *typed_lines,
            "QA_RUFF_TARGETS := \\",
            *ruff_lines,
        )
    )
    (tmp_path / "Makefile").write_text(makefile_text, encoding="utf-8")

    violations = arch_check._check_makefile_gate_targets(tmp_path)

    assert any(
        item.rule == "makefile-promoted-ruff-file" and missing_file in item.detail
        for item in violations
    )


def test_architecture_check_rejects_promoted_typed_file_legacy_ratchet_skip(tmp_path):
    legacy_marker = "QA_TYPE_RATCHET_LEGACY_FILES"
    makefile_text = "\n".join(
        (
            *arch_check._MAKEFILE_MARKERS,
            f"{legacy_marker} :=",
            *arch_check._PROMOTED_TYPED_FILES,
        )
    )
    (tmp_path / "Makefile").write_text(makefile_text, encoding="utf-8")

    violations = arch_check._check_makefile_gate_targets(tmp_path)

    assert any(
        item.rule == "makefile-type-ratchet-legacy-debt" and legacy_marker in item.detail
        for item in violations
    )


def test_architecture_check_rejects_untracked_inertia_decompiler_typed_promotion_file(tmp_path, monkeypatch):
    package_root = tmp_path / "inertia" / "cli"
    package_root.mkdir(parents=True)
    tracked_file = package_root / "tracked.py"
    tracked_file.write_text('"""Tracked."""\nfrom __future__ import annotations\n', encoding="utf-8")
    untracked_file = package_root / "new_module.py"
    untracked_file.write_text('"""Untracked."""\nfrom __future__ import annotations\n', encoding="utf-8")
    monkeypatch.setattr(arch_check, "_PROMOTED_TYPED_FILES", ("inertia/cli/tracked.py",))
    monkeypatch.setattr(arch_check, "_INERTIA_TYPED_PROMOTION_DEBT_FILES", ())

    violations = arch_check._check_inertia_decompiler_typed_promotion_coverage(tmp_path)

    assert any(
        item.rule == "inertia-typed-promotion-coverage" and item.path == "inertia/cli/new_module.py"
        for item in violations
    )


def test_architecture_check_rejects_stale_inertia_decompiler_typed_promotion_debt(tmp_path, monkeypatch):
    package_root = tmp_path / "inertia" / "cli"
    package_root.mkdir(parents=True)
    promoted_file = package_root / "promoted.py"
    promoted_file.write_text('"""Promoted."""\nfrom __future__ import annotations\n', encoding="utf-8")
    monkeypatch.setattr(arch_check, "_PROMOTED_TYPED_FILES", ("inertia/cli/promoted.py",))
    monkeypatch.setattr(arch_check, "_INERTIA_TYPED_PROMOTION_DEBT_FILES", ("inertia/cli/promoted.py",))

    violations = arch_check._check_inertia_decompiler_typed_promotion_coverage(tmp_path)

    assert any(
        item.rule == "inertia-typed-promotion-debt-stale" and item.path == "inertia/cli/promoted.py"
        for item in violations
    )


def test_architecture_check_rejects_untracked_x86_16_typed_promotion_file(tmp_path, monkeypatch):
    package_root = tmp_path / "angr_platforms" / "angr_platforms" / "X86_16"
    package_root.mkdir(parents=True)
    tracked_file = package_root / "tracked.py"
    tracked_file.write_text('"""Tracked."""\nfrom __future__ import annotations\n', encoding="utf-8")
    untracked_file = package_root / "new_module.py"
    untracked_file.write_text('"""Untracked."""\nfrom __future__ import annotations\n', encoding="utf-8")
    monkeypatch.setattr(
        arch_check,
        "_PROMOTED_TYPED_FILES",
        ("angr_platforms/angr_platforms/X86_16/tracked.py",),
    )
    monkeypatch.setattr(arch_check, "_X86_16_TYPED_PROMOTION_DEBT_FILES", ())

    violations = arch_check._check_x86_16_typed_promotion_coverage(tmp_path)

    assert any(
        item.rule == "x86-16-typed-promotion-coverage"
        and item.path == "angr_platforms/angr_platforms/X86_16/new_module.py"
        for item in violations
    )


def test_architecture_check_rejects_stale_x86_16_typed_promotion_debt(tmp_path, monkeypatch):
    package_root = tmp_path / "angr_platforms" / "angr_platforms" / "X86_16"
    package_root.mkdir(parents=True)
    promoted_file = package_root / "promoted.py"
    promoted_file.write_text('"""Promoted."""\nfrom __future__ import annotations\n', encoding="utf-8")
    monkeypatch.setattr(
        arch_check,
        "_PROMOTED_TYPED_FILES",
        ("angr_platforms/angr_platforms/X86_16/promoted.py",),
    )
    monkeypatch.setattr(
        arch_check,
        "_X86_16_TYPED_PROMOTION_DEBT_FILES",
        ("angr_platforms/angr_platforms/X86_16/promoted.py",),
    )

    violations = arch_check._check_x86_16_typed_promotion_coverage(tmp_path)

    assert any(
        item.rule == "x86-16-typed-promotion-debt-stale"
        and item.path == "angr_platforms/angr_platforms/X86_16/promoted.py"
        for item in violations
    )


def test_architecture_check_tracks_pyright_only_promotion_as_full_promotion_debt(tmp_path, monkeypatch):
    package_root = tmp_path / "inertia" / "cli"
    package_root.mkdir(parents=True)
    partial_file = package_root / "partial.py"
    partial_file.write_text('"""Partial."""\nfrom __future__ import annotations\n', encoding="utf-8")
    monkeypatch.setattr(arch_check, "_PROMOTED_TYPED_FILES", ())
    monkeypatch.setattr(arch_check, "_INERTIA_TYPED_PROMOTION_DEBT_FILES", ())
    monkeypatch.setattr(arch_check, "_PYRIGHT_ONLY_TYPED_PROMOTION_FILES", ("inertia/cli/partial.py",))

    violations = arch_check._check_inertia_decompiler_typed_promotion_coverage(tmp_path)

    assert any(
        item.rule == "inertia-pyright-only-promotion-untracked-debt"
        and item.path == "inertia/cli/partial.py"
        for item in violations
    )


def test_architecture_check_rejects_stale_pyright_only_promotion_after_full_promotion(tmp_path, monkeypatch):
    package_root = tmp_path / "inertia" / "cli"
    package_root.mkdir(parents=True)
    promoted_file = package_root / "promoted.py"
    promoted_file.write_text('"""Promoted."""\nfrom __future__ import annotations\n', encoding="utf-8")
    monkeypatch.setattr(arch_check, "_PROMOTED_TYPED_FILES", ("inertia/cli/promoted.py",))
    monkeypatch.setattr(arch_check, "_INERTIA_TYPED_PROMOTION_DEBT_FILES", ())
    monkeypatch.setattr(arch_check, "_PYRIGHT_ONLY_TYPED_PROMOTION_FILES", ("inertia/cli/promoted.py",))

    violations = arch_check._check_inertia_decompiler_typed_promotion_coverage(tmp_path)

    assert any(
        item.rule == "inertia-pyright-only-promotion-stale" and item.path == "inertia/cli/promoted.py"
        for item in violations
    )


def test_architecture_check_requires_pyright_only_promotion_in_typed_makefile_set(tmp_path, monkeypatch):
    partial_file = "inertia/cli/partial.py"
    monkeypatch.setattr(arch_check, "_PYRIGHT_ONLY_TYPED_PROMOTION_FILES", (partial_file,))
    makefile_text = "\n".join(
        (
            *arch_check._MAKEFILE_MARKERS,
            "QA_TYPED_FILES := \\",
            "\tinertia/cli/other.py",
            "QA_RUFF_TARGETS := \\",
            "\tinertia/cli/other.py",
        )
    )
    (tmp_path / "Makefile").write_text(makefile_text, encoding="utf-8")
    (tmp_path / "inertia" / "cli").mkdir(parents=True)
    (tmp_path / "inertia" / "cli" / "other.py").write_text('"""Other."""\n', encoding="utf-8")

    violations = arch_check._check_makefile_gate_targets(tmp_path)

    assert any(item.rule == "makefile-pyright-only-typed-file" and partial_file in item.detail for item in violations)


def test_architecture_check_rejects_full_promotion_debt_in_makefile_typed_targets(tmp_path, monkeypatch):
    debt_file = "angr_platforms/angr_platforms/X86_16/debt.py"
    monkeypatch.setattr(arch_check, "_PROMOTED_TYPED_FILES", ())
    monkeypatch.setattr(arch_check, "_X86_16_TYPED_PROMOTION_DEBT_FILES", (debt_file,))
    monkeypatch.setattr(arch_check, "_INERTIA_TYPED_PROMOTION_DEBT_FILES", ())
    monkeypatch.setattr(arch_check, "_PYRIGHT_ONLY_TYPED_PROMOTION_FILES", ())
    makefile_text = "\n".join(
        (
            *arch_check._MAKEFILE_MARKERS,
            "QA_TYPED_FILES := \\",
            f"\t{debt_file}",
            "QA_RUFF_TARGETS := \\",
            "\tmonkeytype_config.py",
        )
    )
    (tmp_path / "Makefile").write_text(makefile_text, encoding="utf-8")
    debt_path = tmp_path / debt_file
    debt_path.parent.mkdir(parents=True)
    debt_path.write_text('"""Debt."""\nfrom __future__ import annotations\n', encoding="utf-8")

    violations = arch_check._check_makefile_gate_targets(tmp_path)

    assert any(
        item.rule == "makefile-full-promotion-debt-typed-target" and debt_file in item.detail
        for item in violations
    )


def test_architecture_check_rejects_full_promotion_debt_in_makefile_ruff_targets(tmp_path, monkeypatch):
    debt_file = "inertia/cli/debt.py"
    monkeypatch.setattr(arch_check, "_PROMOTED_TYPED_FILES", ())
    monkeypatch.setattr(arch_check, "_X86_16_TYPED_PROMOTION_DEBT_FILES", ())
    monkeypatch.setattr(arch_check, "_INERTIA_TYPED_PROMOTION_DEBT_FILES", (debt_file,))
    monkeypatch.setattr(arch_check, "_PYRIGHT_ONLY_TYPED_PROMOTION_FILES", ())
    makefile_text = "\n".join(
        (
            *arch_check._MAKEFILE_MARKERS,
            "QA_TYPED_FILES := \\",
            "\tmonkeytype_config.py",
            "QA_RUFF_TARGETS := \\",
            f"\t{debt_file}",
        )
    )
    (tmp_path / "Makefile").write_text(makefile_text, encoding="utf-8")
    debt_path = tmp_path / debt_file
    debt_path.parent.mkdir(parents=True)
    debt_path.write_text('"""Debt."""\nfrom __future__ import annotations\n', encoding="utf-8")

    violations = arch_check._check_makefile_gate_targets(tmp_path)

    assert any(
        item.rule == "makefile-full-promotion-debt-ruff-target" and debt_file in item.detail
        for item in violations
    )


def test_architecture_check_allows_pyright_only_debt_in_makefile_typed_targets(tmp_path, monkeypatch):
    partial_file = "inertia/cli/partial.py"
    monkeypatch.setattr(arch_check, "_PROMOTED_TYPED_FILES", ())
    monkeypatch.setattr(arch_check, "_X86_16_TYPED_PROMOTION_DEBT_FILES", ())
    monkeypatch.setattr(arch_check, "_INERTIA_TYPED_PROMOTION_DEBT_FILES", (partial_file,))
    monkeypatch.setattr(arch_check, "_PYRIGHT_ONLY_TYPED_PROMOTION_FILES", (partial_file,))
    makefile_text = "\n".join(
        (
            *arch_check._MAKEFILE_MARKERS,
            "QA_TYPED_FILES := \\",
            f"\t{partial_file}",
            "QA_RUFF_TARGETS := \\",
            "\tmonkeytype_config.py",
        )
    )
    (tmp_path / "Makefile").write_text(makefile_text, encoding="utf-8")
    partial_path = tmp_path / partial_file
    partial_path.parent.mkdir(parents=True)
    partial_path.write_text('"""Partial."""\nfrom __future__ import annotations\n', encoding="utf-8")

    violations = arch_check._check_makefile_gate_targets(tmp_path)

    assert not any(
        item.rule == "makefile-full-promotion-debt-typed-target" and partial_file in item.detail
        for item in violations
    )


def test_architecture_check_requires_focused_contract_tests_in_makefile_quality_targets(tmp_path):
    missing_test = "tests/postprocess/test_x86_16_decompiler_postprocess_jcc.py"
    makefile_text = "\n".join(
        (
            *arch_check._MAKEFILE_MARKERS,
            *arch_check._PROMOTED_TYPED_FILES,
            *(marker for marker in arch_check._FOCUSED_PYTEST_MARKERS if marker != missing_test),
        )
    )
    (tmp_path / "Makefile").write_text(makefile_text, encoding="utf-8")

    violations = arch_check._check_makefile_gate_targets(tmp_path)

    assert any(
        item.rule == "makefile-focused-contract-test" and missing_test in item.detail
        for item in violations
    )


def test_architecture_check_rejects_duplicate_makefile_qa_targets(tmp_path):
    makefile_text = "\n".join(
        (
            "QA_RUFF_TARGETS := \\",
            "\tMakefile \\",
            "\tMakefile",
        )
    )
    (tmp_path / "Makefile").write_text(makefile_text, encoding="utf-8")

    violations = arch_check._check_makefile_gate_targets(tmp_path)

    assert any(
        item.rule == "makefile-duplicate-qa-target" and "QA_RUFF_TARGETS" in item.detail
        for item in violations
    )


def test_architecture_check_rejects_missing_makefile_qa_targets(tmp_path):
    makefile_text = "\n".join(
        (
            "QA_PYTEST_TARGETS := \\",
            "\tangr_platforms/tests/test_missing_contract.py",
        )
    )
    (tmp_path / "Makefile").write_text(makefile_text, encoding="utf-8")

    violations = arch_check._check_makefile_gate_targets(tmp_path)

    assert any(
        item.rule == "makefile-missing-qa-target" and "test_missing_contract.py" in item.detail
        for item in violations
    )


def test_architecture_check_rejects_missing_makefile_qa_nodes(tmp_path):
    test_path = tmp_path / "angr_platforms" / "tests" / "test_contract.py"
    test_path.parent.mkdir(parents=True)
    test_path.write_text("def test_present():\n    pass\n", encoding="utf-8")
    (tmp_path / "Makefile").write_text(
        "QA_PYTEST_TARGETS := "
        "angr_platforms/tests/test_contract.py::test_missing\n",
        encoding="utf-8",
    )

    violations = arch_check._check_makefile_gate_targets(tmp_path)

    assert any(
        item.rule == "makefile-missing-qa-node" and "test_missing" in item.detail
        for item in violations
    )


def test_architecture_check_requires_postprocess_stage_pipeline_contract_gate(tmp_path):
    root = tmp_path / "angr_platforms" / "angr_platforms" / "X86_16"
    root.mkdir(parents=True)
    (root / "decompiler_postprocess_stage.py").write_text(
        "from __future__ import annotations\n"
        "from .pipeline.contracts import assert_pipeline_contracts_8616\n\n"
        "def _run_pipeline_contract_gate_8616():\n"
        "    return None\n",
        encoding="utf-8",
    )

    violations = arch_check._check_postprocess_stage_runs_pipeline_contract_gate(root)

    assert any(item.rule == "postprocess-stage-pipeline-contract-gate" for item in violations)


def test_architecture_check_requires_identical_assignment_arm_structuring_owner(tmp_path):
    root = tmp_path / "angr_platforms" / "angr_platforms" / "X86_16"
    owner_root = root / "structuring"
    owner_root.mkdir(parents=True)
    (owner_root / "return_chains.py").write_text(
        "def identical_assignment_arm_condition_8616():\n"
        "    return None\n\n"
        "def collapse_surplus_identical_assignment_arms_8616():\n"
        "    return None\n",
        encoding="utf-8",
    )
    (root / "decompiler_structuring_stage.py").write_text(
        "from inertia.structuring.return_chains import collapse_surplus_identical_assignment_arms_8616\n\n"
        "def _materialize_structuring_return_chains_8616():\n"
        "    return None\n",
        encoding="utf-8",
    )

    violations = arch_check._check_identical_assignment_arm_structuring_ownership(root)

    assert any(
        item.rule == "identical-assignment-arm-structuring-owner"
        and "must call" in item.detail
        for item in violations
    )


def test_architecture_check_rejects_identical_assignment_arm_postprocess_owner(tmp_path):
    root = tmp_path / "angr_platforms" / "angr_platforms" / "X86_16"
    owner_root = root / "structuring"
    owner_root.mkdir(parents=True)
    (owner_root / "return_chains.py").write_text(
        "def identical_assignment_arm_condition_8616():\n"
        "    return None\n\n"
        "def collapse_surplus_identical_assignment_arms_8616():\n"
        "    return None\n",
        encoding="utf-8",
    )
    (root / "decompiler_structuring_stage.py").write_text(
        "from inertia.structuring.return_chains import collapse_surplus_identical_assignment_arms_8616\n\n"
        "def _materialize_structuring_return_chains_8616():\n"
        "    collapse_surplus_identical_assignment_arms_8616()\n",
        encoding="utf-8",
    )
    (root / "decompiler_postprocess_stage.py").write_text(
        "def identical_assignment_arm_condition_8616():\n"
        "    return None\n",
        encoding="utf-8",
    )

    violations = arch_check._check_identical_assignment_arm_structuring_ownership(root)

    assert any(
        item.rule == "identical-assignment-arm-structuring-owner"
        and "must not be defined in postprocess" in item.detail
        for item in violations
    )


def test_architecture_check_requires_terminal_call_result_after_lowering_replay(tmp_path):
    root = tmp_path / "angr_platforms" / "angr_platforms" / "X86_16"
    owner_root = root / "structuring"
    owner_root.mkdir(parents=True)
    (owner_root / "return_chains.py").write_text(
        "class TerminalCallResultReturnCallbacks8616:\n"
        "    pass\n\n"
        "class TerminalCallResultReturnStats8616:\n"
        "    pass\n\n"
        "class TerminalCallResultReturnStatus8616:\n"
        "    pass\n\n"
        "def materialize_terminal_call_result_return_8616():\n"
        "    return None\n",
        encoding="utf-8",
    )
    (root / "decompiler_structuring_stage.py").write_text(
        "from inertia.structuring.return_chains import materialize_terminal_call_result_return_8616\n\n"
        "def _materialize_structuring_terminal_call_result_return_8616():\n"
        "    materialize_terminal_call_result_return_8616()\n\n"
        "def _replay_structuring_lowering_before_validation_8616():\n"
        "    return None\n\n"
        "def _prime_structuring_validation_semantics_8616():\n"
        "    _materialize_structuring_terminal_call_result_return_8616()\n"
        "    _replay_structuring_lowering_before_validation_8616()\n",
        encoding="utf-8",
    )

    violations = arch_check._check_terminal_call_result_structuring_ownership(root)

    assert any(
        item.rule == "terminal-call-result-structuring-owner"
        and "after final lowering replay" in item.detail
        for item in violations
    )


def test_startup_architecture_check_rejects_terminal_call_result_postprocess_import(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    owner_root = root / "structuring"
    owner_root.mkdir(parents=True)
    (owner_root / "return_chains.py").write_text(
        "class TerminalCallResultReturnCallbacks8616:\n"
        "    pass\n\n"
        "class TerminalCallResultReturnStats8616:\n"
        "    pass\n\n"
        "class TerminalCallResultReturnStatus8616:\n"
        "    pass\n\n"
        "def materialize_terminal_call_result_return_8616():\n"
        "    return None\n",
        encoding="utf-8",
    )
    (root / "decompiler_structuring_stage.py").write_text(
        "from inertia.structuring.return_chains import materialize_terminal_call_result_return_8616\n\n"
        "def _materialize_structuring_terminal_call_result_return_8616():\n"
        "    materialize_terminal_call_result_return_8616()\n\n"
        "def _replay_structuring_lowering_before_validation_8616():\n"
        "    return None\n\n"
        "def _prime_structuring_validation_semantics_8616():\n"
        "    _replay_structuring_lowering_before_validation_8616()\n"
        "    _materialize_structuring_terminal_call_result_return_8616()\n",
        encoding="utf-8",
    )
    postprocess_path = root / "decompiler_postprocess_jcc.py"
    postprocess_path.write_text(
        postprocess_path.read_text(encoding="utf-8")
        + "from inertia.structuring.return_chains import materialize_terminal_call_result_return_8616\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_startup_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "terminal-call-result-structuring-owner"
        and "must not be defined or imported in postprocess" in item.detail
        for item in violations
    )


def test_architecture_check_requires_shared_body_to_call_wide_lowering_owner(tmp_path):
    root = tmp_path / "angr_platforms" / "angr_platforms" / "X86_16"
    lowering_root = root / "lowering"
    structuring_root = root / "structuring"
    lowering_root.mkdir(parents=True)
    structuring_root.mkdir(parents=True)
    (lowering_root / "call_output_stack_objects.py").write_text(
        "def lower_wide_call_return_condition_chain_8616():\n"
        "    return None\n",
        encoding="utf-8",
    )
    (structuring_root / "condition_materialization.py").write_text(
        "from inertia.lowering.call_output_stack_objects import "
        "lower_wide_call_return_condition_chain_8616\n\n"
        "def _materialize_cfg_shared_body_condition_chain_expr_8616():\n"
        "    return None\n",
        encoding="utf-8",
    )

    violations = arch_check._check_shared_body_wide_condition_ownership(root)

    assert any(
        item.rule == "shared-body-wide-condition-layer-owner"
        and "must call" in item.detail
        for item in violations
    )


def test_architecture_check_rejects_shared_body_owner_in_postprocess(tmp_path):
    root = tmp_path / "angr_platforms" / "angr_platforms" / "X86_16"
    lowering_root = root / "lowering"
    structuring_root = root / "structuring"
    lowering_root.mkdir(parents=True)
    structuring_root.mkdir(parents=True)
    (lowering_root / "call_output_stack_objects.py").write_text(
        "def lower_wide_call_return_condition_chain_8616():\n"
        "    return None\n",
        encoding="utf-8",
    )
    (structuring_root / "condition_materialization.py").write_text(
        "from inertia.lowering.call_output_stack_objects import "
        "lower_wide_call_return_condition_chain_8616\n\n"
        "def _materialize_cfg_shared_body_condition_chain_expr_8616():\n"
        "    return lower_wide_call_return_condition_chain_8616()\n",
        encoding="utf-8",
    )
    (root / "decompiler_postprocess_jcc.py").write_text(
        "from .lowering.call_output_stack_objects import "
        "lower_wide_call_return_condition_chain_8616\n",
        encoding="utf-8",
    )

    violations = arch_check._check_shared_body_wide_condition_ownership(root)

    assert any(
        item.rule == "shared-body-wide-condition-layer-owner"
        and "must not be owned or imported by postprocess" in item.detail
        for item in violations
    )


def test_architecture_check_requires_condition_lane_counter_dot_access(tmp_path):
    root = tmp_path / "angr_platforms" / "angr_platforms" / "X86_16"
    root.mkdir(parents=True)
    (root / "decompiler_postprocess_typed_conditions.py").write_text(
        "from __future__ import annotations\n\n"
        "def update(lane):\n"
        "    lane.classified = getattr(lane, 'classified', 0) + 1\n",
        encoding="utf-8",
    )

    violations = arch_check._check_condition_lane_counters_use_dot_access(root)

    assert any(item.rule == "condition-lane-dot-access" for item in violations)


def test_architecture_check_requires_condition_origin_tag_dot_access(tmp_path):
    root = tmp_path / "angr_platforms" / "angr_platforms" / "X86_16"
    condition_root = root / "structuring"
    condition_root.mkdir(parents=True)
    (condition_root / "condition_lowering.py").write_text(
        "from __future__ import annotations\n\n"
        "def condition_origin_tags_8616(condition):\n"
        "    return {'typed_condition': True, 'ins_addr': getattr(condition, 'src_insn', None)}\n",
        encoding="utf-8",
    )

    violations = arch_check._check_condition_origin_tags_use_dot_access(root)

    assert any(item.rule == "condition-origin-tags-dot-access" for item in violations)


def test_architecture_check_requires_agent_context_in_promoted_typed_makefile_set(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    (tmp_path / "Makefile").write_text(
        "\n".join(
            (
                "QA_TYPED_FILES := \\",
                "\tmonkeytype_config.py \\",
                "\tinertia/cli/monkeytype_tools.py \\",
                "\ttools/dev/collect_monkeytype_pytest.py \\",
                "\ttools/dev/apply_monkeytype_annotations.py \\",
                "\ttools/dev/export_monkeytype_stubs.py \\",
                "\ttools/dev/check_decompiler_architecture.py \\",
                "\ttools/dev/test_pipeline.py \\",
                "\ttools/dev/test_ownership_manifest.py \\",
                "\ttools/dev/check_changed_non_test_types.py \\",
                "\ttools/dev/sortdemo_decompiler_status.py",
                "QA_CHANGED_TYPED_FILES := $(filter $(QA_TYPED_FILES),$(PY_CHANGED_FILES))",
                "check-files: linters-files architecture-check-fast agent-context-check test-ownership-check pytest-files",
                "\t$(PYTHON) tools/dev/check_changed_non_test_types.py $(TYPE_RATCHET_SELECTED_FILES)",
                "quality-fast: linters type-ratchet-changed decompiler-check-fast",
                "type-ratchet-changed:",
                "\t$(PYTHON) tools/dev/check_changed_non_test_types.py $(QA_CHANGED_TYPED_FILES)",
                "decompiler-check: architecture-check agent-context-check test-ownership-check pytest test-pipeline",
                "decompiler-check-fast: architecture-check-fast agent-context-check test-ownership-check component-catalog-check test-pipeline-fast",
                "decompiler-check-expanded: architecture-check agent-context-check test-ownership-check pytest test-pipeline-expanded",
                "test-pipeline-fast:",
                "\t$(PYTHON) tools/dev/test_pipeline.py --tier fast --require-external",
                "test-pipeline-expanded:",
                "\t$(PYTHON) tools/dev/test_pipeline.py --tier expanded --require-external",
            )
        ),
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "makefile-promoted-typed-file" and "tools/dev/agent_context_check.py" in item.detail
        for item in violations
    )


def test_architecture_check_requires_quality_gate_in_promoted_typed_makefile_set(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    (tmp_path / "Makefile").write_text(
        "\n".join(
            (
                "QA_TYPED_FILES := \\",
                "\tmonkeytype_config.py \\",
                "\tinertia/cli/monkeytype_tools.py \\",
                "\ttools/dev/collect_monkeytype_pytest.py \\",
                "\ttools/dev/apply_monkeytype_annotations.py \\",
                "\ttools/dev/export_monkeytype_stubs.py \\",
                "\ttools/dev/agent_context_check.py \\",
                "\ttools/dev/check_decompiler_architecture.py \\",
                "\ttools/dev/test_pipeline.py \\",
                "\ttools/dev/test_ownership_manifest.py \\",
                "\ttools/dev/check_changed_non_test_types.py \\",
                "\ttools/dev/sortdemo_decompiler_status.py",
                "QA_CHANGED_TYPED_FILES := $(filter $(QA_TYPED_FILES),$(PY_CHANGED_FILES))",
                "check-files: linters-files architecture-check-fast agent-context-check test-ownership-check pytest-files",
                "\t$(PYTHON) tools/dev/check_changed_non_test_types.py $(TYPE_RATCHET_SELECTED_FILES)",
                "quality-fast: linters type-ratchet-changed decompiler-check-fast",
                "type-ratchet-changed:",
                "\t$(PYTHON) tools/dev/check_changed_non_test_types.py $(QA_CHANGED_TYPED_FILES)",
                "decompiler-check: architecture-check agent-context-check test-ownership-check pytest test-pipeline",
                "decompiler-check-fast: architecture-check-fast agent-context-check test-ownership-check component-catalog-check test-pipeline-fast",
                "decompiler-check-expanded: architecture-check agent-context-check test-ownership-check pytest test-pipeline-expanded",
                "test-pipeline-fast:",
                "\t$(PYTHON) tools/dev/test_pipeline.py --tier fast --require-external",
                "test-pipeline-expanded:",
                "\t$(PYTHON) tools/dev/test_pipeline.py --tier expanded --require-external",
            )
        ),
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "makefile-promoted-typed-file" and "inertia/cli/decompilation_quality.py" in item.detail
        for item in violations
    )


def test_architecture_check_requires_runtime_guard_in_promoted_typed_makefile_set(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    (tmp_path / "Makefile").write_text(
        "\n".join(
            (
                "QA_TYPED_FILES := \\",
                "\tmonkeytype_config.py \\",
                "\tinertia/cli/decompilation_quality.py \\",
                "\tinertia/cli/monkeytype_tools.py \\",
                "\ttools/dev/collect_monkeytype_pytest.py \\",
                "\ttools/dev/apply_monkeytype_annotations.py \\",
                "\ttools/dev/export_monkeytype_stubs.py \\",
                "\ttools/dev/agent_context_check.py \\",
                "\ttools/dev/check_decompiler_architecture.py \\",
                "\ttools/dev/test_pipeline.py \\",
                "\ttools/dev/test_ownership_manifest.py \\",
                "\ttools/dev/check_changed_non_test_types.py \\",
                "\ttools/dev/sortdemo_decompiler_status.py",
                "QA_CHANGED_TYPED_FILES := $(filter $(QA_TYPED_FILES),$(PY_CHANGED_FILES))",
                "check-files: linters-files architecture-check-fast agent-context-check test-ownership-check pytest-files",
                "\t$(PYTHON) tools/dev/check_changed_non_test_types.py $(TYPE_RATCHET_SELECTED_FILES)",
                "quality-fast: linters type-ratchet-changed decompiler-check-fast",
                "type-ratchet-changed:",
                "\t$(PYTHON) tools/dev/check_changed_non_test_types.py $(QA_CHANGED_TYPED_FILES)",
                "decompiler-check: architecture-check agent-context-check test-ownership-check pytest test-pipeline",
                "decompiler-check-fast: architecture-check-fast agent-context-check test-ownership-check component-catalog-check test-pipeline-fast",
                "decompiler-check-expanded: architecture-check agent-context-check test-ownership-check pytest test-pipeline-expanded",
                "test-pipeline-fast:",
                "\t$(PYTHON) tools/dev/test_pipeline.py --tier fast --require-external",
                "test-pipeline-expanded:",
                "\t$(PYTHON) tools/dev/test_pipeline.py --tier expanded --require-external",
            )
        ),
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "makefile-promoted-typed-file"
        and "inertia/cli/architecture_runtime_guard.py" in item.detail
        for item in violations
    )


def test_architecture_check_requires_fast_pipeline_contract_tests(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    scripts = tmp_path / "tools" / "dev"
    scripts.mkdir(parents=True, exist_ok=True)
    (scripts / "test_pipeline.py").write_text(
        "\n".join(
            (
                '"""Curated pipeline."""',
                "FOCUSED_PYTEST_TARGETS = (",
                '    "tools/dev/tests/test_decompiler_architecture_check.py",',
                '    "tools/dev/tests/test_test_pipeline.py",',
                '    "tools/dev/tests/test_check_changed_non_test_types.py",',
                ")",
            )
        ),
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "focused-pipeline-contract-test" for item in violations)


def test_architecture_check_requires_pipeline_fast_tests_in_makefile_pytest_targets(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    scripts = tmp_path / "tools" / "dev"
    scripts.mkdir(parents=True, exist_ok=True)
    (scripts / "test_pipeline.py").write_text(
        "\n".join(
            (
                '"""Curated pipeline."""',
                "FOCUSED_PYTEST_TARGETS = (",
                '    "tools/dev/tests/test_decompiler_architecture_check.py",',
                '    "tools/dev/tests/test_test_pipeline.py",',
                '    "tools/dev/tests/test_test_ownership_manifest.py",',
                '    "tools/dev/tests/test_check_changed_non_test_types.py",',
                '    "tests/cli/test_cli_regeneration.py",',
                '    "tests/postprocess/test_x86_16_decompiler_postprocess_typed_conditions.py",',
                '    "tests/postprocess/test_x86_16_decompiler_postprocess_jcc.py",',
                '    "tests/validation/test_x86_16_validation_canonicalize.py",',
                ")",
            )
        ),
        encoding="utf-8",
    )
    (tmp_path / "Makefile").write_text(
        "\n".join(
            (
                "QA_PYTEST_TARGETS := \\",
                "\ttools/dev/tests/test_decompiler_architecture_check.py \\",
                "\ttools/dev/tests/test_test_pipeline.py \\",
                "\ttools/dev/tests/test_test_ownership_manifest.py \\",
                "\ttools/dev/tests/test_check_changed_non_test_types.py \\",
                "\ttests/postprocess/test_x86_16_decompiler_postprocess_typed_conditions.py \\",
                "\ttests/postprocess/test_x86_16_decompiler_postprocess_jcc.py \\",
                "\ttests/validation/test_x86_16_validation_canonicalize.py",
            )
        ),
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "makefile-pipeline-fast-target" and "test_cli_regeneration.py" in item.detail
        for item in violations
    )


def test_architecture_check_rejects_missing_fast_pipeline_target(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    scripts = tmp_path / "tools" / "dev"
    scripts.mkdir(parents=True, exist_ok=True)
    (scripts / "test_pipeline.py").write_text(
        "\n".join(
            (
                '"""Curated pipeline."""',
                "FOCUSED_PYTEST_TARGETS = (",
                '    "tools/dev/tests/test_decompiler_architecture_check.py",',
                '    "tools/dev/tests/test_test_pipeline.py",',
                '    "tools/dev/tests/test_test_ownership_manifest.py",',
                '    "tools/dev/tests/test_check_changed_non_test_types.py",',
                '    "angr_platforms/tests/test_missing_fast_contract.py",',
                '    "tests/postprocess/test_x86_16_decompiler_postprocess_typed_conditions.py",',
                '    "tests/postprocess/test_x86_16_decompiler_postprocess_jcc.py",',
                '    "tests/validation/test_x86_16_validation_canonicalize.py",',
                ")",
            )
        ),
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "focused-pipeline-missing-target"
        and "test_missing_fast_contract.py" in item.detail
        for item in violations
    )


def test_architecture_check_rejects_missing_fast_pipeline_target_node(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    fast_test = tmp_path / "angr_platforms" / "tests" / "test_fast_contract.py"
    fast_test.parent.mkdir(parents=True, exist_ok=True)
    fast_test.write_text(
        "from __future__ import annotations\n\n"
        "def test_existing_contract():\n"
        "    assert True\n",
        encoding="utf-8",
    )
    scripts = tmp_path / "tools" / "dev"
    scripts.mkdir(parents=True, exist_ok=True)
    (scripts / "test_pipeline.py").write_text(
        "\n".join(
            (
                '"""Curated pipeline."""',
                "FOCUSED_PYTEST_TARGETS = (",
                '    "tools/dev/tests/test_decompiler_architecture_check.py",',
                '    "tools/dev/tests/test_test_pipeline.py",',
                '    "tools/dev/tests/test_test_ownership_manifest.py",',
                '    "tools/dev/tests/test_check_changed_non_test_types.py",',
                '    "angr_platforms/tests/test_fast_contract.py::test_missing_contract",',
                '    "tests/postprocess/test_x86_16_decompiler_postprocess_typed_conditions.py",',
                '    "tests/postprocess/test_x86_16_decompiler_postprocess_jcc.py",',
                '    "tests/validation/test_x86_16_validation_canonicalize.py",',
                ")",
            )
        ),
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "focused-pipeline-missing-target"
        and "test_missing_contract" in item.detail
        for item in violations
    )


def test_architecture_check_rejects_duplicate_fast_pipeline_target(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    scripts = tmp_path / "tools" / "dev"
    scripts.mkdir(parents=True, exist_ok=True)
    (scripts / "test_pipeline.py").write_text(
        "\n".join(
            (
                '"""Curated pipeline."""',
                "FOCUSED_PYTEST_TARGETS = (",
                '    "tools/dev/tests/test_decompiler_architecture_check.py",',
                '    "tools/dev/tests/test_test_pipeline.py",',
                '    "tools/dev/tests/test_test_ownership_manifest.py",',
                '    "tools/dev/tests/test_check_changed_non_test_types.py",',
                '    "tests/cli/test_cli_regeneration.py",',
                '    "tests/cli/test_cli_regeneration.py",',
                '    "tests/postprocess/test_x86_16_decompiler_postprocess_typed_conditions.py",',
                '    "tests/postprocess/test_x86_16_decompiler_postprocess_jcc.py",',
                '    "tests/validation/test_x86_16_validation_canonicalize.py",',
                ")",
            )
        ),
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "focused-pipeline-duplicate-target"
        and "test_cli_regeneration.py" in item.detail
        for item in violations
    )


def test_architecture_check_requires_typed_conditions_before_jcc_fast_tests(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    scripts = tmp_path / "tools" / "dev"
    scripts.mkdir(parents=True, exist_ok=True)
    (scripts / "test_pipeline.py").write_text(
        "\n".join(
            (
                '"""Curated pipeline."""',
                "FOCUSED_PYTEST_TARGETS = (",
                '    "tools/dev/tests/test_decompiler_architecture_check.py",',
                '    "tools/dev/tests/test_test_pipeline.py",',
                '    "tools/dev/tests/test_test_ownership_manifest.py",',
                '    "tools/dev/tests/test_check_changed_non_test_types.py",',
                '    "tests/postprocess/test_x86_16_decompiler_postprocess_jcc.py",',
                '    "tests/postprocess/test_x86_16_decompiler_postprocess_typed_conditions.py",',
                '    "tests/validation/test_x86_16_validation_canonicalize.py",',
                ")",
            )
        ),
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "focused-pipeline-jcc-order" for item in violations)


def test_architecture_check_rejects_slow_pytest_targets_in_fast_pipeline(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    scripts = tmp_path / "tools" / "dev"
    scripts.mkdir(parents=True, exist_ok=True)
    (scripts / "test_pipeline.py").write_text(
        "\n".join(
            (
                '"""Curated pipeline."""',
                "FOCUSED_PYTEST_TARGETS = (",
                '    "tools/dev/tests/test_decompiler_architecture_check.py",',
                '    "tools/dev/tests/test_test_pipeline.py",',
                '    "tools/dev/tests/test_test_ownership_manifest.py",',
                '    "tools/dev/tests/test_check_changed_non_test_types.py",',
                '    "tests/cli/test_cli_regeneration.py",',
                '    "tests/postprocess/test_x86_16_decompiler_postprocess_typed_conditions.py",',
                '    "tests/postprocess/test_x86_16_decompiler_postprocess_jcc.py",',
                '    "tests/validation/test_x86_16_validation_canonicalize.py",',
                '    "tests/cli/test_x86_16_sortdemo_regressions.py",',
                ")",
            )
        ),
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "focused-pipeline-slow-target" and "test_x86_16_sortdemo_regressions.py" in item.detail
        for item in violations
    )


def test_architecture_check_rejects_skip_xfail_in_fast_pipeline_target(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    scripts = tmp_path / "tools" / "dev"
    scripts.mkdir(parents=True, exist_ok=True)
    fast_test = tmp_path / "angr_platforms" / "tests" / "test_fast_contract.py"
    fast_test.parent.mkdir(parents=True, exist_ok=True)
    fast_test.write_text(
        "from __future__ import annotations\n\n"
        "import pytest\n\n"
        "@pytest.mark.skipif(True, reason='optional local fixture')\n"
        "def test_fast_contract():\n"
        "    assert True\n",
        encoding="utf-8",
    )
    (scripts / "test_pipeline.py").write_text(
        "\n".join(
            (
                '"""Curated pipeline."""',
                "PIPELINE_TIERS = {",
                '    "fast": ("unit-focused",),',
                '    "default": ("unit-focused", "ultra-quickc-fixtures", "msc6-tiny-full-pipeline"),',
                '    "expanded": ("unit-focused", "ultra-quickc-fixtures", "msc6-tiny-full-pipeline", "sortdemo-status"),',
                "}",
                "FOCUSED_PYTEST_TARGETS = (",
                '    "angr_platforms/tests/test_fast_contract.py",',
                ")",
            )
        ),
        encoding="utf-8",
    )
    (scripts / "test_ownership_manifest.py").write_text(
        '"""Focused ownership manifest."""\n'
        "from __future__ import annotations\n\n"
        f"{_fast_skip_policy_source()}\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "focused-pipeline-skip-xfail" and "test_fast_contract.py" in item.path
        for item in violations
    )


def test_architecture_check_rejects_external_lane_in_fast_pipeline_tier(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    scripts = tmp_path / "tools" / "dev"
    scripts.mkdir(parents=True, exist_ok=True)
    (scripts / "test_pipeline.py").write_text(
        "\n".join(
            (
                '"""Curated pipeline."""',
                "PIPELINE_TIERS = {",
                '    "fast": ("unit-focused", "msc6-tiny-full-pipeline"),',
                '    "default": ("unit-focused", "ultra-quickc-fixtures", "msc6-tiny-full-pipeline"),',
                '    "expanded": ("unit-focused", "ultra-quickc-fixtures", "msc6-tiny-full-pipeline", "sortdemo-status"),',
                "}",
                "FOCUSED_PYTEST_TARGETS = (",
                '    "tools/dev/tests/test_decompiler_architecture_check.py",',
                '    "tools/dev/tests/test_test_pipeline.py",',
                '    "tools/dev/tests/test_test_ownership_manifest.py",',
                '    "tools/dev/tests/test_check_changed_non_test_types.py",',
                ")",
            )
        ),
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "test-pipeline-tier-contract" and "'fast' tier" in item.detail for item in violations
    )


def test_architecture_check_rejects_expanded_pipeline_without_sortdemo_status(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    scripts = tmp_path / "tools" / "dev"
    scripts.mkdir(parents=True, exist_ok=True)
    (scripts / "test_pipeline.py").write_text(
        "\n".join(
            (
                '"""Curated pipeline."""',
                "PIPELINE_TIERS = {",
                '    "fast": ("unit-focused",),',
                '    "default": ("unit-focused", "ultra-quickc-fixtures", "msc6-tiny-full-pipeline"),',
                '    "expanded": ("unit-focused", "ultra-quickc-fixtures", "msc6-tiny-full-pipeline"),',
                "}",
                "FOCUSED_PYTEST_TARGETS = (",
                '    "tools/dev/tests/test_decompiler_architecture_check.py",',
                '    "tools/dev/tests/test_test_pipeline.py",',
                '    "tools/dev/tests/test_test_ownership_manifest.py",',
                '    "tools/dev/tests/test_check_changed_non_test_types.py",',
                ")",
            )
        ),
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "test-pipeline-tier-contract" and "'expanded' tier" in item.detail for item in violations
    )


def test_architecture_check_requires_ownership_manifest_layer_fallbacks(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    scripts = tmp_path / "tools" / "dev"
    scripts.mkdir(parents=True, exist_ok=True)
    (scripts / "test_ownership_manifest.py").write_text(
        "\n".join(
            (
                '"""Focused ownership manifest."""',
                "TestOwnershipRule(",
                '    owner="ir-layer-fallback",',
                '    paths=("angr_platforms/angr_platforms/X86_16/ir",),',
                '    tests=("tests/ir/test_x86_16_ir_core.py",),',
                ")",
            )
        ),
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "ownership-manifest-layer-fallback" for item in violations)


def test_architecture_check_requires_tail_validation_family_ownership_rule(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    scripts = tmp_path / "tools" / "dev"
    scripts.mkdir(parents=True, exist_ok=True)
    (scripts / "test_ownership_manifest.py").write_text(
        "\n".join(
            (
                '"""Focused ownership manifest."""',
                "TestOwnershipRule(",
                '    owner="ir-layer-fallback",',
                '    paths=("angr_platforms/angr_platforms/X86_16/ir",),',
                '    tests=("tests/ir/test_x86_16_ir_core.py",),',
                "    fallback=True,",
                ")",
            )
        ),
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "ownership-manifest-required-rule" for item in violations)


def test_architecture_check_requires_ownership_manifest_fallback_reason(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    scripts = tmp_path / "tools" / "dev"
    scripts.mkdir(parents=True, exist_ok=True)
    (scripts / "test_ownership_manifest.py").write_text(
        "\n".join(
            (
                '"""Focused ownership manifest."""',
                "TestOwnershipRule(",
                '    owner="ir-layer-fallback",',
                '    paths=("angr_platforms/angr_platforms/X86_16/ir",),',
                '    tests=("tests/ir/test_x86_16_ir_core.py",),',
                "    fallback=True,",
                ")",
            )
        ),
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "ownership-manifest-fallback-reason" for item in violations)


def test_architecture_check_rejects_skip_xfail_in_fast_ownership_manifest_target(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    scripts = tmp_path / "tools" / "dev"
    scripts.mkdir(parents=True, exist_ok=True)
    fast_test = tmp_path / "angr_platforms" / "tests" / "test_manifest_fast_contract.py"
    fast_test.parent.mkdir(parents=True, exist_ok=True)
    fast_test.write_text(
        "from __future__ import annotations\n\n"
        "import pytest\n\n"
        "def test_fast_contract():\n"
        "    pytest.skip('optional local fixture')\n",
        encoding="utf-8",
    )
    (scripts / "test_ownership_manifest.py").write_text(
        "\n".join(
            (
                '"""Focused ownership manifest."""',
                "from __future__ import annotations",
                _fast_skip_policy_source(),
                "TestOwnershipRule(",
                '    owner="sample-fast-rule",',
                '    paths=("sample.py",),',
                '    tests=("angr_platforms/tests/test_manifest_fast_contract.py",),',
                ")",
            )
        ),
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "ownership-manifest-fast-skip-xfail" and "test_manifest_fast_contract.py" in item.path
        for item in violations
    )


def test_architecture_check_rejects_duplicate_ownership_manifest_owner(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    scripts = tmp_path / "tools" / "dev"
    scripts.mkdir(parents=True, exist_ok=True)
    (scripts / "test_ownership_manifest.py").write_text(
        "\n".join(
            (
                '"""Focused ownership manifest."""',
                "from __future__ import annotations",
                _fast_skip_policy_source(),
                "TestOwnershipRule(",
                '    owner="tail-validation-family",',
                '    paths=("inertia/validation/tail_validation_fingerprint.py",),',
                '    tests=("tests/validation/test_x86_16_tail_validation.py",),',
                ")",
                "TestOwnershipRule(",
                '    owner="tail-validation-family",',
                '    paths=("angr_platforms/angr_platforms/X86_16/tail_validation_runtime.py",),',
                '    tests=("angr_platforms/tests/test_x86_16_tail_validation_runtime.py",),',
                ")",
            )
        ),
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "ownership-manifest-duplicate-owner" and "tail-validation-family" in item.detail
        for item in violations
    )


def test_architecture_check_requires_architecture_guard_ownership_rule(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    scripts = tmp_path / "tools" / "dev"
    scripts.mkdir(parents=True, exist_ok=True)
    (scripts / "test_ownership_manifest.py").write_text(
        "\n".join(
            (
                '"""Focused ownership manifest."""',
                "TestOwnershipRule(",
                '    owner="architecture-guard",',
                "    paths=(",
                '        "decompile.py",',
                '        "inertia/cli/cli.py",',
                '        "inertia/cli/cli_core.py",',
                '        "tools/dev/decompile_cod_dir.py",',
                '        "tools/dev/check_decompiler_architecture.py",',
                "    ),",
                '    tests=("tools/dev/tests/test_decompiler_architecture_check.py",),',
                ")",
                "TestOwnershipRule(",
                '    owner="tail-validation-family",',
                '    paths=("inertia/validation/tail_validation_fingerprint.py",),',
                '    tests=("tests/validation/test_x86_16_tail_validation.py",),',
                ")",
            )
        ),
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "ownership-manifest-required-rule"
        and "inertia/cli/architecture_runtime_guard.py" in item.detail
        for item in violations
    )


def test_architecture_check_requires_promoted_fast_test_ownership_rules(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    scripts = tmp_path / "tools" / "dev"
    scripts.mkdir(parents=True, exist_ok=True)
    (scripts / "test_ownership_manifest.py").write_text(
        "\n".join(
            (
                '"""Focused ownership manifest."""',
                "TestOwnershipRule(",
                '    owner="architecture-guard",',
                "    paths=(",
                '        "decompile.py",',
                '        "inertia/cli/architecture_runtime_guard.py",',
                '        "inertia/cli/cli.py",',
                '        "inertia/cli/cli_core.py",',
                '        "tools/dev/decompile_cod_dir.py",',
                '        "tools/dev/check_decompiler_architecture.py",',
                "    ),",
                '    tests=("tools/dev/tests/test_decompiler_architecture_check.py",),',
                ")",
                "TestOwnershipRule(",
                '    owner="tail-validation-family",',
                '    paths=("inertia/validation/tail_validation_fingerprint.py",),',
                '    tests=("tests/validation/test_x86_16_tail_validation.py",),',
                ")",
            )
        ),
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "ownership-manifest-required-rule" and "x86-16-widening-copyprop" in item.detail
        for item in violations
    )


def test_architecture_check_requires_final_emission_ownership_rules(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    scripts = tmp_path / "tools" / "dev"
    scripts.mkdir(parents=True, exist_ok=True)
    (scripts / "test_ownership_manifest.py").write_text(
        "\n".join(
            (
                '"""Focused ownership manifest."""',
                "TestOwnershipRule(",
                '    owner="pipeline-architecture-final-emission-guard",',
                '    paths=("inertia/pipeline/contracts.py",),',
                '    tests=("tests/integration/test_x86_16_pipeline_contracts.py",),',
                ")",
                "TestOwnershipRule(",
                '    owner="x86-16-validation-semantics",',
                '    paths=("inertia/validation/canonicalize.py",),',
                '    tests=("tests/validation/test_x86_16_validation_canonicalize.py",),',
                ")",
            )
        ),
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "ownership-manifest-required-rule"
        and "pipeline-architecture-final-emission-guard" in item.detail
        and "pipeline/architecture_guard.py" in item.detail
        for item in violations
    )
    assert any(
        item.rule == "ownership-manifest-required-rule"
        and "x86-16-validation-semantics" in item.detail
        and "validation_semantics.py" in item.detail
        for item in violations
    )
    assert any(
        item.rule == "ownership-manifest-required-test"
        and "pipeline-architecture-final-emission-guard" in item.detail
        and "test_architecture_guard_rejects_raw_linear_segment_arithmetic" in item.detail
        for item in violations
    )
    assert any(
        item.rule == "ownership-manifest-required-test"
        and "x86-16-validation-semantics" in item.detail
        and "tests/validation/test_x86_16_validation_semantics.py" in item.detail
        for item in violations
    )


def test_architecture_check_rejects_check_files_without_context_guards(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    (tmp_path / "Makefile").write_text(
        "\n".join(
            (
                "check-files: linters-files architecture-check pytest-files",
                "\t$(PYTHON) tools/dev/check_changed_non_test_types.py $(TYPE_RATCHET_SELECTED_FILES)",
                "QA_CHANGED_TYPED_FILES := $(filter $(QA_TYPED_FILES),$(PY_CHANGED_FILES))",
                "quality-fast: linters type-ratchet-changed decompiler-check-fast",
                "type-ratchet-changed:",
                "\t$(PYTHON) tools/dev/check_changed_non_test_types.py $(QA_CHANGED_TYPED_FILES)",
                "decompiler-check: architecture-check agent-context-check test-ownership-check pytest test-pipeline",
                "decompiler-check-fast: architecture-check-fast agent-context-check test-ownership-check component-catalog-check test-pipeline-fast",
                "decompiler-check-expanded: architecture-check agent-context-check test-ownership-check pytest test-pipeline-expanded",
                "test-pipeline-fast:",
                "\t$(PYTHON) tools/dev/test_pipeline.py --tier fast --require-external",
                "test-pipeline-expanded:",
                "\t$(PYTHON) tools/dev/test_pipeline.py --tier expanded --require-external",
            )
        ),
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "makefile-gate-marker"
        and "agent-context-check test-ownership-check" in item.detail
        for item in violations
    )


def test_architecture_check_requires_agent_rules_defer_to_agents_md(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    (tmp_path / "reference" / "agent-rules.md").write_text(
        "Mission\n\nIR -> Alias -> Widening -> Types -> Structuring -> Rewrite\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "agent-rules-canonical-contract" for item in violations)


def test_architecture_check_rejects_duplicate_agent_rules_rulebook(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    agent_rules = tmp_path / "reference" / "agent-rules.md"
    agent_rules.write_text(
        f"{agent_rules.read_text(encoding='utf-8')}\n## Hard Rules\n1. Alias-first.\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "agent-rules-duplicate-rulebook" for item in violations)


def test_architecture_check_rejects_oversized_agent_rules(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    agent_rules = tmp_path / "reference" / "agent-rules.md"
    current_lines = len(agent_rules.read_text(encoding="utf-8").splitlines())
    filler_count = arch_check._AGENT_RULES_MAX_LINES - current_lines + 1
    filler = "\n".join(f"extra supplemental detail {index}" for index in range(filler_count))
    agent_rules.write_text(f"{agent_rules.read_text(encoding='utf-8')}\n{filler}\n", encoding="utf-8")

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "agent-rules-too-large" for item in violations)


def test_architecture_check_rejects_agent_rules_function_fix_rulebook(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    agent_rules = tmp_path / "reference" / "agent-rules.md"
    agent_rules.write_text(
        f"{agent_rules.read_text(encoding='utf-8')}\n"
        "### Function-fix acceptance contract\n"
        "- validation=passed\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "agent-rules-duplicate-rulebook"
        and "Function-fix acceptance contract" in item.detail
        for item in violations
    )


def test_architecture_check_rejects_agent_rules_improving_code_rulebook(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    agent_rules = tmp_path / "reference" / "agent-rules.md"
    agent_rules.write_text(
        f"{agent_rules.read_text(encoding='utf-8')}\n"
        "## Improving code\n"
        "Run quality-fast regularly.\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "agent-rules-duplicate-rulebook" and "## Improving code" in item.detail
        for item in violations
    )


def test_architecture_check_rejects_agent_rules_reference_files_rulebook(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    agent_rules = tmp_path / "reference" / "agent-rules.md"
    agent_rules.write_text(
        f"{agent_rules.read_text(encoding='utf-8')}\n"
        "## Reference files\n"
        "Read project-map before editing.\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "agent-rules-duplicate-rulebook" and "## Reference files" in item.detail
        for item in violations
    )


def test_architecture_check_rejects_agent_rules_persistent_startup_rulebook(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    agent_rules = tmp_path / "reference" / "agent-rules.md"
    agent_rules.write_text(
        f"{agent_rules.read_text(encoding='utf-8')}\n"
        "### Persistent startup contract\n"
        "- Unknown classification means refuse.\n",
        encoding="utf-8",
    )

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "agent-rules-duplicate-rulebook"
        and "Persistent startup contract" in item.detail
        for item in violations
    )


def test_agent_rules_forbidden_markers_cover_reference_rulebook_markers():
    assert set(arch_check._REFERENCE_MAP_FORBIDDEN_RULEBOOK_MARKERS).issubset(
        set(arch_check._AGENT_RULES_FORBIDDEN_MARKERS)
    )


def test_architecture_check_rejects_obsolete_source_backed_status_wording(tmp_path):
    status_script = tmp_path / "tools" / "dev" / "sortdemo_decompiler_status.py"
    status_script.parent.mkdir(parents=True)
    status_script.write_text(
        "from __future__ import annotations\n"
        "def classify(line: str) -> bool:\n"
        "    return 'source-backed quality guard rejected' in line\n",
        encoding="utf-8",
    )

    violations = arch_check._check_status_reporting_not_source_backed(status_script)

    assert any(item.rule == "status-reporting-source-backed-quality" for item in violations)


def test_architecture_check_rejects_sortdemo_status_without_typed_enums(tmp_path):
    status_script = tmp_path / "tools" / "dev" / "sortdemo_decompiler_status.py"
    status_script.parent.mkdir(parents=True)
    status_script.write_text(
        "from __future__ import annotations\n"
        "from dataclasses import dataclass\n\n"
        "@dataclass\n"
        "class FunctionStatus:\n"
        "    failure_status: str | None = None\n"
        "    attempt: str | None = None\n"
        "    validation: str | None = None\n"
        "    def terminal_status(self) -> str:\n"
        "        return 'timeout'\n\n"
        "def _build_triage(records: list[FunctionStatus]) -> dict[str, list[dict[str, object]]]:\n"
        "    return {}\n",
        encoding="utf-8",
    )

    violations = arch_check._check_sortdemo_status_reporting_typed_state(status_script)

    assert any(
        item.rule == "sortdemo-status-typed-state" and "TerminalStatus" in item.detail for item in violations
    )
    assert any(
        item.rule == "sortdemo-status-typed-state" and "FunctionStatus.failure_status" in item.detail
        for item in violations
    )


def test_architecture_check_rejects_sortdemo_triage_from_serialized_dicts(tmp_path):
    status_script = tmp_path / "tools" / "dev" / "sortdemo_decompiler_status.py"
    status_script.parent.mkdir(parents=True)
    status_script.write_text(
        "from __future__ import annotations\n"
        "from dataclasses import dataclass\n"
        "from enum import StrEnum\n\n"
        "class TerminalStatus(StrEnum):\n"
        "    TIMEOUT = 'timeout'\n\n"
        "class FailureStatus(StrEnum):\n"
        "    TIMEOUT = 'timeout'\n\n"
        "class ValidationStatus(StrEnum):\n"
        "    FAILED = 'failed'\n\n"
        "class AttemptStatus(StrEnum):\n"
        "    ERROR = 'error'\n\n"
        "@dataclass\n"
        "class FunctionStatus:\n"
        "    failure_status: FailureStatus | None = None\n"
        "    attempt: AttemptStatus | None = None\n"
        "    validation: ValidationStatus | None = None\n"
        "    def terminal_status(self) -> TerminalStatus:\n"
        "        return TerminalStatus.TIMEOUT\n\n"
        "def _build_triage(functions: list[dict[str, object]]) -> dict[str, list[dict[str, object]]]:\n"
        "    return {}\n",
        encoding="utf-8",
    )

    violations = arch_check._check_sortdemo_status_reporting_typed_state(status_script)

    assert any(
        item.rule == "sortdemo-status-typed-state" and "_build_triage()" in item.detail for item in violations
    )


def test_architecture_check_rejects_source_backed_quality_helper_name(tmp_path):
    quality = tmp_path / "inertia" / "cli" / "decompilation_quality.py"
    quality.parent.mkdir(parents=True)
    quality.write_text(
        "from __future__ import annotations\n"
        "def assess_source_backed_c_text(rendered_text: str) -> object:\n"
        "    return None\n",
        encoding="utf-8",
    )

    violations = arch_check._check_decompilation_quality_not_source_backed_named(quality)

    assert any(item.rule == "decompilation-quality-source-backed-name" for item in violations)


def test_architecture_check_rejects_understand_auto_update(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    (tmp_path / ".understand-anything" / "config.json").write_text('{"autoUpdate": true}\n', encoding="utf-8")

    violations = arch_check.check_decompiler_architecture(root, cli, tmp_path)

    assert any(item.rule == "understand-auto-update" for item in violations)


def test_runtime_architecture_guard_formats_clear_startup_error():
    violation = arch_check.ArchitectureViolation(
        path="angr_platforms/angr_platforms/X86_16/decompiler_postprocess_new.py",
        rule="postprocess-protected-import",
        detail="'.semantics.condition_recovery' is not admitted",
    )

    message = architecture_runtime_guard.format_decompiler_architecture_guard_error((violation,))

    assert "Decompiler architecture guard failed." in message
    assert "before decompiler startup" in message
    assert "make architecture-check" in message
    assert "postprocess-protected-import" in message


def test_runtime_architecture_guard_raises_before_startup(monkeypatch):
    violation = arch_check.ArchitectureViolation(
        path="inertia/cli/cli_decompilation.py",
        rule="cli-x86-16-import",
        detail="bad import",
    )
    monkeypatch.setattr(
        architecture_runtime_guard,
        "_runtime_import_violations",
        lambda _root, _cli: (violation,),
    )

    with pytest.raises(architecture_runtime_guard.DecompilerArchitectureGuardError, match="cli-x86-16-import"):
        architecture_runtime_guard.assert_decompiler_architecture_clean()


def test_runtime_architecture_guard_accepts_current_parent_attestation(monkeypatch):
    monkeypatch.setenv(
        architecture_runtime_guard.ARCHITECTURE_GUARD_VERIFIED_PARENT_PID_ENV,
        str(os.getppid()),
    )

    def fail_if_scanned():
        raise AssertionError("verified serial child must not repeat the static scan")

    monkeypatch.setattr(
        architecture_runtime_guard,
        "_runtime_import_violations",
        lambda _root, _cli: fail_if_scanned(),
    )

    architecture_runtime_guard.assert_decompiler_architecture_clean()


def test_runtime_architecture_guard_reuses_current_process_attestation(monkeypatch):
    monkeypatch.setattr(
        architecture_runtime_guard,
        "_ARCHITECTURE_GUARD_VERIFIED_PROCESS_PID",
        None,
    )
    monkeypatch.setattr(
        architecture_runtime_guard,
        "_architecture_guard_source_fingerprint",
        lambda _root, _cli: "current-source",
    )
    monkeypatch.setattr(
        architecture_runtime_guard,
        "_architecture_guard_cache_is_clean",
        lambda _fingerprint: True,
    )
    architecture_runtime_guard.assert_decompiler_architecture_clean()
    monkeypatch.setattr(
        architecture_runtime_guard,
        "_architecture_guard_source_fingerprint",
        lambda _root, _cli: pytest.fail("same process must reuse its attestation"),
    )

    architecture_runtime_guard.assert_decompiler_architecture_clean()


def test_runtime_architecture_guard_does_not_reuse_forked_process_attestation(monkeypatch):
    monkeypatch.setattr(
        architecture_runtime_guard,
        "_ARCHITECTURE_GUARD_VERIFIED_PROCESS_PID",
        os.getpid() - 1,
    )
    fingerprinted = False

    def fingerprint(_root, _cli):
        nonlocal fingerprinted
        fingerprinted = True
        return "current-source"

    monkeypatch.setattr(
        architecture_runtime_guard,
        "_architecture_guard_source_fingerprint",
        fingerprint,
    )
    monkeypatch.setattr(
        architecture_runtime_guard,
        "_architecture_guard_cache_is_clean",
        lambda _fingerprint: True,
    )

    architecture_runtime_guard.assert_decompiler_architecture_clean()

    assert fingerprinted is True


def test_runtime_architecture_guard_rejects_stale_parent_attestation(monkeypatch):
    violation = arch_check.ArchitectureViolation(
        path="inertia/cli/cli_decompilation.py",
        rule="cli-x86-16-import",
        detail="bad import",
    )
    monkeypatch.setenv(
        architecture_runtime_guard.ARCHITECTURE_GUARD_VERIFIED_PARENT_PID_ENV,
        str(os.getppid() + 1),
    )
    monkeypatch.setattr(
        architecture_runtime_guard,
        "_runtime_import_violations",
        lambda _root, _cli: (violation,),
    )

    with pytest.raises(architecture_runtime_guard.DecompilerArchitectureGuardError, match="cli-x86-16-import"):
        architecture_runtime_guard.assert_decompiler_architecture_clean()


def test_runtime_import_guard_rejects_wrong_layer_postprocess_import(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    postprocess = root / "decompiler_postprocess_jcc.py"
    postprocess.write_text(
        '"""Guarded compatibility bridge.\n\n'
        "Allowed work: cleanup only.\n"
        "Forbidden work: semantic recovery.\n"
        "Owning layer: Structuring.\n"
        '"""\n'
        "from inertia.semantics.condition_recovery import recover\n",
        encoding="utf-8",
    )

    violations = architecture_runtime_guard._runtime_import_violations(root, cli)

    assert any(item.rule == "postprocess-protected-import" for item in violations)


def test_runtime_import_guard_fingerprint_tracks_source_bytes(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    before = architecture_runtime_guard._architecture_guard_source_fingerprint(
        root,
        cli,
    )
    (root / "new_rule.py").write_text(
        "from __future__ import annotations\n",
        encoding="utf-8",
    )

    after = architecture_runtime_guard._architecture_guard_source_fingerprint(
        root,
        cli,
    )

    assert after != before


def test_startup_architecture_guard_reuses_cached_failure(
    tmp_path,
    monkeypatch,
):
    violation = arch_check.ArchitectureViolation(
        path="bad.py",
        rule="wrong-layer",
        detail="semantic recovery crossed the rewrite boundary",
    )
    cache = tmp_path / "startup.json"
    monkeypatch.setattr(architecture_runtime_guard, "_ARCHITECTURE_STARTUP_CACHE_PATH", cache)
    monkeypatch.setattr(
        architecture_runtime_guard.architecture_import_attestation,
        "architecture_startup_source_fingerprint",
        lambda _root, _repo_root: "source-v1",
    )
    architecture_runtime_guard.architecture_import_attestation.store_startup_architecture_verdict(
        cache,
        "source-v1",
        (violation,),
    )
    monkeypatch.setattr(
        arch_check,
        "check_decompiler_startup_architecture",
        lambda *_args, **_kwargs: pytest.fail("cached failure must not be re-evaluated"),
    )

    assert architecture_runtime_guard.cached_decompiler_startup_architecture_violations() == (violation,)


def test_startup_architecture_guard_stores_complete_verdict(tmp_path, monkeypatch):
    cache = tmp_path / "startup.json"
    monkeypatch.setattr(architecture_runtime_guard, "_ARCHITECTURE_STARTUP_CACHE_PATH", cache)
    monkeypatch.setattr(
        architecture_runtime_guard.architecture_import_attestation,
        "architecture_startup_source_fingerprint",
        lambda _root, _repo_root: "source-v1",
    )
    monkeypatch.setattr(
        architecture_runtime_guard,
        "cached_decompiler_architecture_import_violations",
        lambda: (),
    )
    calls = 0

    def evaluate(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        return ()

    monkeypatch.setattr(arch_check, "check_decompiler_startup_architecture", evaluate)

    assert architecture_runtime_guard.cached_decompiler_startup_architecture_violations() == ()
    assert architecture_runtime_guard.cached_decompiler_startup_architecture_violations() == ()
    assert calls == 1


def test_startup_architecture_guard_refuses_concurrent_source_change(
    tmp_path,
    monkeypatch,
):
    cache = tmp_path / "startup.json"
    fingerprints = iter(("source-before", "source-after"))
    monkeypatch.setattr(architecture_runtime_guard, "_ARCHITECTURE_STARTUP_CACHE_PATH", cache)
    monkeypatch.setattr(
        architecture_runtime_guard.architecture_import_attestation,
        "architecture_startup_source_fingerprint",
        lambda _root, _repo_root: next(fingerprints),
    )
    monkeypatch.setattr(
        architecture_runtime_guard,
        "cached_decompiler_architecture_import_violations",
        lambda: (),
    )
    monkeypatch.setattr(arch_check, "check_decompiler_startup_architecture", lambda *_args, **_kwargs: ())

    violations = architecture_runtime_guard.cached_decompiler_startup_architecture_violations()

    assert tuple(item.rule for item in violations) == ("startup-architecture-source-race",)
    assert not cache.exists()


def test_startup_architecture_check_excludes_docs_types_ratchet(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    promoted = tmp_path / "monkeytype_config.py"
    promoted.write_text("from __future__ import annotations\nPUBLIC_VALUE = 1\n", encoding="utf-8")
    makefile = tmp_path / "Makefile"
    makefile.write_text("QA_TYPED_FILES := monkeytype_config.py\n", encoding="utf-8")

    full = arch_check.check_decompiler_architecture(root, cli, tmp_path)
    startup = arch_check.check_decompiler_startup_architecture(root, cli, tmp_path)

    assert any(item.rule == "promoted-typed-public-assignment-annotation" for item in full)
    assert not any(item.rule == "promoted-typed-public-assignment-annotation" for item in startup)


def test_startup_architecture_check_rejects_postprocess_source_text_recovery(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    (root / "decompiler_postprocess_source_text.py").write_text(
        '"""Source text bridge.\n\n'
        "Allowed work: report-only compatibility diagnostics.\n"
        "Forbidden work: semantic recovery from source text.\n"
        "Owning layer: CLI/reporting only.\n"
        '"""\n'
        "from __future__ import annotations\n"
        "def recover(metadata):\n"
        "    return tuple(metadata.source_lines)\n",
        encoding="utf-8",
    )

    startup = arch_check.check_decompiler_startup_architecture(root, cli, tmp_path)

    assert any(item.rule == "postprocess-source-text-recovery" for item in startup)


def test_startup_architecture_check_rejects_duplicate_architecture_table_keys(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    scripts = tmp_path / "tools" / "dev"
    scripts.mkdir(parents=True, exist_ok=True)
    (scripts / "check_decompiler_architecture.py").write_text(
        '"""Static architecture guard.\n\n'
        "Layer: Tooling/gates.\n"
        "Responsibility: enforce architecture.\n"
        '"""\n'
        "from __future__ import annotations\n\n"
        "_POSTPROCESS_LEGACY_IMPORT_ALLOWLIST = {\n"
        '    "decompiler_postprocess_calls.py": frozenset({".cod_extract"}),\n'
        '    "decompiler_postprocess_calls.py": frozenset({".lowering.real_mode_linear"}),\n'
        "}\n",
        encoding="utf-8",
    )

    startup = arch_check.check_decompiler_startup_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "architecture-table-duplicate-key"
        and item.path == "tools/dev/check_decompiler_architecture.py"
        for item in startup
    )


def test_startup_architecture_check_rejects_weak_header_marker_contract(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    scripts = tmp_path / "tools" / "dev"
    scripts.mkdir(parents=True, exist_ok=True)
    (scripts / "check_decompiler_architecture.py").write_text(
        '"""Static architecture guard.\n\n'
        "Layer: Tooling/gates.\n"
        "Responsibility: enforce architecture.\n"
        '"""\n'
        "from __future__ import annotations\n\n"
        "_HELPER_BOUNDARY_HEADER_MARKERS = {\n"
        '    "addressing_helpers.py": ("Layer: Helper boundary", "Responsibility: decode addresses"),\n'
        "}\n",
        encoding="utf-8",
    )

    startup = arch_check.check_decompiler_startup_architecture(root, cli, tmp_path)

    assert any(
        item.rule == "architecture-header-marker-contract"
        and item.path == "tools/dev/check_decompiler_architecture.py"
        for item in startup
    )


def test_decompile_entrypoints_stop_on_wrong_layer_import(tmp_path):
    root, cli = _write_minimal_tree(tmp_path)
    _write_project_awareness_docs(tmp_path)
    target = root / "decompiler_postprocess_bad_guard.py"
    target.write_text(
        '"""Bad postprocess bridge.\n\nDo not add new recovery logic here.\n"""\n'
        "from __future__ import annotations\n"
        "from inertia.semantics.condition_recovery import build_typed_condition_from_cmp_pair_8616\n",
        encoding="utf-8",
    )
    env = {
        **os.environ,
        "INERTIA_ARCH_GUARD_X86_16_ROOT": str(root),
        "INERTIA_ARCH_GUARD_CLI": str(cli),
        "INERTIA_ARCH_GUARD_REPO_ROOT": str(tmp_path),
    }
    commands = (
        [sys.executable, "decompile.py", str(tmp_path / "missing.exe"), "--timeout", "1"],
        [sys.executable, "-m", "inertia.cli.cli", str(tmp_path / "missing.exe"), "--timeout", "1"],
        [sys.executable, "tools/dev/decompile_cod_dir.py", str(tmp_path / "missing-cod-dir"), "--timeout", "1"],
    )
    results = [
        subprocess.run(command, check=False, capture_output=True, text=True, timeout=30, env=env)
        for command in commands
    ]

    for result in results:
        assert result.returncode == 3
        assert "Decompiler architecture guard failed." in result.stderr
        assert "postprocess-protected-import" in result.stderr
        assert "missing.exe" not in result.stderr


def test_cli_core_main_rejects_architecture_violations(monkeypatch):
    violation = arch_check.ArchitectureViolation(
        path="angr_platforms/angr_platforms/X86_16/decompiler_postprocess_new.py",
        rule="postprocess-protected-import",
        detail=".semantics.condition_recovery is not admitted",
    )

    def _boom() -> None:
        raise architecture_runtime_guard.DecompilerArchitectureGuardError(
            architecture_runtime_guard.format_decompiler_architecture_guard_error((violation,))
        )

    monkeypatch.setattr(cli_core, "assert_decompiler_architecture_clean", _boom)
    monkeypatch.setattr(cli_core, "_ARCHITECTURE_GUARD_STATUS_8616", None)

    exit_code = cli_core.main(["--help"])

    assert exit_code == 3


def test_cli_main_proxy_patch_does_not_replace_owner(monkeypatch):
    """Compatibility monkeypatches must not turn the owner entrypoint recursive."""
    owner_main = cli_core.main

    def fake_main(_argv=None):
        return 17

    monkeypatch.setattr(cli, "main", fake_main)

    assert cli.main is fake_main
    assert cli_core.main is owner_main


def test_architecture_check_requires_decompile_entrypoint_runtime_guard(tmp_path):
    (tmp_path / "decompile.py").write_text(
        '"""Entrypoint."""\n'
        "from __future__ import annotations\n"
        "from inertia_decompiler import cli as _cli\n"
        "raise SystemExit(_cli.main())\n",
        encoding="utf-8",
    )
    cli_module = tmp_path / "inertia" / "cli" / "cli.py"
    cli_module.parent.mkdir(parents=True)
    cli_module.write_text(
        '"""CLI entrypoint."""\n'
        "from __future__ import annotations\n"
        "assert_decompiler_architecture_clean()\n",
        encoding="utf-8",
    )
    (tmp_path / "inertia" / "cli" / "cli_core.py").write_text(
        '"""CLI core."""\n'
        "from __future__ import annotations\n"
        "def main(argv: list[str] | None = None) -> int:\n"
        "    _ensure_runtime_architecture_guard_8616()\n"
        "    return 0\n",
        encoding="utf-8",
    )
    scripts = tmp_path / "tools" / "dev"
    scripts.mkdir(parents=True)
    (scripts / "decompile_cod_dir.py").write_text(
        '"""Batch decompiler."""\n'
        "from __future__ import annotations\n"
        "def main() -> int:\n"
        "    return 0\n",
        encoding="utf-8",
    )

    violations = arch_check._check_runtime_architecture_guard_entrypoints(tmp_path)

    assert any(
        item.rule == "runtime-architecture-guard-entrypoint" and item.path == "decompile.py"
        for item in violations
    )
    assert any(
        item.rule == "runtime-architecture-guard-entrypoint" and item.path == "tools/dev/decompile_cod_dir.py"
        for item in violations
    )


def test_architecture_check_requires_cli_core_main_runtime_guard(tmp_path):
    (tmp_path / "decompile.py").write_text(
        '"""Entrypoint."""\n'
        "from __future__ import annotations\n"
        "assert_decompiler_architecture_clean()\n",
        encoding="utf-8",
    )
    cli_module = tmp_path / "inertia" / "cli" / "cli.py"
    cli_module.parent.mkdir(parents=True)
    cli_module.write_text(
        '"""CLI entrypoint."""\n'
        "from __future__ import annotations\n"
        "assert_decompiler_architecture_clean()\n",
        encoding="utf-8",
    )
    (tmp_path / "inertia" / "cli" / "cli_core.py").write_text(
        '"""CLI core."""\n'
        "from __future__ import annotations\n"
        "def main(argv: list[str] | None = None) -> int:\n"
        "    return 0\n",
        encoding="utf-8",
    )

    violations = arch_check._check_runtime_architecture_guard_entrypoints(tmp_path)

    assert any(
        item.rule == "runtime-architecture-guard-entrypoint" and item.path == "inertia/cli/cli_core.py"
        for item in violations
    )


def test_architecture_check_requires_entrypoint_guard_before_decompiler_imports(tmp_path):
    (tmp_path / "decompile.py").write_text(
        '"""Entrypoint."""\n'
        "from __future__ import annotations\n"
        "from inertia_decompiler import cli as _cli\n"
        "assert_decompiler_architecture_clean()\n",
        encoding="utf-8",
    )
    cli_module = tmp_path / "inertia" / "cli" / "cli.py"
    cli_module.parent.mkdir(parents=True)
    cli_module.write_text(
        '"""CLI entrypoint."""\n'
        "from __future__ import annotations\n"
        "assert_decompiler_architecture_clean()\n",
        encoding="utf-8",
    )

    violations = arch_check._check_runtime_architecture_guard_entrypoints(tmp_path)

    assert any(
        item.rule == "runtime-architecture-guard-order" and item.path == "decompile.py"
        for item in violations
    )


def test_architecture_check_allows_try_wrapped_module_level_entrypoint_guard(tmp_path):
    (tmp_path / "decompile.py").write_text(
        '"""Entrypoint."""\n'
        "from __future__ import annotations\n"
        "try:\n"
        "    assert_decompiler_architecture_clean()\n"
        "except Exception:\n"
        "    raise\n"
        "from inertia_decompiler import cli as _cli\n",
        encoding="utf-8",
    )
    cli_module = tmp_path / "inertia" / "cli" / "cli.py"
    cli_module.parent.mkdir(parents=True)
    cli_module.write_text(
        '"""CLI entrypoint."""\n'
        "from __future__ import annotations\n"
        "try:\n"
        "    assert_decompiler_architecture_clean()\n"
        "except Exception:\n"
        "    raise\n",
        encoding="utf-8",
    )

    violations = arch_check._check_runtime_architecture_guard_entrypoints(tmp_path)

    assert not any(
        item.rule.startswith("runtime-architecture-guard") and item.path in {"decompile.py", "inertia/cli/cli.py"}
        for item in violations
    )


def test_architecture_check_rejects_swallowed_module_level_entrypoint_guard(tmp_path):
    (tmp_path / "decompile.py").write_text(
        '"""Entrypoint."""\n'
        "from __future__ import annotations\n"
        "try:\n"
        "    assert_decompiler_architecture_clean()\n"
        "except Exception:\n"
        "    pass\n"
        "from inertia_decompiler import cli as _cli\n",
        encoding="utf-8",
    )
    cli_module = tmp_path / "inertia" / "cli" / "cli.py"
    cli_module.parent.mkdir(parents=True)
    cli_module.write_text(
        '"""CLI entrypoint."""\n'
        "from __future__ import annotations\n"
        "try:\n"
        "    assert_decompiler_architecture_clean()\n"
        "except Exception:\n"
        "    print('continuing')\n",
        encoding="utf-8",
    )

    violations = arch_check._check_runtime_architecture_guard_entrypoints(tmp_path)

    assert any(
        item.rule == "runtime-architecture-guard-swallowed" and item.path == "decompile.py"
        for item in violations
    )
    assert any(
        item.rule == "runtime-architecture-guard-swallowed" and item.path == "inertia/cli/cli.py"
        for item in violations
    )


def test_architecture_check_rejects_entrypoint_guard_hidden_in_dead_helper(tmp_path):
    (tmp_path / "decompile.py").write_text(
        '"""Entrypoint."""\n'
        "from __future__ import annotations\n"
        "def _dead_guard() -> None:\n"
        "    assert_decompiler_architecture_clean()\n"
        "from inertia_decompiler import cli as _cli\n",
        encoding="utf-8",
    )
    cli_module = tmp_path / "inertia" / "cli" / "cli.py"
    cli_module.parent.mkdir(parents=True)
    cli_module.write_text(
        '"""CLI entrypoint."""\n'
        "from __future__ import annotations\n"
        "def _dead_guard() -> None:\n"
        "    assert_decompiler_architecture_clean()\n",
        encoding="utf-8",
    )

    violations = arch_check._check_runtime_architecture_guard_entrypoints(tmp_path)

    assert any(
        item.rule == "runtime-architecture-guard-entrypoint" and item.path == "decompile.py"
        for item in violations
    )
    assert any(
        item.rule == "runtime-architecture-guard-entrypoint" and item.path == "inertia/cli/cli.py"
        for item in violations
    )


def test_architecture_check_requires_cli_core_guard_before_parser_work(tmp_path):
    (tmp_path / "decompile.py").write_text(
        '"""Entrypoint."""\n'
        "from __future__ import annotations\n"
        "assert_decompiler_architecture_clean()\n",
        encoding="utf-8",
    )
    cli_module = tmp_path / "inertia" / "cli" / "cli.py"
    cli_module.parent.mkdir(parents=True)
    cli_module.write_text(
        '"""CLI entrypoint."""\n'
        "from __future__ import annotations\n"
        "assert_decompiler_architecture_clean()\n",
        encoding="utf-8",
    )
    (tmp_path / "inertia" / "cli" / "cli_core.py").write_text(
        '"""CLI core."""\n'
        "from __future__ import annotations\n"
        "def main(argv: list[str] | None = None) -> int:\n"
        "    def _impl() -> int:\n"
        "        parser = _build_cli_argument_parser()\n"
        "        _ensure_runtime_architecture_guard_8616()\n"
        "        return 0\n"
        "    return _impl()\n",
        encoding="utf-8",
    )

    violations = arch_check._check_runtime_architecture_guard_entrypoints(tmp_path)

    assert any(
        item.rule == "runtime-architecture-guard-order" and item.path == "inertia/cli/cli_core.py"
        for item in violations
    )


def test_architecture_check_requires_cod_dir_guard_before_batch_work(tmp_path):
    scripts = tmp_path / "tools" / "dev"
    scripts.mkdir(parents=True)
    (scripts / "decompile_cod_dir.py").write_text(
        '"""Batch decompiler."""\n'
        "from __future__ import annotations\n"
        "def main() -> int:\n"
        "    parser = argparse.ArgumentParser()\n"
        "    guard_exit = _run_runtime_architecture_guard()\n"
        "    return guard_exit\n",
        encoding="utf-8",
    )

    violations = arch_check._check_runtime_architecture_guard_entrypoints(tmp_path)

    assert any(
        item.rule == "runtime-architecture-guard-order" and item.path == "tools/dev/decompile_cod_dir.py"
        for item in violations
    )
