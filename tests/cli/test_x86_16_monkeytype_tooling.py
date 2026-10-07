from __future__ import annotations

from pathlib import Path

import inertia.cli.monkeytype_tools as monkeytype_tools


def test_monkeytype_code_filter_accepts_repo_python_sources():
    assert monkeytype_tools.is_traceable_repo_path(
        Path("/home/xor/vextest/inertia.cli/cli_access_object_hints.py")
    )
    assert monkeytype_tools.is_traceable_repo_path(
        Path("/home/xor/vextest/inertia/alias/alias_model.py")
    )
    assert monkeytype_tools.is_traceable_repo_path(Path("/home/xor/vextest/decompile.py"))


def test_monkeytype_code_filter_rejects_external_sources():
    assert not monkeytype_tools.is_traceable_repo_path(
        Path("/home/xor/vextest/.venv/lib/python3.14/site-packages/monkeytype/cli.py")
    )
    assert not monkeytype_tools.is_traceable_repo_path(Path("/tmp/random_script.py"))


def test_monkeytype_code_filter_uses_code_filename(monkeypatch):
    monkeypatch.setattr(monkeytype_tools, "default_code_filter", lambda code: True)

    repo_code = compile("value = 1", str(monkeytype_tools.REPO_ROOT / "inertia" / "cli" / "runtime_support.py"), "exec")
    external_code = compile("value = 1", "/tmp/random_script.py", "exec")

    assert monkeytype_tools.monkeytype_code_filter(repo_code)
    assert not monkeytype_tools.monkeytype_code_filter(external_code)


def test_parse_list_modules_output_filters_and_sorts_modules():
    output = "\n".join(
        [
            "pytest",
            "inertia.cli.cli_access_object_hints",
            "inertia.alias.alias_model",
            "decompile",
            "inertia.cli.cli_access_object_hints",
            "other.module",
        ]
    )
    assert monkeytype_tools.parse_list_modules_output(output) == (
        "inertia.alias.alias_model",
        "decompile",
        "inertia.cli.cli_access_object_hints",
    )


def test_stub_path_for_module_uses_monkeytype_stub_cache():
    stub_path = monkeytype_tools.stub_path_for_module("inertia.cli.cli_access_object_hints")
    assert stub_path == monkeytype_tools.MONKEYTYPE_STUBS_DIR / "inertia" / "cli" / "cli_access_object_hints.pyi"


def test_source_path_for_module_maps_both_repo_roots():
    assert monkeytype_tools.source_path_for_module("decompile") == monkeytype_tools.REPO_ROOT / "decompile.py"
    assert monkeytype_tools.source_path_for_module("inertia.cli.runtime_support") == (
        monkeytype_tools.REPO_ROOT / "inertia" / "cli" / "runtime_support.py"
    )
    assert monkeytype_tools.source_path_for_module("inertia.alias.alias_model") == (
        monkeytype_tools.REPO_ROOT / "inertia" / "alias" / "alias_model.py"
    )


def test_default_monkeytype_targets_cover_phase7_tests():
    targets = monkeytype_tools.DEFAULT_MONKEYTYPE_TEST_TARGETS
    assert "tests/integration/test_x86_16_access_trait_policy.py" in targets
    assert "tests/integration/test_x86_16_access_trait_arrays.py" in targets
    assert "tests/alias/test_x86_16_segmented_memory.py" in targets
    assert "tests/validation/test_x86_16_tail_validation.py" in targets
