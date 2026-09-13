from __future__ import annotations

import json
import subprocess
import sys

from _pytest.python import CallSpec2

from scripts import pytest_source_index, pytest_source_structure_cache
from scripts.pytest_call_hints import concrete_function_addresses
from scripts.pytest_source_index import (
    build_pytest_source_index,
    clear_pytest_source_index_cache,
    load_pytest_source_index,
)

SKIP_CALLS = frozenset(("pytest.mark.skip", "pytest.skip", "pytest.xfail"))


def test_parameterized_source_lookup_retains_skip_evidence(tmp_path):
    source = "class TestCases:\n    def test_case(self, value):\n        pytest.skip('unavailable')\n"
    index = build_pytest_source_index(source, tmp_path / "test_sample.py", SKIP_CALLS)
    selector = "TestCases::test_case[value::with-separator]"

    assert index.has_node(selector)
    assert index.skip_xfail_lines(selector) == index.skip_xfail_lines("TestCases::test_case")
    assert index.skip_xfail_lines(selector)
    assert index.facts(selector) == index.facts("TestCases::test_case")
    assert not index.has_node("TestCases::test_missing[value]")


class _ParameterizedItem:
    pass


def test_static_call_hint_import_does_not_load_pytest():
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; import scripts.pytest_call_hints; "
            "raise SystemExit('pytest' in sys.modules or '_pytest.python' in sys.modules)",
        ],
        check=False,
    )

    assert result.returncode == 0


def test_source_index_reuses_unchanged_content_and_invalidates_mutation(tmp_path):
    test_path = tmp_path / "test_sample.py"
    test_path.write_text("def test_case():\n    return None\n", encoding="utf-8")
    clear_pytest_source_index_cache()

    first = load_pytest_source_index(test_path, SKIP_CALLS)
    second = load_pytest_source_index(test_path, SKIP_CALLS)
    test_path.write_text("def test_other():\n    return None\n", encoding="utf-8")
    third = load_pytest_source_index(test_path, SKIP_CALLS)

    assert second is first
    assert third is not first
    assert third.has_node("test_other")
    assert not third.has_node("test_case")


def test_loaded_source_index_defers_full_facts_until_requested(tmp_path, monkeypatch):
    test_path = tmp_path / "test_sample.py"
    test_path.write_text("def test_case():\n    assert result.returncode == 0\n", encoding="utf-8")
    original_build = pytest_source_index.build_pytest_source_index
    fact_builds = 0

    def recording_build(source, path, skip_calls):
        nonlocal fact_builds
        fact_builds += 1
        return original_build(source, path, skip_calls)

    clear_pytest_source_index_cache()
    monkeypatch.setattr(pytest_source_index, "build_pytest_source_index", recording_build)

    index = load_pytest_source_index(test_path, SKIP_CALLS)
    assert index.has_node("test_case")
    assert index.skip_xfail_lines("test_case") == ()
    assert fact_builds == 0

    first = index.facts("test_case")
    second = index.facts("test_case")

    assert first is second
    assert first.assertion_count == 1
    assert first.evidence_hints == ("exit-code",)
    assert fact_builds == 1


def test_persistent_structure_cache_reuses_exact_content_without_persisting_facts(
    tmp_path,
    monkeypatch,
):
    cache_root = tmp_path / "cache"
    test_path = tmp_path / "test_sample.py"
    test_path.write_text("def test_case():\n    assert result.returncode == 0\n", encoding="utf-8")
    monkeypatch.setattr(pytest_source_structure_cache, "_REPO_ROOT", tmp_path)
    monkeypatch.setattr(pytest_source_structure_cache, "_CACHE_ROOT", cache_root)

    clear_pytest_source_index_cache()
    first = load_pytest_source_index(test_path, SKIP_CALLS)
    cache_path = next(cache_root.glob("*.json"))
    payload = json.loads(cache_path.read_text(encoding="utf-8"))
    assert "facts" not in payload

    original_parse = pytest_source_index.ast.parse
    parse_count = 0

    def recording_parse(*args, **kwargs):
        nonlocal parse_count
        parse_count += 1
        return original_parse(*args, **kwargs)

    monkeypatch.setattr(pytest_source_index.ast, "parse", recording_parse)
    clear_pytest_source_index_cache()
    cached = load_pytest_source_index(test_path, SKIP_CALLS)
    assert cached.nodes == first.nodes
    assert parse_count == 0

    assert cached.facts("test_case").assertion_count == 1
    assert parse_count == 1

    test_path.write_text("def test_next():\n    assert result.returncode == 0\n", encoding="utf-8")
    clear_pytest_source_index_cache()
    invalidated = load_pytest_source_index(test_path, SKIP_CALLS)
    assert invalidated.has_node("test_next")
    assert not invalidated.has_node("test_case")
    assert parse_count == 2


def test_persistent_structure_cache_refuses_malformed_payload_and_changed_skip_policy(
    tmp_path,
    monkeypatch,
):
    cache_root = tmp_path / "cache"
    test_path = tmp_path / "test_sample.py"
    test_path.write_text("def test_case():\n    pytest.mark.skipif(False)\n", encoding="utf-8")
    monkeypatch.setattr(pytest_source_structure_cache, "_REPO_ROOT", tmp_path)
    monkeypatch.setattr(pytest_source_structure_cache, "_CACHE_ROOT", cache_root)

    clear_pytest_source_index_cache()
    load_pytest_source_index(test_path, SKIP_CALLS)
    cache_path = next(cache_root.glob("*.json"))
    cache_path.write_text("{broken", encoding="utf-8")

    original_parse = pytest_source_index.ast.parse
    parse_count = 0

    def recording_parse(*args, **kwargs):
        nonlocal parse_count
        parse_count += 1
        return original_parse(*args, **kwargs)

    monkeypatch.setattr(pytest_source_index.ast, "parse", recording_parse)
    clear_pytest_source_index_cache()
    repaired = load_pytest_source_index(test_path, SKIP_CALLS)
    assert repaired.has_node("test_case")
    assert parse_count == 1

    clear_pytest_source_index_cache()
    changed_policy = load_pytest_source_index(test_path, SKIP_CALLS | {"pytest.mark.skipif"})
    assert changed_policy.skip_xfail_lines("test_case") == (2,)
    assert parse_count == 2


def test_source_index_preserves_file_class_and_method_skip_scope(tmp_path):
    test_path = tmp_path / "test_sample.py"
    test_path.write_text(
        "import pytest\n\n"
        "def test_plain():\n"
        "    pytest.skip('plain')\n\n"
        "class TestGroup:\n"
        "    def test_case(self):\n"
        "        pytest.xfail('class method')\n",
        encoding="utf-8",
    )

    index = load_pytest_source_index(test_path, SKIP_CALLS)

    assert index.has_node("test_plain")
    assert index.has_node("TestGroup")
    assert index.has_node("TestGroup::test_case")
    assert index.skip_xfail_lines("test_plain") == (4,)
    assert index.skip_xfail_lines("TestGroup") == (8,)
    assert index.skip_xfail_lines("TestGroup::test_case") == (8,)
    assert index.skip_xfail_lines("") == (4, 8)


def test_cached_index_equals_uncached_reference_for_same_source(tmp_path):
    test_path = tmp_path / "test_sample.py"
    source = "import pytest\n\ndef test_case():\n    pytest.skip('reason')\n"
    test_path.write_text(source, encoding="utf-8")

    cached = load_pytest_source_index(test_path, SKIP_CALLS)
    uncached = build_pytest_source_index(source, test_path, SKIP_CALLS)

    assert cached == uncached


def test_source_index_attributes_skip_calls_in_one_nested_scope_walk(tmp_path):
    test_path = tmp_path / "test_sample.py"
    source = (
        "import pytest\n\n"
        "def test_plain():\n"
        "    def nested():\n"
        "        pytest.xfail('nested')\n"
        "    pytest.skip('plain')\n\n"
        "class TestGroup:\n"
        "    @pytest.mark.skipif(False, reason='decorator')\n"
        "    def test_case(self):\n"
        "        pytest.xfail('method')\n"
    )

    index = build_pytest_source_index(source, test_path, SKIP_CALLS | {"pytest.mark.skipif"})

    assert index.skip_xfail_lines("") == (5, 6, 11, 9)
    assert index.skip_xfail_lines("test_plain") == (5, 6)
    assert index.skip_xfail_lines("TestGroup") == (11, 9)
    assert index.skip_xfail_lines("TestGroup::test_case") == (11, 9)


def test_source_index_records_per_node_cost_and_assertion_facts(tmp_path):
    test_path = tmp_path / "test_sample.py"
    source = (
        "import subprocess\n\n"
        "def test_cli():\n"
        "    result = subprocess.run(['tool', 'SORTD.EXE', '--addr'])\n"
        "    _run_decompile_addr(SORTD_EXE, 0x10E70)\n"
        "    assert result.returncode == 0\n"
        "    assert 'validation=passed' in result.stderr\n\n"
        "def test_unit():\n"
        "    assert 1 == 1\n"
    )

    index = build_pytest_source_index(source, test_path, SKIP_CALLS)
    cli_facts = index.facts("test_cli[param]@sortd-group")
    unit_facts = index.facts("test_unit")

    assert cli_facts.subprocess_call_count == 1
    assert cli_facts.effective_subprocess_call_count == 1
    assert cli_facts.assertion_count == 2
    assert cli_facts.effective_assertion_count == 2
    assert cli_facts.assertion_kinds == ("Eq", "In")
    assert cli_facts.evidence_hints == ("diagnostics", "exit-code")
    assert cli_facts.function_address_hints == (0x10E70,)
    assert cli_facts.effective_function_address_hints == (0x10E70,)
    assert cli_facts.input_hints == ("SORTD.EXE", "SORTD_EXE")
    assert cli_facts.effective_input_hints == ("SORTD.EXE", "SORTD_EXE")
    assert cli_facts.option_hints == ("--addr",)
    assert cli_facts.effective_option_hints == ("--addr",)
    assert unit_facts.subprocess_call_count == 0
    assert unit_facts.assertion_count == 1


def test_source_index_resolves_local_helper_assertions_and_expectations(tmp_path):
    test_path = tmp_path / "test_sample.py"
    source = (
        "import pytest\n\n"
        "import subprocess\n\n"
        "def _assert_result(value):\n"
        "    subprocess.run(['tool', 'SORTD.EXE', '--addr'], check=True)\n"
        "    assert value == 3\n\n"
        "def _expect_error():\n"
        "    with pytest.raises(ValueError):\n"
        "        raise ValueError\n\n"
        "def test_delegated_contract():\n"
        "    _run_decompile_addr(SORTDEMO_EXE, 0x10E70)\n"
        "    _assert_result(3)\n"
        "    _expect_error()\n"
    )

    facts = build_pytest_source_index(source, test_path, SKIP_CALLS).facts(
        "test_delegated_contract[param]@group"
    )

    assert facts.assertion_count == 0
    assert facts.effective_assertion_count == 1
    assert facts.expectation_count == 0
    assert facts.effective_expectation_count == 2
    assert facts.expectation_kinds == ()
    assert facts.assertion_sources == ("_assert_result", "_expect_error")
    assert facts.evidence_hints == ("explicit-expectation",)
    assert facts.subprocess_call_count == 0
    assert facts.effective_subprocess_call_count == 1
    assert facts.function_address_hints == (0x10E70,)
    assert facts.effective_function_address_hints == (0x10E70,)
    assert facts.input_hints == ("SORTDEMO_EXE",)
    assert facts.effective_input_hints == ("SORTD.EXE", "SORTDEMO_EXE")
    assert facts.option_hints == ()
    assert facts.effective_option_hints == ("--addr",)
    assert facts.cost_sources == ("_assert_result",)


def test_source_index_records_parameterized_function_addresses(tmp_path):
    source = (
        "import pytest\n\n"
        "@pytest.mark.parametrize(\n"
        "    ('address', 'timeout'),\n"
        "    ((0x1004E, 30), pytest.param(0x100C3, 60)),\n"
        ")\n"
        "def test_function(address, timeout):\n"
        "    assert address > 0\n"
    )

    facts = build_pytest_source_index(source, tmp_path / "test_sample.py", SKIP_CALLS).facts(
        "test_function[65536]"
    )

    assert facts.function_address_hints == (0x1004E, 0x100C3)
    assert facts.effective_function_address_hints == (0x1004E, 0x100C3)


def test_concrete_function_addresses_narrows_static_candidates():
    item = _ParameterizedItem()
    item.callspec = CallSpec2(params={"address": 0x100C3, "timeout": 60})

    assert concrete_function_addresses(item, (0x1004E, 0x100C3)) == (0x100C3,)


def test_source_index_records_assertion_error_and_checked_subprocess(tmp_path):
    source = (
        "import subprocess\n"
        "from angr_platforms.X86_16.structuring import graph\n\n"
        "def test_contract():\n"
        "    subprocess.run(['tool'], check=True)\n"
        "    if False:\n"
        "        raise AssertionError('unreachable')\n"
    )

    facts = build_pytest_source_index(source, tmp_path / "test_sample.py", SKIP_CALLS).facts("test_contract")

    assert facts.expectation_count == 2
    assert facts.effective_expectation_count == 2
    assert facts.expectation_kinds == ("assertion-error", "subprocess-check")
    assert facts.evidence_hints == ("explicit-expectation",)
    assert facts.module_hints == ("angr_platforms.X86_16.structuring", "subprocess")
