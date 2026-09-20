"""An explicit discovery budget must reach recovery and its cache identity."""

from dataclasses import replace
from types import SimpleNamespace

import pytest
from test_discovery_cache_contract import _cache_policy

from inertia_decompiler import cli_function_discovery as discovery
from inertia_decompiler.cli_arg_parser import parse_cli_arguments


def test_catalog_default_is_independent_of_function_timeout(monkeypatch):
    monkeypatch.delenv("INERTIA_CATALOG_TIMEOUT", raising=False)
    args = parse_cli_arguments(["sample.exe", "--timeout", "5"])
    assert args.catalog_timeout == 60
    assert args.timeout == 5


def test_explicit_catalog_budget_overrides_environment(monkeypatch):
    monkeypatch.setenv("INERTIA_CATALOG_TIMEOUT", "90")
    assert parse_cli_arguments(["sample.exe"]).catalog_timeout == 90
    assert parse_cli_arguments(["sample.exe", "--catalog-timeout", "120"]).catalog_timeout == 120


@pytest.mark.parametrize("value", ["0", "-1", "garbage"])
@pytest.mark.parametrize("environment", [False, True])
def test_invalid_catalog_budget_is_rejected(monkeypatch, value, environment):
    monkeypatch.delenv("INERTIA_CATALOG_TIMEOUT", raising=False)
    args = ["sample.exe"]
    if environment:
        monkeypatch.setenv("INERTIA_CATALOG_TIMEOUT", value)
    else:
        args.extend(["--catalog-timeout", value])
    with pytest.raises(SystemExit) as error:
        parse_cli_arguments(args)
    assert error.value.code == 2


def test_catalog_cache_identity_includes_budget():
    policy = _cache_policy()
    assert policy.cache_fields()["catalog_timeout"] == 60
    assert policy.cache_fields() != replace(policy, catalog_timeout=120).cache_fields()


@pytest.mark.parametrize("source_seeds", [[], [0x1000]])
def test_catalog_recovery_consumes_budget(monkeypatch, source_seeds):
    observed = []
    monkeypatch.setattr(discovery, "_rank_pre_entry_source_function_seeds_8616", lambda project: source_seeds)
    monkeypatch.setattr(discovery, "_run_with_timeout_in_daemon_thread", lambda *args, **kwargs: None)

    def seeds(project, **kwargs):
        observed.append(kwargs["timeout"])
        return []

    def source(project, **kwargs):
        observed.append(kwargs["timeout"])
        return [], None

    monkeypatch.setattr(discovery, "_recover_fast_seed_functions", seeds)
    monkeypatch.setattr(discovery, "_recover_pre_entry_source_catalog_8616", source)
    assert discovery._recover_fast_exe_catalog(SimpleNamespace(), timeout=4, window=512,
                                               low_memory=False, limit=None, catalog_timeout=123) == []
    assert observed == [123]
