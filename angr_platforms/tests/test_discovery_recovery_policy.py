"""Richer discovery must retain explicit bounds and analysis policy."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from inertia_decompiler import cli_function_discovery as discovery


@pytest.mark.parametrize("truncated", [False, True])
def test_small_exact_candidate_keeps_bounds_and_policy(monkeypatch, truncated):
    function = SimpleNamespace(addr=0x1000)
    pair = (SimpleNamespace(), function)
    project = SimpleNamespace(factory=SimpleNamespace(
        block=lambda *args, **kwargs: SimpleNamespace(capstone=SimpleNamespace(insns=[object()])),
    ))
    richer = Mock(return_value=pair)
    monkeypatch.setattr(discovery, "_pick_function_lean", Mock(return_value=pair))
    monkeypatch.setattr(discovery, "_pick_function", richer)
    monkeypatch.setattr(discovery, "_function_recovery_score", lambda function: (1, 16))
    monkeypatch.setattr(discovery, "_recovery_score_good_enough", lambda score: True)
    monkeypatch.setattr(discovery, "_exact_region_recovery_looks_truncated", lambda *args: truncated)
    monkeypatch.setattr(discovery, "_stitch_x86_16_exact_function_8616", lambda *args: (function, False))
    monkeypatch.setattr(discovery, "_repair_x86_16_function_graph_8616", lambda *args, **kwargs: None)
    result = discovery._recover_candidate_function_pair(
        project, candidate_addr=0x1000, image_end=0x2000, metadata=None,
        project_entry=0x1800, region_span=0x400, exact_region=(0x1000, 0x1010),
        seed_calling_conventions_enabled=False,
    )
    assert result == pair
    assert richer.call_count == (2 if truncated else 0)
    for call in richer.call_args_list:
        assert call.kwargs["regions"] == [(0x1000, 0x1010)]
        assert call.kwargs["seed_calling_conventions_enabled"] is False


@pytest.mark.parametrize("enabled", [False, True])
def test_richer_picker_obeys_seeding_policy(monkeypatch, enabled):
    function = SimpleNamespace(addr=0x1000)
    cfg = SimpleNamespace(functions={0x1000: function})
    project = SimpleNamespace(
        arch=SimpleNamespace(name="AMD64"),
        analyses=SimpleNamespace(CFGFast=lambda **kwargs: cfg),
    )
    seed = Mock()
    monkeypatch.setattr(discovery, "seed_calling_conventions", seed)
    assert discovery._pick_function(project, 0x1000, seed_calling_conventions_enabled=enabled) == (cfg, function)
    assert seed.call_count == int(enabled)
