from __future__ import annotations

from types import SimpleNamespace
from typing import cast

from angr import Project

import inertia_decompiler.cli_function_discovery as discovery


def test_seed_neighbor_ranking_returns_picklable_addresses_from_fork(monkeypatch) -> None:
    project = SimpleNamespace(entry=0x1000)
    seen: dict[str, int] = {}
    targets = (
        SimpleNamespace(target_addr=0x1100),
        SimpleNamespace(target_addr=0x1080),
        SimpleNamespace(target_addr=0x1100),
    )
    monkeypatch.setattr(
        discovery,
        "_pick_function_lean",
        lambda *_args, **_kwargs: (object(), object()),
    )
    monkeypatch.setattr(
        discovery,
        "collect_neighbor_call_targets",
        lambda _function: targets,
    )

    def _run_in_fork(function, *, timeout: int):
        seen["timeout"] = timeout
        return function()

    monkeypatch.setattr(discovery, "_run_with_timeout_in_fork", _run_in_fork)
    monkeypatch.setattr(
        discovery,
        "_run_with_timeout_in_daemon_thread",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("seed ranking must not leave a live project-mutating thread")
        ),
    )

    result = discovery._collect_neighbor_targets_for_seed_ranking(
        cast(Project, project),  # Intentional minimal third-party project test double.
        bytes(0x400),
        0x1000,
    )

    assert result == {0x1080, 0x1100}
    assert seen == {"timeout": 1}


def test_seed_neighbor_ranking_refuses_failed_isolated_recovery(monkeypatch) -> None:
    project = SimpleNamespace(entry=0x1000)
    monkeypatch.setattr(
        discovery,
        "_run_with_timeout_in_fork",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(TimeoutError),
    )

    assert discovery._collect_neighbor_targets_for_seed_ranking(
        cast(Project, project),
        bytes(0x400),
        0x1000,
    ) == set()


def test_evidence_only_function_recovery_skips_convention_seeding(
    monkeypatch,
) -> None:
    """Alias/Widening census recovery must not run unused convention inference."""
    function = SimpleNamespace(addr=0x1000)
    cfg = SimpleNamespace(functions={0x1000: function})
    project = SimpleNamespace(
        entry=0x1000,
        arch=SimpleNamespace(name="86_16"),
        analyses=SimpleNamespace(CFGFast=lambda **_kwargs: cfg),
        loader=SimpleNamespace(main_object=SimpleNamespace(binary=None)),
    )
    seeded: list[object] = []
    monkeypatch.setattr(
        discovery,
        "seed_calling_conventions",
        seeded.append,
    )

    recovered = discovery._pick_function_lean(
        cast(Project, project),
        0x1000,
        regions=((0x1000, 0x1010),),
        extend_far_calls=False,
        seed_calling_conventions_enabled=False,
    )

    assert recovered == (cfg, function)
    assert seeded == []
