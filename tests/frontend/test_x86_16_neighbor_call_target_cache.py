from __future__ import annotations

from types import SimpleNamespace

import inertia.lowering.analysis_helpers as analysis_helpers

from inertia.lowering.analysis_helpers import (
    CallTargetKind8616,
    CallTargetSeed,
    collect_neighbor_call_targets,
)


def test_call_return_low_ip_is_linearized_by_exact_decoded_fallthrough() -> None:
    instruction = SimpleNamespace(address=0x10069, mnemonic="call", size=2)
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        factory=SimpleNamespace(
            block=lambda _addr, opt_level=0: SimpleNamespace(
                capstone=SimpleNamespace(insns=(instruction,))
            )
        ),
    )
    function = SimpleNamespace(
        project=project,
        get_call_return=lambda _callsite: 0x006B,
    )

    assert analysis_helpers._analysis_function_call_return_8616(function, 0x10069) == 0x1006B


def test_call_return_low_ip_mismatch_is_not_linearized() -> None:
    instruction = SimpleNamespace(address=0x10069, mnemonic="call", size=2)
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        factory=SimpleNamespace(
            block=lambda _addr, opt_level=0: SimpleNamespace(
                capstone=SimpleNamespace(insns=(instruction,))
            )
        ),
    )
    function = SimpleNamespace(
        project=project,
        get_call_return=lambda _callsite: 0x0070,
    )

    assert analysis_helpers._analysis_function_call_return_8616(function, 0x10069) == 0x0070


def test_neighbor_call_targets_reuse_post_sanitization_evidence(monkeypatch) -> None:
    project = SimpleNamespace(
        loader=SimpleNamespace(
            memory=SimpleNamespace(load=lambda _addr, size: b"\x90" * size),
        )
    )
    patch_count = 0

    class Function:
        addr = 0x100
        size = 4
        blocks = ()

        def __init__(self) -> None:
            self.block_addrs_set: set[int] = set()
            self.callsites: dict[int, tuple[int, int]] = {}

        def get_call_sites(self) -> tuple[int, ...]:
            return tuple(self.callsites)

        def get_call_target(self, callsite_addr: int) -> int:
            return self.callsites[callsite_addr][0]

        def get_call_return(self, callsite_addr: int) -> int:
            return self.callsites[callsite_addr][1]

    function = Function()

    def patch_direct_call_sites(_function: object) -> bool:
        nonlocal patch_count
        patch_count += 1
        function.callsites[0x101] = (0x200, 0x104)
        return True

    monkeypatch.setattr(analysis_helpers, "_x86_16_project_for_function_8616", lambda _function: project)
    monkeypatch.setattr(analysis_helpers, "patch_direct_call_sites", patch_direct_call_sites)
    monkeypatch.setattr(analysis_helpers, "_neighbor_image_bounds", lambda _project: (0, 0x1000))
    monkeypatch.setattr(
        analysis_helpers,
        "_analysis_function_call_sites_8616",
        lambda _function: tuple(function.callsites),
    )
    monkeypatch.setattr(
        analysis_helpers,
        "_analysis_function_call_target_8616",
        lambda _function, callsite_addr: function.callsites[callsite_addr][0],
    )
    monkeypatch.setattr(analysis_helpers, "resolve_direct_call_target_from_block", lambda *_args: None)
    monkeypatch.setattr(analysis_helpers, "_direct_call_target_kind_8616", lambda *_args: None)
    monkeypatch.setattr(
        analysis_helpers,
        "_analysis_function_call_return_8616",
        lambda _function, callsite_addr: function.callsites[callsite_addr][1],
    )

    expected = [
        CallTargetSeed(
            callsite_addr=0x101,
            target_addr=0x200,
            return_addr=0x104,
            kind=CallTargetKind8616.CFG_RESOLVED_CALL,
        )
    ]
    assert collect_neighbor_call_targets(function) == expected
    assert collect_neighbor_call_targets(function) == expected
    assert patch_count == 1
