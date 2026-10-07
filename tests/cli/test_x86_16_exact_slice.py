from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.semantics.callsite_summary import (
    CallerReturnUseEvidence8616,
    CallerReturnUseVerdict8616,
)

from inertia.cli.lst_extract import LSTMetadata
import inertia.cli.cli as cli
import inertia.cli.cli_function_discovery as cli_function_discovery
import inertia.cli.x86_16_exact_slice as x86_16_exact_slice
from inertia.cli.x86_16_exact_slice import (
    SAFE_X86_16_SLICE_BASE,
    function_original_addr,
    mark_function_original_addr,
    plan_x86_16_exact_slice,
)


class _BytesMemory:
    def __init__(self, regions: dict[int, bytes]) -> None:
        self._regions = regions

    def load(self, addr: int, size: int) -> bytes:
        return self._regions[addr][:size]


def test_plan_x86_16_exact_slice_rebases_high_linear_addresses() -> None:
    plan = plan_x86_16_exact_slice(0x109E8, 0x10A61)
    assert plan.needs_rebased_slice is True
    assert plan.slice_start == SAFE_X86_16_SLICE_BASE
    assert plan.slice_end == SAFE_X86_16_SLICE_BASE + (0x10A61 - 0x109E8)


def test_plan_x86_16_exact_slice_rebases_semantic_entry_after_padding() -> None:
    plan = plan_x86_16_exact_slice(0x102CC, 0x10491, original_entry=0x102E0)

    assert plan.original_semantic_entry == 0x102E0
    assert plan.slice_start == SAFE_X86_16_SLICE_BASE
    assert plan.slice_semantic_entry == SAFE_X86_16_SLICE_BASE + 0x14
    assert plan.slice_end == SAFE_X86_16_SLICE_BASE + (0x10491 - 0x102CC)


def test_function_original_addr_prefers_marked_original() -> None:
    function = SimpleNamespace(addr=0x1000, info={})
    mark_function_original_addr(function, 0x109E8)
    assert function_original_addr(function) == 0x109E8


def test_function_original_addr_refuses_nonweakrefable_identity_collision(monkeypatch) -> None:
    original = SimpleNamespace(addr=0x1000)
    replacement = SimpleNamespace(addr=0x2000)
    monkeypatch.setattr(x86_16_exact_slice, "id", lambda _function: 1, raising=False)

    mark_function_original_addr(original, 0x109E8)

    assert function_original_addr(replacement) == 0x2000


def test_caller_return_use_collection_checks_label_and_prologue_aliases(monkeypatch) -> None:
    calls: list[tuple[int, tuple[int, ...]]] = []

    def evidence(target_addr: int, verdict: CallerReturnUseVerdict8616) -> CallerReturnUseEvidence8616:
        classified = int(verdict is not CallerReturnUseVerdict8616.UNKNOWN)
        return CallerReturnUseEvidence8616(
            target_addr=target_addr,
            verdict=verdict,
            raw_fact_count=classified,
            normalized_fact_count=classified,
            classified_fact_count=classified,
            materialized_count=classified,
            failure_count=0,
            used_callsite_count=int(verdict is CallerReturnUseVerdict8616.USED),
            unused_callsite_count=int(verdict is CallerReturnUseVerdict8616.UNUSED),
            callsite_addrs=(0x2000,) if classified else (),
        )

    merged_evidence = evidence(0x102CC, CallerReturnUseVerdict8616.UNUSED)

    def collect(_project, target_addr, _function_ranges, *, target_aliases):
        calls.append((target_addr, target_aliases))
        return merged_evidence

    monkeypatch.setattr(cli_function_discovery, "collect_caller_return_use_evidence_8616", collect)

    result = cli_function_discovery._collect_caller_return_use_for_entry_aliases_8616(
        SimpleNamespace(),
        (0x102CC, 0x102E0),
        ((0x10010, 0x1005D),),
    )

    assert calls == [(0x102CC, (0x102CC, 0x102E0))]
    assert result is merged_evidence


def test_caller_return_use_collection_keeps_any_used_alias(monkeypatch) -> None:
    used = CallerReturnUseEvidence8616(
        0x102CC,
        CallerReturnUseVerdict8616.USED,
        1,
        1,
        1,
        1,
        0,
        1,
        0,
        (0x2010,),
    )
    monkeypatch.setattr(
        cli_function_discovery,
        "collect_caller_return_use_evidence_8616",
        lambda _project, target_addr, _ranges, *, target_aliases: used,
    )

    result = cli_function_discovery._collect_caller_return_use_for_entry_aliases_8616(
        SimpleNamespace(),
        (0x102CC, 0x102E0),
        ((0x10010, 0x1005D),),
    )

    assert result is used


def test_caller_return_use_collection_excludes_recursive_prologue_alias() -> None:
    recursive_tail = bytes.fromhex("e8 ed ff c3")
    independent_caller = bytes.fromhex("e8 dd ff b8 00 00")
    project = SimpleNamespace(
        arch=Arch86_16(),
        loader=SimpleNamespace(
            memory=_BytesMemory(
                {
                    0x1030: recursive_tail,
                    0x1040: independent_caller,
                }
            )
        ),
    )

    result = cli_function_discovery._collect_caller_return_use_for_entry_aliases_8616(
        project,
        (0x1020, 0x1030),
        ((0x1030, 0x1034), (0x1040, 0x1046)),
    )

    assert result is not None
    assert result.verdict is CallerReturnUseVerdict8616.UNUSED
    assert result.raw_fact_count == 2
    assert result.normalized_fact_count == 2
    assert result.classified_fact_count == 1
    assert result.excluded_callsite_count == 1
    assert result.failure_count == 0


def test_direct_callee_return_use_collection_records_only_uncached_calls(monkeypatch) -> None:
    existing = CallerReturnUseEvidence8616(
        0x2000,
        CallerReturnUseVerdict8616.USED,
        1,
        1,
        1,
        1,
        0,
        1,
        0,
        (0x1010,),
    )
    project = SimpleNamespace(
        _inertia_caller_return_use_evidence_by_addr_8616={0x2000: existing},
    )
    function = SimpleNamespace()
    monkeypatch.setattr(
        cli_function_discovery,
        "collect_neighbor_call_targets",
        lambda _function: (
            SimpleNamespace(target_addr=0x2000, return_addr=0x1013),
            SimpleNamespace(target_addr=0x3000, return_addr=0x1016),
            SimpleNamespace(target_addr=0x4000, return_addr=None),
        ),
    )
    collected: list[int] = []

    def collect(_project, target_addr, _ranges, *, target_aliases):
        collected.append(target_addr)
        return CallerReturnUseEvidence8616(
            target_addr,
            CallerReturnUseVerdict8616.UNUSED,
            1,
            1,
            1,
            1,
            0,
            0,
            1,
            (0x1013,),
        )

    monkeypatch.setattr(
        cli_function_discovery,
        "collect_caller_return_use_evidence_8616",
        collect,
    )

    evidence = cli_function_discovery._collect_direct_callee_return_use_evidence_8616(
        project,
        function,
        ((0x1000, 0x1100),),
    )

    assert collected == [0x3000]
    assert tuple(evidence) == (0x3000,)
    assert evidence[0x3000].verdict is CallerReturnUseVerdict8616.UNUSED


def test_direct_callee_return_use_collection_joins_public_entry_and_prologue_aliases(
    monkeypatch,
) -> None:
    project = SimpleNamespace()
    function = SimpleNamespace()
    monkeypatch.setattr(
        cli_function_discovery,
        "collect_neighbor_call_targets",
        lambda _function: (
            SimpleNamespace(target_addr=0x10F38, return_addr=0x1054B),
        ),
    )
    observed: list[int] = []

    def collect(_project, target_addr, _ranges, *, target_aliases):
        observed.append(target_addr)
        verdict = CallerReturnUseVerdict8616.UNUSED
        classified = int(verdict is CallerReturnUseVerdict8616.UNUSED)
        return CallerReturnUseEvidence8616(
            target_addr,
            verdict,
            classified,
            classified,
            classified,
            classified,
            0,
            0,
            classified,
            (0x10548,) if classified else (),
        )

    monkeypatch.setattr(
        cli_function_discovery,
        "collect_caller_return_use_evidence_8616",
        collect,
    )

    evidence = cli_function_discovery._collect_direct_callee_return_use_evidence_8616(
        project,
        function,
        ((0x10F18, 0x10F64),),
    )

    assert observed == [0x10F38]
    assert evidence[0x10F38].target_addr == 0x10F38
    assert evidence[0x10F38].verdict is CallerReturnUseVerdict8616.UNUSED


def test_recover_lst_function_uses_rebased_slice_for_high_exact_region(monkeypatch) -> None:
    built = {}

    class FakeMemory:
        def load(self, addr: int, size: int) -> bytes:
            assert addr == 0x109E8
            assert size == 0x79
            return b"\x55\x8b\xec\xc3" + (b"\x40" * (size - 4))

    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        entry=0x10F9A,
        loader=SimpleNamespace(memory=FakeMemory()),
        _inertia_c_target="portable-flat",
    )
    metadata = LSTMetadata(
        data_labels={},
        code_labels={0x109E8: "PercolateUp"},
        code_ranges={0x109E8: (0x109E8, 0x10A61)},
        absolute_addrs=True,
        cod_path=str(Path("/tmp/fake.cod")),
    )

    def fake_build_project_from_bytes(code: bytes, *, base_addr: int, entry_point: int):
        built["base_addr"] = base_addr
        built["entry_point"] = entry_point
        built["size"] = len(code)
        return SimpleNamespace(arch=SimpleNamespace(name="86_16"))

    def fake_pick_function_lean(slice_project, addr, *, regions, data_references, extend_far_calls):
        built["recover_addr"] = addr
        built["regions"] = regions
        function = SimpleNamespace(addr=addr, name="sub", info={}, project=slice_project)
        return SimpleNamespace(functions={addr: function}), function

    monkeypatch.setattr(cli, "_build_project_from_bytes", fake_build_project_from_bytes)
    monkeypatch.setattr(cli, "_inherit_tail_validation_runtime_policy", lambda slice_project, source_project: None)
    monkeypatch.setattr(cli, "_pick_function_lean", fake_pick_function_lean)

    cfg, function = cli._recover_lst_function(
        project,
        metadata,
        0x109E8,
        "PercolateUp",
        timeout=5,
        window=0x200,
    )

    assert cfg is not None
    assert built["base_addr"] == SAFE_X86_16_SLICE_BASE
    assert built["entry_point"] == SAFE_X86_16_SLICE_BASE
    assert built["recover_addr"] == SAFE_X86_16_SLICE_BASE
    assert built["regions"] == [(SAFE_X86_16_SLICE_BASE, SAFE_X86_16_SLICE_BASE + 0x79)]
    assert function.project._inertia_c_target == "portable-flat"
    assert function.name == "PercolateUp"
    assert function_original_addr(function) == 0x109E8
