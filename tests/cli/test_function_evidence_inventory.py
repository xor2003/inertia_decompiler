from __future__ import annotations

from types import SimpleNamespace

import inertia.semantics.function_evidence_inventory as function_evidence_inventory
from inertia.semantics.function_evidence_inventory import (
    FunctionEvidenceKind8616,
    collect_function_binary_evidence_8616,
)


def test_addressable_functions_do_not_alias_when_object_ids_are_reused(monkeypatch) -> None:
    project = SimpleNamespace()
    collected: list[int] = []

    def builder(_project: object | None, function: object) -> tuple[int]:
        address = function.addr
        collected.append(address)
        return (address,)

    monkeypatch.setattr(function_evidence_inventory, "id", lambda _value: 7, raising=False)
    first = SimpleNamespace(addr=0x100, size=8, blocks=())
    second = SimpleNamespace(addr=0x200, size=8, blocks=())

    assert collect_function_binary_evidence_8616(
        project,
        first,
        kind=FunctionEvidenceKind8616.INDEXED_GLOBAL_LOAD_SITES,
        builder=builder,
    ) == (0x100,)
    assert collect_function_binary_evidence_8616(
        project,
        second,
        kind=FunctionEvidenceKind8616.INDEXED_GLOBAL_LOAD_SITES,
        builder=builder,
    ) == (0x200,)
    assert collected == [0x100, 0x200]


def test_recreated_function_range_reuses_binary_evidence() -> None:
    project = SimpleNamespace()
    build_count = 0

    def builder(_project: object | None, function: object) -> tuple[int]:
        nonlocal build_count
        build_count += 1
        return (function.addr,)

    for _iteration in range(2):
        function = SimpleNamespace(addr=0x1234, size=12, blocks=())
        assert collect_function_binary_evidence_8616(
            project,
            function,
            kind=FunctionEvidenceKind8616.INDEXED_GLOBAL_STORES,
            builder=builder,
        ) == (0x1234,)

    assert build_count == 1


def test_changed_binary_surface_invalidates_address_cache() -> None:
    project = SimpleNamespace()
    build_count = 0

    def builder(_project: object | None, function: object) -> tuple[int]:
        nonlocal build_count
        build_count += 1
        return (function.size,)

    first = SimpleNamespace(addr=0x1234, size=12, blocks=())
    changed = SimpleNamespace(addr=0x1234, size=14, blocks=())

    assert collect_function_binary_evidence_8616(
        project,
        first,
        kind=FunctionEvidenceKind8616.NEAR_POINTER_ARGUMENTS,
        builder=builder,
    ) == (12,)
    assert collect_function_binary_evidence_8616(
        project,
        changed,
        kind=FunctionEvidenceKind8616.NEAR_POINTER_ARGUMENTS,
        builder=builder,
    ) == (14,)
    assert build_count == 2


def test_changed_callsite_surface_invalidates_address_cache() -> None:
    project = SimpleNamespace()
    build_count = 0

    class Function:
        addr = 0x1234
        size = 12
        blocks = ()

        def __init__(self) -> None:
            self.target = 0x1400

        def get_call_sites(self) -> tuple[int]:
            return (0x1238,)

        def get_call_target(self, _callsite_addr: int) -> int:
            return self.target

        def get_call_return(self, _callsite_addr: int) -> int:
            return 0x123B

    function = Function()

    def builder(_project: object | None, _function: object) -> tuple[int]:
        nonlocal build_count
        build_count += 1
        return (function.target,)

    assert collect_function_binary_evidence_8616(
        project,
        function,
        kind=FunctionEvidenceKind8616.NEIGHBOR_CALL_TARGETS,
        builder=builder,
    ) == (0x1400,)
    function.target = 0x1500
    assert collect_function_binary_evidence_8616(
        project,
        function,
        kind=FunctionEvidenceKind8616.NEIGHBOR_CALL_TARGETS,
        builder=builder,
    ) == (0x1500,)
    assert build_count == 2


def test_block_only_evidence_does_not_query_callsite_surface() -> None:
    project = SimpleNamespace()

    class Function:
        addr = 0x1234
        size = 12
        blocks = ()

        def get_call_sites(self) -> tuple[int, ...]:
            raise AssertionError("block-only evidence must not inspect callsites")

    function = Function()

    assert collect_function_binary_evidence_8616(
        project,
        function,
        kind=FunctionEvidenceKind8616.INSTRUCTION_SUMMARIES,
        builder=lambda _project, _function: (0x1234,),
    ) == (0x1234,)


def test_changed_content_identity_invalidates_address_cache() -> None:
    project = SimpleNamespace()
    function = SimpleNamespace(addr=0x1234, size=2, blocks=())
    build_count = 0

    def builder(_project: object | None, _function: object) -> tuple[int]:
        nonlocal build_count
        build_count += 1
        return (build_count,)

    assert collect_function_binary_evidence_8616(
        project,
        function,
        kind=FunctionEvidenceKind8616.NEIGHBOR_CALL_TARGETS,
        builder=builder,
        content_identity=b"\x90\xc3",
    ) == (1,)
    assert collect_function_binary_evidence_8616(
        project,
        function,
        kind=FunctionEvidenceKind8616.NEIGHBOR_CALL_TARGETS,
        builder=builder,
        content_identity=b"\xcc\xc3",
    ) == (2,)
    assert build_count == 2


def test_builder_mutation_is_resnapshotted_before_cache_storage() -> None:
    project = SimpleNamespace()
    build_count = 0

    class Function:
        addr = 0x1234
        size = 12
        blocks = ()

        def __init__(self) -> None:
            self.callsites: dict[int, tuple[int, int]] = {}

        def get_call_sites(self) -> tuple[int, ...]:
            return tuple(self.callsites)

        def get_call_target(self, callsite_addr: int) -> int:
            return self.callsites[callsite_addr][0]

        def get_call_return(self, callsite_addr: int) -> int:
            return self.callsites[callsite_addr][1]

    function = Function()

    def builder(_project: object | None, _function: object) -> tuple[int]:
        nonlocal build_count
        build_count += 1
        function.callsites[0x1238] = (0x1400, 0x123B)
        return (0x1400,)

    for _iteration in range(2):
        assert collect_function_binary_evidence_8616(
            project,
            function,
            kind=FunctionEvidenceKind8616.NEIGHBOR_CALL_TARGETS,
            builder=builder,
        ) == (0x1400,)

    assert build_count == 1


def test_opaque_function_cache_retains_and_checks_owner(monkeypatch) -> None:
    project = SimpleNamespace()
    build_count = 0

    def builder(_project: object | None, function: object) -> tuple[object]:
        nonlocal build_count
        build_count += 1
        return (function,)

    monkeypatch.setattr(function_evidence_inventory, "id", lambda _value: 7, raising=False)
    first = object()
    second = object()

    assert collect_function_binary_evidence_8616(
        project,
        first,
        kind=FunctionEvidenceKind8616.INSTRUCTION_SUMMARIES,
        builder=builder,
    ) == (first,)
    assert collect_function_binary_evidence_8616(
        project,
        first,
        kind=FunctionEvidenceKind8616.INSTRUCTION_SUMMARIES,
        builder=builder,
    ) == (first,)
    assert collect_function_binary_evidence_8616(
        project,
        second,
        kind=FunctionEvidenceKind8616.INSTRUCTION_SUMMARIES,
        builder=builder,
    ) == (second,)
    assert build_count == 2
