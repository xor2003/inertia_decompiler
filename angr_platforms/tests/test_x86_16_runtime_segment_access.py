from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CFunctionCall,
    CStatements,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from angr_platforms.X86_16.ir.core import AddressStatus, IRAddress, MemSpace, SegmentOrigin
from angr_platforms.X86_16.ir.segment_contract import (
    SegmentAccessFact,
    SegmentAccessKind,
    SegmentFactVerdict,
    SegmentFunctionContract,
)
from angr_platforms.X86_16.lowering.runtime_segment_access import (
    build_runtime_segment_access_context_8616,
    is_runtime_segment_load_helper_8616,
    runtime_segment_access_offset_expr_8616,
)
from angr_platforms.X86_16.lowering.segmented_global_loads import (
    IndexedSegmentedGlobalLoadSiteEvidence8616,
    _match_byte_store_lvalue_8616,
    _runtime_indexed_global_load_site_8616,
)
from archinfo import ArchX86


class _Codegen:
    def __init__(self) -> None:
        self._next_index = 0
        self.cstyle_null_cmp = False
        self.project = SimpleNamespace(arch=ArchX86())
        self.cfunc = SimpleNamespace(statements=None)

    def next_idx(self, _kind: str) -> int:
        index = self._next_index
        self._next_index += 1
        return index
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _segment_variable(codegen: _Codegen, name: str) -> CVariable:
    return CVariable(
        SimRegisterVariable(codegen.project.arch.registers[name][0], 2, name=name),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )


def _segmented_access(
    codegen: _Codegen,
    segment: str,
    offset: object,
    *,
    width: int = 1,
) -> CFunctionCall:
    return CFunctionCall(
        f"SEG_U{width * 8}",
        None,
        [_segment_variable(codegen, segment), offset],
        codegen=codegen,
    )


def test_runtime_segment_access_returns_proven_ds_offset_expression() -> None:
    codegen = _Codegen()
    offset = CBinaryOp(
        "Add",
        CConstant(0xB4C, SimTypeShort(False), codegen=codegen),
        CConstant(2, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    store = _segmented_access(codegen, "ds", offset)

    assert runtime_segment_access_offset_expr_8616(
        codegen.project,
        codegen,
        store,
        expected_space=MemSpace.DS,
        width=1,
    ) is offset


def test_runtime_segment_load_helper_requires_owned_identity() -> None:
    codegen = _Codegen()
    offset = CConstant(0xB4C, SimTypeShort(False), codegen=codegen)
    tagged = CFunctionCall(
        0x1234,
        None,
        [],
        codegen=codegen,
        tags={"inertia_x86_16_runtime_segment_helper": "SEG_U16"},
    )

    assert is_runtime_segment_load_helper_8616(_segmented_access(codegen, "ds", offset))
    assert is_runtime_segment_load_helper_8616(tagged)
    assert not is_runtime_segment_load_helper_8616(
        CFunctionCall("rand", None, [], codegen=codegen)
    )


def test_runtime_segment_access_refuses_wrong_space_or_width() -> None:
    codegen = _Codegen()
    offset = CConstant(0xB4C, SimTypeShort(False), codegen=codegen)
    es_store = _segmented_access(codegen, "es", offset)

    for width in (1, 2):
        assert runtime_segment_access_offset_expr_8616(
            codegen.project,
            codegen,
            es_store,
            expected_space=MemSpace.DS,
            width=width,
        ) is None


def test_runtime_segment_access_context_skips_index_for_direct_segment(monkeypatch) -> None:
    from angr_platforms.X86_16.lowering import runtime_segment_access

    codegen = _Codegen()
    calls = 0
    original = runtime_segment_access._assignment_sources_8616

    def _counted_sources(root: object):
        nonlocal calls
        calls += 1
        return original(root)

    monkeypatch.setattr(runtime_segment_access, "_assignment_sources_8616", _counted_sources)
    context = build_runtime_segment_access_context_8616(codegen)
    offset = CConstant(0xB4C, SimTypeShort(False), codegen=codegen)
    store = _segmented_access(codegen, "ds", offset)

    for _ in range(2):
        assert runtime_segment_access_offset_expr_8616(
            codegen.project,
            codegen,
            store,
            expected_space=MemSpace.DS,
            width=1,
            context=context,
        ) is offset

    assert calls == 0


def test_runtime_segment_access_context_reuses_index_for_copied_segment(monkeypatch) -> None:
    from angr_platforms.X86_16.lowering import runtime_segment_access

    codegen = _Codegen()
    calls = 0
    original = runtime_segment_access._assignment_sources_8616

    def _counted_sources(root: object):
        nonlocal calls
        calls += 1
        return original(root)

    monkeypatch.setattr(runtime_segment_access, "_assignment_sources_8616", _counted_sources)
    carrier = CVariable(
        SimRegisterVariable(0x200, 2, name="segment_copy"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        [CAssignment(carrier, _segment_variable(codegen, "ds"), codegen=codegen)],
        codegen=codegen,
    )
    context = build_runtime_segment_access_context_8616(codegen)
    offset = CConstant(0xB4C, SimTypeShort(False), codegen=codegen)
    store = CFunctionCall("SEG_U8", None, [carrier, offset], codegen=codegen)

    for _ in range(2):
        assert runtime_segment_access_offset_expr_8616(
            codegen.project,
            codegen,
            store,
            expected_space=MemSpace.DS,
            width=1,
            context=context,
        ) is offset

    assert calls == 1


def test_indexed_lowering_matches_affine_ds_segment_helper_store() -> None:
    codegen = _Codegen()
    index = CVariable(
        SimStackVariable(-2, 2, base="bp", name="local_2"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    scaled = CBinaryOp(
        "Mul",
        index,
        CConstant(2, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    offset = CBinaryOp(
        "Add",
        CConstant(0xB4C, SimTypeShort(False), codegen=codegen),
        scaled,
        codegen=codegen,
    )
    store = _segmented_access(codegen, "ds", offset)

    matched = _match_byte_store_lvalue_8616(
        store,
        project=codegen.project,
        codegen=codegen,
        evidence_by_base={},
    )

    assert matched is not None
    assert matched[0] == 0xB4C
    assert matched[1] is index


def test_runtime_indexed_load_joins_exact_entry_ds_instruction() -> None:
    codegen = _Codegen()
    index = CVariable(
        SimStackVariable(-2, 2, base="bp", name="local_2"),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    offset = CBinaryOp(
        "Add",
        CConstant(0xB4C, SimTypeShort(False), codegen=codegen),
        CBinaryOp(
            "Shl",
            index,
            CConstant(1, SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    load = _segmented_access(codegen, "ds", offset, width=2)
    site = IndexedSegmentedGlobalLoadSiteEvidence8616(
        base_offset=0xB4C,
        width=2,
        index_stack_offset=-2,
        index_shift=1,
        ins_addr=0x1082F,
        stack_stores=(),
    )
    access_fact = SegmentAccessFact(
        block_addr=0x1082F,
        instruction_addr=0x1082F,
        kind=SegmentAccessKind.READ,
        address=IRAddress(
            space=MemSpace.DS,
            offset=0xB4C,
            size=2,
            status=AddressStatus.STABLE,
            segment_origin=SegmentOrigin.PROVEN,
        ),
        segment_register="ds",
        physical_source="ds",
        verdict=SegmentFactVerdict.PROVEN,
    )
    codegen._inertia_segment_function_contract = SegmentFunctionContract(
        function_addr=0x10808,
        accesses=(access_fact,),
    )

    assert (
        _runtime_indexed_global_load_site_8616(
            codegen.project,
            codegen,
            load,
            {site.ins_addr: site},
            copies=None,
        )[0]
        is site
    )

    equivalent_site = replace(site, ins_addr=0x1083F)
    equivalent_fact = replace(
        access_fact,
        block_addr=equivalent_site.ins_addr,
        instruction_addr=equivalent_site.ins_addr,
    )
    codegen._inertia_segment_function_contract = SegmentFunctionContract(
        function_addr=0x10808,
        accesses=(access_fact, equivalent_fact),
    )
    assert (
        _runtime_indexed_global_load_site_8616(
            codegen.project,
            codegen,
            load,
            {site.ins_addr: site, equivalent_site.ins_addr: equivalent_site},
            copies=None,
        )[0]
        is site
    )

    codegen._inertia_segment_function_contract = SegmentFunctionContract(
        function_addr=0x10808,
        accesses=(access_fact, replace(equivalent_fact, physical_source="es")),
    )
    assert (
        _runtime_indexed_global_load_site_8616(
            codegen.project,
            codegen,
            load,
            {site.ins_addr: site, equivalent_site.ins_addr: equivalent_site},
            copies=None,
        )
        is None
    )
