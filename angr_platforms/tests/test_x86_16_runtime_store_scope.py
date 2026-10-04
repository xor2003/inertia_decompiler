"""Regression tests for runtime segmented word-store lvalue coalescing.

Layer: Tests.
Responsibility: pin the evidence contract of
``widening_rules._runtime_word_store_lvalue_8616``. Two adjacent ``SEG_U8``
helper accesses may merge into one ``SEG_U16`` lvalue only when both carry a
lowering-owned typed storage identity that joins adjacently inside one
16-bit segment. Structural offset adjacency alone is not proof: the raw
lifter stores word bytes independently with modulo-16 offsets, so a byte
pair at ``ES:DI`` with ``DI = 0xFFFF`` writes at offsets ``0xFFFF`` and
``0x0000``, while a joined ``SEG_U16`` at ``0xFFFF`` would span
``0xFFFF..0x10000``.
"""

from __future__ import annotations

from collections.abc import Callable
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import (
    CBinaryOp,
    CConstant,
    CFunctionCall,
    CVariable,
)
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable
from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.ir.core import MemSpace
from angr_platforms.X86_16.lowering.runtime_segment_access import (
    RuntimeSegmentAccessContext8616,
)
from angr_platforms.X86_16.widening.segmented_load_identity import (
    SegmentedLoadIdentity8616,
    segmented_load_identity_8616,
    segmented_load_tags_8616,
)
from angr_platforms.X86_16.widening.widening_rules import (
    _runtime_word_store_lvalue_8616,
    _WordStoreCoalesceCtx8616,
)

_FUNC_ADDR = 0x10560
_LOW_INS_ADDR = 0x10570
_HIGH_INS_ADDR = 0x10572


class _DummyCodegen:
    def __init__(self) -> None:
        self._idx = 0
        self.cfunc: SimpleNamespace | None = SimpleNamespace(
            addr=_FUNC_ADDR,
            statements=None,
        )
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx

    def next_node_idx(self) -> int:
        return self.next_idx("")

    def next_ident(self, name: str) -> str:
        return name


def _no_evidence(*_args: object, **_kwargs: object) -> None:
    """Fail-closed stub: callbacks this unit does not exercise return no proof."""
    return None


def _adjacent_claimed(*_args: object, **_kwargs: object) -> bool:
    """Model the structural-adjacency defect: the byte-pair callback trusts shape."""
    return True


def _coalesce_ctx(
    codegen: _DummyCodegen,
    *,
    addr_exprs_are_byte_pair: Callable[..., object] = _adjacent_claimed,
) -> _WordStoreCoalesceCtx8616:
    """Build the real coalescing context with fail-closed unused callbacks."""
    return _WordStoreCoalesceCtx8616(
        project=codegen.project,
        codegen=codegen,
        target_type=SimTypeShort(False),
        debug_widening=False,
        runtime_access_context=RuntimeSegmentAccessContext8616(root=None),
        match_ss_local_plus_const=_no_evidence,
        match_word_rhs_from_byte_pair=_no_evidence,
        promote_direct_stack_cvariable=_no_evidence,
        stack_slot_identity_can_join=_no_evidence,
        canonicalize_stack_cvar_expr=_no_evidence,
        match_byte_store_addr_expr=_no_evidence,
        match_shift_right_8_expr=_no_evidence,
        addr_exprs_are_byte_pair=addr_exprs_are_byte_pair,
        resolve_stack_cvar_from_addr_expr=_no_evidence,
        make_word_dereference_from_addr_expr=_no_evidence,
        classify_segmented_addr_expr=_no_evidence,
        describe_alias_storage=_no_evidence,
        match_byte_load_addr_expr=None,
        same_c_expression=None,
    )


def _segment_carrier(codegen: _DummyCodegen, register_name: str) -> CVariable:
    """Return the architectural segment-register carrier for ``register_name``."""
    reg_offset, reg_size = codegen.project.arch.registers[register_name]
    return CVariable(
        SimRegisterVariable(reg_offset, reg_size, name=register_name),
        codegen=codegen,
    )


def _register_cvar(codegen: _DummyCodegen, register_name: str) -> CVariable:
    """Return one architectural register expression usable as a symbolic offset."""
    return _segment_carrier(codegen, register_name)


def _constant(codegen: _DummyCodegen, value: int) -> CConstant:
    return CConstant(value, SimTypeShort(False), codegen=codegen)


def _identity(space: MemSpace, offset: int, *, region: int = _FUNC_ADDR) -> SegmentedLoadIdentity8616:
    return SegmentedLoadIdentity8616(space=space, offset=offset, width=1, region=region)


def _seg_u8(
    codegen: _DummyCodegen,
    carrier: CVariable,
    offset_expr: object,
    *,
    identity: SegmentedLoadIdentity8616 | None = None,
    ins_addrs: tuple[int, ...] = (),
) -> CFunctionCall:
    """Build one typed ``SEG_U8`` helper access node."""
    tags: dict[str, object] = {"inertia_x86_16_runtime_segment_helper": "SEG_U8"}
    if ins_addrs:
        tags["inertia_source_instruction_addrs"] = ins_addrs
    if identity is not None:
        tags = segmented_load_tags_8616(identity, existing=tags)
    return CFunctionCall("SEG_U8", None, [carrier, offset_expr], codegen=codegen, tags=tags)


def test_runtime_word_store_refuses_unbounded_symbolic_offsets() -> None:
    """DI / DI+1 byte stores stay byte stores: DI can be 0xFFFF and wrap."""
    codegen = _DummyCodegen()
    es = _segment_carrier(codegen, "es")
    di = _register_cvar(codegen, "di")
    di_plus_one = CBinaryOp("Add", di, _constant(codegen, 1), codegen=codegen)
    low = _seg_u8(codegen, es, di, ins_addrs=(_LOW_INS_ADDR,))
    high = _seg_u8(codegen, es, di_plus_one, ins_addrs=(_HIGH_INS_ADDR,))
    ctx = _coalesce_ctx(codegen)

    assert _runtime_word_store_lvalue_8616(ctx, low, high) is None


def test_runtime_word_store_refuses_wrapped_segment_offsets() -> None:
    """A proven ``0xFFFF``/``0x0000`` pair is adjacent in code but wraps the segment."""
    codegen = _DummyCodegen()
    es = _segment_carrier(codegen, "es")
    low = _seg_u8(
        codegen,
        es,
        _constant(codegen, 0xFFFF),
        identity=_identity(MemSpace.ES, 0xFFFF),
        ins_addrs=(_LOW_INS_ADDR,),
    )
    high = _seg_u8(
        codegen,
        es,
        _constant(codegen, 0),
        identity=_identity(MemSpace.ES, 0),
        ins_addrs=(_HIGH_INS_ADDR,),
    )
    ctx = _coalesce_ctx(codegen)

    assert _runtime_word_store_lvalue_8616(ctx, low, high) is None


@pytest.mark.parametrize(
    ("space", "register_name"),
    ((MemSpace.ES, "es"), (MemSpace.DS, "ds")),
)
def test_runtime_word_store_joins_adjacent_typed_identities(
    space: MemSpace,
    register_name: str,
) -> None:
    """Adjacent proven byte identities join into one width-2 word lvalue."""
    codegen = _DummyCodegen()
    carrier = _segment_carrier(codegen, register_name)
    low_offset = _constant(codegen, 0x20)
    low = _seg_u8(
        codegen,
        carrier,
        low_offset,
        identity=_identity(space, 0x20),
        ins_addrs=(_LOW_INS_ADDR,),
    )
    high = _seg_u8(
        codegen,
        carrier,
        _constant(codegen, 0x21),
        identity=_identity(space, 0x21),
        ins_addrs=(_HIGH_INS_ADDR,),
    )
    ctx = _coalesce_ctx(codegen)

    result = _runtime_word_store_lvalue_8616(ctx, low, high)

    assert isinstance(result, CFunctionCall)
    assert result.callee_target == "SEG_U16"
    assert result.args == [carrier, low_offset]
    assert segmented_load_identity_8616(result) == SegmentedLoadIdentity8616(
        space=space,
        offset=0x20,
        width=2,
        region=_FUNC_ADDR,
    )
    assert result.tags["inertia_x86_16_runtime_segment_helper"] == "SEG_U16"
    assert result.tags["inertia_source_instruction_addrs"] == (
        _LOW_INS_ADDR,
        _HIGH_INS_ADDR,
    )


def test_runtime_word_store_refuses_different_spaces() -> None:
    """A DS byte and an ES byte never share one segmented word lvalue."""
    codegen = _DummyCodegen()
    low = _seg_u8(
        codegen,
        _segment_carrier(codegen, "ds"),
        _constant(codegen, 0x20),
        identity=_identity(MemSpace.DS, 0x20),
        ins_addrs=(_LOW_INS_ADDR,),
    )
    high = _seg_u8(
        codegen,
        _segment_carrier(codegen, "es"),
        _constant(codegen, 0x21),
        identity=_identity(MemSpace.ES, 0x21),
        ins_addrs=(_HIGH_INS_ADDR,),
    )
    ctx = _coalesce_ctx(codegen)

    assert _runtime_word_store_lvalue_8616(ctx, low, high) is None


def test_runtime_word_store_refuses_different_regions() -> None:
    """Same-space bytes owned by different regions cannot prove one lvalue."""
    codegen = _DummyCodegen()
    es = _segment_carrier(codegen, "es")
    low = _seg_u8(
        codegen,
        es,
        _constant(codegen, 0x20),
        identity=_identity(MemSpace.ES, 0x20, region=0x10560),
        ins_addrs=(_LOW_INS_ADDR,),
    )
    high = _seg_u8(
        codegen,
        es,
        _constant(codegen, 0x21),
        identity=_identity(MemSpace.ES, 0x21, region=0x20560),
        ins_addrs=(_HIGH_INS_ADDR,),
    )
    ctx = _coalesce_ctx(codegen)

    assert _runtime_word_store_lvalue_8616(ctx, low, high) is None


def test_runtime_word_store_refuses_untagged_concrete_offsets() -> None:
    """Adjacent constants without typed identity carry no alias proof."""
    codegen = _DummyCodegen()
    es = _segment_carrier(codegen, "es")
    low = _seg_u8(codegen, es, _constant(codegen, 0x20), ins_addrs=(_LOW_INS_ADDR,))
    high = _seg_u8(codegen, es, _constant(codegen, 0x21), ins_addrs=(_HIGH_INS_ADDR,))
    ctx = _coalesce_ctx(codegen)

    assert _runtime_word_store_lvalue_8616(ctx, low, high) is None


def test_runtime_word_store_does_not_fabricate_space_from_register_name() -> None:
    """A carrier merely named ``es`` without the ES register offset is no proof."""
    codegen = _DummyCodegen()
    di_offset, di_size = codegen.project.arch.registers["di"]
    fake_es = CVariable(
        SimRegisterVariable(di_offset, di_size, name="es"),
        codegen=codegen,
    )
    low = _seg_u8(codegen, fake_es, _constant(codegen, 0x20), ins_addrs=(_LOW_INS_ADDR,))
    high = _seg_u8(codegen, fake_es, _constant(codegen, 0x21), ins_addrs=(_HIGH_INS_ADDR,))
    ctx = _coalesce_ctx(codegen)

    assert _runtime_word_store_lvalue_8616(ctx, low, high) is None
