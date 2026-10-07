from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimTemporaryVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16

from inertia.semantics.expression_analysis import (
    VirtualValueIdentity8616,
    VirtualValueIdentityKind8616,
    _constant_int_value,
    _mk_fp_components,
    _unwrap_c_casts,
    describe_virtual_value_identity_8616,
)


class _Codegen:
    def __init__(self) -> None:
        self._next_idx = 0
        self.project = SimpleNamespace(arch=Arch86_16())

    def next_idx(self, _name: str) -> int:
        self._next_idx += 1
        return self._next_idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _const(value: int) -> structured_c.CConstant:
    return structured_c.CConstant(value, SimTypeShort(False), codegen=_Codegen())


def test_unwrap_c_casts_returns_inner_expression() -> None:
    inner = _const(0x1234)
    cast = structured_c.CTypeCast(SimTypeShort(False), SimTypeShort(False), inner, codegen=_Codegen())

    assert _unwrap_c_casts(cast) is inner
    assert _constant_int_value(cast) == 0x1234


def test_mk_fp_components_requires_constant_segment_and_offset() -> None:
    call = structured_c.CFunctionCall("MK_FP", None, [_const(0xB800), _const(0x0040)], codegen=_Codegen())

    assert _mk_fp_components(call) == (0xB800, 0x0040)


def test_mk_fp_components_rejects_non_mk_fp_calls() -> None:
    call = structured_c.CFunctionCall("OTHER", None, [_const(0xB800), _const(0x0040)], codegen=_Codegen())

    assert _mk_fp_components(call) is None


def test_virtual_value_identity_prefers_structured_varid() -> None:
    dirty = SimpleNamespace(varid=37, idx=12, oident=99, name="ignored")
    expression = structured_c.CDirtyExpression(dirty, codegen=_Codegen())

    identity = describe_virtual_value_identity_8616(expression)

    assert identity == VirtualValueIdentity8616(VirtualValueIdentityKind8616.VARIABLE_ID, 37)


def test_virtual_value_identity_refuses_dirty_name_only() -> None:
    expression = structured_c.CDirtyExpression(SimpleNamespace(name="vvar_37"), codegen=_Codegen())
    expression.idx = None

    assert describe_virtual_value_identity_8616(expression) is None


def test_virtual_value_identity_uses_typed_temporary_id() -> None:
    expression = structured_c.CVariable(
        SimTemporaryVariable(7, 16),
        codegen=_Codegen(),
    )

    assert describe_virtual_value_identity_8616(expression) == VirtualValueIdentity8616(
        VirtualValueIdentityKind8616.TEMPORARY_ID,
        7,
    )
