from __future__ import annotations

"""Regression tests for stack variable binding and lowering.

AGENTS rule: SS:BP-offset becomes a named stack variable only from proven
stack evidence. Unknown positive BP offsets remain locals unless the function
argument list proves they are arguments.
"""

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeChar, SimTypeLong, SimTypeShort
from angr.sim_variable import SimStackVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir.core import (
    AddressStatus,
    IRAddress,
    MemSpace,
    SegmentOrigin,
)

from inertia.alias.alias_model_impl import (
    AliasFailure,
    AliasStorageFacts,
    _stack_storage_facts_for_segmented_address_8616,
    _StackSlotIdentity,
    alias_facts_for_ir_address_8616,
)
from inertia.lowering.stack_lowering_from_facts import (
    build_stack_variable_bindings_from_alias_facts_8616,
)
from inertia.lowering.stack_lowering_impl import (
    _prefer_bound_stack_cvar_8616,
    _resolve_stack_cvar_at_offset,
)


class _StackResolutionCodegen:
    """Minimal angr codegen boundary for stack-object identity regressions."""

    def __init__(self) -> None:
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cstyle_null_cmp = False
        self._idx = 0
        self.cfunc = SimpleNamespace(arg_list=[], variables_in_use={})

    def next_idx(self, _name: str) -> int:
        """Return a stable synthetic structured-C node index."""
        self._idx += 1
        return self._idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _stack_slot_identity(variable: object) -> tuple[object, object, object] | None:
    """Return exact stack identity for direct resolver tests."""
    if not isinstance(variable, SimStackVariable):
        return None
    return variable.base, variable.offset, variable.size


def _stack_cvar(
    codegen: _StackResolutionCodegen,
    offset: int,
    size: int,
    name: str,
    variable_type: object,
) -> structured_c.CVariable:
    """Build and register one stack C variable for resolver tests."""
    variable = SimStackVariable(offset, size, base="bp", name=name, region=0x1000)
    cvar = structured_c.CVariable(variable, variable_type=variable_type, codegen=codegen)
    codegen.cfunc.variables_in_use[variable] = cvar
    return cvar


def test_stack_resolution_keeps_exact_byte_over_unproven_covering_dword() -> None:
    """An overlapping object is not alias proof that an exact byte belongs to it."""
    codegen = _StackResolutionCodegen()
    exact = _stack_cvar(codegen, -82, 1, "local_52", SimTypeChar(False))
    _stack_cvar(codegen, -85, 4, "local_55", SimTypeLong(False))

    resolved = _resolve_stack_cvar_at_offset(
        codegen,
        -82,
        stack_slot_identity_for_variable=_stack_slot_identity,
        preferred_size=1,
    )

    assert resolved is exact


def test_bound_stack_resolution_requires_matching_width() -> None:
    """Same-offset scalar and wide views remain distinct without widening proof."""
    codegen = _StackResolutionCodegen()
    _stack_cvar(codegen, -2, 4, "iRow", SimTypeLong(False))
    exact = _stack_cvar(codegen, -2, 2, "local_2", SimTypeShort(False))
    detached_var = SimStackVariable(-2, 2, base="bp", name="local_2", region=0x1000)
    detached = structured_c.CVariable(detached_var, variable_type=SimTypeShort(False), codegen=codegen)

    resolved = _prefer_bound_stack_cvar_8616(
        codegen,
        detached,
        lambda owner, offset: _resolve_stack_cvar_at_offset(
            owner,
            offset,
            stack_slot_identity_for_variable=_stack_slot_identity,
            preferred_size=detached_var.size,
        ),
    )

    assert resolved is exact


class TestStackObjectNaming:
    """Stack variable names must not guess arguments from positive offsets alone."""

    def test_stack_object_name_negative(self):
        from inertia.lowering.stack_lowering_impl import _stack_object_name

        name = _stack_object_name(-2)
        assert name.startswith("local_"), f"Expected local_ prefix, got {name}"
        assert "2" in name or "fffe" in name.lower()

    def test_stack_object_name_positive(self):
        from inertia.lowering.stack_lowering_impl import _stack_object_name

        name = _stack_object_name(4)
        assert name.startswith("local_"), f"Expected local_ prefix without argument evidence, got {name}"
        assert "4" in name

    def test_stack_object_name_zero(self):
        from inertia.lowering.stack_lowering_impl import _stack_object_name

        name = _stack_object_name(0)
        assert name.startswith("local_"), f"Expected local_ prefix for offset 0 without argument evidence, got {name}"
        assert "0" in name

    def test_stack_object_name_positive_with_argument_evidence(self):
        from angr.sim_variable import SimStackVariable

        from inertia.lowering.stack_lowering_impl import _stack_object_name

        cfunc = SimpleNamespace(arg_list=[SimpleNamespace(variable=SimStackVariable(4, 2, base="bp"))])
        codegen = SimpleNamespace(cfunc=cfunc)

        assert _stack_object_name(4, codegen=codegen) == "arg_4"

    def test_unknown_positive_stack_slot_uses_local_name_in_codegen_context(self):
        from angr.analyses.decompiler.structured_codegen import c as structured_c
        from angr.sim_variable import SimStackVariable

        from inertia.lowering.stack_lowering_impl import _materialize_stack_cvar_at_offset

        class _FakeCodegen:
            def __init__(self):
                self.project = SimpleNamespace(arch=Arch86_16())
                self.cstyle_null_cmp = False
                self._idx = 0
                self.cfunc = SimpleNamespace(
                    addr=0x1000,
                    arg_list=[],
                    variables_in_use={},
                    unified_local_vars={},
                    sort_local_vars=lambda: None,
                )

            def next_idx(self, _name):
                self._idx += 1
                return self._idx
            def next_node_idx(self) -> int:
                return self.next_idx("")
            def next_ident(self, name: str) -> str:
                return name

        codegen = _FakeCodegen()
        arg_var = SimStackVariable(4, 2, base="bp", name="arg", region=0x1000)
        arg_type = SimTypeShort(False)
        codegen.cfunc.arg_list = [SimpleNamespace(variable=arg_var)]
        codegen.cfunc.variables_in_use = {
            arg_var: structured_c.CVariable(arg_var, variable_type=arg_type, codegen=codegen)
        }

        materialized = _materialize_stack_cvar_at_offset(
            codegen,
            6,
            2,
            resolve_stack_cvar_at_offset=lambda *_args, **_kwargs: None,
            promote_direct_stack_cvariable=lambda *_args, **_kwargs: None,
            stack_type_for_size=lambda size: SimTypeShort(False),
        )

        assert materialized is not None
        materialized_name = getattr(getattr(materialized, "variable", None), "name", None)
        assert materialized_name == "local_6"


class TestStackSlotIdentity:
    """_StackSlotIdentity must track base, offset, width."""

    def test_basic_identity(self):
        slot = _StackSlotIdentity(base="bp", offset=-2, width=2)
        assert slot.base == "bp"
        assert slot.offset == -2
        assert slot.width == 2

    def test_can_join_adjacent(self):
        slot_a = _StackSlotIdentity(base="bp", offset=-4, width=2)
        slot_b = _StackSlotIdentity(base="bp", offset=-2, width=2)
        assert slot_a.can_join(slot_b)

    def test_can_join_adjacent_reverse(self):
        slot_a = _StackSlotIdentity(base="bp", offset=-2, width=2)
        slot_b = _StackSlotIdentity(base="bp", offset=-4, width=2)
        assert slot_b.can_join(slot_a)

    def test_join_adjacent(self):
        slot_a = _StackSlotIdentity(base="bp", offset=-4, width=2)
        slot_b = _StackSlotIdentity(base="bp", offset=-2, width=2)
        joined = slot_a.join(slot_b)
        assert joined is not None
        assert joined.offset == -4
        assert joined.width == 4

    def test_cannot_join_different_base(self):
        slot_a = _StackSlotIdentity(base="bp", offset=-2, width=2)
        slot_b = _StackSlotIdentity(base="sp", offset=-2, width=2)
        assert not slot_a.can_join(slot_b)

    def test_cannot_join_gapped(self):
        slot_a = _StackSlotIdentity(base="bp", offset=-4, width=2)
        slot_b = _StackSlotIdentity(base="bp", offset=-1, width=2)
        assert not slot_a.can_join(slot_b)

    def test_sp_remains_distinct_from_bp(self):
        slot = _StackSlotIdentity(base="sp", offset=-2, width=2)
        assert slot.base == "sp"

    def test_ss_does_not_invent_a_bp_frame(self):
        slot = _StackSlotIdentity(base="ss", offset=-2, width=2)
        assert slot.base == "ss"


class TestStackStorageFactsForSegmentedAddress:
    """SS segment must produce stack storage facts."""

    def test_ss_negative_offset_produces_stack_facts(self):
        facts = _stack_storage_facts_for_segmented_address_8616("ss", -2, 2)
        assert facts is not None
        assert isinstance(facts, AliasStorageFacts)
        assert facts.identity[0] == "stack"
        slot = facts.identity[1]
        assert slot.offset == -2
        assert slot.width == 2

    def test_ss_positive_offset_produces_stack_facts(self):
        facts = _stack_storage_facts_for_segmented_address_8616("ss", 4, 2)
        assert facts is not None
        slot = facts.identity[1]
        assert slot.offset == 4
        assert slot.width == 2

    def test_ds_does_not_produce_stack_facts(self):
        facts = _stack_storage_facts_for_segmented_address_8616("ds", 0, 2)
        assert facts is None

    def test_non_int_offset_is_rejected(self):
        facts = _stack_storage_facts_for_segmented_address_8616("ss", None, 2)
        assert facts is None

    def test_non_ss_segment_rejected(self):
        facts = _stack_storage_facts_for_segmented_address_8616(None, -2, 2)
        assert facts is None

    def test_stack_binding_builder_ignores_non_storage_fact_objects(self):
        stack_fact = _stack_storage_facts_for_segmented_address_8616("ss", -2, 2)
        assert stack_fact is not None

        bindings = build_stack_variable_bindings_from_alias_facts_8616([object(), stack_fact])

        assert len(bindings) == 1
        assert bindings[0].bp_offset == -2
        assert bindings[0].size == 2


class TestAliasFactsForIRAddress:
    """The canonical Alias entry point must classify or explicitly refuse."""

    def test_ss_stack_address_produces_alias_facts(self):
        addr = IRAddress(
            space=MemSpace.SS,
            base=("bp",),
            offset=0xFFFC,
            size=2,
            segment_origin=SegmentOrigin.PROVEN,
            status=AddressStatus.STABLE,
        )
        facts = alias_facts_for_ir_address_8616(addr)
        assert facts is not None
        assert isinstance(facts, AliasStorageFacts)

    def test_stable_sp_address_remains_sp_relative(self):
        addr = IRAddress(
            space=MemSpace.SS,
            base=("sp",),
            offset=-2,
            size=2,
            segment_origin=SegmentOrigin.PROVEN,
            status=AddressStatus.STABLE,
        )

        facts = alias_facts_for_ir_address_8616(addr)

        assert isinstance(facts, AliasStorageFacts)
        assert facts.identity is not None
        _, slot = facts.identity
        assert isinstance(slot, _StackSlotIdentity)
        assert slot.base == "sp"

    def test_symbolic_ds_address_requires_indexed_alias_projection(self):
        addr = IRAddress(
            space=MemSpace.DS,
            base=("bx",),
            offset=0x100,
            size=2,
            segment_origin=SegmentOrigin.PROVEN,
        )
        facts = alias_facts_for_ir_address_8616(addr)
        assert isinstance(facts, AliasFailure)
        assert facts.space == "DS"

    def test_symbolic_es_address_requires_indexed_alias_projection(self):
        addr = IRAddress(
            space=MemSpace.ES,
            base=("di",),
            offset=0x200,
            size=2,
            segment_origin=SegmentOrigin.PROVEN,
        )
        facts = alias_facts_for_ir_address_8616(addr)
        assert isinstance(facts, AliasFailure)
        assert facts.space == "ES"

    def test_unknown_space_returns_none(self):
        addr = IRAddress(space=MemSpace.UNKNOWN, offset=0)
        facts = alias_facts_for_ir_address_8616(addr)
        assert facts is None


class TestAliasFailure:
    """AliasFailure signals unresolvable proven addresses."""

    def test_alias_failure_creation(self):
        failure = AliasFailure(
            reason="proven SS space not classifiable as stack slot",
            offset=0xFFFC,
            space="ss",
        )
        assert failure.reason
        assert failure.offset == 0xFFFC
        assert failure.space == "ss"


class TestStackVariableMaterializationDiagnostics:
    """Verify stack variable naming follows the convention."""

    def test_naming_convention_no_bare_stack_index(self):
        """Generated names should never be 'stack[...]'."""
        from inertia.lowering.stack_lowering_impl import _stack_object_name

        for offset in (-10, -2, 0, 4, 6, 8):
            name = _stack_object_name(offset)
            assert "stack[" not in name, f"Offset {offset} produced bad name: {name}"
            assert "(ss" not in name, f"Offset {offset} produced bad name: {name}"
