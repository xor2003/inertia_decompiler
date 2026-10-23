"""Actual C-AST output observation, freshness and explicit unsupported boundaries."""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest
from angr import ailment
from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.rustylib.ailment import Tags, VirtualVariableCategory
from angr.sim_type import SimType, SimTypeFunction, SimTypeShort
from angr.sim_variable import SimVariable

from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.ir.core import MemSpace
from inertia.lowering.carry_borrow_bit_contracts import CarryBorrowBitLoweringFact8616
from inertia.lowering.codegen_return_origin import ReturnValueOrigin8616
from inertia.lowering.stack_variable_binding import StackVariableBinding
from inertia.pipeline.structured_ast_output import (
    StructuredASTFailure8616,
    StructuredASTPublicationOwnership8616,
    observe_structured_ast_output_8616,
    publish_structured_ast_output_8616,
)
from inertia.semantics.carry_borrow_contracts import CarryBorrowKind8616
from inertia.structuring.condition_chain_provenance import ConditionChainProvenance8616
from inertia.widening.segmented_load_identity import SegmentedLoadIdentity8616

pytestmark = pytest.mark.decompiler

_CARRY_FACT_8616 = CarryBorrowBitLoweringFact8616(
    0x1000, CarryBorrowKind8616.ADD_WITH_CARRY, 0x1000, 0x1004, 0x1008, 0x100C,
)


@pytest.mark.parametrize("replacement", [
    ConditionChainProvenance8616((0x1008, 0x1004)),
    ConditionChainProvenance8616((0x1004, 0x1010)),
    ConditionChainProvenance8616((0x1004,)),
])
def test_condition_chain_provenance_preserves_order_and_membership(
    replacement: ConditionChainProvenance8616,
) -> None:
    """Changing or reordering consumed JCC identities invalidates the output version."""
    codegen, constant = _actual_ast()
    constant.tags["condition_chain"] = ConditionChainProvenance8616((0x1004, 0x1008))
    publication = publish_structured_ast_output_8616(codegen)
    assert publication.observation.complete
    constant.tags["condition_chain"] = replacement
    assert publication.current_snapshot() != publication.observation.snapshot


@pytest.mark.parametrize("replacement", [
    StackVariableBinding(-6, 2, var_name="local_word"),
    StackVariableBinding(-4, 4, var_name="local_word"),
    StackVariableBinding(-4, 2, var_name="renamed_word"),
    StackVariableBinding(-4, 2, var_name="local_word", is_stable=False),
])
def test_stack_binding_preserves_each_live_owned_field(replacement: StackVariableBinding) -> None:
    """Stack coordinates, width, name and stability remain live AST dependencies."""
    codegen, constant = _actual_ast()
    binding = StackVariableBinding(-4, 2, var_name="local_word")
    constant.tags["stack_binding"] = binding
    publication = publish_structured_ast_output_8616(codegen)
    assert publication.observation.complete
    binding.bp_offset = replacement.bp_offset
    binding.size = replacement.size
    binding.var_name = replacement.var_name
    binding.is_stable = replacement.is_stable
    assert publication.current_snapshot() != publication.observation.snapshot


@pytest.mark.parametrize("replacement", [
    replace(_CARRY_FACT_8616, function_addr=0x2000),
    replace(_CARRY_FACT_8616, kind=CarryBorrowKind8616.SUB_WITH_BORROW),
    replace(_CARRY_FACT_8616, low_block_addr=0x1010),
    replace(_CARRY_FACT_8616, low_ins_addr=0x1014),
    replace(_CARRY_FACT_8616, high_block_addr=0x1018),
    replace(_CARRY_FACT_8616, high_ins_addr=0x101C),
])
def test_lowered_carry_borrow_fact_is_complete_and_live(
    replacement: CarryBorrowBitLoweringFact8616,
) -> None:
    """Every consumed low/high instruction coordinate remains part of AST evidence."""
    codegen, constant = _actual_ast()
    constant.tags["lowered_bit_fact"] = _CARRY_FACT_8616
    original = observe_structured_ast_output_8616(codegen)
    assert original.complete
    constant.tags["lowered_bit_fact"] = replacement
    changed = observe_structured_ast_output_8616(codegen)
    assert changed.complete
    assert changed.snapshot != original.snapshot


@pytest.mark.parametrize(
    "replacement",
    [
        SegmentedLoadIdentity8616(MemSpace.ES, 0x20, 2, None),
        SegmentedLoadIdentity8616(MemSpace.DS, 0x22, 2, None),
        SegmentedLoadIdentity8616(MemSpace.DS, 0x20, 4, None),
        SegmentedLoadIdentity8616(MemSpace.DS, 0x20, 2, 1),
    ],
)
def test_segmented_storage_identity_is_complete_and_live(
    replacement: SegmentedLoadIdentity8616,
) -> None:
    """Every alias-proven segmented identity field survives into AST evidence."""
    codegen, constant = _actual_ast()
    constant.tags["storage_identity"] = SegmentedLoadIdentity8616(MemSpace.DS, 0x20, 2, None)
    original = observe_structured_ast_output_8616(codegen)
    assert original.complete
    constant.tags["storage_identity"] = replacement
    changed = observe_structured_ast_output_8616(codegen)
    assert changed.complete
    assert changed.snapshot != original.snapshot


class _Types:
    def __init__(self) -> None:
        self.owned: tuple[SimType, ...] = ()

    def iter_own(self) -> tuple[SimType, ...]:
        return self.owned


class _Manager:
    def __init__(self) -> None:
        self.types = _Types()

    def get_variable_type(self, variable: SimVariable) -> SimType | None:
        return None


class _Codegen:
    def __init__(self) -> None:
        self._index = 0
        self.project = SimpleNamespace(arch=Arch86_16())
        self.cfunc: object | None = None

    def next_ident(self, name: str) -> str:
        return name

    def next_node_idx(self) -> int:
        self._index += 1
        return self._index


def _actual_ast() -> tuple[_Codegen, structured_c.CConstant]:
    generator = _Codegen()
    arch = Arch86_16()
    value_type = SimTypeShort(signed=False).with_arch(arch)
    constant = structured_c.CConstant(3, value_type, codegen=generator)
    body = structured_c.CReturn(constant, codegen=generator)
    generator.cfunc = structured_c.CFunction(
        0x1000, "example", SimTypeFunction([], value_type).with_arch(arch), [],
        body, {}, _Manager(), codegen=generator,
    )
    return generator, constant


def _dirty_virtual_variable_ast() -> tuple[_Codegen, ailment.Expr.VirtualVariable]:
    """Retain the actual native expression carried by a C dirty-expression node."""
    generator, _constant = _actual_ast()
    expression = ailment.Expr.VirtualVariable(
        1, 2, 16, VirtualVariableCategory.REGISTER, oident=16,
    )
    assert isinstance(generator.cfunc, structured_c.CFunction)
    generator.cfunc.statements = structured_c.CReturn(
        structured_c.CDirtyExpression(expression, codegen=generator), codegen=generator,
    )
    return generator, expression


@pytest.mark.parametrize("field", ["idx", "varid", "bits", "category", "oident", "tags"])
def test_dirty_virtual_variable_content_is_complete_and_live(field: str) -> None:
    """Every native variable field participates in the retained output version."""
    generator, expression = _dirty_virtual_variable_ast()
    publication = publish_structured_ast_output_8616(generator)
    assert publication.observation.complete
    assert publication.current_snapshot() == publication.observation.snapshot
    # These setters belong to the installed native AIL boundary.
    if field == "idx":
        expression.idx = 3
    elif field == "bits":
        expression.bits = 32
    elif field == "tags":
        expression.tags["ins_addr"] = 0x1004
    else:
        # Native identity fields are immutable; replace the actual AST payload.
        replacement = ailment.Expr.VirtualVariable(
            expression.idx, 4 if field == "varid" else expression.varid,
            expression.bits,
            VirtualVariableCategory.STACK if field == "category" else expression.category,
            oident=20 if field == "oident" else expression.oident,
        )
        assert isinstance(generator.cfunc, structured_c.CFunction)
        assert isinstance(generator.cfunc.statements, structured_c.CReturn)
        assert isinstance(generator.cfunc.statements.retval, structured_c.CDirtyExpression)
        generator.cfunc.statements.retval.dirty = replacement
    assert publication.current_snapshot() != publication.observation.snapshot


def test_dirty_virtual_variable_unknown_tag_still_refuses() -> None:
    """Supporting native variables must not discard unrepresentable metadata."""
    generator, expression = _dirty_virtual_variable_ast()
    expression.tags["unrepresentable"] = object()
    observation = observe_structured_ast_output_8616(generator)
    assert not observation.complete
    assert observation.failure is StructuredASTFailure8616.FIELD_UNSUPPORTED
    assert observation.field_path[-2:] == ("tags", "value")


def test_actual_ast_snapshot_is_repeatable_and_does_not_render_c() -> None:
    """Observe actual nodes twice without invoking the renderer."""
    generator, _constant = _actual_ast()
    first = observe_structured_ast_output_8616(generator)
    second = observe_structured_ast_output_8616(generator)
    assert first.complete and second.complete
    assert first.snapshot == second.snapshot
    assert first.snapshot is not None and first.snapshot.node_visits >= 3


def test_snapshot_retains_old_output_and_detects_changed_return_value() -> None:
    """Changing an operand invalidates the digest but preserves the old snapshot."""
    generator, constant = _actual_ast()
    before = observe_structured_ast_output_8616(generator)
    assert before.snapshot is not None
    original = before.snapshot.payload_json
    constant.value = 4
    after = observe_structured_ast_output_8616(generator)
    assert after.snapshot is not None
    assert before.snapshot.digest != after.snapshot.digest
    assert before.snapshot.payload_json == original


def test_unknown_tag_data_is_an_explicit_non_result() -> None:
    """Unmodelled producer metadata cannot become a successful publication."""
    generator, constant = _actual_ast()
    constant.tags["unknown_producer_data"] = object()
    observed = observe_structured_ast_output_8616(generator)
    assert not observed.complete and observed.snapshot is None
    assert observed.failure is StructuredASTFailure8616.FIELD_UNSUPPORTED
    assert "tags" in observed.field_path


def test_missing_root_is_not_an_empty_completed_output() -> None:
    """An absent AST must remain a typed non-result."""
    observed = observe_structured_ast_output_8616(SimpleNamespace())
    assert not observed.complete
    assert observed.failure is StructuredASTFailure8616.ROOT_UNAVAILABLE


def test_unavailable_manager_cannot_imply_no_local_declarations() -> None:
    """Missing declaration evidence cannot imply an empty declaration set."""
    generator, _constant = _actual_ast()
    assert isinstance(generator.cfunc, structured_c.CFunction)
    generator.cfunc.variable_manager = None
    observed = observe_structured_ast_output_8616(generator)
    assert not observed.complete
    assert observed.failure is StructuredASTFailure8616.MANAGER_UNAVAILABLE


def test_type_mutation_invalidates_the_snapshot() -> None:
    """The output identity includes the operand type and its signedness."""
    generator, constant = _actual_ast()
    before = observe_structured_ast_output_8616(generator)
    assert before.snapshot is not None
    constant._type.signed = True
    after = observe_structured_ast_output_8616(generator)
    assert after.snapshot is not None
    assert before.snapshot.digest != after.snapshot.digest


def test_runtime_generator_backreference_is_not_traversed() -> None:
    """Execution context may contain cycles without making output recursive."""
    generator, _constant = _actual_ast()
    generator.project.generator = generator
    assert observe_structured_ast_output_8616(generator).complete


def test_cycle_in_actual_ast_data_is_a_typed_refusal() -> None:
    """A cycle in producer data must refuse rather than truncate a snapshot."""
    generator, constant = _actual_ast()
    cycle: list[object] = []
    cycle.append(cycle)
    constant.tags["cycle"] = cycle
    observed = observe_structured_ast_output_8616(generator)
    assert observed.failure is StructuredASTFailure8616.CYCLIC_AST
    assert observed.snapshot is None


def test_rust_tags_are_observed_without_dropping_fields() -> None:
    """The real native tag view supports changes and unknown-value refusals."""
    generator, constant = _actual_ast()
    constant.tags = Tags({"ins_addr": 0x1000})
    first = observe_structured_ast_output_8616(generator)
    assert first.snapshot is not None
    constant.tags["ins_addr"] = 0x1001
    second = observe_structured_ast_output_8616(generator)
    assert second.snapshot is not None
    assert first.snapshot.digest != second.snapshot.digest
    constant.tags["unknown"] = object()
    refused = observe_structured_ast_output_8616(generator)
    assert refused.failure is StructuredASTFailure8616.FIELD_UNSUPPORTED


def test_return_origin_transport_is_part_of_the_output() -> None:
    """A changed return-source contract must change the observed output."""
    generator, constant = _actual_ast()
    constant.tags["origin"] = ReturnValueOrigin8616(0x1000, 0x1000, 16)
    first = observe_structured_ast_output_8616(generator)
    assert first.snapshot is not None
    constant.tags["origin"] = ReturnValueOrigin8616(0x1001, 0x1000, 16)
    second = observe_structured_ast_output_8616(generator)
    assert second.snapshot is not None
    assert first.snapshot.digest != second.snapshot.digest


@pytest.mark.parametrize("field", ["return_instruction_addr", "return_block_addr"])
def test_actual_return_coordinates_are_part_of_the_output(field: str) -> None:
    """A RET-location mutation must invalidate live output independently of its value origin."""
    generator, constant = _actual_ast()
    origin = ReturnValueOrigin8616(0x1000, 0x1000, 16, 0x1200, 0x1100)
    constant.tags["origin"] = origin
    first = observe_structured_ast_output_8616(generator)
    constant.tags["origin"] = replace(origin, **{field: 0x1300})
    second = observe_structured_ast_output_8616(generator)
    assert first.snapshot is not None and second.snapshot is not None
    assert first.snapshot.digest != second.snapshot.digest


def test_numeric_capture_evidence_is_represented_and_mutation_visible() -> None:
    """The new owned scalar capture must survive strict output observation in full."""
    from inertia.alias.numeric_stack_pointer_values import NumericStackPointerAssignment8616
    from inertia.lowering.entry_stack_pointer_capture import EntryStackPointerCapture8616
    from inertia.semantics.numeric_stack_pointer_returns import NumericStackPointerReturn8616
    from inertia.semantics.register_definition_return import RegisterReturnPath8616

    assignment = NumericStackPointerAssignment8616(0x1000, 0x1007, 68, 0x100a, "ax", -2)
    proof = NumericStackPointerReturn8616(assignment, RegisterReturnPath8616(0x100a, "ax", (0x1007,), 0x100f))
    marker = EntryStackPointerCapture8616(0x1000, (proof,))
    generator, constant = _actual_ast()
    constant.tags["capture"] = marker
    first = observe_structured_ast_output_8616(generator)
    assert first.complete and first.snapshot is not None
    changed = replace(proof, assignment=replace(assignment, entry_sp_offset=-4))
    constant.tags["capture"] = replace(marker, uses=(changed,))
    second = observe_structured_ast_output_8616(generator)
    assert second.snapshot is not None
    assert second.snapshot.digest != first.snapshot.digest


@pytest.mark.parametrize("changed_field", ["function_addr", "callee_entry_offset"])
def test_shared_capture_call_scope_is_represented(changed_field: str) -> None:
    """Both capture scope and call-input position belong to the exact snapshot."""
    from inertia.alias.call_stack_positions import CallStackPosition8616
    from inertia.lowering.entry_stack_pointer_capture import EntryStackPointerCapture8616

    proof = CallStackPosition8616(0x1000, 0x1000, 34, 0x1000, 0x1008, 0x1003, 2, 0, -2, 0)
    marker = EntryStackPointerCapture8616(0x1000, (proof,))
    generator, constant = _actual_ast()
    constant.tags["capture"] = marker
    first = observe_structured_ast_output_8616(generator)
    assert first.complete and first.snapshot is not None
    changed = (replace(marker, function_addr=0x2000) if changed_field == "function_addr"
               else replace(marker, uses=(replace(proof, callee_entry_offset=-4),)))
    constant.tags["capture"] = changed
    second = observe_structured_ast_output_8616(generator)
    assert second.complete and second.snapshot is not None
    assert second.snapshot.digest != first.snapshot.digest


def test_local_declaration_manager_is_observed() -> None:
    """Local type definitions used by emission belong to the AST publication."""
    generator, _constant = _actual_ast()
    first = observe_structured_ast_output_8616(generator)
    assert first.snapshot is not None
    assert isinstance(generator.cfunc, structured_c.CFunction)
    generator.cfunc.variable_manager.types.owned = (SimTypeShort(signed=True).with_arch(generator.project.arch),)
    second = observe_structured_ast_output_8616(generator)
    assert second.snapshot is not None
    assert first.snapshot.digest != second.snapshot.digest


def test_live_publication_detects_mutation_before_handoff() -> None:
    """A producer cannot hand off data changed since its publication."""
    generator, constant = _actual_ast()
    publication = publish_structured_ast_output_8616(generator)
    original = publication.current_snapshot()
    assert original is not None
    constant.value = 4
    assert publication.current_snapshot() != original
    assert publication.handoff_to_rewrite(generator) is StructuredASTFailure8616.HANDOFF_OUTPUT_CHANGED
    assert publication.ownership is StructuredASTPublicationOwnership8616.LIVE


def test_handoff_retains_consumed_input_while_rewrite_publishes_new_output() -> None:
    """Authorized cleanup changes the output version without changing its input."""
    generator, constant = _actual_ast()
    structuring = publish_structured_ast_output_8616(generator)
    original = structuring.current_snapshot()
    assert original is not None
    assert structuring.handoff_to_rewrite(generator) is None
    assert isinstance(generator.cfunc, structured_c.CFunction)
    generator.cfunc.name = "renamed_example"
    assert structuring.current_snapshot() == original
    rewrite = publish_structured_ast_output_8616(generator)
    assert rewrite.current_snapshot() is not None
    assert rewrite.current_snapshot() != original
    final = rewrite.current_snapshot()
    constant.value = 5
    assert rewrite.current_snapshot() != final


def test_handoff_requires_actual_consumer_and_cannot_be_repeated() -> None:
    """A matching foreign AST cannot take ownership of the produced object."""
    generator, _constant = _actual_ast()
    foreign, _foreign_constant = _actual_ast()
    publication = publish_structured_ast_output_8616(generator)
    assert publication.handoff_to_rewrite(foreign) is StructuredASTFailure8616.HANDOFF_GENERATOR_CHANGED
    assert publication.ownership is StructuredASTPublicationOwnership8616.LIVE
    assert publication.handoff_to_rewrite(generator) is None
    assert publication.handoff_to_rewrite(generator) is StructuredASTFailure8616.ALREADY_HANDED_OFF


def test_failed_publication_requires_explicit_new_producer_record() -> None:
    """Removing unknown data cannot silently turn a failed publication valid."""
    generator, constant = _actual_ast()
    constant.tags["unknown"] = object()
    publication = publish_structured_ast_output_8616(generator)
    assert publication.current_snapshot() is None
    del constant.tags["unknown"]
    assert publication.current_snapshot() is None
    assert publication.handoff_to_rewrite(generator) is StructuredASTFailure8616.FIELD_UNSUPPORTED
    assert publish_structured_ast_output_8616(generator).current_snapshot() is not None
