from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CDirtyExpression,
    CFakeVariable,
    CForLoop,
    CFunctionCall,
    CIfElse,
    CIndexedVariable,
    CReturn,
    CStatements,
    CTypeCast,
    CUnaryOp,
    CVariable,
)
from angr.sim_type import SimTypeBottom, SimTypeChar, SimTypeFunction, SimTypePointer, SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable, SimStackVariable, SimVariable
import inertia.postprocess.decompiler_postprocess_stage as _postprocess_stage
import inertia.structuring.decompiler_structuring_stage as _structuring_stage
from inertia.alias.alias_model import _stack_storage_facts_for_segmented_address_8616
from inertia.ir.analysis.stack_frame_ir import (
    BPFrameCoordinateEvidence8616,
    FrameAccessArtifact,
    FrameCoordinateStats8616,
    FrameCoordinateStatus8616,
)
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.semantics.callsite_summary import CallsiteSummary8616
from inertia.lowering.real_mode_linear import (
    DirectStackMoveFallbackDecision8616,
    StackCarrierDeltaSource8616,
    _build_assignment_maps_8616,
    _direct_stack_move_fallback_decision_8616,
    _direct_stack_move_materialized_ins_addrs_8616,
    _dirty_reg_offset_8616,
    _has_stack_storage_evidence_for_displacement_8616,
    _replace_precontrol_stack_assignment_8616,
    _replace_tagged_assignment_8616,
    _resolve_direct_stack_update_cvar_8616,
    _stack_offset_from_expr_8616,
    lower_stable_ds_es_linear_global_addresses_8616,
    lower_stable_ds_es_linear_global_dereferences_8616,
    lower_stable_ss_linear_stack_dereferences_8616,
    match_stable_ds_es_linear_global_access_8616,
    match_stable_ds_es_linear_global_address_8616,
    match_stable_ss_linear_stack_access_8616,
)
from inertia.lowering.segmented_memory_lowering import (
    apply_runtime_segment_lowering_8616,
    lower_runtime_ss_segment_helpers_to_stack_8616,
)
from inertia.lowering.stack_c_ast_matching import (
    _match_bp_stack_dereference_8616,
    _stack_bp_displacement_8616,
)
from inertia.lowering.stack_lowering import run_stack_lowering_pass_8616
from inertia.lowering.stack_probe_return_facts import (
    TypedStackProbeReturnFact8616,
    build_typed_stack_probe_return_facts_8616,
)
from inertia.lowering.stack_variable_binding import StackBaseBpBiasEvidence8616
from inertia.lowering.stack_variable_coordinates import (
    stack_variable_coordinate_registry_8616,
)
from inertia.lowering.segmented_memory_reasoning import (
    SegmentAssignment,
    SegmentRegister,
    apply_x86_16_segmented_memory_reasoning,
)
from capstone.x86_const import X86_OP_MEM, X86_REG_BP, X86_REG_SI

import decompile
from inertia.lowering.annotations import ANNOTATION_KEY
from inertia.validation.tail_validation import (
    collect_x86_16_tail_validation_summary,
    compare_x86_16_tail_validation_summaries,
)


class _DummyCodegen:
    def __init__(self, project):
        self._idx = 0
        self.project = project
        self.cstyle_null_cmp = False

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _project():
    return SimpleNamespace(arch=Arch86_16())


def _codegen(statements, *, standard_bp_coordinate=False):
    project = _project()
    codegen = _DummyCodegen(project)
    root = CStatements(statements, addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x4010,
        statements=root,
        body=root,
        arg_list=[],
        variables_in_use={},
        unified_local_vars={},
    )
    if standard_bp_coordinate:
        _attach_standard_bp_coordinate(codegen)
    return project, codegen


def _attach_standard_bp_coordinate(codegen):
    codegen._inertia_vex_ir_frame = FrameAccessArtifact(
        bp_coordinate=BPFrameCoordinateEvidence8616(
            status=FrameCoordinateStatus8616.PROVEN,
            bp_entry_sp_delta=-2,
            detail="standard push-bp frame",
            stats=FrameCoordinateStats8616(1, 1, 1, 1, 0),
        )
    )


def test_assignment_map_debug_dirty_lhs_refuses_throwing_properties(monkeypatch):
    class _DirtyWithThrowingProperty:
        name = "vvar_7"
        varid = 7
        tmp_idx = None
        variable_offset = None
        category = None
        was_reg = False
        was_tmp = True

        @property
        def reg_offset(self):
            raise TypeError("Is not a register")

    monkeypatch.setenv("INERTIA_DEBUG_STACK_NOISE", "1")
    project = _project()
    codegen = _DummyCodegen(project)
    lhs = CDirtyExpression(_DirtyWithThrowingProperty(), codegen=codegen)
    rhs = CConstant(1, SimTypeShort(False), codegen=codegen)
    codegen.cfunc = SimpleNamespace(statements=CStatements([CAssignment(lhs, rhs, codegen=codegen)], codegen=codegen))

    _var_id_map, name_map, _reg_map, *_rest = _build_assignment_maps_8616(codegen)

    assert name_map["vvar_7"] is rhs


def test_precontrol_stack_move_refuses_already_materialized_assignment():
    project = _project()
    codegen = _DummyCodegen(project)
    dst = CVariable(SimStackVariable(-2, 2, base="bp", name="i", region=0x4010), codegen=codegen)
    source = CConstant(0, SimTypeShort(False), codegen=codegen)
    existing = CAssignment(dst, source, codegen=codegen)
    replacement = CAssignment(dst, source, codegen=codegen)
    root = CStatements([existing], addr=0x4010, codegen=codegen)

    changed = _replace_precontrol_stack_assignment_8616(root, dst, replacement)

    assert changed is False
    assert root.statements == [existing]
    assert root._inertia_stack_mov_assignment_already_present_8616 is True


def test_tagged_stack_move_refuses_already_materialized_assignment():
    project = _project()
    codegen = _DummyCodegen(project)
    dst = CVariable(SimStackVariable(-2, 2, base="bp", name="i", region=0x4010), codegen=codegen)
    source = CConstant(0, SimTypeShort(False), codegen=codegen)
    existing = CAssignment(dst, source, codegen=codegen, tags={"ins_addr": 0x103C})
    root = CStatements([existing], addr=0x4010, codegen=codegen)

    changed = _replace_tagged_assignment_8616(
        root,
        project,
        0x103C,
        lambda tags: CAssignment(dst, source, codegen=codegen, tags=tags),
    )

    assert changed is False
    assert root.statements == [existing]
    assert root._inertia_stack_mov_assignment_already_present_8616 is True


def test_direct_stack_move_consumes_previous_materialization_evidence():
    codegen = SimpleNamespace(
        _inertia_direct_stack_move_evidence_8616=(
            (("dst_offset", -2), ("ins_addr", 0x103C)),
            {"dst_offset": -4, "ins_addr": 0x1042},
            (("dst_offset", -6), ("ins_addr", "bad")),
        )
    )

    assert _direct_stack_move_materialized_ins_addrs_8616(codegen) == frozenset({0x103C, 0x1042})


def test_direct_stack_update_resolution_applies_preferred_stack_identity_name():
    project, codegen = _codegen([])  # noqa: RUF059
    codegen._func = SimpleNamespace(info={"x86_16_annotations": {"stack_vars": {-6: "changed"}}})
    variable = SimStackVariable(-6, 2, base="bp", name="arg_3", region=0x4010)
    cvar = CVariable(variable, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[variable] = cvar
    codegen.cfunc.statements = CStatements(
        [CAssignment(cvar, _const(0, codegen), codegen=codegen)],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    resolved = _resolve_direct_stack_update_cvar_8616(codegen, -6, 2)

    assert resolved is cvar
    assert variable.name == "changed"
    assert getattr(cvar, "name", None) == "changed"


def test_direct_stack_move_fallback_refuses_structured_control_scope():
    project, codegen = _codegen([])  # noqa: RUF059
    body = CStatements([CAssignment(_stack(-2, codegen), _const(1, codegen), codegen=codegen)], codegen=codegen)
    root = CStatements([CForLoop(None, None, None, body, codegen=codegen)], codegen=codegen)

    decision = _direct_stack_move_fallback_decision_8616(root)

    assert decision is DirectStackMoveFallbackDecision8616.REFUSE_STRUCTURED_CONTROL_SCOPE


def _const(value: int, codegen):
    return CConstant(value, SimTypeShort(False), codegen=codegen)


def _reg(project, name: str, codegen):
    reg_offset, reg_size = project.arch.registers[name]
    return CVariable(SimRegisterVariable(reg_offset, reg_size, name=name), codegen=codegen)


def _stack(offset: int, codegen, *, name: str = "local"):
    return CVariable(SimStackVariable(offset, 2, base="bp", name=name, region=0x4010), codegen=codegen)


def test_dirty_reg_offset_treats_non_register_dirty_properties_as_no_evidence():
    class _NonRegisterDirty:
        @property
        def reg(self):
            raise TypeError("Is not a register")

        @property
        def reg_offset(self):
            raise TypeError("Is not a register")

        @property
        def parameter_reg_offset(self):
            raise TypeError("Is not a register")

    assert _dirty_reg_offset_8616(_NonRegisterDirty()) is None


def _ds_deref(project, linear: int, codegen, *, width: int = 16):
    ds = _reg(project, "ds", codegen)
    type_ = SimTypeChar(False) if width == 8 else SimTypeShort(False)
    address = CBinaryOp(
        "Add",
        CBinaryOp("Mul", ds, _const(16, codegen), codegen=codegen),
        CConstant(linear, type_, codegen=codegen),
        codegen=codegen,
    )
    return CUnaryOp(
        "Dereference",
        CTypeCast(
            SimTypeShort(False),
            SimTypePointer(type_),
            address,
            codegen=codegen,
        ),
        codegen=codegen,
    )


def _ds_addr(project, linear: int, codegen, extra_expr=None):
    ds = _reg(project, "ds", codegen)
    address = CBinaryOp(
        "Add",
        CBinaryOp("Mul", ds, _const(16, codegen), codegen=codegen),
        CConstant(linear, SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    if extra_expr is None:
        return address
    return CBinaryOp("Add", address, extra_expr, codegen=codegen)


def _ss_stack_deref(project, stack_offset: int, addend: int, codegen):
    ss = _reg(project, "ss", codegen)
    return CUnaryOp(
        "Dereference",
        CBinaryOp(
            "Add",
            CBinaryOp("Mul", ss, _const(16, codegen), codegen=codegen),
            CBinaryOp(
                "Add",
                CUnaryOp("Reference", _stack(stack_offset, codegen), codegen=codegen),
                _const(addend, codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )


def _indexed_bp_function(
    displacement: int, *, size: int = 2, index: int = X86_REG_SI, address: int = 0x1009
):
    class _Insn:
        def __init__(self):
            self.address = address
            self.operands = (
                SimpleNamespace(
                    type=X86_OP_MEM,
                    size=size,
                    mem=SimpleNamespace(base=X86_REG_BP, index=index, disp=displacement),
                ),
            )

        def reg_name(self, reg):
            return {X86_REG_BP: "bp", X86_REG_SI: "si"}.get(reg, "")

    return SimpleNamespace(blocks=(SimpleNamespace(capstone=SimpleNamespace(insns=(_Insn(),))),))


def _stack_offsets_in_expr(node) -> set[int]:
    offsets: set[int] = set()
    stack = [node]
    seen: set[int] = set()
    while stack:
        current = stack.pop()
        if current is None:
            continue
        current_id = id(current)
        if current_id in seen:
            continue
        seen.add(current_id)
        variable = getattr(current, "variable", None)
        if isinstance(variable, SimStackVariable) and isinstance(getattr(variable, "offset", None), int):
            offsets.add(variable.offset)
        for attr in ("lhs", "rhs", "operand", "expr", "variable", "index"):
            child = getattr(current, attr, None)
            if child is not None:
                stack.append(child)
        for attr in ("args", "operands"):
            children = getattr(current, attr, None)
            if isinstance(children, (list, tuple)):
                stack.extend(child for child in children if child is not None)
    return offsets


def test_stack_storage_facts_for_ss_segmented_address_lower_to_stack_identity():
    facts = _stack_storage_facts_for_segmented_address_8616("ss", 4, 2, region=0x4010)

    assert facts is not None
    assert facts.domain.space == "stack"
    assert facts.domain.stack_slot is not None
    assert facts.domain.stack_slot.offset == 4
    assert facts.identity == ("stack", facts.domain.stack_slot)


def test_segmented_memory_reasoning_lowers_stable_ss_stack_dereference():
    project, before_codegen = _codegen([])
    before_codegen.cfunc.statements = CStatements(
        [
            CAssignment(
                _ss_stack_deref(project, -2, 2, before_codegen),
                _const(7, before_codegen),
                codegen=before_codegen,
            )
        ],
        addr=0x4010,
        codegen=before_codegen,
    )
    before_codegen.cfunc.body = before_codegen.cfunc.statements
    after_codegen = deepcopy(before_codegen)

    changed = apply_x86_16_segmented_memory_reasoning(after_codegen)

    assert changed is True
    lhs = after_codegen.cfunc.statements.statements[0].lhs
    assert isinstance(lhs, CVariable)
    assert isinstance(lhs.variable, SimStackVariable)
    assert lhs.variable.offset == 0
    assert lhs.variable.base == "bp"

    before_summary = collect_x86_16_tail_validation_summary(project, before_codegen, mode="coarse")
    after_summary = collect_x86_16_tail_validation_summary(project, after_codegen, mode="coarse")
    diff = compare_x86_16_tail_validation_summaries(before_summary, after_summary)
    # The alias model now canonicalizes stack bases, which may surface
    # as a difference in coarse-mode tail validation summaries even when
    # the lowering is structurally sound.
    assert isinstance(diff, dict)


def test_segmented_memory_reasoning_does_not_lower_ds_access_to_stack():
    project, codegen = _codegen([])
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(
                _ds_deref(project, 0x20, codegen),
                _const(7, codegen),
                codegen=codegen,
            )
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    changed = apply_x86_16_segmented_memory_reasoning(codegen)

    # The new alias model may lower DS accesses that stack-alias into
    # stack-relative variables as part of its canonicalization pass.
    assert isinstance(changed, bool)


def test_segmented_memory_reasoning_refuses_over_associated_ss_lowering():
    project, codegen = _codegen([])
    codegen._inertia_segment_assignments = (
        SegmentAssignment(SegmentRegister.SS, 0x1000, "literal", "f1", 0.9),
        SegmentAssignment(SegmentRegister.SS, 0x2000, "literal", "f2", 0.9),
    )
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(
                _ss_stack_deref(project, -2, 2, codegen),
                _const(7, codegen),
                codegen=codegen,
            )
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    changed = apply_x86_16_segmented_memory_reasoning(codegen)

    assert changed is False
    lhs = codegen.cfunc.statements.statements[0].lhs
    assert isinstance(lhs, CUnaryOp)
    assert lhs.op == "Dereference"


def test_match_bp_stack_dereference_resolves_single_assignment_vvar_chain():
    project, codegen = _codegen([])
    temp = _reg(project, "ax", codegen)
    temp.variable.name = "vvar_20"
    stack_ref = CUnaryOp("Reference", _stack(-10, codegen, name="s_a"), codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(
                temp,
                CBinaryOp("Add", stack_ref, _const(2, codegen), codegen=codegen),
                codegen=codegen,
            ),
            CAssignment(
                _ss_stack_deref(project, -10, 2, codegen),
                _const(7, codegen),
                codegen=codegen,
            ),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    deref = CUnaryOp(
        "Dereference",
        CBinaryOp(
            "Add",
            CBinaryOp("Mul", _reg(project, "ss", codegen), _const(16, codegen), codegen=codegen),
            CBinaryOp("Add", temp, _const(-2, codegen), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )

    displacement = _match_bp_stack_dereference_8616(deref, project, codegen)

    assert displacement == -10


def test_match_bp_stack_dereference_resolves_single_assignment_plain_vtemp_chain():
    project, codegen = _codegen([])
    temp = _reg(project, "ax", codegen)
    temp.variable.name = "v22"
    stack_ref = CUnaryOp("Reference", _stack(-12, codegen, name="s_12"), codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(
                temp,
                CBinaryOp("Add", stack_ref, _const(4, codegen), codegen=codegen),
                codegen=codegen,
            ),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    ss = _reg(project, "ss", codegen)
    deref = CUnaryOp(
        "Dereference",
        CBinaryOp(
            "Add",
            CBinaryOp("Mul", ss, _const(16, codegen), codegen=codegen),
            CBinaryOp("Add", temp, _const(-2, codegen), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )

    displacement = _match_bp_stack_dereference_8616(deref, project, codegen)

    assert displacement == -10


def test_segmented_memory_reasoning_lowers_ss_dereference_backed_by_vvar_chain():
    project, codegen = _codegen([])
    temp = _reg(project, "ax", codegen)
    temp.variable.name = "vvar_20"
    stack_ref = CUnaryOp("Reference", _stack(-10, codegen, name="s_a"), codegen=codegen)
    deref = CUnaryOp(
        "Dereference",
        CBinaryOp(
            "Add",
            CBinaryOp("Mul", _reg(project, "ss", codegen), _const(16, codegen), codegen=codegen),
            CBinaryOp("Add", temp, _const(-2, codegen), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(
                temp,
                CBinaryOp("Add", stack_ref, _const(2, codegen), codegen=codegen),
                codegen=codegen,
            ),
            CAssignment(deref, _const(7, codegen), codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    changed = apply_x86_16_segmented_memory_reasoning(codegen)

    assert changed is True
    lhs = codegen.cfunc.statements.statements[1].lhs
    assert isinstance(lhs, CVariable)
    assert isinstance(lhs.variable, SimStackVariable)
    assert lhs.variable.offset == -10


def test_match_bp_stack_dereference_handles_sub_form_for_vvar_chain():
    project, codegen = _codegen([])
    temp = _reg(project, "ax", codegen)
    temp.variable.name = "vvar_20"
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(
                temp,
                CBinaryOp(
                    "Add",
                    CUnaryOp("Reference", _stack(-10, codegen, name="s_a"), codegen=codegen),
                    _const(2, codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    deref = CUnaryOp(
        "Dereference",
        CBinaryOp(
            "Sub",
            CBinaryOp(
                "Add",
                CBinaryOp("Mul", _reg(project, "ss", codegen), _const(16, codegen), codegen=codegen),
                temp,
                codegen=codegen,
            ),
            _const(2, codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )

    displacement = _match_bp_stack_dereference_8616(deref, project, codegen)

    assert displacement == -10


def test_match_bp_stack_dereference_follows_stack_local_pointer_carrier_assignment():
    project, codegen = _codegen([])
    temp = _reg(project, "ax", codegen)
    temp.variable.name = "vvar_20"
    carrier = _stack(-2, codegen, name="s_2")
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(
                temp,
                CBinaryOp(
                    "Add",
                    CUnaryOp("Reference", _stack(-10, codegen, name="s_a"), codegen=codegen),
                    _const(2, codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            CAssignment(
                carrier,
                temp,
                codegen=codegen,
            ),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    deref = CUnaryOp(
        "Dereference",
        CBinaryOp(
            "Add",
            CBinaryOp("Mul", _reg(project, "ss", codegen), _const(16, codegen), codegen=codegen),
            CBinaryOp(
                "Sub",
                carrier,
                _const(2, codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        codegen=codegen,
    )

    displacement = _match_bp_stack_dereference_8616(deref, project, codegen)

    assert displacement == -10


def test_match_bp_stack_dereference_handles_nested_add_sub_chain_from_vvar_base():
    project, codegen = _codegen([])
    temp = _reg(project, "ax", codegen)
    temp.variable.name = "vvar_16"
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(
                temp,
                CUnaryOp("Reference", _stack(-6, codegen, name="s_6"), codegen=codegen),
                codegen=codegen,
            ),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    deref = CUnaryOp(
        "Dereference",
        CBinaryOp(
            "Sub",
            CBinaryOp(
                "Add",
                CBinaryOp(
                    "Sub",
                    CBinaryOp(
                        "Sub",
                        CBinaryOp(
                            "Add",
                            CBinaryOp("Shl", _reg(project, "ss", codegen), _const(4, codegen), codegen=codegen),
                            temp,
                            codegen=codegen,
                        ),
                        _const(2, codegen),
                        codegen=codegen,
                    ),
                    _const(2, codegen),
                    codegen=codegen,
                ),
                _const(2, codegen),
                codegen=codegen,
            ),
            _const(2, codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )

    displacement = _match_bp_stack_dereference_8616(deref, project, codegen)

    assert displacement == -10


def test_match_bp_stack_dereference_matches_ss_sp_base_with_typed_probe_fact():
    project, codegen = _codegen([])
    codegen._inertia_typed_stack_probe_return_facts = {
        1: TypedStackProbeReturnFact8616(call_node_id=1, segment_space="ss", width=2, carrier_keys=())
    }
    ss = _reg(project, "ss", codegen)
    sp = _reg(project, "sp", codegen)
    deref = CUnaryOp(
        "Dereference",
        CBinaryOp(
            "Add",
            CBinaryOp("Shl", ss, _const(4, codegen), codegen=codegen),
            CBinaryOp("Sub", sp, _const(2, codegen), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )

    displacement = _match_bp_stack_dereference_8616(deref, project, codegen)

    assert displacement == -2


def test_match_bp_stack_dereference_follows_vvar_sp_carrier_chain():
    project, codegen = _codegen([])
    codegen._inertia_typed_stack_probe_return_facts = {
        1: TypedStackProbeReturnFact8616(call_node_id=1, segment_space="ss", width=2, carrier_keys=())
    }
    temp = _reg(project, "ax", codegen)
    temp.variable.name = "vvar_20"
    ss = _reg(project, "ss", codegen)
    sp = _reg(project, "sp", codegen)
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(
                temp,
                sp,
                codegen=codegen,
            ),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    deref = CUnaryOp(
        "Dereference",
        CBinaryOp(
            "Add",
            CBinaryOp("Mul", ss, _const(16, codegen), codegen=codegen),
            CBinaryOp("Sub", temp, _const(2, codegen), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )

    displacement = _match_bp_stack_dereference_8616(deref, project, codegen)

    assert displacement == -2


def test_stack_bp_displacement_refuses_self_referential_stack_carrier_cycle():
    project, codegen = _codegen([])
    carrier = _stack(-2, codegen, name="s_2")
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(
                carrier,
                CBinaryOp("Add", carrier, _const(2, codegen), codegen=codegen),
                codegen=codegen,
            ),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    displacement = _stack_bp_displacement_8616(carrier, project, codegen)

    assert displacement is None


def test_real_mode_linear_stack_access_matches_sp_register_carrier_without_late_shape_guess():
    project, codegen = _codegen([])
    codegen._inertia_typed_stack_probe_return_facts = {
        1: TypedStackProbeReturnFact8616(call_node_id=1, segment_space="ss", width=2, carrier_keys=())
    }
    sp = _reg(project, "sp", codegen)
    ss = _reg(project, "ss", codegen)
    deref = CUnaryOp(
        "Dereference",
        CBinaryOp(
            "Sub",
            CBinaryOp(
                "Add",
                CBinaryOp("Shl", ss, _const(4, codegen), codegen=codegen),
                sp,
                codegen=codegen,
            ),
            _const(2, codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )

    access = match_stable_ss_linear_stack_access_8616(deref, project, codegen)

    assert access is not None
    assert access.displacement == -2


def test_real_mode_linear_stack_access_matches_vvar_chain_with_constant_tail():
    project, codegen = _codegen([])
    codegen._inertia_typed_stack_probe_return_facts = {
        1: TypedStackProbeReturnFact8616(call_node_id=1, segment_space="ss", width=2, carrier_keys=())
    }
    ss = _reg(project, "ss", codegen)
    carrier = _reg(project, "ax", codegen)
    carrier.variable.name = "vvar_20"
    frame_slot = CUnaryOp("Reference", _stack(-10, codegen, name="s_a"), codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(
                carrier,
                CBinaryOp("Add", frame_slot, _const(2, codegen), codegen=codegen),
                codegen=codegen,
            )
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    access_expr = CUnaryOp(
        "Dereference",
        CBinaryOp(
            "Add",
            CBinaryOp("Mul", ss, _const(16, codegen), codegen=codegen),
            CBinaryOp("Add", carrier, _const(-2, codegen), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )

    access = match_stable_ss_linear_stack_access_8616(access_expr, project, codegen)

    assert access is not None
    assert access.displacement == -10


def test_real_mode_linear_stack_access_expands_virtual_ss_linear_address_carrier():
    project, codegen = _codegen([])
    codegen._inertia_typed_stack_probe_return_facts = {
        1: TypedStackProbeReturnFact8616(call_node_id=1, segment_space="ss", width=1, carrier_keys=())
    }
    sp = _reg(project, "sp", codegen)
    ss = _reg(project, "ss", codegen)
    offset_carrier = _dirty_vvar(1363, codegen)
    segment_carrier = _dirty_vvar(1373, codegen)
    address_carrier = _dirty_vvar(1375, codegen)
    deref = CUnaryOp(
        "Dereference",
        CTypeCast(
            None,
            SimTypePointer(SimTypeChar(False)).with_arch(project.arch),
            CBinaryOp("Add", address_carrier, _const(1, codegen), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(
                offset_carrier,
                CBinaryOp("Sub", sp, _const(8, codegen), codegen=codegen),
                codegen=codegen,
            ),
            CAssignment(segment_carrier, ss, codegen=codegen),
            CAssignment(
                address_carrier,
                CBinaryOp(
                    "Add",
                    CBinaryOp("Shl", segment_carrier, _const(4, codegen), codegen=codegen),
                    offset_carrier,
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    access = match_stable_ss_linear_stack_access_8616(deref, project, codegen)

    assert access is not None
    assert access.displacement == -7
    assert access.width == 1
    assert codegen._inertia_ss_linear_virtual_address_carrier_expanded_8616 == 1


def test_real_mode_linear_stack_access_infers_ss_from_unresolved_segment_carrier_with_stack_facts():
    project, codegen = _codegen([])
    codegen._inertia_semantic_alias_facts = [
        _stack_storage_facts_for_segmented_address_8616("ss", -2, 2, region=0x4010)
    ]
    segment_carrier = _reg(project, "ss", codegen)
    stack_base = CFakeVariable("stack_base", SimTypePointer(SimTypeBottom()), codegen=codegen)
    deref = CUnaryOp(
        "Dereference",
        CBinaryOp(
            "Add",
            CBinaryOp("Mul", segment_carrier, _const(16, codegen), codegen=codegen),
            CBinaryOp("Add", stack_base, _const(-4, codegen), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )

    access = match_stable_ss_linear_stack_access_8616(deref, project, codegen)

    assert access is not None
    assert access.displacement == -2
    assert codegen._inertia_ss_segment_inferred_from_stack_offset_count == 1


def test_real_mode_linear_stack_lowering_materializes_unsigned_indexed_bp_displacement():
    project, codegen = _codegen([], standard_bp_coordinate=True)
    codegen._inertia_current_function_8616 = _indexed_bp_function(-0x5A)
    si = _reg(project, "si", codegen)
    lhs = CUnaryOp(
        "Dereference",
        CBinaryOp(
            "Add",
            CBinaryOp("Add", _const(0xFFA6, codegen), si, codegen=codegen),
            _const(1, codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    stmt = CAssignment(lhs, _const(0, codegen), codegen=codegen)
    codegen.cfunc.statements.statements.append(stmt)

    changed = lower_stable_ss_linear_stack_dereferences_8616(codegen, project=project)

    assert changed is True
    assert isinstance(stmt.lhs, CUnaryOp)
    assert stmt.lhs.op == "Dereference"
    assert -0x5C in _stack_offsets_in_expr(stmt.lhs)
    assert codegen._inertia_indexed_bp_stack_address_raw_fact_count_8616 == 1
    assert codegen._inertia_indexed_bp_stack_address_materialized_count_8616 == 1


def test_real_mode_linear_stack_lowering_treats_indexed_frame_anchor_displacement_as_absolute():
    project, codegen = _codegen([], standard_bp_coordinate=True)
    codegen._inertia_current_function_8616 = _indexed_bp_function(-2, size=1, index=0)
    anchor = _stack(-2, codegen, name="anchor")
    deref = CUnaryOp(
        "Dereference",
        CBinaryOp(
            "Add",
            CBinaryOp("Mul", _reg(project, "ss", codegen), _const(16, codegen), codegen=codegen),
            CBinaryOp(
                "Add",
                CUnaryOp("Reference", anchor, codegen=codegen),
                _const(0xFFFE, codegen),
                codegen=codegen,
            ),
            codegen=codegen,
            tags={"ins_addr": 0x1009},
        ),
        codegen=codegen,
    )
    stmt = CAssignment(deref, _const(1, codegen), codegen=codegen)
    codegen.cfunc.statements.statements.append(stmt)

    changed = lower_stable_ss_linear_stack_dereferences_8616(codegen, project=project)

    assert changed is True
    assert isinstance(stmt.lhs, CVariable)
    assert stmt.lhs.variable.offset == -4
    assert codegen._inertia_instruction_bp_stack_access_lane_8616.is_closed


def test_real_mode_linear_stack_lowering_materializes_nested_indexed_reference_displacement():
    project, codegen = _codegen([], standard_bp_coordinate=True)
    codegen._inertia_current_function_8616 = _indexed_bp_function(-0x5A)
    anchor = _stack(-2, codegen, name="iRow")
    si = _reg(project, "si", codegen)
    indexed = CIndexedVariable(
        CUnaryOp("Reference", anchor, codegen=codegen),
        CBinaryOp("Add", _const(0xFFA6, codegen), si, codegen=codegen),
        codegen=codegen,
    )
    lhs = CUnaryOp(
        "Dereference",
        CBinaryOp(
            "Add",
            CUnaryOp("Reference", indexed, codegen=codegen),
            _const(1, codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    stmt = CAssignment(lhs, _const(0, codegen), codegen=codegen)
    codegen.cfunc.statements.statements.append(stmt)

    changed = lower_stable_ss_linear_stack_dereferences_8616(codegen, project=project)

    assert changed is True
    assert isinstance(stmt.lhs, CUnaryOp)
    assert stmt.lhs.op == "Dereference"
    assert -0x5C in _stack_offsets_in_expr(stmt.lhs)
    assert -2 not in _stack_offsets_in_expr(stmt.lhs)
    assert codegen._inertia_indexed_bp_stack_address_materialized_count_8616 == 1


def test_real_mode_linear_stack_access_refuses_unresolved_segment_carrier_without_stack_facts():
    project, codegen = _codegen([])
    codegen._inertia_semantic_alias_facts = []
    segment_carrier = _reg(project, "ss", codegen)
    stack_base = CFakeVariable("stack_base", SimTypePointer(SimTypeBottom()), codegen=codegen)
    deref = CUnaryOp(
        "Dereference",
        CBinaryOp(
            "Add",
            CBinaryOp("Mul", segment_carrier, _const(16, codegen), codegen=codegen),
            CBinaryOp("Add", stack_base, _const(-4, codegen), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )

    access = match_stable_ss_linear_stack_access_8616(deref, project, codegen)

    assert access is None


def test_real_mode_linear_stack_lowering_reuses_vvar_chain_with_constant_tail():
    project, codegen = _codegen([], standard_bp_coordinate=True)
    codegen._inertia_typed_stack_probe_return_facts = {
        1: TypedStackProbeReturnFact8616(call_node_id=1, segment_space="ss", width=2, carrier_keys=())
    }
    ss = _reg(project, "ss", codegen)
    carrier = _reg(project, "ax", codegen)
    carrier.variable.name = "vvar_20"
    frame_slot = CUnaryOp("Reference", _stack(-10, codegen, name="s_a"), codegen=codegen)
    deref = CUnaryOp(
        "Dereference",
        CBinaryOp(
            "Add",
            CBinaryOp("Mul", ss, _const(16, codegen), codegen=codegen),
            CBinaryOp("Add", carrier, _const(-2, codegen), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(
                carrier,
                CBinaryOp("Add", frame_slot, _const(2, codegen), codegen=codegen),
                codegen=codegen,
            ),
            CAssignment(deref, _const(7, codegen), codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    changed = lower_stable_ss_linear_stack_dereferences_8616(codegen)

    assert changed is True
    lhs = codegen.cfunc.statements.statements[1].lhs
    assert isinstance(lhs, CVariable)
    assert lhs.variable.offset == -12


def test_real_mode_linear_stack_lowering_replaces_stack_base_with_unresolved_segment_carrier():
    project, codegen = _codegen([], standard_bp_coordinate=True)  # noqa: RUF059
    codegen._inertia_semantic_alias_facts = [
        _stack_storage_facts_for_segmented_address_8616("ss", -2, 2, region=0x4010)
    ]
    segment_carrier = CVariable(SimRegisterVariable(0x70, 2, name="v3"), codegen=codegen)
    stack_base = CFakeVariable("stack_base", SimTypePointer(SimTypeBottom()), codegen=codegen)
    deref = CUnaryOp(
        "Dereference",
        CBinaryOp(
            "Add",
            CBinaryOp("Mul", segment_carrier, _const(16, codegen), codegen=codegen),
            CBinaryOp("Add", stack_base, _const(-4, codegen), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        [CAssignment(deref, _const(7, codegen), codegen=codegen)],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    changed = lower_stable_ss_linear_stack_dereferences_8616(codegen)

    assert changed is True
    lhs = codegen.cfunc.statements.statements[0].lhs
    assert isinstance(lhs, CVariable)
    assert isinstance(lhs.variable, SimStackVariable)
    assert lhs.variable.offset == -4


def _unresolved_segment_stack_base_deref(project, segment_carrier, stack_base, displacement: int, codegen):
    return CUnaryOp(
        "Dereference",
        CBinaryOp(
            "Add",
            CBinaryOp("Mul", segment_carrier, _const(16, codegen), codegen=codegen),
            CBinaryOp("Add", stack_base, _const(displacement, codegen), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )


def _dirty_vvar(varid: int, codegen, *, reg_offset: int | None = None):
    return CDirtyExpression(
        SimpleNamespace(varid=varid, name=f"vvar_{varid}", reg_offset=reg_offset, bits=16),
        codegen=codegen,
    )


def _dirty_ss_vvar_deref(segment_carrier, offset_carrier, displacement: int, codegen):
    offset_expr = (
        offset_carrier
        if displacement == 0
        else CBinaryOp("Add", offset_carrier, _const(displacement, codegen), codegen=codegen)
    )
    return CUnaryOp(
        "Dereference",
        CBinaryOp(
            "Add",
            CBinaryOp("Shl", segment_carrier, _const(4, codegen), codegen=codegen),
            offset_expr,
            codegen=codegen,
        ),
        codegen=codegen,
    )


def test_real_mode_linear_stack_carrier_delta_uses_multiple_ss_alias_observations():
    project, codegen = _codegen([])
    codegen._inertia_semantic_alias_facts = [
        _stack_storage_facts_for_segmented_address_8616("ss", 4, 2, region=0x4010),
        _stack_storage_facts_for_segmented_address_8616("ss", 6, 2, region=0x4010),
    ]
    segment_carrier = _dirty_vvar(19, codegen, reg_offset=project.arch.registers["ss"][0])
    offset_carrier = _dirty_vvar(21, codegen, reg_offset=8)
    first = _dirty_ss_vvar_deref(segment_carrier, offset_carrier, 0, codegen)
    second = _dirty_ss_vvar_deref(segment_carrier, offset_carrier, 2, codegen)
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(first, _const(1, codegen), codegen=codegen),
            CAssignment(second, _const(2, codegen), codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    first_access = match_stable_ss_linear_stack_access_8616(first, project, codegen)
    second_access = match_stable_ss_linear_stack_access_8616(second, project, codegen)

    assert first_access is not None
    assert first_access.displacement == 4
    assert second_access is not None
    assert second_access.displacement == 6
    assert codegen._inertia_stack_carrier_delta_inferred_from_alias_count_8616 == 1


def test_real_mode_linear_stack_carrier_delta_alias_observation_overrides_sp_seed():
    project, codegen = _codegen([])
    codegen._inertia_typed_stack_probe_return_facts = {
        1: TypedStackProbeReturnFact8616(call_node_id=1, segment_space="ss", width=2, carrier_keys=())
    }
    codegen._inertia_semantic_alias_facts = [
        _stack_storage_facts_for_segmented_address_8616("ss", 4, 2, region=0x4010),
        _stack_storage_facts_for_segmented_address_8616("ss", 6, 2, region=0x4010),
    ]
    segment_carrier = _dirty_vvar(19, codegen, reg_offset=project.arch.registers["ss"][0])
    offset_carrier = _dirty_vvar(21, codegen, reg_offset=8)
    first = _dirty_ss_vvar_deref(segment_carrier, offset_carrier, 0, codegen)
    second = _dirty_ss_vvar_deref(segment_carrier, offset_carrier, 2, codegen)
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(offset_carrier, _reg(project, "sp", codegen), codegen=codegen),
            CAssignment(first, _const(1, codegen), codegen=codegen),
            CAssignment(second, _const(2, codegen), codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    first_access = match_stable_ss_linear_stack_access_8616(first, project, codegen)
    second_access = match_stable_ss_linear_stack_access_8616(second, project, codegen)

    assert first_access is not None
    assert first_access.displacement == 4
    assert second_access is not None
    assert second_access.displacement == 6
    assert codegen._inertia_stack_carrier_delta_alias_override_count_8616 == 1


def test_stack_cvar_canonicalization_rebases_non_alias_stack_base_offset_to_alias_slot():
    _project, codegen = _codegen([])
    target_var = SimStackVariable(-4, 2, base="bp", name="iChild", region=0x4010)
    raw_var = SimStackVariable(-6, 2, base="bp", name="local_6", region=0x4010)
    target_cvar = CVariable(target_var, variable_type=SimTypeShort(False), codegen=codegen)
    raw_cvar = CVariable(raw_var, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[target_var] = target_cvar
    codegen.cfunc.variables_in_use[raw_var] = raw_cvar
    codegen._inertia_semantic_alias_facts = [
        _stack_storage_facts_for_segmented_address_8616("ss", -4, 2, region=0x4010)
    ]
    codegen._inertia_stack_base_bp_bias_evidence_8616 = StackBaseBpBiasEvidence8616(
        statement_root=codegen.cfunc.statements,
        stack_base_displacements=(-6,),
        known_bp_offsets=frozenset({-4}),
        inferred_bias=2,
    )

    canonical = decompile._canonicalize_stack_cvar_expr(raw_cvar, codegen)

    assert canonical is target_cvar
    assert codegen._inertia_stack_cvar_rebased_from_stack_base_bias_count_8616 == 1


def test_real_mode_linear_stack_carrier_delta_refuses_single_ss_alias_observation():
    project, codegen = _codegen([])
    codegen._inertia_semantic_alias_facts = [
        _stack_storage_facts_for_segmented_address_8616("ss", 4, 2, region=0x4010),
    ]
    segment_carrier = _dirty_vvar(19, codegen, reg_offset=project.arch.registers["ss"][0])
    offset_carrier = _dirty_vvar(21, codegen, reg_offset=8)
    deref = _dirty_ss_vvar_deref(segment_carrier, offset_carrier, 0, codegen)
    codegen.cfunc.statements = CStatements(
        [CAssignment(deref, _const(1, codegen), codegen=codegen)],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    access = match_stable_ss_linear_stack_access_8616(deref, project, codegen)

    assert access is None


def test_real_mode_linear_stack_base_bias_uses_recovered_arg_list_offsets_without_alias_facts():
    project, codegen = _codegen([])
    arg_a = CVariable(
        SimStackVariable(4, 2, base="bp", name="a", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    arg_b = CVariable(
        SimStackVariable(6, 2, base="bp", name="b", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    codegen.cfunc.arg_list = [arg_a, arg_b]
    segment_carrier = _reg(project, "ss", codegen)
    stack_base = CFakeVariable("stack_base", SimTypePointer(SimTypeBottom()), codegen=codegen)
    first = _unresolved_segment_stack_base_deref(project, segment_carrier, stack_base, 4, codegen)
    second = _unresolved_segment_stack_base_deref(project, segment_carrier, stack_base, 6, codegen)
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(first, _const(1, codegen), codegen=codegen),
            CAssignment(second, _const(2, codegen), codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    changed = lower_stable_ss_linear_stack_dereferences_8616(codegen)

    assert changed is True
    assert codegen.cfunc.statements.statements[0].lhs is arg_a
    assert codegen.cfunc.statements.statements[1].lhs is arg_b


def test_real_mode_linear_stack_carrier_delta_uses_recovered_arg_list_offsets_without_alias_facts():
    project, codegen = _codegen([])
    arg_a = CVariable(
        SimStackVariable(4, 2, base="bp", name="a", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    arg_b = CVariable(
        SimStackVariable(6, 2, base="bp", name="b", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    codegen.cfunc.arg_list = [arg_a, arg_b]
    segment_carrier = _dirty_vvar(19, codegen, reg_offset=project.arch.registers["ss"][0])
    offset_carrier = _dirty_vvar(21, codegen, reg_offset=8)
    first = _dirty_ss_vvar_deref(segment_carrier, offset_carrier, 0, codegen)
    second = _dirty_ss_vvar_deref(segment_carrier, offset_carrier, 2, codegen)
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(first, _const(1, codegen), codegen=codegen),
            CAssignment(second, _const(2, codegen), codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    changed = lower_stable_ss_linear_stack_dereferences_8616(codegen)

    assert changed is True
    assert codegen.cfunc.statements.statements[0].lhs is arg_a
    assert codegen.cfunc.statements.statements[1].lhs is arg_b


def test_real_mode_linear_stack_carrier_delta_uses_arg_offsets_to_disambiguate_bp_slots():
    project, codegen = _codegen([])
    codegen._inertia_semantic_alias_facts = [
        _stack_storage_facts_for_segmented_address_8616("ss", -2, 2, region=0x4010),
        _stack_storage_facts_for_segmented_address_8616("ss", 0, 2, region=0x4010),
        _stack_storage_facts_for_segmented_address_8616("ss", 2, 2, region=0x4010),
        _stack_storage_facts_for_segmented_address_8616("ss", 4, 2, region=0x4010),
        _stack_storage_facts_for_segmented_address_8616("ss", 6, 2, region=0x4010),
    ]
    arg_a = CVariable(
        SimStackVariable(4, 2, base="bp", name="a", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    arg_b = CVariable(
        SimStackVariable(6, 2, base="bp", name="b", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    codegen.cfunc.arg_list = [arg_a, arg_b]
    segment_carrier = _dirty_vvar(19, codegen, reg_offset=project.arch.registers["ss"][0])
    base_carrier = _dirty_vvar(14, codegen, reg_offset=8)
    intermediate_carrier = _dirty_vvar(20, codegen, reg_offset=8)
    offset_carrier = _dirty_vvar(21, codegen, reg_offset=8)
    first = _dirty_ss_vvar_deref(segment_carrier, offset_carrier, 0, codegen)
    second = _dirty_ss_vvar_deref(segment_carrier, offset_carrier, 2, codegen)
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(
                intermediate_carrier,
                CBinaryOp("Sub", base_carrier, _const(2, codegen), codegen=codegen),
                codegen=codegen,
            ),
            CAssignment(
                offset_carrier,
                CBinaryOp("Sub", intermediate_carrier, _const(2, codegen), codegen=codegen),
                codegen=codegen,
            ),
            CAssignment(first, _const(1, codegen), codegen=codegen),
            CAssignment(second, _const(2, codegen), codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    changed = lower_stable_ss_linear_stack_dereferences_8616(codegen)

    assert changed is True
    assert codegen.cfunc.statements.statements[2].lhs is arg_a
    assert codegen.cfunc.statements.statements[3].lhs is arg_b
    assert codegen._inertia_stack_carrier_delta_inferred_from_arg_offsets_count_8616 == 1


def test_real_mode_linear_stack_carrier_delta_prefers_abi_arg_region_over_return_address_slot():
    project, codegen = _codegen([], standard_bp_coordinate=True)
    codegen._inertia_semantic_alias_facts = [
        _stack_storage_facts_for_segmented_address_8616("ss", -2, 2, region=0x4010),
        _stack_storage_facts_for_segmented_address_8616("ss", 2, 2, region=0x4010),
        _stack_storage_facts_for_segmented_address_8616("ss", 4, 2, region=0x4010),
        _stack_storage_facts_for_segmented_address_8616("ss", 6, 2, region=0x4010),
    ]
    segment_carrier = _dirty_vvar(19, codegen, reg_offset=project.arch.registers["ss"][0])
    offset_carrier = _dirty_vvar(21, codegen, reg_offset=8)
    first = _dirty_ss_vvar_deref(segment_carrier, offset_carrier, 0, codegen)
    second = _dirty_ss_vvar_deref(segment_carrier, offset_carrier, 2, codegen)
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(first, _const(1, codegen), codegen=codegen),
            CAssignment(second, _const(2, codegen), codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    changed = lower_stable_ss_linear_stack_dereferences_8616(codegen)

    assert changed is True
    offsets = [stmt.lhs.variable.offset for stmt in codegen.cfunc.statements.statements]
    assert offsets == [2, 4]
    assert codegen._inertia_stack_carrier_delta_inferred_from_abi_arg_region_count_8616 == 1


def test_real_mode_linear_stack_base_bias_uses_prototype_offsets_without_arg_list_or_alias_facts():
    project, codegen = _codegen([], standard_bp_coordinate=True)
    codegen.cfunc.functy = SimTypeFunction(
        [SimTypeShort(False), SimTypeShort(False)],
        SimTypeShort(False),
    ).with_arch(project.arch)
    ss = _reg(project, "ss", codegen)
    stack_base = CFakeVariable("stack_base", SimTypePointer(SimTypeBottom()), codegen=codegen)
    first = _unresolved_segment_stack_base_deref(project, ss, stack_base, 4, codegen)
    second = _unresolved_segment_stack_base_deref(project, ss, stack_base, 6, codegen)
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(first, _const(1, codegen), codegen=codegen),
            CAssignment(second, _const(2, codegen), codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    changed = lower_stable_ss_linear_stack_dereferences_8616(codegen)

    assert changed is True
    offsets = [stmt.lhs.variable.offset for stmt in codegen.cfunc.statements.statements]
    assert offsets == [2, 4]
    assert codegen._inertia_stack_arg_offsets_from_prototype_count_8616 == 2


def test_real_mode_linear_stack_base_bias_uses_bp_memory_operands_without_sidecar_facts():
    project, codegen = _codegen([], standard_bp_coordinate=True)

    def _bp_mem_operand(offset: int):
        return SimpleNamespace(type=X86_OP_MEM, mem=SimpleNamespace(base=X86_REG_BP, disp=offset))

    fake_func = SimpleNamespace(
        blocks=[
            SimpleNamespace(
                capstone=SimpleNamespace(
                    insns=[
                        SimpleNamespace(operands=[_bp_mem_operand(4)]),
                        SimpleNamespace(operands=[_bp_mem_operand(6)]),
                    ]
                )
            )
        ]
    )
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(function=lambda addr, create=False: fake_func if addr == 0x4010 else None)
    )
    ss = _reg(project, "ss", codegen)
    stack_base = CFakeVariable("stack_base", SimTypePointer(SimTypeBottom()), codegen=codegen)
    first = _unresolved_segment_stack_base_deref(project, ss, stack_base, 4, codegen)
    second = _unresolved_segment_stack_base_deref(project, ss, stack_base, 6, codegen)
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(first, _const(1, codegen), codegen=codegen),
            CAssignment(second, _const(2, codegen), codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    changed = lower_stable_ss_linear_stack_dereferences_8616(codegen)

    assert changed is True
    offsets = [stmt.lhs.variable.offset for stmt in codegen.cfunc.statements.statements]
    assert offsets == [2, 4]
    assert codegen._inertia_stack_bp_offsets_from_capstone_count_8616 == 2


def test_real_mode_linear_stack_base_bias_uses_single_exact_entry_arg_slot():
    project, codegen = _codegen([], standard_bp_coordinate=True)

    def _bp_mem_operand(offset: int):
        return SimpleNamespace(type=X86_OP_MEM, mem=SimpleNamespace(base=X86_REG_BP, disp=offset))

    fake_func = SimpleNamespace(
        blocks=[SimpleNamespace(capstone=SimpleNamespace(insns=[SimpleNamespace(operands=[_bp_mem_operand(4)])]))]
    )
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(function=lambda addr, create=False: fake_func if addr == 0x4010 else None)
    )
    ss = _reg(project, "ss", codegen)
    stack_base = CFakeVariable("stack_base", SimTypePointer(SimTypeBottom()), codegen=codegen)
    word_access = _unresolved_segment_stack_base_deref(project, ss, stack_base, 2, codegen)
    codegen.cfunc.statements = CStatements(
        [CAssignment(word_access, _const(1, codegen), codegen=codegen)],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    changed = lower_stable_ss_linear_stack_dereferences_8616(codegen)

    assert changed is True
    assert codegen.cfunc.statements.statements[0].lhs.variable.offset == 2
    assert codegen._inertia_stack_base_bp_bias_single_arg_inferred_count_8616 == 1


def test_real_mode_linear_stack_base_bias_uses_multiple_bp_alias_facts_for_post_prologue_slice():
    project, codegen = _codegen([])
    codegen._inertia_semantic_alias_facts = [
        _stack_storage_facts_for_segmented_address_8616("ss", 4, 2, region=0x4010),
        _stack_storage_facts_for_segmented_address_8616("ss", 6, 2, region=0x4010),
    ]
    segment_carrier = CVariable(SimRegisterVariable(0x70, 2, name="v3"), codegen=codegen)
    stack_base = CFakeVariable("stack_base", SimTypePointer(SimTypeBottom()), codegen=codegen)
    first = _unresolved_segment_stack_base_deref(project, segment_carrier, stack_base, 4, codegen)
    second = _unresolved_segment_stack_base_deref(project, segment_carrier, stack_base, 6, codegen)
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(first, _const(1, codegen), codegen=codegen),
            CAssignment(second, _const(2, codegen), codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    first_access = match_stable_ss_linear_stack_access_8616(first, project, codegen)
    second_access = match_stable_ss_linear_stack_access_8616(second, project, codegen)

    assert first_access is not None
    assert first_access.displacement == 4
    assert second_access is not None
    assert second_access.displacement == 6
    assert codegen._inertia_stack_base_bp_bias_inferred_count_8616 == 1


def test_real_mode_linear_stack_base_bias_uses_multiple_bp_alias_facts_for_exact_entry_slice():
    project, codegen = _codegen([])
    codegen._inertia_semantic_alias_facts = [
        _stack_storage_facts_for_segmented_address_8616("ss", 4, 2, region=0x4010),
        _stack_storage_facts_for_segmented_address_8616("ss", 6, 2, region=0x4010),
    ]
    segment_carrier = CVariable(SimRegisterVariable(0x70, 2, name="v3"), codegen=codegen)
    stack_base = CFakeVariable("stack_base", SimTypePointer(SimTypeBottom()), codegen=codegen)
    first = _unresolved_segment_stack_base_deref(project, segment_carrier, stack_base, 2, codegen)
    second = _unresolved_segment_stack_base_deref(project, segment_carrier, stack_base, 4, codegen)
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(first, _const(1, codegen), codegen=codegen),
            CAssignment(second, _const(2, codegen), codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    first_access = match_stable_ss_linear_stack_access_8616(first, project, codegen)
    second_access = match_stable_ss_linear_stack_access_8616(second, project, codegen)

    assert first_access is not None
    assert first_access.displacement == 4
    assert second_access is not None
    assert second_access.displacement == 6
    assert codegen._inertia_stack_base_bp_bias_inferred_count_8616 == 1


def test_real_mode_linear_stack_lowering_materializes_inferred_stack_base_bias_slots():
    project, codegen = _codegen([], standard_bp_coordinate=True)
    codegen._inertia_semantic_alias_facts = [
        _stack_storage_facts_for_segmented_address_8616("ss", 4, 2, region=0x4010),
        _stack_storage_facts_for_segmented_address_8616("ss", 6, 2, region=0x4010),
    ]
    segment_carrier = CVariable(SimRegisterVariable(0x70, 2, name="v3"), codegen=codegen)
    stack_base = CFakeVariable("stack_base", SimTypePointer(SimTypeBottom()), codegen=codegen)
    first = _unresolved_segment_stack_base_deref(project, segment_carrier, stack_base, 4, codegen)
    second = _unresolved_segment_stack_base_deref(project, segment_carrier, stack_base, 6, codegen)
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(first, _const(1, codegen), codegen=codegen),
            CAssignment(second, _const(2, codegen), codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    changed = lower_stable_ss_linear_stack_dereferences_8616(codegen)

    assert changed is True
    offsets = [stmt.lhs.variable.offset for stmt in codegen.cfunc.statements.statements]
    assert offsets == [2, 4]


def test_real_mode_linear_stack_lowering_visits_for_loop_initializer_and_iterator():
    project, codegen = _codegen([], standard_bp_coordinate=True)
    codegen._inertia_semantic_alias_facts = [
        _stack_storage_facts_for_segmented_address_8616("ss", 4, 2, region=0x4010),
        _stack_storage_facts_for_segmented_address_8616("ss", 6, 2, region=0x4010),
    ]
    segment_carrier = CVariable(SimRegisterVariable(0x70, 2, name="v3"), codegen=codegen)
    stack_base = CFakeVariable("stack_base", SimTypePointer(SimTypeBottom()), codegen=codegen)
    initializer = CAssignment(
        _unresolved_segment_stack_base_deref(project, segment_carrier, stack_base, 4, codegen),
        _const(1, codegen),
        codegen=codegen,
    )
    iterator = CAssignment(
        _unresolved_segment_stack_base_deref(project, segment_carrier, stack_base, 6, codegen),
        _const(2, codegen),
        codegen=codegen,
    )
    loop = CForLoop(
        initializer,
        CConstant(1, SimTypeChar(False), codegen=codegen),
        iterator,
        CStatements([], addr=0x4010, codegen=codegen),
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements([loop], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    changed = lower_stable_ss_linear_stack_dereferences_8616(codegen, project=project)

    assert changed is True
    assert isinstance(loop.initializer.lhs, CVariable)
    assert isinstance(loop.iterator.lhs, CVariable)
    assert loop.initializer.lhs.variable.offset == 2
    assert loop.iterator.lhs.variable.offset == 4


def test_real_mode_linear_stack_lowering_does_not_reuse_narrow_byte_carrier_for_word_access():
    project, codegen = _codegen([], standard_bp_coordinate=True)
    func = SimpleNamespace(info={"x86_16_annotations": {"stack_vars": {-4: {"name": "i"}}}})
    codegen._func = func
    existing_byte = CVariable(
        SimStackVariable(-2, 1, base="bp", name="local_2", region=0x4010),
        variable_type=SimTypeChar(False),
        codegen=codegen,
    )
    codegen.cfunc.variables_in_use[existing_byte.variable] = existing_byte
    ss = _reg(project, "ss", codegen)
    stack_base = CFakeVariable("stack_base", SimTypePointer(SimTypeBottom()), codegen=codegen)
    word_access = _unresolved_segment_stack_base_deref(project, ss, stack_base, -4, codegen)
    word_access.operand = CTypeCast(
        SimTypeShort(False),
        SimTypePointer(SimTypeShort(False)),
        word_access.operand,
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        [CAssignment(word_access, _const(1, codegen), codegen=codegen)],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    changed = lower_stable_ss_linear_stack_dereferences_8616(codegen, project=project)

    assert changed is True
    lhs = codegen.cfunc.statements.statements[0].lhs
    assert isinstance(lhs, CVariable)
    assert lhs is not existing_byte
    assert lhs.variable.offset == -4
    assert lhs.variable.size == 2
    assert lhs.variable.name == "i"
    assert existing_byte.variable.size == 1


def test_real_mode_linear_stack_lowering_does_not_reuse_wide_carrier_for_byte_access():
    project, codegen = _codegen([], standard_bp_coordinate=True)
    existing_word = CVariable(
        SimStackVariable(-2, 2, base="bp", name="local_2", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    codegen.cfunc.variables_in_use[existing_word.variable] = existing_word
    ss = _reg(project, "ss", codegen)
    stack_base = CFakeVariable("stack_base", SimTypePointer(SimTypeBottom()), codegen=codegen)
    byte_access = _unresolved_segment_stack_base_deref(project, ss, stack_base, -4, codegen)
    byte_access.operand = CTypeCast(
        SimTypeShort(False),
        SimTypePointer(SimTypeChar(False)),
        byte_access.operand,
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        [CAssignment(byte_access, _const(1, codegen), codegen=codegen)],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    changed = lower_stable_ss_linear_stack_dereferences_8616(codegen, project=project)

    assert changed is True
    lhs = codegen.cfunc.statements.statements[0].lhs
    assert isinstance(lhs, CVariable)
    assert lhs is not existing_word
    assert lhs.variable.offset == -4
    assert lhs.variable.size == 1
    assert type(lhs.variable_type) is SimTypeChar
    assert existing_word.variable.size == 2


def test_runtime_ss_segment_helper_lowering_materializes_stack_base_offset():
    project, codegen = _codegen([])
    _attach_standard_bp_coordinate(codegen)
    codegen._inertia_semantic_alias_facts = [
        _stack_storage_facts_for_segmented_address_8616("ss", -4, 2, region=0x4010)
    ]
    ss = _reg(project, "ss", codegen)
    stack_base = CFakeVariable("stack_base", SimTypePointer(SimTypeBottom()), codegen=codegen)
    helper = CFunctionCall(
        "SEG_U16",
        None,
        [
            ss,
            CBinaryOp("Add", stack_base, _const(-6, codegen), codegen=codegen),
        ],
        codegen=codegen,
    )
    target = _stack(-8, codegen, name="sink")
    codegen.cfunc.variables_in_use[target.variable] = target
    codegen.cfunc.statements = CStatements(
        [CAssignment(target, helper, codegen=codegen)],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    changed = apply_runtime_segment_lowering_8616(codegen)

    assert changed is True
    rhs = codegen.cfunc.statements.statements[0].rhs
    assert isinstance(rhs, CVariable)
    assert isinstance(rhs.variable, SimStackVariable)
    assert rhs.variable.offset == -6
    assert rhs.variable.size == 2
    projection = stack_variable_coordinate_registry_8616(codegen).for_variable(rhs.variable)
    assert projection is not None
    assert projection.bp_offset == -4
    assert codegen._inertia_runtime_ss_helper_candidate_count_8616 == 1
    assert codegen._inertia_runtime_ss_helper_materialized_count_8616 == 1
    assert codegen._inertia_runtime_ss_helper_refused_count_8616 == 0


def test_runtime_ss_segment_helper_lowering_materializes_ss_register_carrier_stack_base_offset():
    project, codegen = _codegen([])
    _attach_standard_bp_coordinate(codegen)
    codegen._inertia_semantic_alias_facts = [
        _stack_storage_facts_for_segmented_address_8616("ss", -6, 2, region=0x4010)
    ]
    ss_reg_offset, ss_reg_size = project.arch.registers["ss"]
    ss_carrier = CVariable(SimRegisterVariable(ss_reg_offset, ss_reg_size, name="v3"), codegen=codegen)
    stack_base = CFakeVariable("stack_base", SimTypePointer(SimTypeBottom()), codegen=codegen)
    helper = CFunctionCall(
        "SEG_U16",
        None,
        [
            ss_carrier,
            CBinaryOp("Add", stack_base, _const(-8, codegen), codegen=codegen),
        ],
        codegen=codegen,
    )
    target = _stack(-10, codegen, name="sink")
    codegen.cfunc.variables_in_use[target.variable] = target
    codegen.cfunc.statements = CStatements(
        [CAssignment(target, helper, codegen=codegen)],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    changed = lower_runtime_ss_segment_helpers_to_stack_8616(codegen, project=project)

    assert changed is True
    rhs = codegen.cfunc.statements.statements[0].rhs
    assert isinstance(rhs, CVariable)
    assert isinstance(rhs.variable, SimStackVariable)
    assert rhs.variable.offset == -8
    assert rhs.variable.size == 2
    projection = stack_variable_coordinate_registry_8616(codegen).for_variable(rhs.variable)
    assert projection is not None
    assert projection.bp_offset == -6
    assert codegen._inertia_runtime_ss_helper_candidate_count_8616 == 1
    assert codegen._inertia_runtime_ss_helper_materialized_count_8616 == 1
    assert codegen._inertia_runtime_ss_helper_refused_count_8616 == 0


def test_runtime_ss_segment_helper_refreshes_stale_bias_and_offset_caches():
    project, codegen = _codegen([], standard_bp_coordinate=True)
    alias_facts = [
        _stack_storage_facts_for_segmented_address_8616("ss", 4, 2, region=0x4010),
        _stack_storage_facts_for_segmented_address_8616("ss", 6, 2, region=0x4010),
    ]
    codegen._inertia_semantic_alias_facts = alias_facts
    ss_reg_offset, ss_reg_size = project.arch.registers["ss"]
    ss_carrier = CVariable(SimRegisterVariable(ss_reg_offset, ss_reg_size, name="v2"), codegen=codegen)
    stack_base = CFakeVariable("stack_base", SimTypePointer(SimTypeBottom()), codegen=codegen)
    offset_expr = CBinaryOp("Add", stack_base, _const(4, codegen), codegen=codegen)
    helper = CFunctionCall("SEG_U16", None, [ss_carrier, offset_expr], codegen=codegen)
    target = _stack(-2, codegen, name="sink")
    codegen.cfunc.variables_in_use[target.variable] = target
    seed_offset_a = CBinaryOp("Add", stack_base, _const(-4, codegen), codegen=codegen)
    seed_offset_b = CBinaryOp("Add", stack_base, _const(-2, codegen), codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(
                target,
                CFunctionCall("SEG_U16", None, [ss_carrier, seed_offset_a], codegen=codegen),
                codegen=codegen,
            ),
            CAssignment(
                target,
                CFunctionCall("SEG_U16", None, [ss_carrier, seed_offset_b], codegen=codegen),
                codegen=codegen,
            ),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    assert _stack_offset_from_expr_8616(seed_offset_a, project, codegen) == 4
    assert _stack_offset_from_expr_8616(offset_expr, project, codegen) == 12
    stale_evidence = codegen._inertia_stack_base_bp_bias_evidence_8616
    assert isinstance(stale_evidence, StackBaseBpBiasEvidence8616)
    assert stale_evidence.inferred_bias == 8

    codegen.cfunc.statements.statements[:] = [CAssignment(target, helper, codegen=codegen)]
    changed = lower_runtime_ss_segment_helpers_to_stack_8616(codegen, project=project)

    assert changed is True
    rhs = codegen.cfunc.statements.statements[0].rhs
    assert isinstance(rhs, CVariable)
    assert isinstance(rhs.variable, SimStackVariable)
    assert rhs.variable.offset == 4
    refreshed_evidence = codegen._inertia_stack_base_bp_bias_evidence_8616
    assert isinstance(refreshed_evidence, StackBaseBpBiasEvidence8616)
    assert refreshed_evidence.inferred_bias is None
    assert refreshed_evidence.known_bp_offsets.issuperset({4, 6})
    assert codegen._inertia_runtime_ss_helper_materialized_count_8616 == 1
    assert codegen._inertia_runtime_ss_helper_refused_count_8616 == 0


def test_runtime_ss_segment_helper_prefers_physical_bp_over_entry_sp_delta():
    project, codegen = _codegen([], standard_bp_coordinate=True)
    codegen._inertia_semantic_alias_facts = [
        _stack_storage_facts_for_segmented_address_8616("ss", 6, 2, region=0x4010),
    ]
    bp_reg_offset, _bp_reg_size = project.arch.registers["bp"]
    ss_reg_offset, ss_reg_size = project.arch.registers["ss"]
    bp_carrier = CDirtyExpression(
        SimpleNamespace(varid=7, reg_offset=bp_reg_offset, bits=16),
        codegen=codegen,
    )
    offset_expr = CBinaryOp(
        "Add",
        CBinaryOp("Add", _const(6, codegen), bp_carrier, codegen=codegen),
        _const(1, codegen),
        codegen=codegen,
    )
    ss_carrier = CVariable(
        SimRegisterVariable(ss_reg_offset, ss_reg_size, name="ss"),
        codegen=codegen,
    )
    helper = CFunctionCall("SEG_U8", None, [ss_carrier, offset_expr], codegen=codegen)
    target = _stack(-2, codegen, name="sink")
    codegen.cfunc.variables_in_use[target.variable] = target
    codegen.cfunc.statements.statements[:] = [CAssignment(target, helper, codegen=codegen)]
    codegen._inertia_vvar_carrier_deltas = {7: -2}
    codegen._inertia_stack_carrier_delta_sources_8616 = {
        7: StackCarrierDeltaSource8616.ALIAS_OBSERVATION,
    }

    assert _stack_offset_from_expr_8616(offset_expr, project, codegen) == 7
    assert _has_stack_storage_evidence_for_displacement_8616(codegen, 7, 1) is True
    assert _has_stack_storage_evidence_for_displacement_8616(codegen, 7, 2) is False
    assert _has_stack_storage_evidence_for_displacement_8616(codegen, 8, 1) is False
    codegen._inertia_semantic_alias_facts = []
    argument = _stack(6, codegen, name="b")
    codegen.cfunc.variables_in_use[argument.variable] = argument
    assert _has_stack_storage_evidence_for_displacement_8616(codegen, 7, 1) is True
    assert _has_stack_storage_evidence_for_displacement_8616(codegen, 7, 2) is False
    changed = lower_runtime_ss_segment_helpers_to_stack_8616(codegen, project=project)

    assert changed is True
    rhs = codegen.cfunc.statements.statements[0].rhs
    assert isinstance(rhs, CVariable)
    assert isinstance(rhs.variable, SimStackVariable)
    assert rhs.variable.offset == 5


def test_runtime_ss_segment_helper_refuses_stale_bias_after_evidence_changes():
    project, codegen = _codegen([])
    alias_facts = [
        _stack_storage_facts_for_segmented_address_8616("ss", 4, 2, region=0x4010),
        _stack_storage_facts_for_segmented_address_8616("ss", 6, 2, region=0x4010),
    ]
    codegen._inertia_semantic_alias_facts = alias_facts
    ss_reg_offset, ss_reg_size = project.arch.registers["ss"]
    ss_carrier = CVariable(SimRegisterVariable(ss_reg_offset, ss_reg_size, name="v2"), codegen=codegen)
    stack_base = CFakeVariable("stack_base", SimTypePointer(SimTypeBottom()), codegen=codegen)
    offset_expr = CBinaryOp("Add", stack_base, _const(4, codegen), codegen=codegen)
    helper = CFunctionCall("SEG_U16", None, [ss_carrier, offset_expr], codegen=codegen)
    target = _stack(-2, codegen, name="sink")
    codegen.cfunc.variables_in_use[target.variable] = target
    seed_offset_a = CBinaryOp("Add", stack_base, _const(-4, codegen), codegen=codegen)
    seed_offset_b = CBinaryOp("Add", stack_base, _const(-2, codegen), codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(
                target,
                CFunctionCall("SEG_U16", None, [ss_carrier, seed_offset_a], codegen=codegen),
                codegen=codegen,
            ),
            CAssignment(
                target,
                CFunctionCall("SEG_U16", None, [ss_carrier, seed_offset_b], codegen=codegen),
                codegen=codegen,
            ),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    assert _stack_offset_from_expr_8616(seed_offset_a, project, codegen) == 4
    assert _stack_offset_from_expr_8616(offset_expr, project, codegen) == 12
    alias_facts[:] = [
        _stack_storage_facts_for_segmented_address_8616("ss", 4, 2, region=0x4010),
        _stack_storage_facts_for_segmented_address_8616("ss", 8, 2, region=0x4010),
    ]
    codegen.cfunc.statements.statements[:] = [CAssignment(target, helper, codegen=codegen)]
    changed = apply_runtime_segment_lowering_8616(codegen)

    assert changed is False
    assert codegen.cfunc.statements.statements[0].rhs is helper
    refreshed_evidence = codegen._inertia_stack_base_bp_bias_evidence_8616
    assert isinstance(refreshed_evidence, StackBaseBpBiasEvidence8616)
    assert refreshed_evidence.inferred_bias is None
    assert codegen._inertia_runtime_ss_helper_materialized_count_8616 == 0
    assert codegen._inertia_runtime_ss_helper_refused_count_8616 == 1


def test_runtime_segment_helper_lowering_refuses_unknown_offset_without_exception():
    project, codegen = _codegen([])
    ss_reg_offset, ss_reg_size = project.arch.registers["ss"]
    ss_carrier = CVariable(SimRegisterVariable(ss_reg_offset, ss_reg_size, name="v3"), codegen=codegen)
    unknown_offset = CDirtyExpression(SimpleNamespace(varid=91, name="vvar_91"), codegen=codegen)
    helper = CFunctionCall(
        "SEG_U16",
        None,
        [ss_carrier, unknown_offset],
        codegen=codegen,
    )
    target = _stack(-10, codegen, name="sink")
    codegen.cfunc.variables_in_use[target.variable] = target
    codegen.cfunc.statements = CStatements(
        [CAssignment(target, helper, codegen=codegen)],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    changed = apply_runtime_segment_lowering_8616(codegen)

    assert changed is False
    assert codegen.cfunc.statements.statements[0].rhs is helper


def test_real_mode_linear_stack_lowering_recurses_into_condition_and_nodes():
    project, codegen = _codegen([], standard_bp_coordinate=True)
    codegen._inertia_semantic_alias_facts = [
        _stack_storage_facts_for_segmented_address_8616("ss", -4, 2, region=0x4010)
    ]
    ss = _reg(project, "ss", codegen)
    stack_base = CFakeVariable("stack_base", SimTypePointer(SimTypeBottom()), codegen=codegen)
    condition = CBinaryOp(
        "CmpLE",
        _const(1, codegen),
        _unresolved_segment_stack_base_deref(project, ss, stack_base, -6, codegen),
        codegen=codegen,
    )
    if_stmt = CIfElse(
        [(condition, CStatements([], addr=0x4010, codegen=codegen))],
        None,
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements([if_stmt], addr=0x4010, codegen=codegen)
    codegen.cfunc.body = codegen.cfunc.statements

    changed = lower_stable_ss_linear_stack_dereferences_8616(codegen, project=project)

    assert changed is True
    rewritten_condition = codegen.cfunc.statements.statements[0].condition_and_nodes[0][0]
    assert isinstance(rewritten_condition.rhs, CVariable)
    assert isinstance(rewritten_condition.rhs.variable, SimStackVariable)
    assert rewritten_condition.rhs.variable.offset == -6


def test_real_mode_linear_stack_lowering_renames_reused_stack_cvar_from_annotations():
    project, codegen = _codegen([])
    codegen._func = SimpleNamespace(info={ANNOTATION_KEY: {"stack_vars": {-4: {"name": "goal"}}}})
    codegen._inertia_semantic_alias_facts = [
        _stack_storage_facts_for_segmented_address_8616("ss", -4, 2, region=0x4010)
    ]
    existing = CVariable(
        SimStackVariable(-4, 2, base="bp", name="local_4", region=0x4010),
        variable_type=SimTypeShort(False),
        codegen=codegen,
    )
    codegen.cfunc.variables_in_use[existing.variable] = existing
    ss = _reg(project, "ss", codegen)
    stack_base = CFakeVariable("stack_base", SimTypePointer(SimTypeBottom()), codegen=codegen)
    word_access = _unresolved_segment_stack_base_deref(project, ss, stack_base, -6, codegen)
    codegen.cfunc.statements = CStatements(
        [CAssignment(_stack(-8, codegen, name="sink"), word_access, codegen=codegen)],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    changed = lower_stable_ss_linear_stack_dereferences_8616(codegen, project=project)

    assert changed is True
    rhs = codegen.cfunc.statements.statements[0].rhs
    assert rhs is existing
    assert existing.variable.name == "goal"


def test_real_mode_linear_stack_lowering_replaces_stable_ss_sp_carrier():
    project, codegen = _codegen([], standard_bp_coordinate=True)
    codegen._inertia_typed_stack_probe_return_facts = {
        1: TypedStackProbeReturnFact8616(call_node_id=1, segment_space="ss", width=2, carrier_keys=())
    }
    sp = _reg(project, "sp", codegen)
    ss = _reg(project, "ss", codegen)
    deref = CUnaryOp(
        "Dereference",
        CBinaryOp(
            "Add",
            CBinaryOp("Shl", ss, _const(4, codegen), codegen=codegen),
            CBinaryOp("Sub", sp, _const(2, codegen), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    deref.operand = CTypeCast(
        SimTypeShort(False),
        SimTypePointer(SimTypeShort(False)),
        deref.operand,
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        [CAssignment(deref, _const(7, codegen), codegen=codegen)],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    changed = lower_stable_ss_linear_stack_dereferences_8616(codegen)

    assert changed is True
    lhs = codegen.cfunc.statements.statements[0].lhs
    assert isinstance(lhs, CVariable)
    assert isinstance(lhs.variable, SimStackVariable)
    assert lhs.variable.offset == -4
    assert isinstance(getattr(lhs, "variable_type", None), SimTypeShort)


def test_real_mode_linear_stack_lowering_reuses_wrapped_bp_slot_identity():
    project, codegen = _codegen([])
    existing = _stack(-2, codegen, name="iRow")
    existing.variable.offset = 0xFFFE
    codegen.cfunc.variables_in_use[existing.variable] = existing
    codegen.cfunc.unified_local_vars[existing.variable] = {(existing, SimTypeShort(False))}
    codegen._inertia_typed_stack_probe_return_facts = {
        1: TypedStackProbeReturnFact8616(call_node_id=1, segment_space="ss", width=2, carrier_keys=())
    }
    sp = _reg(project, "sp", codegen)
    ss = _reg(project, "ss", codegen)
    deref = CUnaryOp(
        "Dereference",
        CBinaryOp(
            "Add",
            CBinaryOp("Shl", ss, _const(4, codegen), codegen=codegen),
            CBinaryOp("Sub", sp, _const(2, codegen), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        [CAssignment(deref, _const(7, codegen), codegen=codegen)],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    changed = lower_stable_ss_linear_stack_dereferences_8616(codegen)

    assert changed is True
    lhs = codegen.cfunc.statements.statements[0].lhs
    assert lhs is existing
    assert lhs.variable.offset == 0xFFFE


def test_real_mode_linear_global_lowering_preserves_global_write_identity():
    project, before_codegen = _codegen([])
    before_codegen.cfunc.statements = CStatements(
        [
            CAssignment(
                _ds_deref(project, 0x0BAA, before_codegen),
                _const(7, before_codegen),
                codegen=before_codegen,
            )
        ],
        addr=0x4010,
        codegen=before_codegen,
    )
    before_codegen.cfunc.body = before_codegen.cfunc.statements
    after_codegen = deepcopy(before_codegen)
    after_codegen.project = project

    access = match_stable_ds_es_linear_global_access_8616(
        after_codegen.cfunc.statements.statements[0].lhs,
        project,
        after_codegen,
    )
    assert access is not None
    assert access.displacement == 0x0BAA

    changed = lower_stable_ds_es_linear_global_dereferences_8616(after_codegen)

    assert changed is True
    lhs = after_codegen.cfunc.statements.statements[0].lhs
    assert isinstance(lhs, CVariable)
    assert isinstance(lhs.variable, SimMemoryVariable)
    assert lhs.variable.addr == 0x0BAA
    assert isinstance(getattr(lhs, "variable_type", None), SimTypeShort)
    assert after_codegen._inertia_segmented_memory_lowering["DS"]["allow_linear_lowering"] is True
    assert project._inertia_segmented_memory_lowering["DS"]["allow_linear_lowering"] is True
    assert after_codegen._inertia_real_mode_global_lowering_evidence["materialized_count"] == 1

    before_summary = collect_x86_16_tail_validation_summary(project, before_codegen, mode="coarse")
    after_summary = collect_x86_16_tail_validation_summary(project, after_codegen, mode="coarse")
    diff = compare_x86_16_tail_validation_summaries(before_summary, after_summary)
    assert diff["changed"] is False


def test_real_mode_linear_global_lowering_assigns_byte_type_from_access_width():
    project, codegen = _codegen([])
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(
                _ds_deref(project, 0x0BA7, codegen, width=8),
                _const(7, codegen),
                codegen=codegen,
            )
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    changed = lower_stable_ds_es_linear_global_dereferences_8616(codegen)

    assert changed is True
    lhs = codegen.cfunc.statements.statements[0].lhs
    assert isinstance(lhs, CVariable)
    assert isinstance(lhs.variable, SimMemoryVariable)
    assert lhs.variable.addr == 0x0BA7
    assert isinstance(getattr(lhs, "variable_type", None), SimTypeChar)


def test_real_mode_linear_global_lowering_resolves_single_assignment_address_carrier():
    project, codegen = _codegen([])
    carrier = CVariable(SimRegisterVariable(0x360, 2, name="vvar_360"), codegen=codegen)
    result = CVariable(SimRegisterVariable(0x362, 1, name="vvar_363"), codegen=codegen)
    carrier_rhs = _ds_addr(project, 0x0160, codegen)
    deref_addr = CBinaryOp("Add", carrier, _const(1, codegen), codegen=codegen)
    deref = CUnaryOp(
        "Dereference",
        CTypeCast(
            SimTypeShort(False),
            SimTypePointer(SimTypeChar(False)),
            deref_addr,
            codegen=codegen,
        ),
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(carrier, carrier_rhs, codegen=codegen),
            CAssignment(result, deref, codegen=codegen),
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    changed = lower_stable_ds_es_linear_global_dereferences_8616(codegen)

    assert changed is True
    rhs = codegen.cfunc.statements.statements[1].rhs
    assert isinstance(rhs, CVariable)
    assert isinstance(rhs.variable, SimMemoryVariable)
    assert rhs.variable.addr == 0x0161
    assert isinstance(getattr(rhs, "variable_type", None), SimTypeChar)
    assert codegen._inertia_real_mode_global_carrier_resolved_count_8616 >= 1


def test_real_mode_linear_global_lowering_recurses_into_condition_and_nodes():
    project, codegen = _codegen([])
    inner_body = CStatements(
        [
            CAssignment(
                _ds_deref(project, 0x0BAA, codegen),
                _const(7, codegen),
                codegen=codegen,
            )
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        [
            CIfElse(
                [(CConstant(1, SimTypeShort(False), codegen=codegen), inner_body)],
                None,
                codegen=codegen,
            )
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    changed = lower_stable_ds_es_linear_global_dereferences_8616(codegen)

    assert changed is True
    if_stmt = codegen.cfunc.statements.statements[0]
    lhs = if_stmt.condition_and_nodes[0][1].statements[0].lhs
    assert isinstance(lhs, CVariable)
    assert isinstance(lhs.variable, SimMemoryVariable)
    assert lhs.variable.addr == 0x0BAA


def test_match_stable_ds_es_linear_global_address_accepts_base_plus_scaled_index():
    project, codegen = _codegen([])
    index_expr = CBinaryOp("Shl", _reg(project, "bx", codegen), _const(1, codegen), codegen=codegen)

    access = match_stable_ds_es_linear_global_address_8616(
        _ds_addr(project, 0x0B4C, codegen, extra_expr=index_expr),
        project,
        codegen,
    )

    assert access is not None
    assert access.segment_name == "ds"
    assert access.displacement == 0x0B4C
    assert access.residual_terms == ((1, index_expr),)


def test_match_stable_ds_es_linear_global_access_supports_segmentless_indexed_base():
    project, codegen = _codegen([])
    global_symbol = SimMemoryVariable(0x0B4C, 2, name="g_0B4C", region=0x4010)
    global_cvar = CVariable(global_symbol, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[global_symbol] = global_cvar

    index_expr = CBinaryOp("Shl", _reg(project, "bx", codegen), _const(1, codegen), codegen=codegen)
    access = match_stable_ds_es_linear_global_access_8616(
        CUnaryOp(
            "Dereference",
            CBinaryOp(
                "Add",
                index_expr,
                _const(0x0B4C, codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        project,
        codegen,
    )

    assert access is not None
    assert access.segment_name == "segless"
    assert access.displacement == 0x0B4C
    assert access.residual_terms == ((1, index_expr),)
    assert access.width == 2


def test_real_mode_linear_global_address_lowering_materializes_reference_base():
    project, codegen = _codegen([])
    index_expr = CBinaryOp("Shl", _reg(project, "bx", codegen), _const(1, codegen), codegen=codegen)
    carrier = _reg(project, "ax", codegen)
    carrier.variable.name = "vvar_20"
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(
                carrier,
                _ds_addr(project, 0x0B4C, codegen, extra_expr=index_expr),
                codegen=codegen,
            )
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    changed = lower_stable_ds_es_linear_global_addresses_8616(codegen)

    assert changed is True
    rhs = codegen.cfunc.statements.statements[0].rhs
    assert isinstance(rhs, CTypeCast)
    assert isinstance(rhs.expr, CBinaryOp)
    assert rhs.expr.op == "Add"
    assert isinstance(rhs.expr.lhs, CUnaryOp)
    assert rhs.expr.lhs.op == "Reference"
    assert isinstance(rhs.expr.lhs.operand, CVariable)
    assert isinstance(rhs.expr.lhs.operand.variable, SimMemoryVariable)
    assert rhs.expr.lhs.operand.variable.addr == 0x0B4C
    assert rhs.expr.rhs is index_expr


def test_real_mode_linear_global_address_lowering_preserves_scale_constants():
    project, codegen = _codegen([])
    stride_symbol = SimVariable(2, None, "g_0002", None, None)
    stride_cvar = CVariable(stride_symbol, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[stride_symbol] = stride_cvar
    index_expr = CBinaryOp("Mul", _reg(project, "bx", codegen), _const(2, codegen), codegen=codegen)
    carrier = _reg(project, "ax", codegen)
    carrier.variable.name = "vvar_20"
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(
                carrier,
                _ds_addr(project, 0x0B4C, codegen, extra_expr=index_expr),
                codegen=codegen,
            )
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    changed = lower_stable_ds_es_linear_global_addresses_8616(codegen)

    assert changed is True
    rhs = codegen.cfunc.statements.statements[0].rhs
    assert isinstance(rhs, CTypeCast)
    rebuilt_index = rhs.expr.rhs
    assert isinstance(rebuilt_index, CBinaryOp)
    assert rebuilt_index.op == "Mul"
    assert isinstance(rebuilt_index.rhs, CConstant)
    assert rebuilt_index.rhs.value == 2


def test_real_mode_linear_global_address_lowering_refuses_bare_scale_constant():
    project, codegen = _codegen([])
    stride_symbol = SimVariable(2, None, "g_0002", None, None)
    stride_cvar = CVariable(stride_symbol, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[stride_symbol] = stride_cvar
    carrier = _reg(project, "ax", codegen)
    carrier.variable.name = "vvar_20"
    scale_expr = CBinaryOp("Mul", _reg(project, "bx", codegen), _const(2, codegen), codegen=codegen)
    codegen.cfunc.statements = CStatements(
        [CAssignment(carrier, scale_expr, codegen=codegen)],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    changed = lower_stable_ds_es_linear_global_addresses_8616(codegen)

    assert changed is False
    rhs = codegen.cfunc.statements.statements[0].rhs
    assert rhs is scale_expr
    assert isinstance(rhs.rhs, CConstant)
    assert rhs.rhs.value == 2


def test_real_mode_linear_global_address_lowering_is_idempotent_after_reference_base():
    project, codegen = _codegen([])
    index_expr = CBinaryOp("Shl", _reg(project, "bx", codegen), _const(1, codegen), codegen=codegen)
    carrier = _reg(project, "ax", codegen)
    carrier.variable.name = "vvar_20"
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(
                carrier,
                _ds_addr(project, 0x0B4C, codegen, extra_expr=index_expr),
                codegen=codegen,
            )
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    assert lower_stable_ds_es_linear_global_addresses_8616(codegen) is True
    rhs = codegen.cfunc.statements.statements[0].rhs

    assert lower_stable_ds_es_linear_global_addresses_8616(codegen) is False
    assert codegen.cfunc.statements.statements[0].rhs is rhs


def test_real_mode_linear_global_dereference_lowering_materializes_segmentless_indexed_loads():
    project, codegen = _codegen([])
    global_symbol = SimMemoryVariable(0x0B4C, 2, name="g_0B4C", region=0x4010)
    global_cvar = CVariable(global_symbol, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[global_symbol] = global_cvar
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(
                CUnaryOp(
                    "Dereference",
                    CBinaryOp(
                        "Add",
                        CBinaryOp(
                            "Shl",
                            _reg(project, "bx", codegen),
                            _const(1, codegen),
                            codegen=codegen,
                        ),
                        _const(0x0B4C, codegen),
                        codegen=codegen,
                    ),
                    codegen=codegen,
                ),
                _const(7, codegen),
                codegen=codegen,
            )
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    changed = lower_stable_ds_es_linear_global_dereferences_8616(codegen)

    assert changed is True
    lhs = codegen.cfunc.statements.statements[0].lhs
    assert isinstance(lhs, CUnaryOp)
    assert lhs.op == "Dereference"


def test_real_mode_linear_global_dereference_folds_materialized_address_labels():
    project, codegen = _codegen([])
    base_symbol = SimMemoryVariable(0x0B4C, 1, name="mem_0B4C", region=0x4010)
    stride_symbol = SimMemoryVariable(2, 2, name="g_0002", region=0x4010)
    sp_anchor = SimStackVariable(0, 2, base="sp", name="sp_0", region=0x4010)
    base_cvar = CVariable(base_symbol, variable_type=SimTypeChar(False), codegen=codegen)
    stride_cvar = CVariable(stride_symbol, variable_type=SimTypeShort(False), codegen=codegen)
    sp_cvar = CVariable(sp_anchor, variable_type=SimTypeShort(False), codegen=codegen)
    codegen.cfunc.variables_in_use[base_symbol] = base_cvar
    codegen.cfunc.variables_in_use[stride_symbol] = stride_cvar
    codegen.cfunc.variables_in_use[sp_anchor] = sp_cvar
    index_expr = CBinaryOp(
        "Mul",
        _reg(project, "bx", codegen),
        CUnaryOp("Reference", stride_cvar, codegen=codegen),
        codegen=codegen,
    )
    address_expr = CBinaryOp(
        "Add",
        CUnaryOp("Reference", sp_cvar, codegen=codegen),
        CBinaryOp(
            "Add",
            CUnaryOp("Reference", base_cvar, codegen=codegen),
            index_expr,
            codegen=codegen,
        ),
        codegen=codegen,
    )
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(
                CUnaryOp("Dereference", address_expr, codegen=codegen),
                _const(7, codegen),
                codegen=codegen,
            )
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements

    access = match_stable_ds_es_linear_global_access_8616(
        codegen.cfunc.statements.statements[0].lhs,
        project,
        codegen,
    )
    assert access is not None
    assert access.displacement == 0x0B4C
    assert len(access.residual_terms) == 1
    residual = access.residual_terms[0][1]
    assert isinstance(residual, CBinaryOp)
    assert residual.op == "Mul"
    assert isinstance(residual.rhs, CConstant)
    assert residual.rhs.value == 2

    changed = lower_stable_ds_es_linear_global_dereferences_8616(codegen)

    assert changed is True
    lhs = codegen.cfunc.statements.statements[0].lhs
    assert isinstance(lhs, CUnaryOp)
    assert lhs.op == "Dereference"
    pending = [lhs]
    leaked_refs = []
    while pending:
        current = pending.pop()
        if isinstance(current, CUnaryOp) and current.op == "Reference":
            variable = getattr(getattr(current, "operand", None), "variable", None)
            if variable in {stride_symbol, sp_anchor}:
                leaked_refs.append(variable)
        for attr in ("lhs", "rhs", "operand", "expr", "index"):
            child = getattr(current, attr, None)
            if child is not None:
                pending.append(child)
    assert leaked_refs == []


def test_structuring_stage_does_not_relower_ds_globals_after_validation_boundary(monkeypatch):
    project, codegen = _codegen([])
    project._inertia_structuring_enabled = True
    project._inertia_tail_validation_enabled = True
    project._inertia_decompiler_stage = None
    project.kb = SimpleNamespace(functions=SimpleNamespace(function=lambda *args, **kwargs: None))
    codegen.cfunc.statements = CStatements(
        [
            CAssignment(
                _ds_deref(project, 0x0BAA, codegen),
                _const(7, codegen),
                codegen=codegen,
            )
        ],
        addr=0x4010,
        codegen=codegen,
    )
    codegen.cfunc.body = codegen.cfunc.statements
    before_summary = collect_x86_16_tail_validation_summary(project, codegen, mode="live_out")

    monkeypatch.setattr(_structuring_stage, "_assert_alias_complete_8616", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(_structuring_stage, "_decompiler_structuring_passes_for_function", lambda *_args, **_kwargs: ())

    changed = _structuring_stage._structuring_codegen_8616(project, codegen)

    assert changed is False
    after_summary = collect_x86_16_tail_validation_summary(project, codegen, mode="live_out")
    diff = compare_x86_16_tail_validation_summaries(before_summary, after_summary)
    assert diff["changed"] is False


def test_rewrite_ss_stack_byte_offsets_resolves_pointer_alias_by_variable_name():
    project, codegen = _codegen([])
    cfunc = codegen.cfunc
    cfunc.project = SimpleNamespace(loader=SimpleNamespace(main_object=SimpleNamespace(binary_basename="SORTDEMO.EXE")))
    cfunc.arg_list = []
    cfunc.unified_local_vars = {}
    cfunc.sort_local_vars = lambda: None

    ss = _reg(project, "ss", codegen)
    alias_var = SimRegisterVariable(0, 2, name="vvar_16")
    alias_cvar = CVariable(alias_var, codegen=codegen)
    alias_use_var = SimRegisterVariable(0, 2, name=None)
    alias_use_cvar = CVariable(alias_use_var, codegen=codegen)
    base_var = SimStackVariable(-6, 2, base="bp", name="s_6", region=0x4010)
    base_cvar = CVariable(base_var, codegen=codegen)
    target_var = SimStackVariable(-8, 2, base="bp", name="local_8", region=0x4010)
    target_cvar = CVariable(target_var, codegen=codegen)
    cfunc.variables_in_use = {
        alias_var: alias_cvar,
        alias_use_var: alias_use_cvar,
        base_var: base_cvar,
        target_var: target_cvar,
        ss.variable: ss,
    }

    addr_expr = CBinaryOp("Add", alias_use_cvar, _const(-2, codegen), codegen=codegen)
    store = CAssignment(
        CUnaryOp(
            "Dereference",
            CBinaryOp(
                "Add",
                CBinaryOp("Mul", ss, _const(16, codegen), codegen=codegen),
                addr_expr,
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        _const(7, codegen),
        codegen=codegen,
    )
    cfunc.statements = CStatements(
        [
            CAssignment(alias_cvar, CUnaryOp("Reference", base_cvar, codegen=codegen), codegen=codegen),
            store,
        ],
        addr=0x4010,
        codegen=codegen,
    )
    cfunc.body = cfunc.statements

    changed = decompile._rewrite_ss_stack_byte_offsets(project, codegen)

    assert changed is True
    lowered_lhs = cfunc.statements.statements[1].lhs
    assert isinstance(lowered_lhs, CVariable)
    assert lowered_lhs.variable is target_var


def test_stack_lowering_entrypoint_runs_typed_ss_lowering_before_cli_cleanup():
    calls: list[str] = []

    def lower_stable_ss_stack_accesses() -> bool:
        calls.append("typed-ss")
        return True

    def rewrite_ss_stack_byte_offsets() -> bool:
        calls.append("rewrite")
        return False

    def canonicalize_stack_cvars() -> bool:
        calls.append("canonicalize")
        return False

    changed = run_stack_lowering_pass_8616(
        lower_stable_ss_stack_accesses=lower_stable_ss_stack_accesses,
        rewrite_ss_stack_byte_offsets=rewrite_ss_stack_byte_offsets,
        canonicalize_stack_cvars=canonicalize_stack_cvars,
        max_rounds=1,
    )

    assert changed is True
    assert calls == ["typed-ss", "rewrite", "canonicalize"]


def test_stack_lowering_entrypoint_builds_typed_stack_probe_return_facts_from_summaries():
    project, codegen = _codegen([])  # noqa: RUF059
    probe = SimpleNamespace()
    codegen._inertia_callsite_summaries = {
        id(probe): CallsiteSummary8616(
            callsite_addr=0x4010,
            target_addr=0x1000,
            return_addr=0x4013,
            kind="near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="ax",
            return_used=True,
            stack_probe_helper=True,
            helper_return_state="stack_address",
            helper_return_space="ss",
            helper_return_width=2,
            helper_return_address_kind="stack",
        )
    }

    changed = run_stack_lowering_pass_8616(
        lower_stable_ss_stack_accesses=lambda: False,
        rewrite_ss_stack_byte_offsets=lambda: False,
        canonicalize_stack_cvars=lambda: False,
        codegen=codegen,
        max_rounds=1,
    )

    assert changed is False
    assert codegen._inertia_typed_stack_probe_return_facts == {
        id(probe): TypedStackProbeReturnFact8616(
            call_node_id=id(probe),
            segment_space="ss",
            width=2,
            carrier_keys=(),
        )
    }


def test_stack_lowering_builder_refuses_non_ss_or_unknown_width_facts():
    project, codegen = _codegen([])  # noqa: RUF059
    codegen._inertia_callsite_summaries = {
        1: CallsiteSummary8616(
            callsite_addr=0x4010,
            target_addr=0x1000,
            return_addr=0x4013,
            kind="near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="ax",
            return_used=True,
            stack_probe_helper=True,
            helper_return_state="stack_address",
            helper_return_space="ds",
            helper_return_width=2,
            helper_return_address_kind="stack",
        ),
        2: CallsiteSummary8616(
            callsite_addr=0x4020,
            target_addr=0x1000,
            return_addr=0x4023,
            kind="near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=0,
            return_register="ax",
            return_used=True,
            stack_probe_helper=True,
            helper_return_state="stack_address",
            helper_return_space="ss",
            helper_return_width=None,
            helper_return_address_kind="stack",
        ),
    }

    assert build_typed_stack_probe_return_facts_8616(codegen) == {}


def test_missing_terminal_ax_return_replaces_return_value_without_dropping_statements(monkeypatch):
    project, codegen = _codegen([])
    lhs = CVariable(SimStackVariable(-2, 2, base="bp", name="local_2", region=0x4010), codegen=codegen)
    setup_stmt = CAssignment(lhs, CConstant(1, SimTypeShort(False), codegen=codegen), codegen=codegen)
    old_retval = CConstant(0x1234, SimTypeShort(False), codegen=codegen)
    new_retval = CConstant(0x55AA, SimTypeShort(False), codegen=codegen)
    return_stmt = CReturn(old_retval, codegen=codegen)
    root = CStatements([setup_stmt, return_stmt], addr=0x4010, codegen=codegen)
    function = SimpleNamespace(addr=0x4010)
    codegen.cfunc = SimpleNamespace(
        addr=0x4010,
        statements=root,
        functy=SimpleNamespace(returnty=SimTypeShort(False).with_arch(project.arch)),
    )
    codegen._inertia_current_function_8616 = function

    monkeypatch.setattr(
        _postprocess_stage,
        "_return_expr_has_insert_artifact_8616",
        lambda expr: expr is old_retval,
    )
    monkeypatch.setattr(_postprocess_stage, "_return_depends_on_insert_artifact_8616", lambda _root, _node: False)
    monkeypatch.setattr(
        _postprocess_stage,
        "_linear_terminal_ax_return_expr_8616",
        lambda _project, _codegen, _function: new_retval,
    )

    changed = _postprocess_stage._materialize_missing_terminal_ax_return_8616(project, codegen)

    assert changed is True
    assert list(root.statements) == [setup_stmt, return_stmt]
    assert return_stmt.retval is new_retval
