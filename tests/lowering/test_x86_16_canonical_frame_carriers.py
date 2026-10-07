from __future__ import annotations

from types import SimpleNamespace

from angr.ailment.expression import VirtualVariable, VirtualVariableCategory
from angr.analyses.decompiler.structured_codegen.c import (
    CAssignment,
    CBinaryOp,
    CConstant,
    CDirtyExpression,
    CFunctionCall,
    CStatements,
    CVariable,
)
from angr.rustylib.ailment import Tags
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimMemoryVariable, SimRegisterVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.lowering.frame_register_carriers import (
    collect_frame_register_carriers_8616,
)
from inertia.lowering.real_mode_linear import (
    prune_frame_prologue_stack_assignments_8616,
)
from capstone.x86_const import (
    X86_INS_MOV,
    X86_INS_POP,
    X86_INS_PUSH,
    X86_INS_RET,
    X86_OP_REG,
    X86_REG_BP,
    X86_REG_SP,
)

from inertia.validation.validation_dataflow import validate_structured_def_use_8616


class _Codegen:
    """Minimal dynamic angr codegen boundary used by the focused regression."""

    def __init__(self, project: object) -> None:
        self._idx = 0
        self.project = project
        self.cstyle_null_cmp = False

    def next_idx(self, _name: str) -> int:
        """Return a deterministic structured-C node index."""
        self._idx += 1
        return self._idx
    def next_node_idx(self) -> int:
        return self.next_idx("")
    def next_ident(self, name: str) -> str:
        return name


def _register_operand(register: int) -> SimpleNamespace:
    """Build one minimal Capstone register operand boundary."""
    return SimpleNamespace(type=X86_OP_REG, size=2, reg=register)


def _instruction(
    address: int,
    size: int,
    instruction_id: int,
    *registers: int,
) -> SimpleNamespace:
    """Build one minimal decoded instruction boundary."""
    return SimpleNamespace(
        address=address,
        size=size,
        id=instruction_id,
        operands=tuple(_register_operand(register) for register in registers),
    )


def test_canonical_bp_frame_prunes_entry_and_epilogue_carriers() -> None:
    project = SimpleNamespace(arch=Arch86_16(), _inertia_c_target="portable-flat")
    codegen = _Codegen(project)
    word_type = SimTypeShort(False)

    def register(name: str) -> CVariable:
        """Build one typed physical-register C variable."""
        offset = project.arch.registers[name][0]
        variable = SimRegisterVariable(offset, 2, name=name)
        return CVariable(variable, variable_type=word_type, codegen=codegen)

    sp = register("sp")
    bp = register("bp")
    ax = register("ax")
    two = CConstant(2, word_type, codegen=codegen)
    one = CConstant(1, word_type, codegen=codegen)
    push_carrier = CAssignment(
        sp,
        CBinaryOp("Sub", sp, two, codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x1000},
    )
    setup_carrier = CAssignment(bp, sp, codegen=codegen, tags={"ins_addr": 0x1001})
    body_assignment = CAssignment(ax, one, codegen=codegen, tags={"ins_addr": 0x1010})
    teardown_carrier = CAssignment(sp, bp, codegen=codegen, tags={"ins_addr": 0x1020})
    pop_carrier = CAssignment(bp, sp, codegen=codegen, tags={"ins_addr": 0x1022})
    return_carrier = CAssignment(
        sp,
        CBinaryOp("Add", sp, two, codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x1023},
    )
    root = CStatements(
        [
            push_carrier,
            setup_carrier,
            body_assignment,
            teardown_carrier,
            pop_carrier,
            return_carrier,
        ],
        addr=0x1000,
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        statements=root,
        body=root,
        arg_list=[],
        variables_in_use={},
        unified_local_vars={},
    )
    instructions = (
        _instruction(0x1000, 1, X86_INS_PUSH, X86_REG_BP),
        _instruction(0x1001, 2, X86_INS_MOV, X86_REG_BP, X86_REG_SP),
        _instruction(0x1020, 2, X86_INS_MOV, X86_REG_SP, X86_REG_BP),
        _instruction(0x1022, 1, X86_INS_POP, X86_REG_BP),
        _instruction(0x1023, 1, X86_INS_RET),
    )
    function = SimpleNamespace(
        addr=0x1000,
        blocks=(
            SimpleNamespace(
                addr=0x1000,
                capstone=SimpleNamespace(insns=instructions),
            ),
        ),
    )

    changed = prune_frame_prologue_stack_assignments_8616(
        project,
        codegen,
        function=function,
    )

    assert changed is True
    assert root.statements == [body_assignment]
    stats = codegen._inertia_frame_prologue_carrier_prune_8616
    assert (
        stats.raw_fact_count,
        stats.normalized_fact_count,
        stats.classified_fact_count,
        stats.materialized_count,
        stats.failure_count,
    ) == (5, 5, 5, 5, 0)
    assert validate_structured_def_use_8616(root).issues == ()


def test_canonical_bp_frame_prunes_regenerated_segmented_store_with_rust_tags() -> None:
    project = SimpleNamespace(arch=Arch86_16(), _inertia_c_target="portable-flat")
    codegen = _Codegen(project)
    word_type = SimTypeShort(False)

    def register(name: str) -> CVariable:
        """Build one typed physical-register C variable."""
        offset = project.arch.registers[name][0]
        variable = SimRegisterVariable(offset, 2, name=name)
        return CVariable(variable, variable_type=word_type, codegen=codegen)

    bp_offset = project.arch.registers["bp"][0]
    sp_offset = project.arch.registers["sp"][0]

    def dirty(varid: int, category: VirtualVariableCategory, oident: int) -> CDirtyExpression:
        """Build one exact current-angr virtual register or temporary carrier."""
        return CDirtyExpression(
            VirtualVariable(varid, varid, 16, category, oident=oident),
            codegen=codegen,
        )

    bp_snapshot = dirty(338, VirtualVariableCategory.TMP, 0)
    sp_snapshot = dirty(339, VirtualVariableCategory.TMP, 1)
    runtime_ss = CVariable(
        SimMemoryVariable(0, 2, name="inertia_ss"),
        variable_type=word_type,
        codegen=codegen,
    )
    saved_bp = CFunctionCall(
        "SEG_U16",
        None,
        [
            runtime_ss,
            CBinaryOp(
                "Sub",
                dirty(339, VirtualVariableCategory.TMP, 1),
                CConstant(2, word_type, codegen=codegen),
                codegen=codegen,
            ),
        ],
        codegen=codegen,
        tags=Tags({"inertia_x86_16_runtime_segment_helper": "SEG_U16"}),
    )
    carriers = [
        CAssignment(
            bp_snapshot,
            dirty(24, VirtualVariableCategory.REGISTER, bp_offset),
            codegen=codegen,
            tags=Tags({"ins_addr": 0x1000, "vex_block_addr": 0x1000, "vex_stmt_idx": 1}),
        ),
        CAssignment(
            sp_snapshot,
            dirty(23, VirtualVariableCategory.REGISTER, sp_offset),
            codegen=codegen,
            tags=Tags({"ins_addr": 0x1000, "vex_block_addr": 0x1000, "vex_stmt_idx": 2}),
        ),
        CAssignment(
            dirty(31, VirtualVariableCategory.REGISTER, sp_offset),
            CBinaryOp(
                "Sub",
                dirty(339, VirtualVariableCategory.TMP, 1),
                CConstant(2, word_type, codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
            tags=Tags({"ins_addr": 0x1000, "vex_block_addr": 0x1000, "vex_stmt_idx": 4}),
        ),
        CAssignment(
            dirty(340, VirtualVariableCategory.TMP, 3),
            runtime_ss,
            codegen=codegen,
            tags=Tags({"ins_addr": 0x1000, "vex_block_addr": 0x1000, "vex_stmt_idx": 5}),
        ),
        CAssignment(
            saved_bp,
            dirty(338, VirtualVariableCategory.TMP, 0),
            codegen=codegen,
            tags=Tags({"ins_addr": 0x1000, "vex_block_addr": 0x1000, "vex_stmt_idx": 10}),
        ),
    ]
    body = CAssignment(
        register("ax"),
        CConstant(1, word_type, codegen=codegen),
        codegen=codegen,
        tags={"ins_addr": 0x1010},
    )
    nested = CStatements(carriers, codegen=codegen)
    root = CStatements([nested, body], addr=0x1000, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        statements=root,
        body=root,
        arg_list=[],
        variables_in_use={},
        unified_local_vars={},
    )
    function = SimpleNamespace(
        addr=0x1000,
        blocks=(
            SimpleNamespace(
                addr=0x1000,
                capstone=SimpleNamespace(
                    insns=(
                        _instruction(0x1000, 1, X86_INS_PUSH, X86_REG_BP),
                        _instruction(0x1001, 2, X86_INS_MOV, X86_REG_BP, X86_REG_SP),
                    )
                ),
            ),
        ),
    )

    changed = prune_frame_prologue_stack_assignments_8616(
        project,
        codegen,
        function=function,
    )

    assert changed is True
    assert nested.statements == []
    assert root.statements == [nested, body]
    stats = codegen._inertia_frame_prologue_carrier_prune_8616
    assert stats.classified_fact_count == stats.materialized_count == 5
    assert stats.failure_count == 0
    lane = next(
        lane
        for lane in codegen._inertia_semantic_lanes_8616
        if lane.name == "frame-prologue-register-carriers"
    )
    assert (lane.raw, lane.normalized, lane.classified, lane.materialized, lane.failures) == (2, 2, 2, 2, 0)


def test_frame_register_carriers_refuse_ambiguous_same_instruction_definition() -> None:
    project = SimpleNamespace(arch=Arch86_16(), _inertia_c_target="portable-flat")
    codegen = _Codegen(project)
    sp_offset = project.arch.registers["sp"][0]

    def dirty(varid: int, category: VirtualVariableCategory, oident: int) -> CDirtyExpression:
        """Build one exact current-angr virtual register or temporary carrier."""
        return CDirtyExpression(
            VirtualVariable(varid, varid, 16, category, oident=oident),
            codegen=codegen,
        )

    tags = Tags({"ins_addr": 0x1000, "vex_block_addr": 0x1000})
    root = CStatements(
        [
            CAssignment(
                dirty(339, VirtualVariableCategory.TMP, 1),
                dirty(23, VirtualVariableCategory.REGISTER, sp_offset),
                codegen=codegen,
                tags=tags,
            ),
            CAssignment(
                dirty(339, VirtualVariableCategory.TMP, 1),
                dirty(31, VirtualVariableCategory.REGISTER, sp_offset),
                codegen=codegen,
                tags=tags,
            ),
        ],
        codegen=codegen,
    )

    resolution = collect_frame_register_carriers_8616(root, project, 0x1000)

    assert (
        resolution.raw_fact_count,
        resolution.normalized_fact_count,
        resolution.classified_fact_count,
        resolution.materialized_count,
        resolution.failure_count,
    ) == (2, 2, 0, 0, 2)
    assert resolution.resolve(dirty(339, VirtualVariableCategory.TMP, 1)) is None


def test_frame_register_carrier_candidate_is_not_classified_without_frame_proof() -> None:
    project = SimpleNamespace(arch=Arch86_16(), _inertia_c_target="portable-flat")
    codegen = _Codegen(project)
    sp_offset = project.arch.registers["sp"][0]
    tags = Tags({"ins_addr": 0x1000, "vex_block_addr": 0x1000})
    root = CStatements(
        [
            CAssignment(
                CDirtyExpression(
                    VirtualVariable(339, 339, 16, VirtualVariableCategory.TMP, oident=1),
                    codegen=codegen,
                ),
                CDirtyExpression(
                    VirtualVariable(23, 23, 16, VirtualVariableCategory.REGISTER, oident=sp_offset),
                    codegen=codegen,
                ),
                codegen=codegen,
                tags=tags,
            )
        ],
        codegen=codegen,
    )

    resolution = collect_frame_register_carriers_8616(root, project, 0x1000).with_frame_proof(False)

    assert (
        resolution.raw_fact_count,
        resolution.normalized_fact_count,
        resolution.classified_fact_count,
        resolution.materialized_count,
        resolution.failure_count,
    ) == (1, 1, 0, 0, 0)
