"""Tests for binary-proven callee pointer parameter classification."""

from types import SimpleNamespace

from angr.sim_type import SimTypeFunction, SimTypePointer, SimTypeShort
from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.lowering.callee_pointer_contracts import (
    CalleePointerArgumentEvidence8616,
    callee_pointer_argument_evidence_by_addr_8616,
    record_callee_pointer_argument_evidence_8616,
    transfer_callee_pointer_argument_evidence_8616,
)
from inertia.lowering.callee_pointer_evidence import (
    apply_callee_pointer_argument_evidence_at_address_8616,
    callee_pointer_argument_indices_at_address_8616,
    callee_pointer_argument_is_proven_8616,
    recover_callee_pointer_argument_evidence_at_address_8616,
)
from capstone.x86_const import (
    X86_INS_MOV,
    X86_INS_RET,
    X86_INS_TEST,
    X86_OP_MEM,
    X86_OP_REG,
    X86_REG_AX,
    X86_REG_BP,
    X86_REG_BX,
    X86_REG_INVALID,
    X86_REG_SI,
)

from inertia.lowering.analysis_helpers import (
    seed_wide_stack_prototype_from_binary_address_8616,
)


def _reg(register: int) -> SimpleNamespace:
    return SimpleNamespace(type=X86_OP_REG, reg=register)


def _mem(base: int, *, displacement: int = 0) -> SimpleNamespace:
    return SimpleNamespace(
        type=X86_OP_MEM,
        size=2,
        mem=SimpleNamespace(
            base=base,
            index=X86_REG_INVALID,
            disp=displacement,
        ),
    )


def _insn(
    instruction_id: int,
    mnemonic: str,
    *operands: SimpleNamespace,
) -> SimpleNamespace:
    return SimpleNamespace(
        id=instruction_id,
        mnemonic=mnemonic,
        operands=operands,
    )


class _Functions:
    def __init__(self, function: SimpleNamespace) -> None:
        self._function = function

    def function(
        self,
        *,
        name: str,
        create: bool,
    ) -> SimpleNamespace | None:
        assert create is False
        return self._function if name == "sub_107b8" else None


def test_promotes_two_binary_proven_near_pointer_parameters() -> None:
    arch = Arch86_16()
    instructions = (
        _insn(X86_INS_MOV, "mov", _reg(X86_REG_BX), _mem(X86_REG_BP, displacement=4)),
        _insn(X86_INS_MOV, "mov", _reg(X86_REG_AX), _mem(X86_REG_BX)),
        _insn(X86_INS_MOV, "mov", _reg(X86_REG_SI), _mem(X86_REG_BP, displacement=6)),
        _insn(X86_INS_MOV, "mov", _mem(X86_REG_SI), _reg(X86_REG_AX)),
        _insn(X86_INS_RET, "ret"),
    )
    function = SimpleNamespace(
        addr=0x107B8,
        info={},
        prototype=SimTypeFunction(
            [SimTypeShort(False), SimTypeShort(False)],
            SimTypeShort(False),
        ).with_arch(arch),
        is_prototype_guessed=True,
    )
    block = SimpleNamespace(capstone=SimpleNamespace(insns=instructions))
    project = SimpleNamespace(
        arch=arch,
        factory=SimpleNamespace(
            block=lambda _address, **_kwargs: block,
        ),
        kb=SimpleNamespace(functions=_Functions(function)),
    )

    assert apply_callee_pointer_argument_evidence_at_address_8616(
        project,
        function,
        0x107B8,
    )
    assert all(
        isinstance(argument, SimTypePointer)
        for argument in function.prototype.args
    )
    assert tuple(argument.size for argument in function.prototype.args) == (16, 16)
    evidence = project._inertia_callee_pointer_argument_evidence_8616[
        function.addr
    ]
    assert evidence.raw_fact_count == 2
    assert evidence.normalized_fact_count == 2
    assert evidence.classified_fact_count == 2
    assert evidence.materialized_count == 2
    assert evidence.failure_count == 0
    assert evidence.pointer_stack_offsets == (4, 6)
    assert evidence.pointer_argument_indices == (0, 1)
    assert evidence.ambiguous_displaced_stack_offsets == ()
    assert callee_pointer_argument_is_proven_8616(
        project,
        "sub_107b8",
        1,
    )


def test_read_only_pointer_classification_does_not_mutate_prototype() -> None:
    arch = Arch86_16()
    instructions = (
        _insn(X86_INS_MOV, "mov", _reg(X86_REG_BX), _mem(X86_REG_BP, displacement=4)),
        _insn(X86_INS_MOV, "mov", _reg(X86_REG_AX), _mem(X86_REG_BX)),
        _insn(X86_INS_RET, "ret"),
    )
    prototype = SimTypeFunction(
        [SimTypeShort(False)],
        SimTypeShort(False),
    ).with_arch(arch)
    function = SimpleNamespace(
        addr=0x107B8,
        info={},
        prototype=prototype,
        is_prototype_guessed=True,
    )
    block = SimpleNamespace(capstone=SimpleNamespace(insns=instructions))
    project = SimpleNamespace(
        arch=arch,
        factory=SimpleNamespace(block=lambda _address, **_kwargs: block),
        kb=SimpleNamespace(functions=_Functions(function)),
    )

    evidence = recover_callee_pointer_argument_evidence_at_address_8616(
        project,
        0x107B8,
        prototype,
    )

    assert evidence.closes_classification
    assert evidence.pointer_argument_indices == (0,)
    assert function.prototype is prototype
    assert isinstance(function.prototype.args[0], SimTypeShort)


def test_records_contiguous_pointer_prefix_before_prototype_exists() -> None:
    arch = Arch86_16()
    instructions = (
        _insn(X86_INS_MOV, "mov", _reg(X86_REG_BX), _mem(X86_REG_BP, displacement=4)),
        _insn(X86_INS_MOV, "mov", _reg(X86_REG_AX), _mem(X86_REG_BX)),
        _insn(X86_INS_RET, "ret"),
    )
    function = SimpleNamespace(
        addr=0x107B8,
        info={},
        prototype=None,
        is_prototype_guessed=True,
    )
    block = SimpleNamespace(capstone=SimpleNamespace(insns=instructions))
    project = SimpleNamespace(
        arch=arch,
        factory=SimpleNamespace(
            block=lambda _address, **_kwargs: block,
        ),
        kb=SimpleNamespace(functions=_Functions(function)),
    )

    assert apply_callee_pointer_argument_evidence_at_address_8616(
        project,
        function,
        0x107B8,
    )
    assert callee_pointer_argument_is_proven_8616(
        project,
        "sub_107b8",
        0,
    )


def test_transfers_validated_pointer_evidence_between_project_views() -> None:
    source_project = SimpleNamespace()
    target_project = SimpleNamespace()
    source = CalleePointerArgumentEvidence8616(
        target_addr=0x107B8,
        raw_fact_count=2,
        normalized_fact_count=2,
        classified_fact_count=2,
        materialized_count=2,
        failure_count=0,
        pointer_stack_offsets=(4, 6),
        pointer_argument_indices=(0, 1),
        ambiguous_displaced_stack_offsets=(),
    )
    record_callee_pointer_argument_evidence_8616(source_project, source)

    assert transfer_callee_pointer_argument_evidence_8616(
        source_project,
        target_project,
        source_addr=0x107B8,
        target_addr=0x17B8,
    )
    transferred = callee_pointer_argument_evidence_by_addr_8616(target_project)
    assert transferred[0x17B8] == CalleePointerArgumentEvidence8616(
        target_addr=0x17B8,
        raw_fact_count=2,
        normalized_fact_count=2,
        classified_fact_count=2,
        materialized_count=2,
        failure_count=0,
        pointer_stack_offsets=(4, 6),
        pointer_argument_indices=(0, 1),
        ambiguous_displaced_stack_offsets=(),
    )
    assert not transfer_callee_pointer_argument_evidence_8616(
        source_project,
        target_project,
        source_addr=0x107B8,
        target_addr=0x17B8,
    )


def test_cross_project_seed_transfers_pointer_evidence_without_prototype(
    monkeypatch,
) -> None:
    source_project = SimpleNamespace()
    target_project = SimpleNamespace()
    source_function = SimpleNamespace(
        prototype=None,
        calling_convention=None,
        is_prototype_guessed=True,
    )
    target_function = SimpleNamespace(
        prototype=None,
        calling_convention=None,
        is_prototype_guessed=True,
    )

    def classify_pointer(
        project: object,
        _function: object,
        address: int,
    ) -> bool:
        record_callee_pointer_argument_evidence_8616(
            project,
            CalleePointerArgumentEvidence8616(
                target_addr=address,
                raw_fact_count=1,
                normalized_fact_count=1,
                classified_fact_count=1,
                materialized_count=1,
                failure_count=0,
                pointer_stack_offsets=(4,),
                pointer_argument_indices=(0,),
                ambiguous_displaced_stack_offsets=(),
            ),
        )
        return True

    monkeypatch.setattr(
        "inertia.frontend.x86_16.calling_convention_compat."
        "apply_x86_16_wide_stack_prototype_evidence_at_address",
        lambda *_args: False,
    )
    monkeypatch.setattr(
        "inertia.lowering.callee_pointer_evidence."
        "apply_callee_pointer_argument_evidence_at_address_8616",
        classify_pointer,
    )

    assert not seed_wide_stack_prototype_from_binary_address_8616(
        source_project,
        source_function,
        target_function,
        0x107B8,
        target_project=target_project,
        target_address=0x17B8,
    )
    transferred = callee_pointer_argument_evidence_by_addr_8616(target_project)
    assert transferred[0x17B8].pointer_argument_indices == (0,)


def test_records_contiguous_pointer_prefix_with_incomplete_prototype() -> None:
    arch = Arch86_16()
    instructions = (
        _insn(X86_INS_MOV, "mov", _reg(X86_REG_BX), _mem(X86_REG_BP, displacement=4)),
        _insn(X86_INS_MOV, "mov", _reg(X86_REG_AX), _mem(X86_REG_BX)),
        _insn(X86_INS_MOV, "mov", _reg(X86_REG_SI), _mem(X86_REG_BP, displacement=6)),
        _insn(X86_INS_MOV, "mov", _mem(X86_REG_SI), _reg(X86_REG_AX)),
        _insn(X86_INS_RET, "ret"),
    )
    scalar_type = SimTypeShort(False)
    function = SimpleNamespace(
        addr=0x107B8,
        info={},
        prototype=SimTypeFunction([scalar_type], scalar_type).with_arch(arch),
        is_prototype_guessed=True,
    )
    block = SimpleNamespace(capstone=SimpleNamespace(insns=instructions))
    project = SimpleNamespace(
        arch=arch,
        factory=SimpleNamespace(block=lambda _address, **_kwargs: block),
        kb=SimpleNamespace(functions=_Functions(function)),
    )

    assert apply_callee_pointer_argument_evidence_at_address_8616(
        project,
        function,
        0x107B8,
    )
    assert len(function.prototype.args) == 2
    assert all(
        isinstance(argument, SimTypePointer)
        for argument in function.prototype.args
    )
    assert callee_pointer_argument_indices_at_address_8616(
        project,
        0x107B8,
    ) == (0, 1)


def test_displaced_scalar_table_index_does_not_promote_pointer_parameter() -> None:
    arch = Arch86_16()
    instructions = (
        _insn(
            X86_INS_MOV,
            "mov",
            _reg(X86_REG_BX),
            _mem(X86_REG_BP, displacement=4),
        ),
        _insn(
            X86_INS_TEST,
            "test",
            _mem(X86_REG_BX, displacement=0x33B),
            SimpleNamespace(type=0, imm=2),
        ),
        _insn(X86_INS_RET, "ret"),
    )
    scalar_type = SimTypeShort(False)
    function = SimpleNamespace(
        addr=0x107B8,
        info={},
        prototype=SimTypeFunction([scalar_type], scalar_type).with_arch(arch),
        is_prototype_guessed=True,
    )
    block = SimpleNamespace(capstone=SimpleNamespace(insns=instructions))
    project = SimpleNamespace(
        arch=arch,
        factory=SimpleNamespace(block=lambda _address, **_kwargs: block),
        kb=SimpleNamespace(functions=_Functions(function)),
    )

    assert not apply_callee_pointer_argument_evidence_at_address_8616(
        project,
        function,
        0x107B8,
    )
    assert not isinstance(function.prototype.args[0], SimTypePointer)
    evidence = project._inertia_callee_pointer_argument_evidence_8616[
        function.addr
    ]
    assert evidence.raw_fact_count == 1
    assert evidence.classified_fact_count == 0
    assert evidence.failure_count == 1
    assert evidence.ambiguous_displaced_stack_offsets == (4,)
