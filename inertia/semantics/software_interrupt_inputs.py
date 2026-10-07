"""Recover typed register inputs consumed by software interrupts.

Layer: Semantics.
Responsibility: classify binary-proven interrupt services and resolve their
required register values from typed IR. This module never reads assembly text,
COD/source metadata, names, or rendered C, and it never mutates codegen.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from inertia.frontend.x86_16.interrupt_contract import interrupt_vector_from_core_addr_8616
from inertia.ir.core import (
    AddressStatus,
    IRAddress,
    IRBinaryValue,
    IRBlock,
    IRFunctionArtifact,
    IRInstr,
    IRValue,
    MemSpace,
)
from inertia.ir.logical_memory_contracts import IRLogicalMemoryArtifact8616
from inertia.ir.logical_memory_scalar_projection import project_logical_stack_word_value_8616
from inertia.ir.scalar_definitions import (
    ScalarDefinitionIndex8616,
    build_scalar_definition_index_8616,
)

type IRScalarValue8616 = IRValue | IRBinaryValue

__all__ = [
    "IRScalarValue8616",
    "SoftwareInterruptAbiSpec8616",
    "SoftwareInterruptInputArtifact8616",
    "SoftwareInterruptInputFact8616",
    "SoftwareInterruptInputStats8616",
    "SoftwareInterruptRefusalKind8616",
    "build_software_interrupt_input_artifact_8616",
    "software_interrupt_value_fingerprint_8616",
]


class SoftwareInterruptRefusalKind8616(StrEnum):
    """Typed reasons why a known interrupt ABI could not be proven."""

    REQUIRED_REGISTER_UNRESOLVED = "required-register-unresolved"


@dataclass(frozen=True, slots=True)
class SoftwareInterruptAbiSpec8616:
    """One selector-specific software-interrupt input contract."""

    vector: int
    selector_register: str
    selector_value: int
    argument_registers: tuple[str, ...]
    result_register: str | None


@dataclass(frozen=True, slots=True)
class SoftwareInterruptInputFact8616:
    """Exact register values consumed and produced at one interrupt callsite."""

    callsite_addr: int
    target_addr: int
    vector: int
    selector_value: int
    argument_registers: tuple[str, ...]
    argument_values: tuple[IRScalarValue8616, ...]
    result_register: str | None


@dataclass(frozen=True, slots=True)
class SoftwareInterruptInputStats8616:
    """Closed evidence-loop counters for interrupt input recovery."""

    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0


@dataclass(frozen=True, slots=True)
class SoftwareInterruptInputArtifact8616:
    """Typed interrupt input facts and explicit recovery refusals."""

    facts: tuple[SoftwareInterruptInputFact8616, ...] = ()
    refusals: tuple[tuple[int, SoftwareInterruptRefusalKind8616, str], ...] = ()
    stats: SoftwareInterruptInputStats8616 = SoftwareInterruptInputStats8616()


_INTERRUPT_ABI_SPECS_8616: tuple[SoftwareInterruptAbiSpec8616, ...] = (
    SoftwareInterruptAbiSpec8616(
        vector=0x21,
        selector_register="ah",
        selector_value=0x48,
        argument_registers=("bx",),
        result_register="ax",
    ),
    SoftwareInterruptAbiSpec8616(
        vector=0x33,
        selector_register="ax",
        selector_value=0x0004,
        argument_registers=("ax", "cx", "dx"),
        result_register="ax",
    ),
)

_BINARY_OPS_8616: dict[str, str] = {
    "Iop_Add16": "Add",
    "Iop_Or16": "Or",
    "Iop_Shr16": "Shr",
    "Iop_Shl16": "Shl",
}

_REGISTER_SIZES_8616: dict[str, int] = {
    "al": 1,
    "ah": 1,
    "bl": 1,
    "bh": 1,
    "cl": 1,
    "ch": 1,
    "dl": 1,
    "dh": 1,
    "ax": 2,
    "bx": 2,
    "cx": 2,
    "dx": 2,
    "si": 2,
    "di": 2,
    "bp": 2,
    "sp": 2,
    "ds": 2,
    "es": 2,
    "fs": 2,
    "gs": 2,
    "eax": 4,
    "ebx": 4,
    "ecx": 4,
    "edx": 4,
    "esi": 4,
    "edi": 4,
    "ebp": 4,
    "esp": 4,
}


def _tmp_id_8616(value: IRValue | None) -> int | None:
    """Return an exact VEX temporary id from an IR destination."""
    if value is None or value.space is not MemSpace.TMP or value.name is None:
        return None
    if not value.name.startswith("t") or not value.name[1:].isdigit():
        return None
    return int(value.name[1:])


def _resolve_value_8616(
    value: object,
    temp_values: dict[int, IRScalarValue8616],
    register_values: dict[str, IRScalarValue8616 | None],
) -> IRScalarValue8616 | None:
    """Resolve one typed IR value through exact same-block definitions."""
    if isinstance(value, IRBinaryValue):
        lhs = _resolve_value_8616(value.lhs, temp_values, register_values)
        rhs = _resolve_value_8616(value.rhs, temp_values, register_values)
        if lhs is None or rhs is None:
            return None
        return IRBinaryValue(value.op, lhs, rhs, size=value.size)
    if not isinstance(value, IRValue):
        return None
    if value.source_tmp is not None:
        return temp_values.get(value.source_tmp)
    if value.space is MemSpace.REG and value.name is not None:
        register_name = value.name.lower()
        if register_name in register_values:
            return register_values[register_name]
        return value
    if value.space in {MemSpace.CONST, MemSpace.SS}:
        return value
    return None


def _stack_load_value_8616(instr: IRInstr) -> IRValue | None:
    """Return a typed stack value for one exact stable SS load."""
    if instr.op != "LOAD" or len(instr.args) != 1:
        return None
    address = instr.args[0]
    if (
        not isinstance(address, IRAddress)
        or address.space is not MemSpace.SS
        or address.status is not AddressStatus.STABLE
        or len(address.base) != 1
        or address.base[0].lower() not in {"bp", "sp"}
    ):
        return None
    return IRValue(
        MemSpace.SS,
        name=address.base[0].lower(),
        offset=address.offset,
        size=address.size or instr.size,
        memory_access_insn=instr.addr,
    )


def _record_definition_8616(
    instr: IRInstr,
    temp_values: dict[int, IRScalarValue8616],
    register_values: dict[str, IRScalarValue8616 | None],
    definitions: ScalarDefinitionIndex8616,
    logical_memory: IRLogicalMemoryArtifact8616 | None,
    *,
    function_addr: int,
    block_addr: int,
    instr_index: int,
) -> None:
    """Apply one supported typed-IR definition to same-block value state."""
    temp_id = _tmp_id_8616(instr.dst)
    stack_value = _stack_load_value_8616(instr)
    if temp_id is not None and stack_value is not None:
        temp_values[temp_id] = stack_value
        return
    logical_word = project_logical_stack_word_value_8616(
        instr,
        definitions,
        logical_memory,
        function_addr=function_addr,
        block_addr=block_addr,
        before_index=instr_index,
    )
    if temp_id is not None and logical_word is not None:
        temp_values[temp_id] = logical_word
        return
    if temp_id is not None and instr.op in _BINARY_OPS_8616 and len(instr.args) == 2:
        lhs = _resolve_value_8616(instr.args[0], temp_values, register_values)
        rhs = _resolve_value_8616(instr.args[1], temp_values, register_values)
        byte_stack_recombination = (
            logical_memory is None
            and instr.size > 1
            and any(
                isinstance(value, IRValue)
                and value.space is MemSpace.SS
                and value.size < instr.size
                for value in (lhs, rhs)
            )
        )
        if lhs is not None and rhs is not None and not byte_stack_recombination:
            temp_values[temp_id] = IRBinaryValue(
                _BINARY_OPS_8616[instr.op],
                lhs,
                rhs,
                size=instr.size,
            )
        else:
            temp_values.pop(temp_id, None)
        return
    if instr.op != "MOV" or len(instr.args) != 1 or instr.dst is None:
        return
    resolved = _resolve_value_8616(instr.args[0], temp_values, register_values)
    if temp_id is not None:
        if resolved is None:
            temp_values.pop(temp_id, None)
        else:
            temp_values[temp_id] = resolved
        return
    if instr.dst.space is MemSpace.REG and instr.dst.name is not None:
        register_name = instr.dst.name.lower()
        if resolved is None:
            register_values[register_name] = None
        else:
            register_values[register_name] = resolved


def _interrupt_call_target_8616(instr: IRInstr) -> tuple[int, int, int] | None:
    """Return callsite, target, and vector for one typed-IR interrupt call."""
    if instr.op != "CALL" or len(instr.args) != 1 or instr.addr is None:
        return None
    target = instr.args[0]
    if not isinstance(target, IRValue) or target.space is not MemSpace.CONST or target.const is None:
        return None
    vector = interrupt_vector_from_core_addr_8616(target.const)
    return None if vector is None else (instr.addr, target.const, vector)


def _matching_spec_8616(
    vector: int,
    register_values: dict[str, IRScalarValue8616 | None],
) -> SoftwareInterruptAbiSpec8616 | None:
    """Select an interrupt ABI only from an exact constant selector."""
    for spec in _INTERRUPT_ABI_SPECS_8616:
        if spec.vector != vector:
            continue
        selector = register_values.get(spec.selector_register)
        if isinstance(selector, IRValue) and selector.space is MemSpace.CONST and selector.const == spec.selector_value:
            return spec
    return None


def _required_register_value_8616(
    register_name: str,
    register_values: dict[str, IRScalarValue8616 | None],
) -> IRScalarValue8616 | None:
    """Resolve a required ABI register, preserving an untouched entry value."""
    if register_name in register_values:
        return register_values[register_name]
    size = _REGISTER_SIZES_8616.get(register_name)
    if size is None:
        return None
    return IRValue(MemSpace.REG, name=register_name, size=size)


def _facts_from_block_8616(
    block: IRBlock,
    definitions: ScalarDefinitionIndex8616,
    logical_memory: IRLogicalMemoryArtifact8616 | None,
    *,
    function_addr: int,
) -> tuple[list[SoftwareInterruptInputFact8616], list[tuple[int, SoftwareInterruptRefusalKind8616, str]], int, int, int]:
    """Recover interrupt facts and counters from one typed IR block."""
    temp_values: dict[int, IRScalarValue8616] = {}
    register_values: dict[str, IRScalarValue8616 | None] = {}
    facts: list[SoftwareInterruptInputFact8616] = []
    refusals: list[tuple[int, SoftwareInterruptRefusalKind8616, str]] = []
    raw_count = 0
    normalized_count = 0
    classified_count = 0
    for instr_index, instr in enumerate(block.instrs):
        call_target = _interrupt_call_target_8616(instr)
        if call_target is None:
            _record_definition_8616(
                instr,
                temp_values,
                register_values,
                definitions,
                logical_memory,
                function_addr=function_addr,
                block_addr=block.addr,
                instr_index=instr_index,
            )
            continue
        raw_count += 1
        normalized_count += 1
        callsite_addr, target_addr, vector = call_target
        spec = _matching_spec_8616(vector, register_values)
        if spec is None:
            continue
        classified_count += 1
        values = tuple(
            _required_register_value_8616(name, register_values)
            for name in spec.argument_registers
        )
        if any(value is None for value in values):
            missing = ",".join(
                name for name, value in zip(spec.argument_registers, values, strict=True) if value is None
            )
            refusals.append(
                (
                    callsite_addr,
                    SoftwareInterruptRefusalKind8616.REQUIRED_REGISTER_UNRESOLVED,
                    missing,
                )
            )
            continue
        facts.append(
            SoftwareInterruptInputFact8616(
                callsite_addr=callsite_addr,
                target_addr=target_addr,
                vector=vector,
                selector_value=spec.selector_value,
                argument_registers=spec.argument_registers,
                argument_values=tuple(value for value in values if value is not None),
                result_register=spec.result_register,
            )
        )
    return facts, refusals, raw_count, normalized_count, classified_count


def build_software_interrupt_input_artifact_8616(
    artifact: IRFunctionArtifact,
) -> SoftwareInterruptInputArtifact8616:
    """Build typed software-interrupt inputs from exact same-block IR facts."""
    definitions = build_scalar_definition_index_8616(artifact)
    facts: list[SoftwareInterruptInputFact8616] = []
    refusals: list[tuple[int, SoftwareInterruptRefusalKind8616, str]] = []
    raw_count = normalized_count = classified_count = 0
    for block in artifact.blocks:
        block_facts, block_refusals, raw, normalized, classified = _facts_from_block_8616(
            block,
            definitions,
            artifact.logical_memory,
            function_addr=artifact.function_addr,
        )
        facts.extend(block_facts)
        refusals.extend(block_refusals)
        raw_count += raw
        normalized_count += normalized
        classified_count += classified
    return SoftwareInterruptInputArtifact8616(
        facts=tuple(facts),
        refusals=tuple(refusals),
        stats=SoftwareInterruptInputStats8616(
            raw_fact_count=raw_count,
            normalized_fact_count=normalized_count,
            classified_fact_count=classified_count,
            materialized_count=len(facts),
            failure_count=len(refusals),
        ),
    )


def software_interrupt_value_fingerprint_8616(value: IRScalarValue8616) -> str:
    """Return a deterministic identity for one proven interrupt argument."""
    if isinstance(value, IRBinaryValue):
        lhs = software_interrupt_value_fingerprint_8616(value.lhs)
        rhs = software_interrupt_value_fingerprint_8616(value.rhs)
        return f"{value.op}({lhs},{rhs}):size{value.size}"
    if value.space is MemSpace.CONST and value.const is not None:
        return f"const:{value.const:#x}:size{value.size}"
    if value.space is MemSpace.SS and value.name is not None:
        return f"stack:SS:{value.name.upper()}{value.offset:+#x}:size{value.size}"
    if value.space is MemSpace.REG and value.name is not None:
        return f"reg:{value.name.lower()}:size{value.size}"
    return f"unresolved:{value.space.value}:{value.name or ''}:size{value.size}"
