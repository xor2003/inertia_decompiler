"""Resolve constant real-mode indirect jumps from decoded binary evidence.

Layer: Frontend.
Responsibility: publish typed, conservative targets for exact immediate-stack
selector transfers into DS-relative near-indirect jumps.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import Protocol, cast

from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_OP_REG

__all__ = [
    "ConstantIndirectJumpArtifact8616",
    "ConstantIndirectJumpRecord8616",
    "ConstantIndirectJumpStatus8616",
    "collect_constant_indirect_jump_edges_8616",
]


class _MemoryOperandBoundary8616(Protocol):
    """Capstone memory fields consumed by the frontend resolver."""

    base: int
    index: int
    scale: int
    disp: int


class _OperandBoundary8616(Protocol):
    """Capstone operand fields consumed by the frontend resolver."""

    type: int
    imm: int
    reg: int
    size: int
    mem: _MemoryOperandBoundary8616


class _DecodedInstructionBoundary8616(Protocol):
    """Decoded Capstone instruction fields used at the third-party boundary."""

    address: int
    mnemonic: str
    operands: Sequence[_OperandBoundary8616]

    def reg_name(self, register_id: int) -> str:
        """Return Capstone's canonical register name."""
        ...


class _InstructionBoundary8616(Protocol):
    """angr wrapper fields for a decoded Capstone instruction."""

    insn: _DecodedInstructionBoundary8616


class _CapstoneBoundary8616(Protocol):
    """Decoded instruction sequence exposed by an angr block."""

    insns: Sequence[object]


class _BlockBoundary8616(Protocol):
    """angr block fields consumed by the resolver."""

    addr: int
    capstone: _CapstoneBoundary8616


class _MemoryBoundary8616(Protocol):
    """CLE memory read boundary."""

    def load(self, address: int, size: int) -> bytes:
        """Read mapped bytes at one linear address."""
        ...


class _MainObjectBoundary8616(Protocol):
    """MZ loader facts required for relocation-backed segment candidates."""

    mz_load_segment: int
    mz_relocation_entries: Sequence[tuple[int, int]]
    initial_register_values: Mapping[str, int]


class _LoaderBoundary8616(Protocol):
    """CLE loader fields consumed by the resolver."""

    memory: _MemoryBoundary8616
    main_object: _MainObjectBoundary8616


class _ProjectBoundary8616(Protocol):
    """angr project fields consumed at the frontend boundary."""

    loader: _LoaderBoundary8616
    _inertia_original_project: object
    _inertia_original_linear_delta: int


class ConstantIndirectJumpStatus8616(Enum):
    """Typed classification for one decoded near-indirect jump site."""

    RESOLVED = "resolved"
    POP_SELECTOR_MISSING = "pop_selector_missing"
    PREDECESSOR_AMBIGUOUS = "predecessor_ambiguous"
    IMMEDIATE_PUSH_MISSING = "immediate_push_missing"
    SELECTOR_OUT_OF_RANGE = "selector_out_of_range"
    MZ_CONTEXT_MISSING = "mz_context_missing"
    TABLE_TARGET_AMBIGUOUS = "table_target_ambiguous"


@dataclass(frozen=True, slots=True)
class ConstantIndirectJumpRecord8616:
    """Resolution or typed refusal for one decoded indirect jump."""

    site_addr: int
    source_block_addr: int
    status: ConstantIndirectJumpStatus8616
    selector_register: str | None = None
    selector_byte_offset: int | None = None
    table_segment: int | None = None
    table_linear_addr: int | None = None
    target_ip: int | None = None
    target_linear_addr: int | None = None
    projected_target_addr: int | None = None


@dataclass(frozen=True, slots=True)
class ConstantIndirectJumpArtifact8616:
    """Closed evidence counters and records for decoded indirect jump sites."""

    records: tuple[ConstantIndirectJumpRecord8616, ...]
    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int

    @property
    def complete(self) -> bool:
        """Return whether every observed candidate resolved uniquely."""
        return (
            self.raw_fact_count > 0
            and self.raw_fact_count == self.normalized_fact_count
            and self.normalized_fact_count == self.classified_fact_count
            and self.classified_fact_count == self.materialized_count + self.failure_count
            and self.failure_count == 0
        )

    @property
    def resolved_edges(self) -> tuple[tuple[int, int], ...]:
        """Return accepted source-block to projected-target edges."""
        return tuple(
            (record.source_block_addr, record.projected_target_addr)
            for record in self.records
            if record.status is ConstantIndirectJumpStatus8616.RESOLVED
            and record.projected_target_addr is not None
        )


def _decoded_instruction_8616(instruction: object) -> _DecodedInstructionBoundary8616:
    """Unwrap one angr Capstone instruction at the dynamic boundary."""
    wrapper = cast(_InstructionBoundary8616, instruction)
    try:
        return wrapper.insn
    except AttributeError:
        return cast(_DecodedInstructionBoundary8616, instruction)


def _block_instructions_8616(block: object) -> tuple[_DecodedInstructionBoundary8616, ...]:
    """Return decoded instructions for one dynamic angr block."""
    boundary = cast(_BlockBoundary8616, block)
    try:
        instructions = tuple(boundary.capstone.insns)
    except (AttributeError, TypeError):
        return ()
    return tuple(_decoded_instruction_8616(instruction) for instruction in instructions)


def _indirect_jump_shape_8616(
    block: object,
) -> tuple[int, int, str, int] | None:
    """Return ``(site, source, base-register, displacement)`` for exact JMP m16."""
    instructions = _block_instructions_8616(block)
    if not instructions:
        return None
    jump = instructions[-1]
    if jump.mnemonic.lower() != "jmp" or len(jump.operands) != 1:
        return None
    operand = jump.operands[0]
    if operand.type != X86_OP_MEM or operand.size != 2:
        return None
    memory = operand.mem
    if memory.base == 0 or memory.index != 0 or memory.scale not in {0, 1}:
        return None
    register_name = jump.reg_name(memory.base).lower()
    if register_name not in {"ax", "bx", "cx", "dx", "si", "di", "bp", "sp"}:
        return None
    source_addr = cast(_BlockBoundary8616, block).addr
    return jump.address, source_addr, register_name, int(memory.disp)


def _pop_selector_register_8616(block: object, expected_register: str) -> bool:
    """Require the indirect jump to be immediately preceded by POP of its base."""
    instructions = _block_instructions_8616(block)
    if len(instructions) < 2:
        return False
    pop = instructions[-2]
    if pop.mnemonic.lower() != "pop" or len(pop.operands) != 1:
        return False
    operand = pop.operands[0]
    return operand.type == X86_OP_REG and pop.reg_name(operand.reg).lower() == expected_register


def _immediate_push_for_site_8616(
    source_addr: int,
    blocks_by_addr: Mapping[int, object],
    predecessors: Mapping[int, tuple[int, ...]],
) -> tuple[int | None, ConstantIndirectJumpStatus8616 | None]:
    """Walk a unique predecessor chain to the LIFO PUSH immediate owner."""
    current = source_addr
    visited: set[int] = set()
    for _depth in range(16):
        incoming = predecessors.get(current, ())
        if len(incoming) != 1:
            return None, ConstantIndirectJumpStatus8616.PREDECESSOR_AMBIGUOUS
        current = incoming[0]
        if current in visited:
            return None, ConstantIndirectJumpStatus8616.PREDECESSOR_AMBIGUOUS
        visited.add(current)
        block = blocks_by_addr.get(current)
        if block is None:
            return None, ConstantIndirectJumpStatus8616.IMMEDIATE_PUSH_MISSING
        for instruction in reversed(_block_instructions_8616(block)):
            mnemonic = instruction.mnemonic.lower()
            if mnemonic in {"call", "lcall", "callq"}:
                continue
            if mnemonic == "push":
                if len(instruction.operands) != 1 or instruction.operands[0].type != X86_OP_IMM:
                    return None, ConstantIndirectJumpStatus8616.IMMEDIATE_PUSH_MISSING
                return int(instruction.operands[0].imm) & 0xFFFF, None
            if mnemonic.startswith(("push", "pop")) or mnemonic in {"enter", "leave"}:
                return None, ConstantIndirectJumpStatus8616.IMMEDIATE_PUSH_MISSING
    return None, ConstantIndirectJumpStatus8616.IMMEDIATE_PUSH_MISSING


def _original_project_context_8616(project: object) -> tuple[object, int]:
    """Return original-image project and slice-to-original linear delta."""
    boundary = cast(_ProjectBoundary8616, project)
    try:
        original = boundary._inertia_original_project
    except AttributeError:
        return project, 0
    try:
        delta = boundary._inertia_original_linear_delta
    except AttributeError:
        return original, 0
    return original, delta if isinstance(delta, int) else 0


def _relocated_segment_candidates_8616(project: object) -> tuple[int, ...] | None:
    """Read unique relocated segment words from an MZ loader image."""
    boundary = cast(_ProjectBoundary8616, project)
    try:
        loader = boundary.loader
        main_object = loader.main_object
        load_segment = main_object.mz_load_segment
        relocations = tuple(main_object.mz_relocation_entries)
    except (AttributeError, TypeError):
        return None
    if not isinstance(load_segment, int) or not relocations:
        return None
    load_base = load_segment << 4
    values: set[int] = set()
    for reloc_offset, reloc_segment in relocations:
        address = load_base + (int(reloc_segment) << 4) + int(reloc_offset)
        try:
            data = bytes(loader.memory.load(address, 2))
        except (KeyError, TypeError, ValueError):
            continue
        if len(data) == 2:
            values.add(int.from_bytes(data, "little"))
    return tuple(sorted(values))


def _initialized_data_segment_candidates_8616(project: object) -> tuple[int, ...] | None:
    """Return relocated words used by exact adjacent DS initialization instructions."""
    boundary = cast(_ProjectBoundary8616, project)
    try:
        loader = boundary.loader
        main_object = loader.main_object
        load_segment = main_object.mz_load_segment
        relocations = tuple(main_object.mz_relocation_entries)
    except (AttributeError, TypeError):
        return None
    if not isinstance(load_segment, int) or not relocations:
        return None
    load_base = load_segment << 4
    candidates: set[int] = set()
    for reloc_offset, reloc_segment in relocations:
        relocation_addr = load_base + (int(reloc_segment) << 4) + int(reloc_offset)
        try:
            value_bytes = bytes(loader.memory.load(relocation_addr, 2))
            mov_window = bytes(loader.memory.load(relocation_addr - 1, 5))
            push_window = bytes(loader.memory.load(relocation_addr - 1, 4))
        except (KeyError, TypeError, ValueError):
            continue
        if len(value_bytes) != 2:
            continue
        value = int.from_bytes(value_bytes, "little")
        mov_register = mov_window[0] - 0xB8 if len(mov_window) == 5 else -1
        exact_mov_ds = (
            0 <= mov_register <= 7
            and mov_window[1:3] == value_bytes
            and mov_window[3] == 0x8E
            and mov_window[4] == 0xD8 + mov_register
        )
        exact_push_pop_ds = (
            len(push_window) == 4
            and push_window[0] == 0x68
            and push_window[1:3] == value_bytes
            and push_window[3] == 0x1F
        )
        if exact_mov_ds or exact_push_pop_ds:
            candidates.add(value)
    return tuple(sorted(candidates))


def _table_target_candidates_8616(
    project: object,
    *,
    projection_project: object,
    displacement: int,
    selector_byte_offset: int,
    original_delta: int,
    region_start: int,
    region_end: int,
) -> tuple[tuple[int, int, int, int, int], ...] | None:
    """Return relocation-backed table candidates whose prefix targets stay in-region."""
    boundary = cast(_ProjectBoundary8616, project)
    try:
        loader = boundary.loader
        initial_registers = loader.main_object.initial_register_values
        code_segment = initial_registers["cs"]
    except (AttributeError, KeyError, TypeError):
        return None
    segments = _relocated_segment_candidates_8616(project)
    if not isinstance(code_segment, int) or segments is None:
        return None
    initialized_data_segments = _initialized_data_segment_candidates_8616(project)
    if initialized_data_segments:
        segments = initialized_data_segments
    projection_boundary = cast(_ProjectBoundary8616, projection_project)
    require_projected_mapping = projection_project is not project
    projection_memory: _MemoryBoundary8616 | None = None
    if require_projected_mapping:
        try:
            projection_memory = projection_boundary.loader.memory
        except AttributeError:
            return None
    table_offset = displacement & 0xFFFF
    candidates: set[tuple[int, int, int, int, int]] = set()
    for data_segment in segments:
        prefix = _table_prefix_candidate_8616(
            loader,
            projection_memory,
            code_segment=code_segment,
            table_linear=(data_segment << 4) + table_offset,
            selector_byte_offset=selector_byte_offset,
            original_delta=original_delta,
            region_start=region_start,
            region_end=region_end,
            require_projected_mapping=require_projected_mapping,
        )
        if prefix is not None:
            candidates.add(
                (data_segment, (data_segment << 4) + table_offset, *prefix)
            )
    return tuple(sorted(candidates))


def _table_prefix_candidate_8616(
    loader: _LoaderBoundary8616,
    projection_memory: _MemoryBoundary8616 | None,
    *,
    code_segment: int,
    table_linear: int,
    selector_byte_offset: int,
    original_delta: int,
    region_start: int,
    region_end: int,
    require_projected_mapping: bool,
) -> tuple[int, int, int] | None:
    """Return the proven last prefix target for one relocation-backed table."""
    selected_ip: int | None = None
    selected_linear: int | None = None
    selected_projected: int | None = None
    for byte_offset in range(0, selector_byte_offset + 1, 2):
        try:
            data = bytes(loader.memory.load(table_linear + byte_offset, 2))
        except (KeyError, TypeError, ValueError):
            return None
        if len(data) != 2:
            return None
        target_ip = int.from_bytes(data, "little")
        target_linear = (code_segment << 4) + target_ip
        projected_target = target_linear - original_delta
        if not (region_start <= projected_target < region_end):
            return None
        if require_projected_mapping:
            assert projection_memory is not None
            try:
                projected_byte = bytes(projection_memory.load(projected_target, 1))
            except (KeyError, TypeError, ValueError):
                return None
            if len(projected_byte) != 1:
                return None
        selected_ip = target_ip
        selected_linear = target_linear
        selected_projected = projected_target
    if selected_ip is None or selected_linear is None or selected_projected is None:
        return None
    return selected_ip, selected_linear, selected_projected


def collect_constant_indirect_jump_edges_8616(
    project: object,
    *,
    blocks: Sequence[object],
    successor_edges: Sequence[tuple[int, int]],
    region_start: int,
    region_end: int,
) -> ConstantIndirectJumpArtifact8616:
    """Resolve exact immediate-stack selectors into unique near jump targets."""
    blocks_by_addr = {
        cast(_BlockBoundary8616, block).addr: block
        for block in blocks
    }
    predecessor_lists: dict[int, list[int]] = {}
    for source, target in successor_edges:
        predecessor_lists.setdefault(target, []).append(source)
    predecessors = {
        target: tuple(sorted(set(sources)))
        for target, sources in predecessor_lists.items()
    }
    original_project, original_delta = _original_project_context_8616(project)
    records: list[ConstantIndirectJumpRecord8616] = []
    for block_addr in sorted(blocks_by_addr):
        block = blocks_by_addr[block_addr]
        shape = _indirect_jump_shape_8616(block)
        if shape is None:
            continue
        site_addr, source_addr, selector_register, displacement = shape
        if not _pop_selector_register_8616(block, selector_register):
            records.append(
                ConstantIndirectJumpRecord8616(
                    site_addr,
                    source_addr,
                    ConstantIndirectJumpStatus8616.POP_SELECTOR_MISSING,
                    selector_register=selector_register,
                )
            )
            continue
        selector, refusal = _immediate_push_for_site_8616(source_addr, blocks_by_addr, predecessors)
        if selector is None:
            records.append(
                ConstantIndirectJumpRecord8616(
                    site_addr,
                    source_addr,
                    refusal or ConstantIndirectJumpStatus8616.IMMEDIATE_PUSH_MISSING,
                    selector_register=selector_register,
                )
            )
            continue
        if selector > 0x200 or selector & 1:
            records.append(
                ConstantIndirectJumpRecord8616(
                    site_addr,
                    source_addr,
                    ConstantIndirectJumpStatus8616.SELECTOR_OUT_OF_RANGE,
                    selector_register=selector_register,
                    selector_byte_offset=selector,
                )
            )
            continue
        candidates = _table_target_candidates_8616(
            original_project,
            projection_project=project,
            displacement=displacement,
            selector_byte_offset=selector,
            original_delta=original_delta,
            region_start=region_start,
            region_end=region_end,
        )
        if candidates is None:
            status = ConstantIndirectJumpStatus8616.MZ_CONTEXT_MISSING
        elif len(candidates) != 1:
            status = ConstantIndirectJumpStatus8616.TABLE_TARGET_AMBIGUOUS
        else:
            data_segment, table_linear, target_ip, target_linear, projected_target = candidates[0]
            records.append(
                ConstantIndirectJumpRecord8616(
                    site_addr,
                    source_addr,
                    ConstantIndirectJumpStatus8616.RESOLVED,
                    selector_register=selector_register,
                    selector_byte_offset=selector,
                    table_segment=data_segment,
                    table_linear_addr=table_linear,
                    target_ip=target_ip,
                    target_linear_addr=target_linear,
                    projected_target_addr=projected_target,
                )
            )
            continue
        records.append(
            ConstantIndirectJumpRecord8616(
                site_addr,
                source_addr,
                status,
                selector_register=selector_register,
                selector_byte_offset=selector,
            )
        )
    raw_count = len(records)
    materialized_count = sum(
        record.status is ConstantIndirectJumpStatus8616.RESOLVED
        for record in records
    )
    return ConstantIndirectJumpArtifact8616(
        records=tuple(records),
        raw_fact_count=raw_count,
        normalized_fact_count=raw_count,
        classified_fact_count=raw_count,
        materialized_count=materialized_count,
        failure_count=raw_count - materialized_count,
    )
