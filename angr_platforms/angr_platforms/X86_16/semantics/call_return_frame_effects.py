"""Publish exact VEX ownership for source-invisible CALL return-frame effects.

Layer: Semantics.
Responsibility: join decoded x86 CALL instructions to the exact VEX statements
that update SP and write their machine return frames.
This module owns instruction-effect meaning only. It does not inspect structured
C, choose variables, mutate codegen, or perform rewrite/postprocess cleanup.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.

The custom x86-16 lifter must model CALL stack effects for execution and tail
validation. Structured C already represents those effects with a call, so later
Lowering may consume their projections only through the typed statement keys
published here. Address-only, expression-shape, and rendered-text matching are
not sufficient ownership evidence.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol, cast

from capstone.x86_const import X86_INS_CALL, X86_INS_LCALL

from ..pipeline.errors import PipelineHardError
from .call_return_frame_projections import (
    CallReturnFrameEffectKey8616,
    CallReturnFrameProjectionCollection8616,
    collect_call_return_frame_store_projections_8616,
)

__all__ = [
    "CallReturnFrameEffectCollection8616",
    "CallReturnFrameEffectFact8616",
    "CallReturnFrameEffectKey8616",
    "CallReturnFrameEffectRole8616",
    "MachineCallFrame8616",
    "collect_call_return_frame_effects_8616",
    "decode_machine_call_frame_8616",
]

type DynamicValue = Any
type _CollectionCacheKey8616 = tuple[
    int,
    tuple[tuple[int, int], ...],
    tuple[tuple[int, int], ...],
]


class CallReturnFrameEffectRole8616(StrEnum):
    """One source-invisible machine effect emitted by a CALL instruction."""

    STACK_POINTER_UPDATE = "stack_pointer_update"
    STACK_STORE = "stack_store"


@dataclass(frozen=True, slots=True)
class MachineCallFrame8616:
    """Encoded CALL frame, independent of target ABI or argument cleanup."""

    callsite_addr: int
    return_addr: int
    operand_bits: int
    far: bool

    @property
    def frame_bytes(self) -> int:
        """Return the complete IP/EIP and optional CS slot width."""
        return (self.operand_bits // 8) * (2 if self.far else 1)


@dataclass(frozen=True, slots=True)
class CallReturnFrameEffectFact8616:
    """Exact semantic ownership of one VEX CALL-frame effect."""

    key: CallReturnFrameEffectKey8616
    role: CallReturnFrameEffectRole8616


@dataclass(frozen=True, slots=True)
class CallReturnFrameEffectCollection8616:
    """Closed evidence census for CALL-frame effect collection."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int
    effects: tuple[CallReturnFrameEffectFact8616, ...]
    projection_collection: CallReturnFrameProjectionCollection8616


class _ProjectCallReturnFrameCacheSurface8616(Protocol):
    """Owned project extension retaining immutable CALL-frame facts."""

    _inertia_call_return_frame_effect_cache_8616: dict[
        _CollectionCacheKey8616,
        CallReturnFrameEffectCollection8616,
    ]


def _collection_cache_8616(
    project: object,
) -> dict[_CollectionCacheKey8616, CallReturnFrameEffectCollection8616]:
    """Return the validated project-owned CALL-frame fact cache."""
    surface = cast(_ProjectCallReturnFrameCacheSurface8616, project)
    try:
        cache = surface._inertia_call_return_frame_effect_cache_8616
    except AttributeError:
        cache = {}
        surface._inertia_call_return_frame_effect_cache_8616 = cache
    if not isinstance(cache, dict):
        raise TypeError("CALL return-frame effect cache must be a dict")
    return cache


def decode_machine_call_frame_8616(project: object, address: int) -> MachineCallFrame8616 | None:
    """Decode one exact CALL's frame at the dynamic angr/Capstone boundary."""
    project_dynamic = cast(DynamicValue, project)
    try:
        wrappers = tuple(
            project_dynamic.factory.block(
                address,
                num_inst=1,
                opt_level=0,
            ).capstone.insns
            or ()
        )
        if len(wrappers) != 1:
            return None
        instruction = wrappers[0].insn
        if instruction.id not in {X86_INS_CALL, X86_INS_LCALL}:
            return None
        if instruction.address != address or instruction.size <= 0:
            return None
        # Capstone labels operand-size-overridden FF /3 as CALL, not LCALL.
        # The decoded opcode and ModRM extension still identify a far transfer.
        far = instruction.id == X86_INS_LCALL or (
            instruction.opcode[0] == 0xFF and (instruction.modrm & 0x38) == 0x18
        )
        return MachineCallFrame8616(
            address, address + instruction.size,
            32 if 0x66 in instruction.prefix else 16,
            far,
        )
    except (AttributeError, KeyError, TypeError, ValueError):
        return None


def _unoptimized_vex_block_8616(project: object, block: object) -> DynamicValue | None:
    """Re-lift one known function block without VEX statement optimization."""
    project_dynamic = cast(DynamicValue, project)
    block_dynamic = cast(DynamicValue, block)
    try:
        block_addr = block_dynamic.addr
        block_size = block_dynamic.size
        if not isinstance(block_addr, int) or not isinstance(block_size, int) or block_size <= 0:
            return None
        return project_dynamic.factory.block(
            block_addr,
            size=block_size,
            opt_level=0,
        ).vex
    except (AttributeError, KeyError, TypeError, ValueError):
        return None


def _block_identity_8616(block: object) -> tuple[int, int] | None:
    """Return one cache-safe address/size pair from an angr function block."""
    block_dynamic = cast(DynamicValue, block)
    try:
        block_addr = block_dynamic.addr
        block_size = block_dynamic.size
    except AttributeError:
        return None
    if not isinstance(block_addr, int) or not isinstance(block_size, int) or block_size <= 0:
        return None
    return block_addr, block_size


def _effect_roles_for_call_8616(
    vex: DynamicValue,
    callsite_addr: int,
    return_addr: int,
    *,
    sp_offset: int,
    far_call: bool,
) -> tuple[tuple[int, CallReturnFrameEffectRole8616], ...] | None:
    """Classify the complete VEX frame sequence for one exact CALL IMark."""
    current_addr: int | None = None
    matched_length: int | None = None
    roles: list[tuple[int, CallReturnFrameEffectRole8616]] = []
    matched_imark_count = 0
    for statement_index, statement_value in enumerate(tuple(vex.statements or ())):
        statement = cast(DynamicValue, statement_value)
        tag = statement.tag
        if tag == "Ist_IMark":
            current_addr = statement.addr
            if current_addr == callsite_addr:
                matched_imark_count += 1
                matched_length = statement.len
            continue
        if current_addr != callsite_addr:
            continue
        if tag == "Ist_Put" and statement.offset == sp_offset:
            roles.append(
                (statement_index, CallReturnFrameEffectRole8616.STACK_POINTER_UPDATE)
            )
        elif tag == "Ist_Store":
            roles.append((statement_index, CallReturnFrameEffectRole8616.STACK_STORE))

    if (
        matched_imark_count != 1
        or not isinstance(matched_length, int)
        or matched_length <= 0
        or callsite_addr + matched_length != return_addr
    ):
        return None
    role_sequence = tuple(role for _index, role in roles)
    sp_role = CallReturnFrameEffectRole8616.STACK_POINTER_UPDATE
    store_role = CallReturnFrameEffectRole8616.STACK_STORE
    accepted = (
        {
            (sp_role, store_role, sp_role, store_role),
            (sp_role, store_role, store_role, sp_role, store_role),
            (sp_role, store_role, sp_role, store_role, store_role),
            (sp_role, store_role, store_role, sp_role, store_role, store_role),
        }
        if far_call
        else {
            (sp_role, store_role),
            (sp_role, store_role, store_role),
        }
    )
    if role_sequence not in accepted:
        return None
    return tuple(roles)


def _relift_function_blocks_8616(project: object, blocks: tuple[object, ...]) -> list[tuple[int, DynamicValue]]:
    """Retain only address-bound unoptimized blocks from this function census."""
    result: list[tuple[int, DynamicValue]] = []
    for block in blocks:
        block_addr = cast(DynamicValue, block).addr
        vex = _unoptimized_vex_block_8616(project, block)
        if isinstance(block_addr, int) and vex is not None:
            result.append((block_addr, vex))
    return result


def _unique_call_effects_8616(
    project: object, callsite_addr: int, return_addr: int,
    vex_blocks: list[tuple[int, DynamicValue]], sp_offset: int,
) -> tuple[int, DynamicValue, tuple[tuple[int, CallReturnFrameEffectRole8616], ...]] | None:
    """Match one decoded CALL to exactly one complete VEX effect sequence."""
    if not isinstance(callsite_addr, int) or not isinstance(return_addr, int):
        return None
    frame = decode_machine_call_frame_8616(project, callsite_addr)
    if frame is None or frame.return_addr != return_addr:
        return None
    matches: list[tuple[int, DynamicValue, tuple[tuple[int, CallReturnFrameEffectRole8616], ...]]] = []
    for block_addr, vex in vex_blocks:
        roles = _effect_roles_for_call_8616(
            vex, callsite_addr, return_addr, sp_offset=sp_offset, far_call=frame.far,
        )
        if roles is not None:
            matches.append((block_addr, vex, roles))
    return matches[0] if len(matches) == 1 else None


def collect_call_return_frame_effects_8616(
    project: object,
    function: object,
    return_addr_by_callsite: Mapping[int, int],
) -> CallReturnFrameEffectCollection8616:
    """Collect complete exact VEX frame effects for decoded near and far CALLs."""
    project_dynamic = cast(DynamicValue, project)
    function_dynamic = cast(DynamicValue, function)
    try:
        sp_offset = project_dynamic.arch.sp_offset
        blocks = tuple(function_dynamic.blocks or ())
    except (AttributeError, KeyError, TypeError):
        sp_offset = None
        blocks = ()
    raw_count = len(return_addr_by_callsite)
    block_signature = tuple(
        identity
        for block_value in blocks
        if (identity := _block_identity_8616(block_value)) is not None
    )
    try:
        function_addr = function_dynamic.addr
    except AttributeError:
        function_addr = None
    cache_key = (
        (
            function_addr,
            block_signature,
            tuple(sorted(return_addr_by_callsite.items())),
        )
        if isinstance(function_addr, int) and len(block_signature) == len(blocks)
        else None
    )
    cache = _collection_cache_8616(project)
    if cache_key is not None and cache_key in cache:
        return cache[cache_key]
    if not isinstance(sp_offset, int) or not blocks:
        result = CallReturnFrameEffectCollection8616(
            raw_count,
            0,
            0,
            0,
            raw_count,
            (),
            CallReturnFrameProjectionCollection8616(0, 0, 0, 0, 0, (), ()),
        )
        if cache_key is not None:
            cache[cache_key] = result
        return result

    vex_blocks = _relift_function_blocks_8616(project, blocks)

    effects: list[CallReturnFrameEffectFact8616] = []
    projection_collections: list[CallReturnFrameProjectionCollection8616] = []
    normalized_count = 0
    for callsite_addr, return_addr in sorted(return_addr_by_callsite.items()):
        matched = _unique_call_effects_8616(project, callsite_addr, return_addr, vex_blocks, sp_offset)
        if matched is None:
            continue
        normalized_count += 1
        block_addr, vex, roles = matched
        effects.extend(
            CallReturnFrameEffectFact8616(
                CallReturnFrameEffectKey8616(
                    callsite_addr,
                    block_addr,
                    statement_index,
                ),
                role,
            )
            for statement_index, role in roles
        )
        projection_collections.append(
            collect_call_return_frame_store_projections_8616(
                vex,
                callsite_addr=callsite_addr,
                vex_block_addr=block_addr,
                store_statement_indices=(
                    statement_index
                    for statement_index, role in roles
                    if role is CallReturnFrameEffectRole8616.STACK_STORE
                ),
            )
        )

    effect_tuple = tuple(effects)
    projection_collection = CallReturnFrameProjectionCollection8616(
        raw_fact_count=sum(item.raw_fact_count for item in projection_collections),
        normalized_fact_count=sum(item.normalized_fact_count for item in projection_collections),
        classified_fact_count=sum(item.classified_fact_count for item in projection_collections),
        materialized_count=sum(item.materialized_count for item in projection_collections),
        failure_count=sum(item.failure_count for item in projection_collections),
        projections=tuple(fact for item in projection_collections for fact in item.projections),
        refusals=tuple(refusal for item in projection_collections for refusal in item.refusals),
    )
    if not projection_collection.closed or (
        projection_collection.classified_fact_count > 0
        and projection_collection.materialized_count == 0
    ):
        raise PipelineHardError("CALL-frame projection aggregation did not close")
    result = CallReturnFrameEffectCollection8616(
        raw_fact_count=raw_count,
        normalized_fact_count=normalized_count,
        classified_fact_count=len(effect_tuple),
        materialized_count=len(effect_tuple),
        failure_count=max(raw_count - normalized_count, 0),
        effects=effect_tuple,
        projection_collection=projection_collection,
    )
    if cache_key is not None:
        cache[cache_key] = result
    return result
