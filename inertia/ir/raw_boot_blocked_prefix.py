"""Layer: IR.
Responsibility: retain immutable missing-service prerequisites within one request.

These records prohibit repeating an impossible startup crossing; they never
grant an invocation domain or memoize successful replay evidence.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, cast

from archinfo import Arch
from capstone import CS_GRP_CALL, CS_GRP_INT, CS_GRP_IRET, CS_GRP_JUMP, CS_GRP_RET
from capstone.x86 import X86_INS_HLT, X86_INS_INT, X86_INS_UD2

from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.frontend.x86_16.frontend_capstone_block import DirectCapstoneInstruction8616
from inertia.frontend.x86_16.frontend_function_boundary import ExactFunctionRangeBoundary8616
from inertia.frontend.x86_16.mz_static_boot import MzStaticBoot8616

from .core import IRFunctionArtifact
from .function_ir_registry import _existing_registry_8616
from .real16_boot_entry_link import RawBootEntrySurface8616
from .real16_declared_interrupt8616 import interrupt_call_vector_8616
from .real16_invocation_domain import Real16InvocationDomain8616, Real16InvocationFailure8616, Real16InvocationKind8616

if TYPE_CHECKING:
    from .entry_domain_call_preservation import Real16InvocationSource8616


@dataclass(frozen=True, slots=True)
class RawBootBlockedPrefix8616:
    """Pinned missing-service dependency with conservative snapshot guards."""

    project: object
    source: Real16InvocationSource8616
    head_addr: int
    callsite_addr: int
    premise: Real16InvocationDomain8616
    architecture: Arch86_16
    architecture_key: tuple[object, ...]
    index_key: tuple[object, ...]
    registry: dict[int, IRFunctionArtifact] | None
    registry_items: tuple[tuple[int, IRFunctionArtifact], ...]


def _architecture_key_8616(architecture: Arch) -> tuple[object, ...]:
    """Bind native lifting inputs, preserving the established segmented key."""
    if isinstance(architecture, Arch86_16):
        lifting_key = architecture.lifting_semantics_key_8616()
        vex_offsets = tuple(sorted(architecture.vex_offsets.items()))
    else:
        lifting_key = (
            "native-vex", architecture.name, architecture.bits, architecture.vex_arch,
            architecture.memory_endness, architecture.register_endness,
            architecture.instruction_endness,
            tuple(sorted(architecture.register_names.items())),
            json.dumps(architecture.vex_archinfo, sort_keys=True, allow_nan=False),
        )
        # Standard VEX architectures use their register map without the
        # segmented frontend's additional offset overrides.
        vex_offsets = ()
    return (
        lifting_key,
        architecture.cs_arch, architecture.cs_mode,
        tuple(sorted(architecture.registers.items())),
        vex_offsets,
    )


def _index_key_8616(source: Real16InvocationSource8616) -> tuple[object, ...]:
    """Snapshot mutable index maps as well as the frozen caller inventory."""
    index = source.callsite_index
    return (
        tuple(sorted(index._entries_by_normalized_target.items())),
        tuple(sorted(index._entries_by_exact_far_target.items())),
        index.stats, index.entry_identities, index.caller_censuses,
    )


def _static_service_missing_8616(source: Real16InvocationSource8616, head_addr: int) -> bool:
    """Require immutable header state and no alternative service or entry inputs."""
    return (
        type(source.boot) is MzStaticBoot8616
        and not source.declared_services
        and not source.callsite_index.for_target(head_addr)
    )


def _refusal_surface_8616(
    premise: Real16InvocationDomain8616,
) -> tuple[IRFunctionArtifact, ExactFunctionRangeBoundary8616] | None:
    """Locate only raw boot intake or the exact registered universal boot body.

    This selects native inputs for a missing-prerequisite check. It neither
    authenticates a successful invocation nor turns scoped IR into universal IR.
    """
    if type(premise.chain) is RawBootEntrySurface8616:
        return premise.chain.artifact, premise.chain.boundary
    if premise.chain is not None or premise.kind is not Real16InvocationKind8616.BOOT_ENTRY_PATH:
        return None
    coverage = premise.coverage
    if coverage is None or coverage.scoped_view is not None or coverage.failure is not None:
        return None
    registry = _existing_registry_8616(premise.project)
    if registry is None or registry.get(coverage.artifact.function_addr) is not coverage.artifact:
        return None
    return coverage.artifact, coverage.boundary


def _native_instructions_8616(boundary: ExactFunctionRangeBoundary8616) -> dict[int, Any]:
    """Index retained Capstone instructions at the third-party decode boundary."""
    native: dict[int, Any] = {}
    for block in boundary.blocks:
        for instruction in cast(Any, block).capstone.insns:
            if type(instruction) is not DirectCapstoneInstruction8616:
                return {}
            native[instruction.address] = instruction.insn
    return native


def _boot_bytes_8616(boot: MzStaticBoot8616, address: int, size: int) -> bytes | None:
    """Read one contiguous span from the retained immutable relocated image."""
    for start, chunk in boot.image.chunks:
        if start <= address and address + size <= start + len(chunk):
            return bytes(chunk[address - start:address - start + size])
    return None


def _native_prefix_reaches_int_8616(
    artifact: IRFunctionArtifact, boundary: ExactFunctionRangeBoundary8616, boot: MzStaticBoot8616,
    instruction_addr: int, vector: int,
) -> bool:
    """Bind native bytes and forbid preceding transfers before the refused INT."""
    native = _native_instructions_8616(boundary)
    address = artifact.function_addr
    while address <= instruction_addr:
        instruction = native.get(address)
        if instruction is None or instruction.size <= 0:
            return False
        if bytes(instruction.bytes) != _boot_bytes_8616(boot, address, instruction.size):
            return False
        if address == instruction_addr:
            return instruction.id == X86_INS_INT and len(instruction.operands) == 1 and instruction.operands[0].imm == vector
        if (
            any(instruction.group(group) for group in (CS_GRP_CALL, CS_GRP_INT, CS_GRP_IRET, CS_GRP_JUMP, CS_GRP_RET))
            or instruction.id in (X86_INS_HLT, X86_INS_UD2)
        ):
            return False
        address += instruction.size
    return False


def _unavoidable_interrupt_8616(premise: Real16InvocationDomain8616, boot: MzStaticBoot8616) -> bool:
    """Authenticate contiguous native entry rows before the exact refused INT."""
    surface = _refusal_surface_8616(premise)
    site = premise.refusal_site
    if surface is None or site is None:
        return False
    artifact, boundary = surface
    head = artifact.function_addr
    if site.function_addr != head or site.block_addr != head:
        return False
    blocks = tuple(block for block in artifact.blocks if block.addr == head)
    if len(blocks) != 1:
        return False
    refused = tuple(row for row in blocks[0].instrs if row.addr == site.instruction_addr and row.op == "CALL")
    if len(refused) != 1:
        return False
    vector = interrupt_call_vector_8616(refused[0])
    return vector is not None and _native_prefix_reaches_int_8616(artifact, boundary, boot, site.instruction_addr, vector)


def _bound_refusal_8616(
    premise: Real16InvocationDomain8616, project: object, source: Real16InvocationSource8616,
    head_addr: int, callsite_addr: int,
) -> bool:
    """Reject foreign surfaces and non-classified failures before retention."""
    surface = _refusal_surface_8616(premise)
    if surface is None:
        return False
    artifact, boundary = surface
    return (
        premise.project is project and premise.boot is source.boot
        and premise.callsite_addr == callsite_addr
        and artifact.function_addr == head_addr
        and boundary.project is project
        and boundary.addr == head_addr
        and premise.failure_count > 0
        and premise.classified_fact_count == premise.materialized_count + premise.failure_count
    )


def retain_raw_boot_blocked_prefix_8616(
    project: object, source: Real16InvocationSource8616,
    head_addr: int, callsite_addr: int, premise: Real16InvocationDomain8616 | None,
) -> RawBootBlockedPrefix8616 | None:
    """Retain only a real, immutable, unavoidable missing-service dependency."""
    if (
        premise is None
        or premise.failure is not Real16InvocationFailure8616.DECLARED_SERVICE_UNPROVEN
        or not _static_service_missing_8616(source, head_addr)
        or not _bound_refusal_8616(premise, project, source, head_addr, callsite_addr)
        or not _unavoidable_interrupt_8616(premise, cast(MzStaticBoot8616, source.boot))
    ):
        return None
    architecture = cast(Any, project).arch
    if type(architecture) is not Arch86_16:
        return None
    registry = _existing_registry_8616(project)
    record = RawBootBlockedPrefix8616(
        project, source, head_addr, callsite_addr, premise, architecture,
        _architecture_key_8616(architecture), _index_key_8616(source), registry,
        () if registry is None else tuple(sorted(registry.items())),
    )
    return record if raw_boot_blocked_prefix_matches_8616(record, project, source, head_addr, callsite_addr) else None


def raw_boot_blocked_prefix_matches_8616(
    record: RawBootBlockedPrefix8616, project: object,
    source: Real16InvocationSource8616, head_addr: int, callsite_addr: int,
) -> bool:
    """Recheck current inputs without replaying or claiming a successful proof."""
    if (
        record.project is not project or record.source is not source
        or record.head_addr != head_addr or record.callsite_addr != callsite_addr
        or not _static_service_missing_8616(source, head_addr)
    ):
        return False
    architecture = cast(Any, project).arch
    if architecture is not record.architecture or _architecture_key_8616(architecture) != record.architecture_key:
        return False
    if _index_key_8616(source) != record.index_key:
        return False
    registry = _existing_registry_8616(project)
    if registry is not record.registry:
        return False
    current = () if registry is None else tuple(sorted(registry.items()))
    if len(current) != len(record.registry_items) or any(
        address != prior_address or artifact is not prior_artifact
        for (address, artifact), (prior_address, prior_artifact) in zip(current, record.registry_items, strict=True)
    ):
        return False
    boot = cast(MzStaticBoot8616, source.boot)
    memory = cast(Any, project).loader.memory
    try:
        return all(bytes(memory.load(address, len(chunk))) == chunk for address, chunk in boot.image.chunks)
    except KeyError:
        # CLE's mapped-byte boundary reports an unmapped span by KeyError.
        return False
