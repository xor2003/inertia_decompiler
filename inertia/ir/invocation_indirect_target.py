"""Invocation-bound discovery of one native indirect destination.

Layer: IR.
Responsibility: evaluate an acyclic native prefix using the existing scalar and
path-memory semantics. A result is conditional discovery, never closed function
coverage or permission to register a universal successor.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, cast

from inertia.frontend.x86_16.frontend_direct_callsite_index import DecodedDirectCallsite8616
from inertia.semantics.direct_near_call_target_binding import prove_direct_near_call_target_binding_from_decoded_8616

from . import real16_edge_feasibility8616 as edges
from . import real16_invocation_domain as census
from . import vex_import as importer
from .core import IRBlock, IRFunctionArtifact, IRValue
from .real16_fused_caller_prefix import FusedCallerPrefix8616
from .real16_path_memory8616 import restore_path_memory_8616
from .segment_call_preservation import segment_call_dependency_traversal_scope_8616
from .vex_import import IRImportRefusalReason8616, _block_to_ir


def _producers() -> tuple[object, ...]:
    """Reuse existing native-import and scalar-effect producer inventories."""
    return (_block_to_ir, *importer._native_import_producers_8616(), *census._fused_callee_producers_8616())


_CANONICAL_PRODUCERS = _producers()


def _producers_current() -> bool:
    """Refuse substituted native/effect producers before granting an edge."""
    current = _producers()
    return len(current) == len(_CANONICAL_PRODUCERS) and all(
        actual is expected for actual, expected in zip(current, _CANONICAL_PRODUCERS, strict=True)
    )


class _Factory(Protocol):
    """Angr native block boundary used only for fresh import."""

    def block(self, addr: int, *, opt_level: int) -> object:
        """Lift native bytes at one requested instruction boundary."""
        ...


class _Project(Protocol):
    """Third-party factory surface."""

    factory: _Factory


@dataclass(frozen=True, slots=True)
class InvocationIndirectTarget8616:
    """One replayable conditional edge, without complete-function authority."""

    invocation: census.Real16InvocationDomain8616
    decoded_call: DecodedDirectCallsite8616
    function_addr: int
    block_addr: int
    instruction_addr: int
    target: int
    native_spans: tuple[tuple[int, bytes], ...]


def discover_invocation_indirect_target_8616(
    invocation: census.Real16InvocationDomain8616,
    decoded_call: DecodedDirectCallsite8616,
) -> InvocationIndirectTarget8616 | None:
    """Discover a singleton under fresh caller authority; unknown paths refuse.

    Consumers must replay this producer and compare the retained receipt before
    applying its edge. This API does not assert callee return or preservation.
    """
    with segment_call_dependency_traversal_scope_8616():
        return _discover(invocation, decoded_call)


def _discover(
    invocation: census.Real16InvocationDomain8616,
    decoded_call: DecodedDirectCallsite8616,
) -> InvocationIndirectTarget8616 | None:
    """Bind a current near CALL before evaluating its pending native prefix."""
    if not _producers_current() or type(invocation) is not census.Real16InvocationDomain8616 or not invocation.complete:
        return None
    surface = census._retained_parent_census_surface_8616(invocation)
    if surface is None or invocation.callsite_memory is None:
        return None
    caller, _ = surface
    block = census._callsite_block_8616(caller, invocation.callsite_addr)
    if isinstance(block, census.Real16InvocationFailure8616):
        return None
    calls = tuple(row for row in block.instrs if row.op == "CALL" and row.addr == invocation.callsite_addr)
    if len(calls) != 1:
        return None
    binding = prove_direct_near_call_target_binding_from_decoded_8616(
        invocation.project, block=block, instruction=calls[0], decoded=decoded_call, invocation=invocation,
    )
    if not binding.complete or type(binding.target_addr) is not int:
        return None
    seed_authority = _seed_authority(invocation)
    if seed_authority is None:
        return None
    evidence = census._invocation_boot_evidence_8616(invocation.boot)
    if isinstance(evidence, census.Real16InvocationFailure8616):
        return None
    registers = dict(invocation.callsite_call_state)
    selector = registers.get("cs")
    if type(selector) is not int or "ss" not in registers:
        return None
    ctx = census._PathCensusContext8616(
        project=invocation.project, selector=selector, image=evidence.image,
        boot=invocation.boot, chain=invocation.chain, call_preservations=(),
        entry_call_preservations=(), declared_services=(),
        environment_digest=evidence.environment_digest, environment=evidence.environment,
        arena=evidence.arena, service_consumptions=[], stop_block_addr=None, callsite_addr=None,
        callsite_call_state=None, callsite_memory=None,
        manifest={(base, len(data)) for base, data in evidence.image.chunks},
        machine_bytes={}, native_blocks={}, checked_stores=0, censused_callees=set(),
        raw_facts=set(), normalized_facts=set(), classified_facts=set(), materialized_facts=set(),
        failures=0, work_units=0, work_limit=census._CENSUS_WORK_LIMIT_8616,
        deadline=census._census_deadline_8616(),
        initial_memory=census._invocation_initial_memory_for_entry_8616(evidence, invocation.chain),
    )
    state = census._PathState8616(registers, restore_path_memory_8616(invocation.callsite_memory))
    if _seed_authority(invocation) != seed_authority:
        return None
    return _walk(ctx, invocation, decoded_call, binding.target_addr, state, seed_authority)


def _walk(
    ctx: census._PathCensusContext8616, invocation: census.Real16InvocationDomain8616,
    decoded_call: DecodedDirectCallsite8616, head: int, state: census._PathState8616,
    seed_authority: tuple[object, ...],
) -> InvocationIndirectTarget8616 | None:
    """Visit a bounded unique native path, preserving all scalar/store checks."""
    visited: set[int] = set()
    spans: dict[int, bytes] = {}
    current = head
    for _ in range(64):
        if current in visited or not (ctx.selector << 4) <= current < (ctx.selector << 4) + 0x10000:
            return None
        visited.add(current)
        native = _native_block(ctx.project, current)
        if native is None:
            return None
        block, pending = _discovery_block(native)
        if not _supported_block(block):
            return None
        terminal = block.instrs[-1]
        ctx.callsite_addr = terminal.addr
        if census._census_block_bytes_8616(ctx, block, stop_after=None) is not None:
            return None
        artifact = IRFunctionArtifact(head, (block,))
        ctx.native_blocks[head] = {block.addr: block}
        prefix = census._prepare_ordinary_path_block_8616(ctx, artifact, block, state, None)
        if not isinstance(prefix, FusedCallerPrefix8616):
            return None
        result = census._resume_path_block_8616(ctx, artifact, block, prefix, None)
        if isinstance(result, census.Real16InvocationFailure8616):
            return None
        spans.update(ctx.machine_bytes)
        target = _target(block, prefix)
        if type(target) is not int:
            return None
        if pending:
            return _seal(ctx, invocation, decoded_call, head, block, target, spans, seed_authority)
        current, state = target, result
    return None


def _native_block(project: object, address: int) -> object | None:
    """Translate only known frontend decode boundary failures to refusal."""
    try:
        return cast(_Project, project).factory.block(address, opt_level=0)
    except census._DECODE_REFUSAL_TYPES_8616:
        return None


def _discovery_block(native: object) -> tuple[IRBlock, bool]:
    """Retain a missing terminal only with the explicit pending refusal."""
    block, _, _ = _block_to_ir(native)
    pending = not block.instrs or block.instrs[-1].op not in ("CJMP", "JMP", "RET", "CALL")
    if pending:
        block, _, _ = _block_to_ir(native, indirect_terminal_pending=True)
    return block, pending


def _supported_block(block: IRBlock) -> bool:
    """Never skip an unsupported effect or silently cross another call."""
    return bool(
        block.instrs and block.instrs[-1].op in ("CJMP", "JMP")
        and not any(row.op == "CALL" for row in block.instrs)
        and all(item.kind is IRImportRefusalReason8616.INDIRECT_TERMINAL_PENDING for item in block.refusals)
    )


def _target(block: IRBlock, prefix: FusedCallerPrefix8616) -> int | None:
    """Use canonical known-bits branch and scalar target interpretation."""
    terminal = block.instrs[-1]
    if terminal.op == "CJMP":
        return edges._cjmp_live_successor_8616(
            terminal, block.successor_addrs,
            {name: (0xFFFFFFFF, value) for name, value in prefix.registers.items()},
            {name: (0xFFFFFFFF, value) for name, value in prefix.tmps.items()},
        )
    if terminal.op == "JMP" and len(terminal.args) == 1 and isinstance(terminal.args[0], IRValue):
        return census._eval_value_8616(terminal.args[0], prefix.registers, prefix.tmps)
    return None


def _seal(
    ctx: census._PathCensusContext8616, invocation: census.Real16InvocationDomain8616,
    decoded_call: DecodedDirectCallsite8616, head: int, block: IRBlock, target: int,
    spans: dict[int, bytes],
    seed_authority: tuple[object, ...],
) -> InvocationIndirectTarget8616 | None:
    """Keep fresh source authority and closed resource/effect accounting."""
    terminal = block.instrs[-1]
    if not isinstance(terminal.args[0], IRValue) or type(terminal.addr) is not int:
        return None
    if not (ctx.selector << 4) <= target < (ctx.selector << 4) + 0x10000:
        return None
    decoded = census._machine_census_8616(ctx, target)
    if isinstance(decoded, census.Real16InvocationFailure8616) or target not in decoded:
        return None
    size, encoded = decoded[target]
    if census._loaded_bytes_8616(ctx.project, target, size) != encoded:
        return None
    if not invocation.complete or not _producers_current() or census._census_resource_failure_8616(ctx) is not None:
        return None
    if not all(census._loaded_bytes_8616(ctx.project, addr, len(data)) == data for addr, data in spans.items()):
        return None
    if _seed_authority(invocation) != seed_authority:
        return None
    if ctx.failures or ctx.classified_facts != ctx.materialized_facts:
        return None
    return InvocationIndirectTarget8616(
        invocation, decoded_call, head, block.addr, terminal.addr, target, tuple(sorted(spans.items())),
    )


def _seed_authority(invocation: census.Real16InvocationDomain8616) -> tuple[object, ...] | None:
    """Detach actual scalar/memory inputs so replay cannot silently replace them."""
    evidence = census._invocation_boot_evidence_8616(invocation.boot)
    memory = invocation.callsite_memory
    if isinstance(evidence, census.Real16InvocationFailure8616) or memory is None:
        return None
    initial = census._invocation_initial_memory_for_entry_8616(evidence, invocation.chain)
    if initial is None:
        return None
    return (
        id(invocation.project), id(invocation.boot), id(invocation.chain), invocation.callsite_addr,
        invocation.callsite_call_state, memory.known, memory.unknown, memory.tainted,
        initial.chunks, initial.write_ranges, evidence.source, evidence.environment_digest,
    )
