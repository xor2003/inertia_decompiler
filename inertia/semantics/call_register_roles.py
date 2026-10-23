"""Compute the four distinct register roles of one exact CALL.

Layer: Semantics.
Responsibility: derive independently evidenced input/pass, possible-clobber,
caller-dead and result roles from decoded callee coverage, caller CFG
liveness and proven call-output facts. Roles are bound to the exact call
block/index/address/target/return-edge identity; gaps keep typed
partial/unknown coverage instead of fabricated complete masks.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, cast

from angr.errors import SimEngineError

from inertia.alias.domains import (
    register_domain_for_name,
    register_view_for_name,
)
from inertia.frontend.x86_16.frontend_block_inventory import (
    decoded_block_instructions_8616,
)
from inertia.frontend.x86_16.frontend_instruction_kinds import (
    is_x86_16_call_mnemonic_8616,
)
from inertia.frontend.x86_16.frontend_instruction_reachability import (
    InstructionReachabilityEvidence8616,
    collect_instruction_reachability_8616,
)
from inertia.frontend.x86_16.synthetic_call_stub_evidence import (
    is_synthetic_call_stub_8616,
)
from inertia.ir.core import IRFunctionArtifact, MemSpace

from .call_output_contracts import (
    CallOutputFact8616,
    CallOutputFailure8616,
    CallOutputVerdict8616,
    validate_call_output_fact_8616,
)
from .call_register_effects import (
    SyntheticCallRegisterEffectVerdict8616,
    classify_synthetic_call_register_effect_8616,
)
from .call_register_role_contracts import (
    CALL_REGISTER_ROLE_KINDS_8616,
    FULL_DOMAIN_MASK_8616,
    TRACKED_REGISTER_DOMAIN_NAMES_8616,
    CallRegisterDomainBits8616,
    CallRegisterRoleCoverage8616,
    CallRegisterRoleEvidence8616,
    CallRegisterRoleFailure8616,
    CallRegisterRoleKind8616,
    CallRegisterRoleResult8616,
    CallRegisterRolesArtifact8616,
    CallRegisterRolesFact8616,
    CallRegisterRoleStats8616,
)
from .register_source_block_inventory import (
    RegisterSourceBlockInventory8616,
    collect_register_source_block_inventory_8616,
)
from .register_value_preservation import (
    decoded_register_bit_effects_8616,
    register_value_family_8616,
)

if TYPE_CHECKING:
    # Type-only imports: callsite_summary and call_outputs transitively
    # import this module's consumer (callsite_register_provenance), so a
    # runtime import would close a cycle. The annotations stay exact.
    from .call_outputs import CallOutputArtifact8616
    from .callsite_summary import CallsiteSummary8616


__all__ = (
    "build_call_register_roles_8616",
    "build_callsite_register_role_fact_8616",
)

_DOMAIN_COUNT_8616 = len(TRACKED_REGISTER_DOMAIN_NAMES_8616)
_DOMAIN_INDEX_8616: dict[str, int] = {
    name: index for index, name in enumerate(TRACKED_REGISTER_DOMAIN_NAMES_8616)
}
_DOMAIN_QUERY_NAMES_8616: tuple[str, ...] = tuple(
    name.lower() for name in TRACKED_REGISTER_DOMAIN_NAMES_8616
)
_RETURN_MNEMONICS_8616 = frozenset({"ret", "retf", "retw", "iret", "iretq"})


class _LoaderObject8616(Protocol):
    """Loaded image bounds exposed at the dynamic angr boundary."""

    min_addr: int
    max_addr: int


class _Loader8616(Protocol):
    """Loader surface needed to bound callee reachability."""

    main_object: _LoaderObject8616


class _Project8616(Protocol):
    """Project surface needed for bounded callee reachability."""

    loader: _Loader8616


class _Instruction8616(Protocol):
    """Decoded instruction fields consumed by register-role analysis."""

    address: int
    mnemonic: str


def _refused_role_8616(
    kind: CallRegisterRoleKind8616,
    *failures: CallRegisterRoleFailure8616,
) -> CallRegisterRoleEvidence8616:
    """Return one closed refusal retaining the typed failure reasons."""
    return CallRegisterRoleEvidence8616(
        kind,
        CallRegisterRoleCoverage8616.UNKNOWN_REFUSE,
        (),
        (),
        failures,
        1,
        1,
        0,
        0,
        1,
    )


def _role_evidence_8616(
    kind: CallRegisterRoleKind8616,
    *,
    complete: bool,
    known: Sequence[int],
    role: Sequence[int],
    witnesses: set[int],
    failures: tuple[CallRegisterRoleFailure8616, ...],
) -> CallRegisterRoleEvidence8616:
    """Assemble closed per-domain evidence from decided bit masks."""
    domains = tuple(
        CallRegisterDomainBits8616(name, known[index], role[index])
        for index, name in enumerate(TRACKED_REGISTER_DOMAIN_NAMES_8616)
    )
    decided = sum(entry.known_bits != 0 for entry in domains)
    coverage = (
        CallRegisterRoleCoverage8616.COMPLETE
        if complete
        else CallRegisterRoleCoverage8616.PARTIAL
    )
    return CallRegisterRoleEvidence8616(
        kind,
        coverage,
        domains,
        tuple(sorted(witnesses)),
        failures,
        _DOMAIN_COUNT_8616,
        _DOMAIN_COUNT_8616,
        decided,
        decided,
        _DOMAIN_COUNT_8616 - decided,
    )


def _instruction_domain_effects_8616(
    instruction: object,
) -> tuple[tuple[int, int] | None, ...]:
    """Return per-domain (read, write) 16-bit masks, or None when undecided."""
    return tuple(
        decoded_register_bit_effects_8616(instruction, name)
        for name in _DOMAIN_QUERY_NAMES_8616
    )


@dataclass(frozen=True, slots=True)
class _BlockDomainScan8616:
    """Per-domain block-local masks with unsupported-transfer witnesses."""

    incoming_reads: tuple[int, ...]
    writes: tuple[int, ...]
    unsupported: tuple[int, ...]
    nested_call: bool


def _scan_instructions_8616(
    instructions: tuple[object, ...],
    start_index: int = 0,
    initial_incoming: Sequence[int] | None = None,
    read_witnesses: set[int] | None = None,
) -> _BlockDomainScan8616:
    """Scan instructions in read-before-write order for every tracked domain.

    ``incoming_reads`` covers bits read while still holding the value the
    scan start supplied; ``writes`` covers every possibly written bit. A
    nested call or an instruction without decided effects conservatively
    reads and writes every still-live bit of every domain.
    """
    incoming = [0] * _DOMAIN_COUNT_8616
    writes = [0] * _DOMAIN_COUNT_8616
    still_incoming = (
        list(initial_incoming)
        if initial_incoming is not None
        else [FULL_DOMAIN_MASK_8616] * _DOMAIN_COUNT_8616
    )
    unsupported: list[int] = []
    nested_call = False
    for instruction in instructions[start_index:]:
        boundary = cast(_Instruction8616, instruction)
        try:
            mnemonic = boundary.mnemonic.lower()
            address = boundary.address
        except AttributeError:
            mnemonic = ""
            address = -1
        if is_x86_16_call_mnemonic_8616(mnemonic):
            nested_call = True
            effects: tuple[tuple[int, int] | None, ...] = (None,) * _DOMAIN_COUNT_8616
        else:
            effects = _instruction_domain_effects_8616(instruction)
        if any(item is None for item in effects):
            unsupported.append(address)
            effects = tuple(
                item if item is not None else (FULL_DOMAIN_MASK_8616, FULL_DOMAIN_MASK_8616)
                for item in effects
            )
        for index in range(_DOMAIN_COUNT_8616):
            read_bits, write_bits = effects[index] or (0, 0)
            if read_witnesses is not None and read_bits & still_incoming[index]:
                read_witnesses.add(address)
            incoming[index] |= read_bits & still_incoming[index]
            writes[index] |= write_bits
            still_incoming[index] &= ~write_bits
    return _BlockDomainScan8616(
        tuple(incoming),
        tuple(writes),
        tuple(sorted(set(unsupported))),
        nested_call,
    )


@dataclass(frozen=True, slots=True)
class _DecodedBlock8616:
    """Normalized decoded block surface consumed by role analysis."""

    block_addr: int
    instructions: tuple[object, ...]


def _normalize_decoded_block_8616(block: object) -> _DecodedBlock8616 | None:
    """Project an angr or direct Capstone block into decoded instructions."""
    try:
        block_addr = int(block.addr)  # type: ignore[attr-defined]
    except (AttributeError, TypeError, ValueError):
        return None
    try:
        instructions = tuple(block.capstone.insns)  # type: ignore[attr-defined]
    except (AttributeError, TypeError):
        try:
            instructions = tuple(block.instructions)  # type: ignore[attr-defined]
        except (AttributeError, TypeError):
            return None
    return _DecodedBlock8616(block_addr, instructions)


def _callee_region_8616(project: object) -> tuple[int, int] | None:
    """Return the loaded main-object bounds for bounded callee traversal."""
    boundary = cast(_Project8616, project)
    try:
        region_start = int(boundary.loader.main_object.min_addr)
        region_end = int(boundary.loader.main_object.max_addr) + 1
    except (AttributeError, TypeError, ValueError):
        return None
    if region_end <= region_start:
        return None
    return region_start, region_end


def _callee_reachability_8616(
    project: object,
    target_addr: int,
) -> InstructionReachabilityEvidence8616 | None:
    """Collect bounded binary reachability from the exact call target."""
    region = _callee_region_8616(project)
    if region is None:
        return None
    try:
        return collect_instruction_reachability_8616(
            project,
            entry=target_addr,
            region_start=region[0],
            region_end=region[1],
        )
    except (AttributeError, SimEngineError, TypeError, ValueError):
        return None


def _fixpoint_pass_limit_8616(block_count: int) -> int:
    """Bound monotone mask fixpoints by the number of settable bits."""
    return block_count * _DOMAIN_COUNT_8616 * 16 + 2


def _single_block_leaf_8616(
    project: object,
    target_addr: int,
) -> tuple[tuple[object, ...], bool]:
    """Decode the exact target as one block when no bounded CFG exists."""
    try:
        instructions = decoded_block_instructions_8616(
            project,
            target_addr,
            opt_level=0,
        )
    except (AttributeError, SimEngineError, TypeError, ValueError, KeyError):
        return (), False
    if not instructions:
        return (), False
    last = cast(_Instruction8616, instructions[-1])
    try:
        terminal = last.mnemonic.lower()
    except AttributeError:
        return tuple(instructions), False
    if terminal not in _RETURN_MNEMONICS_8616:
        return tuple(instructions), False
    return tuple(instructions), True


def _callee_roles_8616(
    project: object | None,
    callsite_addr: int | None,
    target_addr: int | None,
) -> tuple[CallRegisterRoleEvidence8616, CallRegisterRoleEvidence8616]:
    """Compute callee-side input/pass and possible-clobber role evidence."""
    if project is None or target_addr is None:
        failure = (
            CallRegisterRoleFailure8616.CALL_IDENTITY_INCOMPLETE
            if target_addr is None
            else CallRegisterRoleFailure8616.CALLEE_EVIDENCE_MISSING
        )
        return _refused_role_8616(CallRegisterRoleKind8616.INPUT, failure), _refused_role_8616(
            CallRegisterRoleKind8616.MAY_CLOBBER, failure
        )
    if is_synthetic_call_stub_8616(project, target_addr):
        return _synthetic_callee_roles_8616(project, callsite_addr, target_addr)
    return _binary_callee_roles_8616(project, target_addr)


def _synthetic_callee_roles_8616(
    project: object,
    callsite_addr: int | None,
    target_addr: int,
) -> tuple[CallRegisterRoleEvidence8616, CallRegisterRoleEvidence8616]:
    """Map the registered synthetic-call ABI onto its proven 16-bit views."""
    input_role = _refused_role_8616(
        CallRegisterRoleKind8616.INPUT,
        CallRegisterRoleFailure8616.CALLEE_EVIDENCE_MISSING,
    )
    if callsite_addr is None:
        return input_role, _refused_role_8616(
            CallRegisterRoleKind8616.MAY_CLOBBER,
            CallRegisterRoleFailure8616.CALL_IDENTITY_INCOMPLETE,
        )
    known = [0] * _DOMAIN_COUNT_8616
    clobbered = [0] * _DOMAIN_COUNT_8616
    failures: list[CallRegisterRoleFailure8616] = []
    for index, name in enumerate(_DOMAIN_QUERY_NAMES_8616):
        effect = classify_synthetic_call_register_effect_8616(
            project,
            callsite_addr=callsite_addr,
            target_addr=target_addr,
            register=name,
        )
        if not effect.closes_evidence:
            continue
        if effect.verdict is SyntheticCallRegisterEffectVerdict8616.PRESERVED:
            known[index] = FULL_DOMAIN_MASK_8616
        elif effect.verdict is SyntheticCallRegisterEffectVerdict8616.CLOBBERED:
            known[index] = FULL_DOMAIN_MASK_8616
            clobbered[index] = FULL_DOMAIN_MASK_8616
    if not any(known):
        return input_role, _refused_role_8616(
            CallRegisterRoleKind8616.MAY_CLOBBER,
            CallRegisterRoleFailure8616.CALLEE_EVIDENCE_MISSING,
        )
    if any(bits != FULL_DOMAIN_MASK_8616 for bits in known):
        failures.append(CallRegisterRoleFailure8616.CALLEE_COVERAGE_PARTIAL)
    clobber_role = _role_evidence_8616(
        CallRegisterRoleKind8616.MAY_CLOBBER,
        complete=not failures,
        known=known,
        role=clobbered,
        witnesses=set(),
        failures=tuple(failures),
    )
    return input_role, clobber_role


def _reachable_callee_graph_8616(
    reachability: InstructionReachabilityEvidence8616,
    target_addr: int,
    failure_reasons: list[CallRegisterRoleFailure8616],
) -> tuple[dict[int, _DecodedBlock8616], dict[int, set[int]], bool]:
    """Normalize bounded callee reachability into blocks and successors."""
    blocks: dict[int, _DecodedBlock8616] = {}
    for raw_block in reachability.blocks:
        normalized = _normalize_decoded_block_8616(raw_block)
        if normalized is not None and normalized.instructions:
            blocks[normalized.block_addr] = normalized
    successors: dict[int, set[int]] = {addr: set() for addr in blocks}
    edge_gaps = False
    for source, destination in reachability.successor_edges:
        if source in successors and destination in blocks:
            successors[source].add(destination)
        else:
            edge_gaps = True
    complete = bool(reachability.complete) and not edge_gaps and bool(blocks)
    if edge_gaps or not reachability.complete or target_addr not in blocks:
        failure_reasons.append(CallRegisterRoleFailure8616.CALLEE_COVERAGE_PARTIAL)
    return blocks, successors, complete and target_addr in blocks


def _binary_callee_roles_8616(
    project: object,
    target_addr: int,
) -> tuple[CallRegisterRoleEvidence8616, CallRegisterRoleEvidence8616]:
    """Compute callee roles from exact bounded binary reachability.

    May-clobber and input masks stay honest under partial coverage: observed
    effects are real may-evidence while their complement remains undecided.
    Absence-of-write is provable only with complete callee coverage.
    """
    reachability = _callee_reachability_8616(project, target_addr)
    failure_reasons: list[CallRegisterRoleFailure8616] = []
    if reachability is not None:
        blocks, successors, complete = _reachable_callee_graph_8616(
            reachability, target_addr, failure_reasons
        )
    else:
        blocks, successors, complete = {}, {}, False

    if not blocks:
        instructions, complete = _single_block_leaf_8616(project, target_addr)
        if instructions:
            blocks = {target_addr: _DecodedBlock8616(target_addr, instructions)}
            successors = {target_addr: set()}
        else:
            failure_reasons.append(CallRegisterRoleFailure8616.CALLEE_EVIDENCE_MISSING)
    if not blocks:
        return _refused_role_8616(
            CallRegisterRoleKind8616.INPUT,
            CallRegisterRoleFailure8616.CALLEE_EVIDENCE_MISSING,
        ), _refused_role_8616(
            CallRegisterRoleKind8616.MAY_CLOBBER,
            CallRegisterRoleFailure8616.CALLEE_EVIDENCE_MISSING,
        )

    scans, complete = _scan_callee_blocks_8616(
        blocks, successors, complete, failure_reasons
    )

    input_bits, live_in, converged = _incoming_input_bits_8616(
        blocks, scans, successors, target_addr,
    )
    if not converged:
        complete = False
        failure_reasons.append(CallRegisterRoleFailure8616.CALLEE_COVERAGE_PARTIAL)

    input_witnesses: set[int] = set()
    for block_addr, block in blocks.items():
        _scan_instructions_8616(
            block.instructions,
            initial_incoming=live_in[block_addr],
            read_witnesses=input_witnesses,
        )
    input_witnesses.discard(-1)
    clobber_witnesses = _write_witnesses_8616(blocks)

    role_input = list(input_bits)
    role_clobber = [
        _union_writes(scans, index) for index in range(_DOMAIN_COUNT_8616)
    ]
    known_input = [0] * _DOMAIN_COUNT_8616
    known_clobber = [0] * _DOMAIN_COUNT_8616
    for index in range(_DOMAIN_COUNT_8616):
        if complete:
            known_input[index] = FULL_DOMAIN_MASK_8616
            known_clobber[index] = FULL_DOMAIN_MASK_8616
        else:
            known_input[index] = role_input[index]
            known_clobber[index] = role_clobber[index]

    failures = tuple(failure_reasons)
    input_role = _role_evidence_8616(
        CallRegisterRoleKind8616.INPUT,
        complete=complete,
        known=known_input,
        role=role_input,
        witnesses=input_witnesses,
        failures=failures,
    )
    clobber_role = _role_evidence_8616(
        CallRegisterRoleKind8616.MAY_CLOBBER,
        complete=complete,
        known=known_clobber,
        role=role_clobber,
        witnesses=clobber_witnesses,
        failures=failures,
    )
    return input_role, clobber_role


def _scan_callee_blocks_8616(
    blocks: dict[int, _DecodedBlock8616],
    successors: dict[int, set[int]],
    complete: bool,
    failure_reasons: list[CallRegisterRoleFailure8616],
) -> tuple[dict[int, _BlockDomainScan8616], bool]:
    """Scan callee blocks and flag unsupported transfers or bad sinks."""
    scans: dict[int, _BlockDomainScan8616] = {}
    unsupported_seen = False
    nested_seen = False
    for block_addr, block in blocks.items():
        scan = _scan_instructions_8616(block.instructions)
        scans[block_addr] = scan
        unsupported_seen = unsupported_seen or bool(scan.unsupported)
        nested_seen = nested_seen or scan.nested_call
        last = cast(_Instruction8616, block.instructions[-1])
        try:
            terminal = last.mnemonic.lower()
        except AttributeError:
            terminal = ""
        sink_ok = (
            not successors[block_addr]
            if terminal in _RETURN_MNEMONICS_8616
            else bool(successors[block_addr])
        )
        if not sink_ok:
            # A decoded sink that is not a return is a nonreturning or
            # unsupported exit; observed effects stay may-valid.
            complete = False
            failure_reasons.append(
                CallRegisterRoleFailure8616.CALLEE_COVERAGE_PARTIAL
            )
    if unsupported_seen or nested_seen:
        failure_reasons.append(CallRegisterRoleFailure8616.CALLEE_TRANSFER_UNSUPPORTED)
        complete = False
    return scans, complete


def _union_writes(scans: dict[int, _BlockDomainScan8616], index: int) -> int:
    """Union one domain's write mask across every decoded callee block."""
    mask = 0
    for scan in scans.values():
        mask |= scan.writes[index]
    return mask


def _write_witnesses_8616(blocks: dict[int, _DecodedBlock8616]) -> set[int]:
    """Return addresses of instructions that may write a tracked domain."""
    witnesses: set[int] = set()
    for block in blocks.values():
        for instruction in block.instructions:
            boundary = cast(_Instruction8616, instruction)
            try:
                address = boundary.address
            except AttributeError:
                continue
            if is_x86_16_call_mnemonic_8616(boundary.mnemonic.lower()):
                witnesses.add(address)
                continue
            effects = _instruction_domain_effects_8616(instruction)
            if any(item is None for item in effects) or any(
                item is not None and item[1] for item in effects
            ):
                witnesses.add(address)
    witnesses.discard(-1)
    return witnesses


def _incoming_input_bits_8616(
    blocks: dict[int, _DecodedBlock8616],
    scans: dict[int, _BlockDomainScan8616],
    successors: dict[int, set[int]],
    entry_addr: int,
) -> tuple[list[int], dict[int, list[int]], bool]:
    """Propagate still-incoming bits forward to bound input reads.

    The callee entry keeps every bit live: the caller's incoming value
    reaches a block while no dominating write has covered it. The join is a
    union so partial writes and converging paths retain may-input bits.
    """
    predecessors: dict[int, set[int]] = {addr: set() for addr in blocks}
    for source, targets in successors.items():
        for target in targets:
            if target in predecessors:
                predecessors[target].add(source)
    live_in: dict[int, list[int]] = {
        addr: [0] * _DOMAIN_COUNT_8616 for addr in blocks
    }
    if entry_addr in live_in:
        live_in[entry_addr] = [FULL_DOMAIN_MASK_8616] * _DOMAIN_COUNT_8616
    converged = _propagate_incoming_8616(
        blocks, scans, predecessors, live_in, entry_addr
    )
    input_bits = [0] * _DOMAIN_COUNT_8616
    for block_addr in blocks:
        scan = scans[block_addr]
        for index in range(_DOMAIN_COUNT_8616):
            input_bits[index] |= live_in[block_addr][index] & scan.incoming_reads[index]
    return input_bits, live_in, converged


def _propagate_incoming_8616(
    blocks: dict[int, _DecodedBlock8616],
    scans: dict[int, _BlockDomainScan8616],
    predecessors: dict[int, set[int]],
    live_in: dict[int, list[int]],
    entry_addr: int,
) -> bool:
    """Iterate the may-incoming join until the masks converge."""
    for _pass in range(_fixpoint_pass_limit_8616(len(blocks))):
        changed = False
        for block_addr in sorted(blocks):
            if block_addr == entry_addr:
                continue
            joined = [0] * _DOMAIN_COUNT_8616
            for predecessor in predecessors[block_addr]:
                scan = scans[predecessor]
                source = live_in[predecessor]
                for index in range(_DOMAIN_COUNT_8616):
                    joined[index] |= source[index] & ~scan.writes[index]
            if joined != live_in[block_addr]:
                live_in[block_addr] = joined
                changed = True
        if not changed:
            return True
    return False


@dataclass(frozen=True, slots=True)
class _ContinuationStart8616:
    """Exact start of the caller continuation after one CALL."""

    block_addr: int
    start_index: int


def _locate_call_8616(
    blocks: dict[int, _DecodedBlock8616],
    callsite_addr: int | None,
) -> tuple[int, int] | None:
    """Find the block and index of the exact decoded call instruction."""
    if callsite_addr is None:
        return None
    for block_addr in sorted(blocks):
        for index, instruction in enumerate(blocks[block_addr].instructions):
            try:
                address = cast(_Instruction8616, instruction).address
            except AttributeError:
                continue
            if address == callsite_addr:
                return block_addr, index
    return None


def _continuation_start_8616(
    blocks: dict[int, _DecodedBlock8616],
    successors: dict[int, set[int]],
    callsite_addr: int | None,
    call_block_addr: int | None,
    return_block_addr: int | None,
) -> _ContinuationStart8616 | None:
    """Resolve the exact continuation after the CALL, or refuse."""
    located = _locate_call_8616(blocks, callsite_addr)
    if located is None:
        if return_block_addr is not None and return_block_addr in blocks:
            return _ContinuationStart8616(return_block_addr, 0)
        return None
    block_addr, index = located
    if call_block_addr is not None and block_addr != call_block_addr:
        return None
    if index + 1 < len(blocks[block_addr].instructions):
        if return_block_addr is not None and return_block_addr != block_addr:
            return None
        return _ContinuationStart8616(block_addr, index + 1)
    targets = tuple(sorted(successors.get(block_addr, ())))
    if return_block_addr is not None:
        if return_block_addr not in targets:
            return None
        return _ContinuationStart8616(return_block_addr, 0)
    if len(targets) != 1:
        return None
    return _ContinuationStart8616(targets[0], 0)


def _caller_liveness_8616(
    reachable: set[int],
    scans: dict[int, _BlockDomainScan8616],
    successors: dict[int, set[int]],
) -> tuple[dict[int, list[int]], dict[int, list[int]], bool]:
    """Backward liveness over caller continuation blocks.

    Exit blocks expose every still-live bit to an unknown outer caller, so
    nothing live there can ever be caller-dead.
    """
    live_in: dict[int, list[int]] = {
        addr: [0] * _DOMAIN_COUNT_8616 for addr in reachable
    }
    live_out: dict[int, list[int]] = {}
    converged = False
    for _pass in range(_fixpoint_pass_limit_8616(len(reachable))):
        changed = False
        for block_addr in sorted(reachable):
            if successors[block_addr]:
                outgoing = [0] * _DOMAIN_COUNT_8616
                for target in successors[block_addr]:
                    if target not in live_in:
                        continue
                    source = live_in[target]
                    for index in range(_DOMAIN_COUNT_8616):
                        outgoing[index] |= source[index]
            else:
                outgoing = [FULL_DOMAIN_MASK_8616] * _DOMAIN_COUNT_8616
            if live_out.get(block_addr) != outgoing:
                live_out[block_addr] = outgoing
                changed = True
            scan = scans[block_addr]
            incoming = [
                scan.incoming_reads[index]
                | (live_out[block_addr][index] & ~scan.writes[index])
                for index in range(_DOMAIN_COUNT_8616)
            ]
            if incoming != live_in[block_addr]:
                live_in[block_addr] = incoming
                changed = True
        if not changed:
            converged = True
            break
    return live_in, live_out, converged


def _caller_graph_8616(
    inventory: RegisterSourceBlockInventory8616 | None,
    function_addr: int | None,
) -> tuple[dict[int, _DecodedBlock8616], dict[int, set[int]], bool] | None:
    """Normalize the caller inventory into blocks, successors and gaps."""
    if (
        inventory is None
        or not inventory.blocks
        or (function_addr is not None and inventory.function_addr != function_addr)
    ):
        return None
    blocks = {
        evidence.block_addr: _DecodedBlock8616(evidence.block_addr, evidence.instructions)
        for evidence in inventory.blocks
    }
    successors: dict[int, set[int]] = {addr: set() for addr in blocks}
    gaps = not inventory.complete
    for evidence in inventory.blocks:
        for predecessor in evidence.predecessors:
            if predecessor in successors:
                successors[predecessor].add(evidence.block_addr)
            else:
                gaps = True
    return blocks, successors, gaps


def _continuation_reachable_8616(
    start_addr: int,
    blocks: dict[int, _DecodedBlock8616],
    successors: dict[int, set[int]],
) -> set[int]:
    """Collect every continuation block reachable after the CALL."""
    reachable: set[int] = set()
    queue = [start_addr]
    while queue:
        current = queue.pop()
        if current in reachable or current not in blocks:
            continue
        reachable.add(current)
        queue.extend(sorted(successors[current], reverse=True))
    return reachable


def _continuation_obstacles_8616(
    reachable: set[int],
    scans: dict[int, _BlockDomainScan8616],
    successors: dict[int, set[int]],
    blocks: dict[int, _DecodedBlock8616],
    gaps: bool,
) -> tuple[bool, bool, bool]:
    """Detect evidence gaps, unsupported transfers and nested calls."""
    unsupported_seen = False
    nested_seen = False
    for block_addr in reachable:
        scan = scans[block_addr]
        unsupported_seen = unsupported_seen or bool(scan.unsupported)
        nested_seen = nested_seen or scan.nested_call
        block = blocks[block_addr]
        last = cast(_Instruction8616, block.instructions[-1])
        try:
            terminal = last.mnemonic.lower()
        except AttributeError:
            terminal = ""
        if (
            terminal not in _RETURN_MNEMONICS_8616
            and not is_x86_16_call_mnemonic_8616(terminal)
            and not successors[block_addr]
        ):
            # Ambiguous sink: an unresolved edge or non-returning exit may
            # still observe the register, so the continuation stays partial.
            gaps = True
    return gaps, unsupported_seen, nested_seen


def _caller_dead_role_8616(
    inventory: RegisterSourceBlockInventory8616 | None,
    function_addr: int | None,
    callsite_addr: int | None,
    call_block_addr: int | None,
    return_block_addr: int | None,
) -> CallRegisterRoleEvidence8616:
    """Prove bits overwritten before any read on every caller continuation.

    Exit blocks expose every still-live bit to an unknown outer caller, a
    nested call conservatively reads and writes all live bits, and missing
    edges, unreadable blocks or an unproved fixpoint keep bits undecided —
    none of them can prove a bit dead.
    """
    kind = CallRegisterRoleKind8616.CALLER_DEAD
    caller_graph = _caller_graph_8616(inventory, function_addr)
    if caller_graph is None:
        return _refused_role_8616(
            kind,
            CallRegisterRoleFailure8616.CALLER_EVIDENCE_MISSING,
        )
    blocks, successors, gaps = caller_graph
    start = _continuation_start_8616(
        blocks,
        successors,
        callsite_addr,
        call_block_addr,
        return_block_addr,
    )
    if start is None:
        return _refused_role_8616(
            kind,
            CallRegisterRoleFailure8616.CALLER_CONTINUATION_MISSING,
        )

    scans: dict[int, _BlockDomainScan8616] = {
        block_addr: _scan_instructions_8616(block.instructions)
        for block_addr, block in blocks.items()
    }
    # The analyzed CALL itself sits before the continuation inside the start
    # block; its effects never reach the return-edge value.
    start_scan = _scan_instructions_8616(
        blocks[start.block_addr].instructions,
        start.start_index,
    )
    scans[start.block_addr] = start_scan

    reachable = _continuation_reachable_8616(start.block_addr, blocks, successors)
    reentered = start.start_index > 0 and any(
        start.block_addr in successors[other] for other in reachable
    )
    if reentered:
        # A back-edge to the block head re-executes the pre-CALL prefix; its
        # reads and writes must not be conflated with the suffix entry.
        scans[start.block_addr] = _scan_instructions_8616(
            blocks[start.block_addr].instructions
        )
    gaps, unsupported_seen, nested_seen = _continuation_obstacles_8616(
        reachable, scans, successors, blocks, gaps,
    )

    _live_in, live_out, converged = _caller_liveness_8616(
        reachable, scans, successors
    )

    known = [0] * _DOMAIN_COUNT_8616
    dead = [0] * _DOMAIN_COUNT_8616
    failures: list[CallRegisterRoleFailure8616] = []
    live_at_start = [
        start_scan.incoming_reads[index]
        | (live_out.get(start.block_addr, [0] * _DOMAIN_COUNT_8616)[index]
           & ~start_scan.writes[index])
        for index in range(_DOMAIN_COUNT_8616)
    ]
    if converged and not (gaps or unsupported_seen or nested_seen):
        for index in range(_DOMAIN_COUNT_8616):
            known[index] = FULL_DOMAIN_MASK_8616
            dead[index] = FULL_DOMAIN_MASK_8616 & ~live_at_start[index]
    else:
        # Partial coverage: only bits observed live are decided (not dead).
        # Absent evidence — missing blocks or edges, nested calls, unsupported
        # transfers, an unproved fixpoint — can never certify a bit as dead.
        failures.append(CallRegisterRoleFailure8616.CALLER_COVERAGE_PARTIAL)
        for index in range(_DOMAIN_COUNT_8616):
            known[index] = live_at_start[index]
    witnesses = {
        witness
        for block_addr in reachable
        for witness in scans[block_addr].unsupported
        if witness >= 0
    }
    return _role_evidence_8616(
        kind,
        complete=converged and not failures,
        known=known,
        role=dead,
        witnesses=witnesses,
        failures=tuple(failures),
    )


def _result_role_8616(
    callsite_addr: int | None,
    call_block_addr: int | None,
    call_instr_index: int | None,
    target_addr: int | None,
    return_block_addr: int | None,
    output_fact: CallOutputFact8616 | None,
) -> tuple[CallRegisterRoleEvidence8616, tuple[CallRegisterRoleResult8616, ...]]:
    """Bind proven output registers to the exact call identity.

    A refused or identity-mismatched output fact can never surface as a
    proven result; an unsupported register view refuses instead of
    truncating into a narrower tracked domain.
    """
    kind = CallRegisterRoleKind8616.RESULT
    if output_fact is None:
        return _refused_role_8616(
            kind,
            CallRegisterRoleFailure8616.OUTPUT_FACT_MISSING,
        ), ()
    if output_fact.verdict is not CallOutputVerdict8616.PROVEN:
        return _refused_role_8616(
            kind,
            CallRegisterRoleFailure8616.OUTPUT_FACT_REFUSED,
        ), ()
    identity_matches = (
        output_fact.call_block_addr == call_block_addr
        and output_fact.call_instr_index == call_instr_index
        and output_fact.callsite_addr == callsite_addr
        and output_fact.target_addr == target_addr
        and output_fact.return_block_addr == return_block_addr
    )
    if not identity_matches:
        return _refused_role_8616(
            kind,
            CallRegisterRoleFailure8616.OUTPUT_FACT_MISMATCH,
        ), ()
    inconsistent = validate_call_output_fact_8616(output_fact)
    if inconsistent:
        mapped = {
            (
                CallRegisterRoleFailure8616.OUTPUT_VIEW_UNSUPPORTED
                if failure is CallOutputFailure8616.OUTPUT_WIDTH_MISMATCH
                else CallRegisterRoleFailure8616.OUTPUT_FACT_MISMATCH
            )
            for failure in inconsistent
        }
        return _refused_role_8616(kind, *sorted(mapped)), ()
    assert callsite_addr is not None
    assert target_addr is not None
    assert return_block_addr is not None
    known = [FULL_DOMAIN_MASK_8616] * _DOMAIN_COUNT_8616
    role = [0] * _DOMAIN_COUNT_8616
    results: list[CallRegisterRoleResult8616] = []
    failures: list[CallRegisterRoleFailure8616] = []
    witnesses: set[int] = set()
    for output in output_fact.outputs:
        if output.space is not MemSpace.REG or output.name is None:
            continue
        register = output.name.lower()
        domain = register_domain_for_name(register)
        view = register_view_for_name(register)
        if domain is None or view is None:
            family = register_value_family_8616(register)
            affected = {
                name_domain.name
                for name in family
                if (name_domain := register_domain_for_name(name)) is not None
            }
            for name in affected or set(TRACKED_REGISTER_DOMAIN_NAMES_8616):
                known[_DOMAIN_INDEX_8616[name]] = 0
            failures.append(CallRegisterRoleFailure8616.OUTPUT_VIEW_UNSUPPORTED)
            continue
        mask = ((1 << view.bit_width) - 1) << view.bit_offset
        role[_DOMAIN_INDEX_8616[domain.name]] |= mask
        results.append(
            CallRegisterRoleResult8616(
                register,
                domain.name,
                mask,
                callsite_addr,
                target_addr,
                return_block_addr,
                output_fact.shape,
            )
        )
        witnesses.add(callsite_addr)
    return _role_evidence_8616(
        kind,
        complete=not failures,
        known=known,
        role=role,
        witnesses=witnesses,
        failures=tuple(failures),
    ), tuple(results)


def build_callsite_register_role_fact_8616(
    project: object | None,
    *,
    callsite_addr: int | None,
    call_block_addr: int | None = None,
    call_instr_index: int | None = None,
    target_addr: int | None = None,
    return_block_addr: int | None = None,
    caller_inventory: RegisterSourceBlockInventory8616 | None = None,
    caller_function_addr: int | None = None,
    output_fact: CallOutputFact8616 | None = None,
) -> CallRegisterRolesFact8616:
    """Build the four register roles for one exact CALL identity.

    Each role consumes only its own evidence: callee reads before overwrite
    prove inputs, observed callee writes prove possible clobbers, caller
    continuation liveness proves caller-dead bits, and only an identity-bound
    proven output fact proves results.
    """
    input_role, clobber_role = _callee_roles_8616(
        project,
        callsite_addr,
        target_addr,
    )
    dead_role = _caller_dead_role_8616(
        caller_inventory,
        caller_function_addr,
        callsite_addr,
        call_block_addr,
        return_block_addr,
    )
    result_role, results = _result_role_8616(
        callsite_addr,
        call_block_addr,
        call_instr_index,
        target_addr,
        return_block_addr,
        output_fact,
    )
    roles = {
        evidence.kind: evidence
        for evidence in (input_role, clobber_role, dead_role, result_role)
    }
    return CallRegisterRolesFact8616(
        call_block_addr,
        call_instr_index,
        callsite_addr,
        target_addr,
        return_block_addr,
        tuple(roles[kind] for kind in CALL_REGISTER_ROLE_KINDS_8616),
        results,
    )


def build_call_register_roles_8616(
    project: object | None,
    function: object | None,
    artifact: IRFunctionArtifact,
    summaries: Mapping[int, CallsiteSummary8616],
    outputs: CallOutputArtifact8616,
) -> CallRegisterRolesArtifact8616:
    """Build the register-role artifact for every CALL in one function IR.

    The producer consumes the authoritative callsite summaries and the exact
    output facts published by ``materialize_call_outputs_8616``. CALL
    enumeration runs on the source IR snapshot retained on the output
    artifact — ``CallOutputFact8616.call_instr_index`` names indexes in that
    snapshot, before any return-edge ``CALL_OUTPUT`` prefix insertions moved
    them in the enriched output IR. Caller-dead evidence uses the exact
    caller CFG inventory when available; results bind only to output facts
    whose identity matches the call.
    """
    caller_inventory = (
        collect_register_source_block_inventory_8616(function)
        if function is not None
        else None
    )
    facts_by_call: dict[tuple[int, int], CallOutputFact8616] = {
        (fact.call_block_addr, fact.call_instr_index): fact
        for fact in outputs.facts
    }
    source = (
        artifact
        if outputs.source_function is None
        else outputs.source_function
    )

    facts: list[CallRegisterRolesFact8616] = []
    stats = [0, 0, 0, 0, 0]
    for block in source.blocks:
        for instr_index, instruction in enumerate(block.instrs):
            if instruction.op != "CALL":
                continue
            callsite_addr = instruction.addr
            summary = (
                summaries.get(callsite_addr) if callsite_addr is not None else None
            )
            target_addr = summary.target_addr if summary is not None else None
            return_block_addr = summary.return_addr if summary is not None else None
            output_fact = facts_by_call.get((block.addr, instr_index))
            if output_fact is not None and output_fact.callsite_addr != callsite_addr:
                output_fact = None
            fact = build_callsite_register_role_fact_8616(
                project,
                callsite_addr=callsite_addr,
                call_block_addr=block.addr,
                call_instr_index=instr_index,
                target_addr=target_addr,
                return_block_addr=return_block_addr,
                caller_inventory=caller_inventory,
                caller_function_addr=source.function_addr,
                output_fact=output_fact,
            )
            facts.append(fact)
            for evidence in fact.roles:
                stats[0] += evidence.raw_fact_count
                stats[1] += evidence.normalized_fact_count
                stats[2] += evidence.classified_fact_count
                stats[3] += evidence.materialized_count
                stats[4] += evidence.failure_count
    return CallRegisterRolesArtifact8616(
        source.function_addr,
        tuple(facts),
        CallRegisterRoleStats8616(*stats),
        output_facts=outputs.facts,
        source_function=source,
        output_function=outputs.function,
    )
