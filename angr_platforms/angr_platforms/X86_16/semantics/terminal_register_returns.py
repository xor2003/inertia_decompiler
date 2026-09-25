"""Classify terminal AX byte-lane writes from bounded binary paths.

Layer: Semantics.
Responsibility: expose typed AL/AH/AX return-width evidence from binary
instructions without choosing a C type or mutating a function prototype.
Forbidden: source/COD/name evidence, C-AST rewriting, or prototype repair.
Owns instruction effects, flags, branch meaning, and expression interpretation.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol, cast

from angr.errors import SimEngineError, SimTranslationError

from ..frontend_function_block_decode import (
    FunctionBlockDecodeArtifact8616,
    collect_function_block_decode_artifact_8616,
)
from ..frontend_instruction_reachability import decoded_block_instructions_8616
from ..function_evidence_inventory import (
    FunctionEvidenceKind8616,
    collect_function_binary_evidence_8616,
)
from .branch_target_return import (
    TerminalAxReturnEffect8616,
    TerminalAxReturnEffectKind8616,
    terminal_ax_return_effect_8616,
)
from .terminal_register_restore import terminal_register_restore_sites_8616
from .terminal_value_roles import (
    TerminalAxReturnEvidence8616,
    TerminalAxReturnLane8616,
    TerminalAxUse8616,
    TerminalAxUseKind8616,
    TerminalReturnStorageState8616,
    terminal_ax_use_8616,
)

__all__ = [
    "TerminalAxReturnEvidence8616",
    "TerminalAxReturnLane8616",
    "TerminalReturnStorageState8616",
    "collect_terminal_ax_return_evidence_8616",
    "terminal_ax_return_lane_states_8616",
]

_CONDITIONAL_BRANCHES_8616 = frozenset({
    "ja", "jae", "jb", "jbe", "jc", "jcxz", "je", "jg", "jge", "jl", "jle", "jna", "jnae",
    "jnb", "jnbe", "jnc", "jne", "jng", "jnge", "jnl", "jnle", "jno", "jnp", "jns", "jnz",
    "jo", "jp", "jpe", "jpo", "js", "jz", "loop", "loope", "loopne", "loopnz", "loopz",
})


class _FunctionSurface8616(Protocol):
    """angr function fields consumed by terminal-path semantics."""

    addr: int
    block_addrs_set: set[int]


@dataclass(frozen=True, slots=True)
class _TerminalAxScanState8616:
    """One finite typed transfer state at a function block entry."""

    block_addr: int
    lanes: TerminalAxReturnLane8616
    dx_ax_pair_proven: bool
    call_output_lanes: TerminalAxReturnLane8616
    local_definition_lanes: TerminalAxReturnLane8616
    local_pointer_output_lanes: TerminalAxReturnLane8616


def _inner_instruction_8616(insn: object) -> object:
    """Return an angr wrapper's underlying capstone instruction."""
    # Dynamic angr/capstone compatibility boundary.
    return getattr(insn, "insn", insn)


def _register_name_8616(insn: object, reg_id: int) -> str:
    """Return a normalized capstone register name."""
    try:
        return str(cast(Any, _inner_instruction_8616(insn)).reg_name(reg_id)).lower()
    except Exception:
        return ""


def _written_register_8616(insn: object, effect_dst: str | None) -> str | None:
    """Return the explicitly written return-carrier register, if proven."""
    if effect_dst in {"ax", "al", "ah", "dx"}:
        return effect_dst
    # The typed effect vocabulary is intentionally incomplete. This fallback
    # accepts only instructions whose first register operand is a destination.
    inner = _inner_instruction_8616(insn)
    # Dynamic capstone compatibility boundary.
    mnemonic = str(getattr(inner, "mnemonic", "") or "").lower()
    if mnemonic not in {
        "mov", "lea", "pop", "add", "adc", "sub", "sbb", "and", "or", "xor",
        "inc", "dec", "shl", "sal", "shr", "sar", "rol", "ror", "rcl", "rcr",
    }:
        return None
    # Dynamic capstone compatibility boundary.
    operands = tuple(getattr(inner, "operands", ()) or ())
    if not operands:
        return None
    # Dynamic capstone compatibility boundary.
    if int(getattr(operands[0], "type", -1)) != 1:
        return None
    # Dynamic capstone compatibility boundary.
    reg_name = _register_name_8616(insn, int(getattr(operands[0], "reg", 0) or 0))
    return reg_name if reg_name in {"ax", "al", "ah", "dx"} else None


def _written_lane_8616(insn: object, effect_dst: str | None) -> TerminalAxReturnLane8616:
    """Return a proven AX lane written by one instruction."""
    return {
        "ax": TerminalAxReturnLane8616.WORD,
        "al": TerminalAxReturnLane8616.LOW,
        "ah": TerminalAxReturnLane8616.HIGH,
    }.get(_written_register_8616(insn, effect_dst) or "", TerminalAxReturnLane8616.NONE)


def _preserves_terminal_return_storage_8616(insn: object, mnemonic: str) -> bool:
    """Return whether one proven epilogue instruction preserves DX:AX."""
    if mnemonic in {"nop", "pop", "leave", "jmp", "ljmp", "ret", "retf", "iret"}:
        return True
    if mnemonic != "mov":
        return False
    inner = cast(Any, _inner_instruction_8616(insn))
    operands: tuple[Any, ...] = tuple(inner.operands or ())
    if len(operands) != 2 or any(int(cast(Any, operand).type) != 1 for operand in operands):
        return False
    names = tuple(_register_name_8616(insn, int(cast(Any, operand).reg or 0)) for operand in operands)
    return names == ("sp", "bp")


def _direct_jump_target_8616(insn: object) -> int | None:
    """Return a direct immediate jump target, if present."""
    inner = _inner_instruction_8616(insn)
    # Dynamic capstone compatibility boundary.
    operands = tuple(getattr(inner, "operands", ()) or ())
    if len(operands) != 1:
        return None
    operand = operands[0]
    # Dynamic capstone compatibility boundary.
    if int(getattr(operand, "type", -1)) != 2:
        return None
    # Dynamic capstone compatibility boundary.
    target = getattr(operand, "imm", None)
    return target if isinstance(target, int) else None


def _instruction_fallthrough_8616(insn: object) -> int | None:
    """Return the next instruction address across the Capstone boundary."""
    inner = cast(Any, _inner_instruction_8616(insn))
    try:
        address = inner.address
        size = inner.size
    except AttributeError:
        return None
    if not isinstance(address, int) or not isinstance(size, int) or size <= 0:
        return None
    return address + size


def _instruction_address_8616(insn: object) -> int | None:
    """Return one decoded instruction address across a dynamic third-party Capstone boundary."""
    address = getattr(_inner_instruction_8616(insn), "address", None)
    return address if isinstance(address, int) else None


def _decoded_instructions_by_block_8616(
    project: object,
    block_addrs: frozenset[int],
    direct_decode: FunctionBlockDecodeArtifact8616,
) -> dict[int, tuple[object, ...]]:
    """Return complete direct evidence or rebuild the legacy exact fallback."""
    if direct_decode.complete:
        return direct_decode.instructions_by_block()
    decoded: dict[int, tuple[object, ...]] = {}
    for block_addr in sorted(block_addrs):
        try:
            instructions = decoded_block_instructions_8616(cast(Any, project), block_addr, opt_level=0)
        except (KeyError, SimEngineError, SimTranslationError, ValueError):
            continue
        if instructions:
            decoded[block_addr] = instructions
    return decoded


@dataclass(slots=True)
class _LaneFlow8616:
    """Mutable per-path lane state carried across one terminal AX scan."""

    lanes: TerminalAxReturnLane8616
    dx_ax_pair_proven: bool
    call_output_lanes: TerminalAxReturnLane8616
    local_definition_lanes: TerminalAxReturnLane8616
    local_pointer_output_lanes: TerminalAxReturnLane8616

    def snapshot(self) -> _LaneFlow8616:
        """Return an independent copy for one successor path."""
        return _LaneFlow8616(
            self.lanes,
            self.dx_ax_pair_proven,
            self.call_output_lanes,
            self.local_definition_lanes,
            self.local_pointer_output_lanes,
        )


@dataclass(slots=True)
class _TerminalAxEvidenceScan8616:
    """Bounded path scan collecting terminal AX lane evidence."""

    project_dynamic: Any
    block_addrs: frozenset[int]
    decoded_by_block: Mapping[int, tuple[object, ...]]
    explicit_restore_sites: frozenset[int]
    terminal_states: set[TerminalReturnStorageState8616] = field(default_factory=set)
    visited_states: set[_TerminalAxScanState8616] = field(default_factory=set)
    raw_fact_count: int = 0
    normalized_fact_count: int = 0
    classified_fact_count: int = 0
    materialized_count: int = 0
    failure_count: int = 0

    def _record_terminal(self, flow: _LaneFlow8616) -> None:
        """Materialize one classified terminal-path state into the evidence set."""
        self.raw_fact_count += 1
        self.normalized_fact_count += 1
        self.classified_fact_count += 1
        self.materialized_count += 1
        self.terminal_states.add(
            TerminalReturnStorageState8616(
                flow.lanes,
                flow.dx_ax_pair_proven,
                flow.call_output_lanes,
                flow.local_pointer_output_lanes,
            )
        )

    def _record_failure(self) -> None:
        """Record one reachable control-flow fact that could not be classified."""
        self.raw_fact_count += 1
        self.failure_count += 1

    def _block_instructions(self, block_addr: int) -> tuple[object, ...]:
        """Return decoded instructions for one block or empty on refusal."""
        insns = self.decoded_by_block.get(block_addr)
        if insns is not None:
            return insns
        try:
            return cast(
                tuple[object, ...],
                decoded_block_instructions_8616(self.project_dynamic, block_addr, opt_level=0),
            )
        except (KeyError, SimEngineError, SimTranslationError, ValueError):
            return ()

    def scan(self, block_addr: int, flow: _LaneFlow8616) -> None:
        """Propagate one finite typed state once through an entry-reachable block."""
        state = _TerminalAxScanState8616(
            block_addr,
            flow.lanes,
            flow.dx_ax_pair_proven,
            flow.call_output_lanes,
            flow.local_definition_lanes,
            flow.local_pointer_output_lanes,
        )
        if state in self.visited_states:
            return
        self.visited_states.add(state)
        insns = self._block_instructions(block_addr)
        if not insns:
            self._record_failure()
            return
        for insn in insns:
            effect = terminal_ax_return_effect_8616(insn)
            ax_use = terminal_ax_use_8616(insn)
            mnemonic = str(cast(Any, _inner_instruction_8616(insn)).mnemonic or "").lower()
            if self._apply_effect(insn, effect, ax_use, mnemonic, flow):
                continue
            if self._dispatch_edge(insn, mnemonic, flow):
                return
        self._propagate_fallthrough(insns[-1], flow)

    def _apply_effect(
        self,
        insn: object,
        effect: TerminalAxReturnEffect8616,
        ax_use: TerminalAxUse8616,
        mnemonic: str,
        flow: _LaneFlow8616,
    ) -> bool:
        """Apply one instruction's lane effects; return True to skip edges."""
        if effect.kind is TerminalAxReturnEffectKind8616.CALL_CLOBBER:
            flow.lanes = TerminalAxReturnLane8616.WORD
            flow.dx_ax_pair_proven = False
            flow.call_output_lanes = TerminalAxReturnLane8616.WORD
            flow.local_definition_lanes = TerminalAxReturnLane8616.NONE
            flow.local_pointer_output_lanes = TerminalAxReturnLane8616.NONE
            return False
        written_register = _written_register_8616(insn, effect.dst_reg)
        if _instruction_address_8616(insn) in self.explicit_restore_sites:
            self._apply_restore(written_register, flow)
            return True
        self._apply_write(insn, effect, written_register, mnemonic, flow)
        self._apply_use(ax_use, flow)
        return False

    @staticmethod
    def _apply_restore(written_register: str | None, flow: _LaneFlow8616) -> None:
        """Reset lanes proven consumed by an explicit terminal restore."""
        if written_register in {"ax", "al", "ah"}:
            flow.lanes = TerminalAxReturnLane8616.NONE
            flow.call_output_lanes = TerminalAxReturnLane8616.NONE
            flow.local_definition_lanes = TerminalAxReturnLane8616.NONE
            flow.local_pointer_output_lanes = TerminalAxReturnLane8616.NONE
            flow.dx_ax_pair_proven = False
        elif written_register == "dx":
            flow.dx_ax_pair_proven = False

    @staticmethod
    def _apply_write(
        insn: object,
        effect: TerminalAxReturnEffect8616,
        written_register: str | None,
        mnemonic: str,
        flow: _LaneFlow8616,
    ) -> None:
        """Apply register-write lane effects for one instruction."""
        if written_register in {"ax", "al", "ah"}:
            written = _written_lane_8616(insn, effect.dst_reg)
            flow.lanes = (
                written if written == TerminalAxReturnLane8616.WORD else flow.lanes | written
            )
            flow.call_output_lanes &= ~written
            flow.local_definition_lanes &= ~written
            flow.local_pointer_output_lanes &= ~written
            if (
                effect.kind is TerminalAxReturnEffectKind8616.MOV_REG_STACK
                and isinstance(effect.mem_disp, int)
                and effect.mem_disp < 0
            ):
                flow.local_definition_lanes |= written
            flow.dx_ax_pair_proven = False
        elif written_register == "dx":
            explicit_lanes = flow.lanes & ~flow.call_output_lanes
            flow.dx_ax_pair_proven = (
                explicit_lanes == TerminalAxReturnLane8616.WORD
                and mnemonic in {"adc", "mov", "sbb"}
            )
        elif flow.dx_ax_pair_proven and not _preserves_terminal_return_storage_8616(insn, mnemonic):
            flow.dx_ax_pair_proven = False

    @staticmethod
    def _apply_use(ax_use: TerminalAxUse8616, flow: _LaneFlow8616) -> None:
        """Apply AX-use lane effects for one instruction."""
        if ax_use.kind is TerminalAxUseKind8616.MEMORY_EFFECT:
            flow.local_pointer_output_lanes |= (
                ax_use.lanes & flow.lanes & flow.local_definition_lanes
            )
        elif ax_use.kind in {
            TerminalAxUseKind8616.OTHER,
            TerminalAxUseKind8616.UNKNOWN_REFUSE,
        }:
            flow.local_pointer_output_lanes &= ~ax_use.lanes

    def _dispatch_edge(
        self,
        insn: object,
        mnemonic: str,
        flow: _LaneFlow8616,
    ) -> bool:
        """Handle terminal/branch mnemonics; return whether the block ends."""
        if mnemonic in {"ret", "retf", "iret"}:
            self._record_terminal(flow)
            return True
        if mnemonic in {"jmp", "ljmp"}:
            target = _direct_jump_target_8616(insn)
            if isinstance(target, int) and target in self.block_addrs:
                self.scan(target, flow.snapshot())
            else:
                self._record_failure()
            return True
        if mnemonic in _CONDITIONAL_BRANCHES_8616:
            target = _direct_jump_target_8616(insn)
            fallthrough = _instruction_fallthrough_8616(insn)
            successors = tuple(dict.fromkeys((target, fallthrough)))
            for successor in successors:
                if isinstance(successor, int) and successor in self.block_addrs:
                    self.scan(successor, flow.snapshot())
                else:
                    self._record_failure()
            return True
        return False

    def _propagate_fallthrough(self, last_insn: object, flow: _LaneFlow8616) -> None:
        """Propagate the lane state along the block's fallthrough edge."""
        fallthrough = _instruction_fallthrough_8616(last_insn)
        if isinstance(fallthrough, int) and fallthrough in self.block_addrs:
            self.scan(fallthrough, flow.snapshot())
        else:
            self._record_failure()


def _collect_terminal_ax_return_evidence_uncached_8616(
    project: object,
    function: object,
    direct_decode: FunctionBlockDecodeArtifact8616,
) -> TerminalAxReturnEvidence8616:
    """Collect closed AX lane evidence along bounded paths to binary returns."""
    function_surface = cast(_FunctionSurface8616, function)
    try:
        block_addrs = frozenset(int(addr) for addr in (function_surface.block_addrs_set or ()))
    except AttributeError:
        block_addrs = frozenset()
    try:
        entry_addr = function_surface.addr
    except AttributeError:
        entry_addr = None
    if not isinstance(entry_addr, int):
        entry_addr = min(block_addrs, default=None)
    if not isinstance(entry_addr, int) or entry_addr not in block_addrs:
        return TerminalAxReturnEvidence8616(frozenset(), 1, 0, 0, 0, 1)
    project_dynamic = cast(Any, project)
    decoded_by_block = _decoded_instructions_by_block_8616(
        project,
        block_addrs,
        direct_decode,
    )
    explicit_restore_sites = (
        terminal_register_restore_sites_8616(decoded_by_block, entry_addr)
        if frozenset(decoded_by_block) == block_addrs
        else frozenset()
    )
    scan = _TerminalAxEvidenceScan8616(
        project_dynamic,
        block_addrs,
        decoded_by_block,
        explicit_restore_sites,
    )
    scan.scan(
        entry_addr,
        _LaneFlow8616(
            TerminalAxReturnLane8616.NONE,
            False,
            TerminalAxReturnLane8616.NONE,
            TerminalAxReturnLane8616.NONE,
            TerminalAxReturnLane8616.NONE,
        ),
    )
    return TerminalAxReturnEvidence8616(
        storage_states=frozenset(scan.terminal_states),
        raw_fact_count=scan.raw_fact_count,
        normalized_fact_count=scan.normalized_fact_count,
        classified_fact_count=scan.classified_fact_count,
        materialized_count=scan.materialized_count,
        failure_count=scan.failure_count,
    )


def collect_terminal_ax_return_evidence_8616(
    project: object,
    function: object,
) -> TerminalAxReturnEvidence8616:
    """Return immutable terminal AX evidence for the exact binary surface."""
    direct_decode = collect_function_block_decode_artifact_8616(project, function)

    def _build(
        cached_project: object | None,
        cached_function: object,
    ) -> tuple[TerminalAxReturnEvidence8616]:
        """Adapt the semantic collector to the binary evidence inventory."""
        evidence_project = project if cached_project is None else cached_project
        return (
            _collect_terminal_ax_return_evidence_uncached_8616(
                evidence_project,
                cached_function,
                direct_decode,
            ),
        )

    cached: tuple[TerminalAxReturnEvidence8616, ...] = collect_function_binary_evidence_8616(
        project,
        function,
        kind=FunctionEvidenceKind8616.TERMINAL_AX_RETURNS,
        builder=_build,
        content_identity=direct_decode.content_identity if direct_decode.complete else None,
    )
    if len(cached) != 1:
        raise RuntimeError("terminal AX evidence inventory did not materialize exactly one result")
    return cached[0]


def terminal_ax_return_lane_states_8616(
    project: object,
    function: object,
) -> frozenset[TerminalAxReturnLane8616]:
    """Return the compatibility lane-state view of closed terminal evidence."""
    evidence = collect_terminal_ax_return_evidence_8616(project, function)
    return evidence.states if evidence.complete else frozenset()
