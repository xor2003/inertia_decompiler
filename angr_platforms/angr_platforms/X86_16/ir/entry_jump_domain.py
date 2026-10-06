"""Function-entry fetch-domain proof for retained terminal jumps.

Layer: IR / control-domain evidence.
Responsibility: discharge the ``terminal_jump_selector_window_unproved``
obligation for a retained unconditional word-form near jump when a
function-entry theorem applies: the function root is the native fetch head,
a complete typed instruction/effect census covers every path from the root
to the transfer, every reachable successor edge stays inside the census —
an exterior edge means the claimed region is not closed and is retained as
typed PATH_INCOMPLETE — every reachable instruction preserves ``cs`` under
the authoritative scalar-effect owner (an unclassified effect is typed
UNKNOWN_EFFECT_ON_PATH, never guessed), the segment solver reproves CS
identity unchanged from the entry state at every reachable instruction, the
decoded transfer binds to the imported block-``next`` terminal's native
origin and to its symbolic operand — the operand must be the imported
``next`` temporary itself — and the decoded bytes are verified against a
bounded native re-lift of the transfer block under an explicit project
source authority: the re-lifted tail bytes must equal the supplied encoding
exactly, and the re-lifted ``next`` expression must read the same recorded
temporary. A caller-supplied tag, name, or copied provenance record cannot
repair tampered bytes, and an absent source authority refuses honestly
rather than trusting the decoded carrier. The decoded loader-linear
target is invariant across every selector capable of fetching both the root
and the jump. The final published edge set is revalidated end to end —
path closure plus segment solving — under the same deterministic term
budget before any admission stands. A function with no pending candidates
takes a constant-cost fast path with no census and no solver run. The
proof product carries a typed source binding — a canonical digest of the
exact function/block surface the proof consumed, including fields that
dataclass equality ignores (captured temporary identities, access
provenance) — and application consumes the typed ``IRFunctionArtifact``
being patched, so its own ``function_addr`` root is verified against the
recorded binding before any digest comparison: a proof applied to an
artifact whose root moved refuses with a typed ``STALE_INPUT``
non-result even when every block is byte-identical, and a same-address
or body-only match is not the proved input. The default
per-instruction all-selector gate stays in force; this module only
adds a separately proven, narrower fetch domain. A call or a ``PROVEN``
tag alone is never evidence; the segment solver is rerun on the same
artifact instead of trusting retained artifacts or serialized receipts.
Owns typed Value, Address, Condition, instruction facts, and lossless
normalization.
Do not perform alias-state ownership, widening, lowering/materialization,
structuring, rewrite, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Protocol, cast

import pyvex
from angr.errors import SimEngineError, SimTranslationError
from pyvex.errors import PyVEXError

from ..arch_86_16 import Arch86_16
from ..control_coordinates import ControlAddressDomain, ControlWidth
from ..relative_control_edge import DecodedRelativeEdge
from .core import (
    IRBlock,
    IRFunctionArtifact,
    IRInstr,
    IRRefusal,
    IRValue,
    MemSpace,
    SegmentOrigin,
)
from .entry_domain_call_preservation import EntryDomainCallPreservation8616
from .instruction_origin import IRInstructionOrigin8616
from .scalar_instruction_effects import (
    ScalarInstructionEffectKind8616,
    scalar_instruction_effect_8616,
)
from .segment_state_solver import (
    SegmentStateSolution8616,
    solve_segment_state_8616,
)
from .segment_state_transfer import (
    SEGMENT_REGISTERS,
    InstructionStateKey,
    SegmentRegisterState,
)
from .vex_terminal_jump import (
    TerminalJumpEvidence8616,
    TerminalJumpRefusalReason8616,
)

if TYPE_CHECKING:
    from .real16_invocation_domain import Real16InvocationDomain8616

__all__ = [
    "AdmittedTerminalJump8616",
    "EntryJumpDomainApplication8616",
    "EntryJumpDomainApplicationStatus8616",
    "EntryJumpDomainBudget8616",
    "EntryJumpDomainLedgerEntry8616",
    "EntryJumpDomainProof8616",
    "EntryJumpDomainRefusal8616",
    "EntryJumpDomainSourceBinding8616",
    "EntryJumpDomainStage8616",
    "EntryJumpDomainStats8616",
    "PendingTerminalJump8616",
    "apply_entry_jump_domain_8616",
    "collect_pending_terminal_jumps_8616",
    "prove_entry_jump_domains_8616",
]

_CS_REGISTER_8616 = "cs"
_SELECTOR_MAX_8616 = 0xFFFF

# A block-terminal control sink recognized at this layer: its register
# effects leave the proof region entirely, so the effect owner is not asked
# to classify it. Every other terminal position must classify closed.
_SINK_TERMINAL_OPS_8616: frozenset[str] = frozenset({"RET"})


class EntryJumpDomainStage8616(StrEnum):
    """Five-stage evidence ledger for one entry-domain proof."""

    ENTRY = "entry"
    CENSUS = "census"
    PATH = "path"
    SEGMENT = "segment"
    TRANSFER = "transfer"


class EntryJumpDomainRefusal8616(StrEnum):
    """Typed reason the entry-domain proof cannot discharge a jump."""

    ENTRY_BLOCK_MISSING = "entry_jump_domain_entry_block_missing"
    ENTRY_FETCH_UNPROVED = "entry_jump_domain_entry_fetch_unproved"
    BLOCK_CENSUS_INCOMPLETE = "entry_jump_domain_block_census_incomplete"
    PATH_REFUSAL_PRESENT = "entry_jump_domain_path_refusal_present"
    PATH_INCOMPLETE = "entry_jump_domain_path_incomplete"
    OPAQUE_TERMINAL_ON_PATH = "entry_jump_domain_opaque_terminal_on_path"
    CALL_ON_PATH = "entry_jump_domain_call_on_path"
    CS_WRITE_INTERFERENCE = "entry_jump_domain_cs_write_interference"
    UNKNOWN_EFFECT_ON_PATH = "entry_jump_domain_unknown_effect_on_path"
    CS_IDENTITY_MISMATCH = "entry_jump_domain_cs_identity_mismatch"
    JOINT_WINDOW_UNPROVED = "entry_jump_domain_joint_window_unproved"
    TRANSFER_FACT_MISMATCH = "entry_jump_domain_transfer_fact_mismatch"
    NATIVE_SOURCE_UNPROVED = "entry_jump_domain_native_source_unproved"
    BUDGET_EXCEEDED = "entry_jump_domain_budget_exceeded"
    APPLICATION_INPUT_STALE = "entry_jump_domain_application_input_stale"


@dataclass(frozen=True, slots=True)
class EntryJumpDomainBudget8616:
    """Deterministic term budget; no wall-clock deadline, same input same cost."""

    max_terms: int = 65536
    max_iterations: int = 17


@dataclass(frozen=True, slots=True)
class EntryJumpDomainLedgerEntry8616:
    """One recorded fact consumed by the entry-domain proof."""

    stage: EntryJumpDomainStage8616
    fact: str
    detail: str

    def to_dict(self) -> dict[str, object]:
        """Serialize one ledger entry for diagnostics and workers."""
        return {
            "stage": self.stage.value,
            "fact": self.fact,
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class PendingTerminalJump8616:
    """A retained terminal jump whose only open obligation is the window gate."""

    block_addr: int
    decoded: DecodedRelativeEdge

    def to_dict(self) -> dict[str, object]:
        """Serialize the pending-jump identity for diagnostics."""
        return {
            "block_addr": self.block_addr,
            "head": self.decoded.head,
            "form": self.decoded.form.value,
            "encoding_digest": self.decoded.encoding_digest,
        }


@dataclass(frozen=True, slots=True)
class _ScopedCallDependency8616:
    """One conditional callsite proof consumed under an authenticated entry.

    A surrogate on the proof path may only read a conditional
    preservation record under a scope that reauthenticates against the
    record's required entry. The retained triple — callsite coordinate,
    the exact record object consumed, and the authenticated consuming
    entry — is what application replays: ``record.complete_for(scope)``
    re-runs both the scope check and the whole retained evidence chain,
    so a stale scope or revoked conditional chain revokes the admission
    that consumed it instead of silently persisting.
    """

    callsite_addr: int
    record: EntryDomainCallPreservation8616 = field(compare=False)
    scope: Real16InvocationDomain8616 = field(compare=False)

    def to_dict(self) -> dict[str, object]:
        """Serialize the dependency for diagnostics; it is not fresh proof."""
        return {
            "callsite_addr": self.callsite_addr,
            "record": self.record.to_dict(),
            "scope": self.scope.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class AdmittedTerminalJump8616:
    """A discharged terminal jump with its proven loader-linear target.

    ``invocation`` retains the complete source-bound caller-domain premise
    when the admission was discharged by one instead of the default joint
    fetch-window bound; it is excluded from equality because the domain
    record is an identity-anchored proof object, and it is replayed end to
    end at application revalidation. ``call_dependencies`` retains every
    conditional callsite proof the admitting view consumed under an
    authenticated entry — application revalidates each retained
    dependency under its recorded scope before any edge materializes.
    """

    block_addr: int
    head: int
    target: int
    invocation: Real16InvocationDomain8616 | None = field(default=None, compare=False)
    invocation_scope: Real16InvocationDomain8616 | None = field(default=None, compare=False)
    call_dependencies: tuple[_ScopedCallDependency8616, ...] = field(
        default=(), compare=False
    )

    def to_dict(self) -> dict[str, object]:
        """Serialize the discharged edge for diagnostics and workers."""
        return {
            "block_addr": self.block_addr,
            "head": self.head,
            "target": self.target,
            "invocation": (
                None
                if self.invocation is None
                else self.invocation.to_dict()
            ),
            "invocation_scope": None if self.invocation_scope is None else self.invocation_scope.to_dict(),
            "call_dependencies": [
                dependency.to_dict()
                for dependency in self.call_dependencies
            ],
        }


_SOURCE_BINDING_FORMAT_8616 = "entry_jump_domain_source_binding_8616/v1"


def _canonical_source_8616(
    function_addr: int, blocks: tuple[IRBlock, ...],
) -> str:
    """Serialize the exact artifact surface a domain proof consumes.

    Every owned ``to_dict`` emits its complete field surface — including
    the provenance fields dataclass equality is instructed to ignore, such
    as a value's captured ``source_tmp``/``memory_access_insn`` and a
    condition's ``width_bits`` — so the canonical form distinguishes any
    changed opcode, operand, temporary identity, effect destination,
    refusal, successor set, or block membership/order. Block order is
    significant: reordering the census changes the canonical form.
    """
    return json.dumps(
        {
            "format": _SOURCE_BINDING_FORMAT_8616,
            "function_addr": function_addr,
            "blocks": [block.to_dict() for block in blocks],
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def _source_digest_8616(
    function_addr: int, blocks: tuple[IRBlock, ...],
) -> str:
    """Digest the canonical source surface for typed binding comparison."""
    return hashlib.sha256(
        _canonical_source_8616(function_addr, blocks).encode("utf-8")
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class EntryJumpDomainSourceBinding8616:
    """Exact proved-input identity for one batch domain proof.

    ``digest`` is taken over the canonical form of ``function_addr`` and
    every consumed block; ``pending`` retains the exact projected
    candidates the proof classified, so application can also verify each
    admitted edge is backed by a recorded pending candidate. A proof
    applied to input that recomputes a different digest — changed opcode,
    operand, captured temporary, effect destination, block set, or
    successor edge — is stale evidence and must not materialize.
    """

    function_addr: int
    block_count: int
    digest: str
    pending: tuple[PendingTerminalJump8616, ...]

    def to_dict(self) -> dict[str, object]:
        """Serialize the binding for diagnostics; it is not fresh proof."""
        return {
            "function_addr": self.function_addr,
            "block_count": self.block_count,
            "digest": self.digest,
            "pending": [candidate.to_dict() for candidate in self.pending],
        }


@dataclass(frozen=True, slots=True)
class EntryJumpDomainStats8616:
    """Closed five-stage accounting for the batch domain proof."""

    raw_fact_count: int
    normalized_fact_count: int
    classified_fact_count: int
    materialized_count: int
    failure_count: int

    @property
    def closed(self) -> bool:
        """Every classified candidate either materialized or was refused."""
        counts = (
            self.raw_fact_count,
            self.normalized_fact_count,
            self.classified_fact_count,
            self.materialized_count,
            self.failure_count,
        )
        if not all(type(count) is int and count >= 0 for count in counts):
            return False
        return bool(
            self.classified_fact_count
            == self.materialized_count + self.failure_count
            and self.normalized_fact_count <= self.raw_fact_count
        )

    def to_dict(self) -> dict[str, int]:
        """Serialize the evidence ledger for diagnostics and workers."""
        return {
            "raw_fact_count": self.raw_fact_count,
            "normalized_fact_count": self.normalized_fact_count,
            "classified_fact_count": self.classified_fact_count,
            "materialized_count": self.materialized_count,
            "failure_count": self.failure_count,
        }


@dataclass(frozen=True, slots=True)
class EntryJumpDomainProof8616:
    """Batch entry-domain proof product for one function's pending jumps.

    ``admitted`` maps each discharged jump head to its proven loader-linear
    target. ``refusals`` retains every candidate that could not be proved;
    a refusal here means the default per-instruction window gate remains in
    force for that jump, never that the jump was dropped.
    ``source_binding`` records the exact input surface the proof consumed;
    application is bound to it and refuses any other input as stale.
    ``call_preservations`` retains the exact source-bound callsite evidence
    the proof consulted so consumers can audit which calls were admitted
    onto the region and which kept their default refusal.
    """

    function_addr: int
    source_binding: EntryJumpDomainSourceBinding8616
    admitted: tuple[AdmittedTerminalJump8616, ...]
    refusals: tuple[IRRefusal, ...]
    ledger: tuple[EntryJumpDomainLedgerEntry8616, ...]
    stats: EntryJumpDomainStats8616
    terms_consumed: int
    iterations: int
    call_preservations: tuple[EntryDomainCallPreservation8616, ...] = ()
    invocation_scope: Real16InvocationDomain8616 | None = field(default=None, compare=False)

    def admitted_target_for(self, head: int) -> int | None:
        """Return the proven target for one discharged jump head."""
        for jump in self.admitted:
            if jump.head == head:
                return jump.target
        return None

    def to_dict(self) -> dict[str, object]:
        """Serialize the proof product for diagnostics and workers."""
        return {
            "invocation_scope": None if self.invocation_scope is None else self.invocation_scope.to_dict(),
            "function_addr": self.function_addr,
            "source_binding": self.source_binding.to_dict(),
            "admitted": [jump.to_dict() for jump in self.admitted],
            "refusals": [refusal.to_dict() for refusal in self.refusals],
            "ledger": [entry.to_dict() for entry in self.ledger],
            "stats": self.stats.to_dict(),
            "terms_consumed": self.terms_consumed,
            "iterations": self.iterations,
            "call_preservations": [
                preservation.to_dict() for preservation in self.call_preservations
            ],
        }


class EntryJumpDomainApplicationStatus8616(StrEnum):
    """Typed discharge decision for one proof application."""

    APPLIED = "applied"
    EMPTY = "empty"
    STALE_INPUT = "stale_input"


@dataclass(frozen=True, slots=True)
class EntryJumpDomainApplication8616:
    """Typed result of applying one proof to a supplied block surface.

    ``APPLIED`` means the consuming artifact's own root equals the proved
    root, its blocks recomputed the proof's recorded source binding, and
    every admitted edge was materialized onto the returned blocks.
    ``EMPTY`` means the bound input carried no admitted edges; the input
    blocks are returned unchanged. ``STALE_INPUT`` is the typed
    non-result: the consuming root moved, the supplied surface is not the
    proved input, or an admitted edge lacks a recorded pending candidate —
    the input blocks are returned unmodified and ``refusals`` carries the
    typed ``APPLICATION_INPUT_STALE`` reason. No status ever clears a
    refusal or publishes an edge that the binding did not cover.
    """

    status: EntryJumpDomainApplicationStatus8616
    blocks: tuple[IRBlock, ...]
    applied: tuple[AdmittedTerminalJump8616, ...]
    refusals: tuple[IRRefusal, ...]
    invocation_scope: Real16InvocationDomain8616 | None = field(default=None, compare=False)

    def to_dict(self) -> dict[str, object]:
        """Serialize the discharge decision for diagnostics and workers."""
        return {
            "invocation_scope": None if self.invocation_scope is None else self.invocation_scope.to_dict(),
            "status": self.status.value,
            "applied": [jump.to_dict() for jump in self.applied],
            "refusals": [refusal.to_dict() for refusal in self.refusals],
        }


def collect_pending_terminal_jumps_8616(
    evidence_by_block: Mapping[int, TerminalJumpEvidence8616],
) -> dict[int, PendingTerminalJump8616]:
    """Project retained evidence into domain-proof candidates.

    Only a retained, decoded, unconditional jump whose sole open obligation
    is ``SELECTOR_WINDOW_UNPROVED`` is a candidate; every other failure
    keeps its default refusal and never reaches this proof.
    """
    pending: dict[int, PendingTerminalJump8616] = {}
    for block_addr, evidence in sorted(evidence_by_block.items()):
        if (
            evidence.retain
            and evidence.decoded is not None
            and evidence.failure
            is TerminalJumpRefusalReason8616.SELECTOR_WINDOW_UNPROVED
        ):
            pending[block_addr] = PendingTerminalJump8616(
                block_addr=block_addr, decoded=evidence.decoded,
            )
    return pending


def _instruction_state_key_8616(
    block_addr: int, index: int, instr: IRInstr,
) -> InstructionStateKey:
    """Reproduce the solver's exact per-instruction state key."""
    return instr.addr if isinstance(instr.addr, int) else (block_addr, index)


def _writes_cs_8616(instr: IRInstr) -> bool:
    """Detect an explicit typed CS write in one IR instruction."""
    return (
        instr.op != "CALL"
        and isinstance(instr.dst, IRValue)
        and instr.dst.space is MemSpace.REG
        and instr.dst.name == _CS_REGISTER_8616
    )


def _word_jump_form_8616(decoded: DecodedRelativeEdge) -> bool:
    """Accept only unconditional word-width jumps, derived from owned facts.

    The self-validating decode already fixes form, operand width, and
    conditionality from the retained bytes, so the accepted domain follows
    from those typed properties — an unconditional, non-call, word-width
    edge is exactly a 16-bit near jump. No opcode or form list is
    duplicated here.
    """
    return (
        decoded.width is ControlWidth.WORD
        and not decoded.is_conditional
        and not decoded.is_call
    )


class _NativeReliftBlock8616(Protocol):
    """Minimal angr block surface consumed by the bounded native re-lift."""

    addr: object
    size: object
    bytes: object
    vex: object


class _NativeReliftFactory8616(Protocol):
    """Minimal angr factory surface consumed by the bounded native re-lift."""

    block: Callable[..., object]


class _NativeReliftProject8616(Protocol):
    """Minimal angr project surface: arch domain plus the block factory."""

    arch: object
    factory: _NativeReliftFactory8616


@dataclass(frozen=True, slots=True)
class _NativeRelift8616:
    """Bounded native re-lift result: lifted block surface or typed failure."""

    lifted: object | None
    failure: tuple[EntryJumpDomainRefusal8616, str] | None


_MAX_NATIVE_RELIFT_BYTES_8616 = 4096


def _external_int_8616(value: object) -> int:
    """Coerce external pyvex/angr integer-like values without owning them."""
    return int(cast(Any, value))


def _native_source_available_8616(project: object | None) -> bool:
    """The source authority must be an x86-16 loader-linear angr project."""
    if project is None:
        return False
    try:
        arch = cast(_NativeReliftProject8616, project).arch
        factory = cast(_NativeReliftProject8616, project).factory
        native_block_lifter = factory.block
    except AttributeError:
        return False
    return bool(
        isinstance(arch, Arch86_16)
        and arch.control_address_domain is ControlAddressDomain.LOADER_LINEAR
        and callable(native_block_lifter)
    )


def _block_next_origin_8616(
    terminal: IRInstr, block_addr: int,
) -> IRInstructionOrigin8616 | None:
    """Return the terminal's recorded block-``next`` provenance, or refuse it.

    The retained terminal must carry its own native provenance: recorded at
    the pyvex boundary as this block's ``next`` expression reading a real
    temporary at a real statement position. A caller-supplied evidence tag
    is never the association.
    """
    origin = terminal.origin
    if not (
        isinstance(origin, IRInstructionOrigin8616)
        and origin.block_addr == block_addr
        and origin.is_block_next
        and type(origin.block_next_tmp) is int
        and type(origin.statement_index) is int
    ):
        return None
    return origin


def _transfer_operand_bound_8616(
    terminal: IRInstr,
    origin: IRInstructionOrigin8616,
    decoded: DecodedRelativeEdge,
) -> bool:
    """Bind the terminal operand to the imported ``next`` expression.

    The operand must be exactly the imported ``next`` expression — a
    temporary-typed value whose recorded source temporary is the very
    temporary ``next`` reads — or the loader-linear constant this proof
    itself publishes, which can only appear when the same decoded edge was
    already discharged. Anything else means the decoded carrier is not the
    operand the importer produced for these bytes.
    """
    if len(terminal.args) != 1 or not isinstance(terminal.args[0], IRValue):
        return False
    operand = terminal.args[0]
    if operand.space is MemSpace.TMP:
        return bool(
            type(operand.source_tmp) is int
            and operand.source_tmp == origin.block_next_tmp
        )
    return bool(
        operand.space is MemSpace.CONST
        and type(operand.const) is int
        and operand.const == decoded.next_head + decoded.displacement
    )


def _segment_solve_terms_8616(blocks: tuple[IRBlock, ...]) -> int:
    """Deterministic term charge for one segment-solver run.

    The solver's internal counter is not observable here, so each run is
    charged a census-shaped bound over the exact patched blocks it
    consumes. Same input always costs the same terms; a budget too small
    to afford the run refuses instead of silently skipping revalidation.
    """
    return sum(1 + len(block.instrs) for block in blocks)


def _joint_fetch_window_8616(heads: tuple[int, ...]) -> tuple[int, int] | None:
    """Intersect the selector fetch windows of the given loader-linear heads.

    A selector ``s`` can fetch loader-linear ``h`` only when
    ``(s << 4) <= h <= (s << 4) + 0xFFFF``. The joint window is the
    intersection over every proof-relevant head; an empty intersection means
    no single selector fetches both the root and the transfer.
    """
    minimum = 0
    maximum = _SELECTOR_MAX_8616
    for head in heads:
        lo = (head - _SELECTOR_MAX_8616 + 0xF) // 0x10
        hi = head // 0x10
        minimum = max(minimum, lo, 0)
        maximum = min(maximum, hi, _SELECTOR_MAX_8616)
    if minimum > maximum:
        return None
    return minimum, maximum


def _window_invariant_target_8616(
    decoded: DecodedRelativeEdge, root: int,
) -> int | None:
    """Prove the decoded linear target under the joint fetch window.

    The runtime taken destination under selector ``s`` is
    ``(s << 4) + ((head - (s << 4) + size + disp) mod 2^16)``; it equals the
    decoded loader-linear target ``next_head + disp`` for every ``s`` in the
    joint root/jump window exactly when the target lies inside that window's
    common reachable band. This is the closed-form content of the verified
    parent-jump entry theorem, evaluated without trusting any receipt.
    """
    window = _joint_fetch_window_8616((root, decoded.head))
    if window is None:
        return None
    target = decoded.next_head + decoded.displacement
    minimum, maximum = window
    if (maximum << 4) <= target <= (minimum << 4) + _SELECTOR_MAX_8616:
        return target
    return None


class _Ledger8616:
    """Mutable accumulation surface closed into the frozen proof product."""

    def __init__(self) -> None:
        self.entries: list[EntryJumpDomainLedgerEntry8616] = []

    def record(
        self, stage: EntryJumpDomainStage8616, fact: str, detail: str,
    ) -> None:
        """Append one typed fact to the five-stage ledger."""
        self.entries.append(
            EntryJumpDomainLedgerEntry8616(stage=stage, fact=fact, detail=detail)
        )


class _Budget8616:
    """Deterministic decreasing term counter."""

    def __init__(self, budget: EntryJumpDomainBudget8616) -> None:
        self.remaining = budget.max_terms
        self.consumed = 0

    def consume(self, terms: int) -> bool:
        """Consume terms; False means the deterministic budget ran out."""
        if self.remaining < terms:
            return False
        self.remaining -= terms
        self.consumed += terms
        return True


def _patched_blocks_8616(
    blocks: tuple[IRBlock, ...], admitted: Mapping[int, int],
) -> tuple[IRBlock, ...]:
    """Project admitted jump edges into block successor sets for re-solving."""
    if not admitted:
        return blocks
    return tuple(
        IRBlock(
            addr=block.addr,
            instrs=block.instrs,
            refusals=block.refusals,
            successor_addrs=tuple(sorted(
                {*block.successor_addrs, admitted[block.addr]}
            )) if block.addr in admitted else block.successor_addrs,
        )
        for block in blocks
    )


@dataclass(frozen=True, slots=True)
class _ReachableRegion8616:
    """Typed reachability over the census: members plus exterior edges.

    ``exterior`` retains each ``(block_addr, successor)`` edge whose
    successor is not enumerated in the census. An exterior edge means the
    claimed reachable region is not closed, so it is surfaced for a typed
    PATH_INCOMPLETE refusal instead of being silently ignored.
    """

    reachable: frozenset[int]
    exterior: tuple[tuple[int, int], ...]


def _reachable_blocks_8616(
    blocks_by_addr: Mapping[int, IRBlock], entry: int,
) -> _ReachableRegion8616 | None:
    """Walk typed in-function successor edges from the entry block.

    ``None`` is returned only when the entry coordinate itself is absent
    from the census, which cannot happen after the entry gate. Successors
    outside the census are never followed, but they are retained as
    exterior edges — the theorem quantifies over a closed region, so an
    edge leaving the enumeration is proof debt, not a legitimate exit.
    """
    reachable: set[int] = set()
    exterior: set[tuple[int, int]] = set()
    work = [entry]
    while work:
        addr = work.pop()
        if addr in reachable:
            continue
        block = blocks_by_addr.get(addr)
        if block is None:
            return None
        reachable.add(addr)
        for succ in block.successor_addrs:
            if succ in blocks_by_addr:
                if succ not in reachable:
                    work.append(succ)
            else:
                exterior.add((addr, succ))
    return _ReachableRegion8616(
        frozenset(reachable), tuple(sorted(exterior)),
    )


def _block_refusal_8616(
    block: IRBlock, addr: int,
) -> tuple[EntryJumpDomainRefusal8616, str] | None:
    """Refuse when a reachable block carries any non-pending refusal."""
    for refusal in block.refusals:
        if (
            refusal.kind
            != TerminalJumpRefusalReason8616.SELECTOR_WINDOW_UNPROVED.value
            or refusal.block_addr != addr
        ):
            return (
                EntryJumpDomainRefusal8616.PATH_REFUSAL_PRESENT,
                f"reachable block 0x{addr:x} carries refusal {refusal.kind}",
            )
    return None


def _effect_gate_8616(
    instr: IRInstr,
) -> tuple[EntryJumpDomainRefusal8616, str] | None:
    """Consume the authoritative scalar-effect owner's UNKNOWN closure."""
    if (
        scalar_instruction_effect_8616(instr).kind
        is ScalarInstructionEffectKind8616.UNKNOWN
    ):
        return (
            EntryJumpDomainRefusal8616.UNKNOWN_EFFECT_ON_PATH,
            f"reachable instruction {instr.addr:#x} has unclassified "
            "register effects",
        )
    return None


def _instruction_gate_8616(
    block: IRBlock,
    addr: int,
    is_terminal: bool,
    instr: IRInstr,
    transfer_blocks: frozenset[int],
) -> tuple[EntryJumpDomainRefusal8616, str] | None:
    """Gate one reachable instruction for the entry-domain theorem.

    A call lacks a bound CS-preservation record and an explicit typed
    ``cs`` destination is interference, whatever the position. Two
    terminal positions are exempt from the effect check only: a recognized
    sink whose effects leave the region, and a domain-proof transfer site
    whose operand stays symbolic until the TRANSFER stage discharges it.
    A successor-less non-sink terminal is an opaque end of the region.
    """
    if instr.op == "CALL":
        return (
            EntryJumpDomainRefusal8616.CALL_ON_PATH,
            f"reachable call at {instr.addr:#x} lacks a bound "
            "preservation proof",
        )
    if _writes_cs_8616(instr):
        return (
            EntryJumpDomainRefusal8616.CS_WRITE_INTERFERENCE,
            f"reachable instruction {instr.addr:#x} writes cs",
        )
    if not is_terminal:
        return _effect_gate_8616(instr)
    if addr in transfer_blocks:
        return None
    if not block.successor_addrs:
        if instr.op in _SINK_TERMINAL_OPS_8616:
            return None
        return (
            EntryJumpDomainRefusal8616.OPAQUE_TERMINAL_ON_PATH,
            f"reachable block 0x{addr:x} ends in opaque terminal "
            f"{instr.op}",
        )
    return _effect_gate_8616(instr)


class _ProofRun8616:
    """Mutable proof session accumulating ledger, refusals, and admissions.

    The run owns the deterministic term budget, the five-stage ledger, and
    the fixpoint state; each stage method either records typed evidence or
    extends the refusal set, never mutating the consumed artifact.
    """

    def __init__(
        self,
        artifact: IRFunctionArtifact,
        pending: Mapping[int, PendingTerminalJump8616],
        raw_count: int,
        normalized: int,
        project: object | None,
        binding: EntryJumpDomainSourceBinding8616,
        budget: EntryJumpDomainBudget8616,
        call_preservations: tuple[EntryDomainCallPreservation8616, ...] = (),
        invocation_resolver: Callable[
            [int], Real16InvocationDomain8616 | None
        ] | None = None,
    ) -> None:
        self.artifact = artifact
        self.pending = dict(pending)
        self.call_preservations = call_preservations
        self.invocation_resolver = invocation_resolver
        self.project = project
        self.binding = binding
        self.raw_count = raw_count
        self.normalized = normalized
        self.budget = budget
        self.terms = _Budget8616(budget)
        self.ledger = _Ledger8616()
        self.refusals: list[IRRefusal] = []
        self.admitted: dict[int, int] = {}
        self.block_targets: dict[int, int] = {}
        self.admitted_invocations: dict[int, Real16InvocationDomain8616] = {}
        self.call_dependencies: dict[int, _ScopedCallDependency8616] = {}
        self.invocation_scope: Real16InvocationDomain8616 | None = None
        self.iterations = 0
        self.exhausted = False
        self.bound_callsites: set[int] = set()

    def refuse(
        self,
        candidate: PendingTerminalJump8616 | None,
        reason: EntryJumpDomainRefusal8616,
        detail: str,
        block_addr: int | None,
    ) -> None:
        """Record one typed refusal and its ledger fact."""
        self.refusals.append(IRRefusal(reason.value, detail, block_addr))
        if candidate is not None:
            self.ledger.record(
                EntryJumpDomainStage8616.TRANSFER,
                "refused",
                f"{reason.value}: {detail}",
            )

    def refuse_all(
        self,
        candidates: Mapping[int, PendingTerminalJump8616],
        reason: EntryJumpDomainRefusal8616,
        detail: str,
    ) -> None:
        """Refuse every still-open candidate with the same typed reason."""
        for candidate in candidates.values():
            self.refuse(candidate, reason, detail, candidate.block_addr)

    def stage_entry(self) -> bool:
        """Stage ENTRY: the root must be a decoded, aligned entry block."""
        blocks_by_addr = {block.addr: block for block in self.artifact.blocks}
        entry_block = blocks_by_addr.get(self.artifact.function_addr)
        if (
            entry_block is None
            or not entry_block.instrs
            or entry_block.instrs[0].addr != self.artifact.function_addr
        ):
            self.ledger.record(
                EntryJumpDomainStage8616.ENTRY,
                "refused",
                "function root is not a decoded block head",
            )
            self.refuse_all(
                self.pending,
                EntryJumpDomainRefusal8616.ENTRY_BLOCK_MISSING,
                "function entry block is missing, empty, or misaligned",
            )
            return False
        self.ledger.record(
            EntryJumpDomainStage8616.ENTRY,
            "root_fetch",
            f"entry block decodes at native root 0x{self.artifact.function_addr:x}",
        )
        return True

    def stage_census(self) -> bool:
        """Stage CENSUS: every block needs a complete typed instruction stream."""
        census_failure = False
        for block in self.artifact.blocks:
            if not self.terms.consume(1 + len(block.instrs)):
                census_failure = True
                break
            if not block.instrs:
                census_failure = True
                self.ledger.record(
                    EntryJumpDomainStage8616.CENSUS,
                    "refused",
                    f"block 0x{block.addr:x} has no typed instructions",
                )
                continue
            for index, instr in enumerate(block.instrs):
                if not isinstance(instr.addr, int):
                    census_failure = True
                    self.ledger.record(
                        EntryJumpDomainStage8616.CENSUS,
                        "refused",
                        f"block 0x{block.addr:x} instruction {index} lacks an address",
                    )
        if census_failure:
            self.refuse_all(
                self.pending,
                EntryJumpDomainRefusal8616.BLOCK_CENSUS_INCOMPLETE,
                "reachable instruction census is incomplete or budget-exceeded",
            )
            return False
        self.ledger.record(
            EntryJumpDomainStage8616.CENSUS,
            "complete",
            f"{len(self.artifact.blocks)} blocks fully enumerated",
        )
        return True

    def path_interference(
        self,
        blocks_by_addr: Mapping[int, IRBlock],
        region: _ReachableRegion8616 | None,
        transfer_blocks: frozenset[int],
    ) -> tuple[EntryJumpDomainRefusal8616, str] | None:
        """Stage PATH: classify reachable control and scan for interference.

        The reachable region must be closed: an exterior successor edge is
        typed PATH_INCOMPLETE. Every reachable instruction must preserve
        ``cs`` under the authoritative scalar-effect owner — a call lacks a
        bound preservation record, an explicit typed ``cs`` destination is
        interference, and an effect the owner cannot close is unclassified
        proof debt, never assumed benign.
        """
        if region is None:
            return (
                EntryJumpDomainRefusal8616.PATH_INCOMPLETE,
                "the entry block itself is missing from the census",
            )
        if region.exterior:
            source, target = region.exterior[0]
            return (
                EntryJumpDomainRefusal8616.PATH_INCOMPLETE,
                f"reachable block 0x{source:x} lists successor "
                f"0x{target:x} outside the census",
            )
        for addr in sorted(region.reachable):
            block = blocks_by_addr[addr]
            if not self.terms.consume(1):
                return (
                    EntryJumpDomainRefusal8616.BUDGET_EXCEEDED,
                    "block scan budget exhausted",
                )
            failure = _block_refusal_8616(block, addr)
            if failure is not None:
                return failure
            failure = self._instruction_effects_8616(
                block, addr, transfer_blocks,
            )
            if failure is not None:
                return failure
        return None

    def _instruction_effects_8616(
        self,
        block: IRBlock,
        addr: int,
        transfer_blocks: frozenset[int],
    ) -> tuple[EntryJumpDomainRefusal8616, str] | None:
        """Scan one reachable block's instructions for interference."""
        for index, instr in enumerate(block.instrs):
            if not self.terms.consume(1):
                return (
                    EntryJumpDomainRefusal8616.BUDGET_EXCEEDED,
                    "instruction scan budget exhausted",
                )
            failure = _instruction_gate_8616(
                block, addr, index == len(block.instrs) - 1, instr,
                transfer_blocks,
            )
            if failure is not None:
                return failure
        return None

    def entry_cs_state(
        self, patched_blocks: tuple[IRBlock, ...],
    ) -> tuple[SegmentStateSolution8616 | None, SegmentRegisterState | None]:
        """Stage SEGMENT: rerun the solver on this exact artifact.

        Each run is charged the census-shaped term bound first; a run the
        remaining budget cannot afford is not performed and flags the run
        as exhausted instead of producing unbudgeted evidence.
        """
        if not self.terms.consume(_segment_solve_terms_8616(patched_blocks)):
            self.exhausted = True
            return None, None
        patched_artifact = IRFunctionArtifact(
            function_addr=self.artifact.function_addr,
            blocks=patched_blocks,
        )
        solution = solve_segment_state_8616(patched_artifact, None, ())
        entry_cs = solution.entry_states.get(
            self.artifact.function_addr, {},
        ).get(_CS_REGISTER_8616)
        return solution, entry_cs

    def cs_invariant(
        self,
        solution: SegmentStateSolution8616,
        blocks_by_addr: Mapping[int, IRBlock],
        reachable: frozenset[int],
        entry_cs: SegmentRegisterState,
    ) -> bool:
        """Require the entry CS identity at every reachable instruction."""
        for addr in sorted(reachable):
            scan_block = blocks_by_addr[addr]
            for index, instr in enumerate(scan_block.instrs):
                state = solution.instruction_entry_states.get(
                    _instruction_state_key_8616(addr, index, instr), {},
                ).get(_CS_REGISTER_8616)
                if state is None or state != entry_cs:
                    return False
        return True

    def _consuming_scope_8616(
        self, callsite_addr: int, required: Real16InvocationDomain8616,
    ) -> Real16InvocationDomain8616 | None:
        """Resolve the authenticated consuming entry for one conditional record.

        A conditional record names the invocation-local premise its
        Semantics binding consumed; this run may only read it under a
        scope that reauthenticates against that exact entry. The resolver
        is asked for the premise bound to the same callsite inside this
        identical artifact, and ``same_real16_entry_scope_8616`` — not
        selector or address coincidence — decides whether the resolved
        and required entries transport through a coterminous proven edge.
        A missing resolver, a missing premise, or a foreign entry returns
        ``None`` so the record stays conditional and the call keeps its
        default refusal.
        """
        resolver = self.invocation_resolver
        if resolver is None or self.project is None:
            return None
        scope = resolver(callsite_addr)
        from .real16_invocation_domain import (
            Real16InvocationDomain8616,
            same_real16_entry_scope_8616,
        )

        if type(scope) is not Real16InvocationDomain8616:
            return None
        if not same_real16_entry_scope_8616(scope, required):
            return None
        if self.invocation_scope is None:
            self.invocation_scope = scope
        elif not same_real16_entry_scope_8616(scope, self.invocation_scope):
            return None
        return self.invocation_scope

    def _call_substitutes_8616(
        self, original_block: IRBlock, instr: IRInstr,
    ) -> tuple[IRInstr, ...]:
        """Model one bound CS-preserving CALL as its proved segment writes.

        Only a complete per-callsite preservation proof bound to the
        identical in-flight block and instruction objects may replace the
        call; every other call keeps its instruction so the default
        CALL_ON_PATH refusal still applies. Conditional records — proofs
        whose Semantics binding consumed an invocation-local premise —
        are read only under an authenticated consuming entry, and every
        such consumption is retained on the run so the admission
        revalidates it at application time. The surrogate writes model
        exactly the proved boundary effect — one unknown-provenance write
        for each segment register the callee closure does not preserve —
        never widening what the callee evidence admitted. When the callee
        preserves every segment register the single fallback write to the
        unobserved ``ax`` keeps the typed instruction stream nonempty and
        mirrors the call boundary's general-register drop.
        """
        candidates = tuple(
            proof
            for proof in self.call_preservations
            if proof.block is original_block and proof.instruction is instr
        )
        if len(candidates) != 1 or not self.terms.consume(1):
            return (instr,)
        proof = candidates[0]
        required = proof.required_scope
        scope: Real16InvocationDomain8616 | None = None
        if required is not None:
            scope = self._consuming_scope_8616(
                instr.addr if type(instr.addr) is int else -1, required,
            )
            if scope is None:
                return (instr,)
        if not proof.complete_for(scope):
            return (instr,)
        preserved = frozenset(proof.preserved_registers_for(scope))
        if _CS_REGISTER_8616 not in preserved:
            return (instr,)
        if scope is not None and type(instr.addr) is int:
            self.call_dependencies.setdefault(
                instr.addr,
                _ScopedCallDependency8616(
                    callsite_addr=instr.addr, record=proof, scope=scope,
                ),
            )
        if instr.addr is not None and instr.addr not in self.bound_callsites:
            self.bound_callsites.add(instr.addr)
            target_addr = proof.target_addr
            self.ledger.record(
                EntryJumpDomainStage8616.PATH,
                "call_bound",
                f"call at {instr.addr:#x} carries bound cs-preserving "
                "callee evidence"
                + ("" if type(target_addr) is not int else f" targeting {target_addr:#x}"),
            )
        surrogates = tuple(
            IRInstr(
                "MOV",
                IRValue(MemSpace.REG, name=register, size=2),
                (IRValue(MemSpace.UNKNOWN, size=2),),
                size=2,
                addr=instr.addr,
            )
            for register in SEGMENT_REGISTERS
            if register not in preserved
        )
        if not surrogates:
            surrogates = (
                IRInstr(
                    "MOV",
                    IRValue(MemSpace.REG, name="ax", size=2),
                    (IRValue(MemSpace.UNKNOWN, size=2),),
                    size=2,
                    addr=instr.addr,
                ),
            )
        return surrogates

    def _call_preservation_view_8616(
        self, blocks: tuple[IRBlock, ...],
    ) -> tuple[IRBlock, ...]:
        """Replace each bound CS-preserving CALL in the solver/gate view.

        The patched block stream keeps identical instruction objects for
        every non-CALL instruction, so a bound proof's recorded block and
        instruction identities still point at this view's sources.
        """
        if not self.call_preservations:
            return blocks
        view: list[IRBlock] = []
        for original, block in zip(self.artifact.blocks, blocks, strict=True):
            if not any(instr.op == "CALL" for instr in block.instrs):
                view.append(block)
                continue
            instrs: list[IRInstr] = []
            for instr in block.instrs:
                if instr.op != "CALL":
                    instrs.append(instr)
                    continue
                instrs.extend(self._call_substitutes_8616(original, instr))
            view.append(
                IRBlock(
                    addr=block.addr,
                    instrs=tuple(instrs),
                    refusals=block.refusals,
                    successor_addrs=block.successor_addrs,
                )
            )
        return tuple(view)

    def _native_relift_8616(
        self, block: IRBlock, decoded: DecodedRelativeEdge,
    ) -> _NativeRelift8616:
        """Re-lift the bounded transfer-block span under the source authority.

        The re-lift is bounded to ``block.addr .. decoded.next_head`` — the
        imported block extent the decoded terminal must end — and the lifted
        surface must expose coherent address, size, byte, and VEX surfaces
        before any byte comparison runs. Failure at this boundary is typed
        ``NATIVE_SOURCE_UNPROVED`` or ``TRANSFER_FACT_MISMATCH``, never a
        guessed surface.
        """
        project = self.project
        if not _native_source_available_8616(project):
            return _NativeRelift8616(
                None,
                (
                    EntryJumpDomainRefusal8616.NATIVE_SOURCE_UNPROVED,
                    "no x86-16 loader-linear native source authority supplied",
                ),
            )
        size = decoded.next_head - block.addr
        if not 0 < size <= _MAX_NATIVE_RELIFT_BYTES_8616:
            return _NativeRelift8616(
                None,
                (
                    EntryJumpDomainRefusal8616.TRANSFER_FACT_MISMATCH,
                    f"decoded extent 0x{size:x} does not bound the transfer "
                    f"block at 0x{block.addr:x}",
                ),
            )
        try:
            lifted = cast(
                _NativeReliftProject8616, project,
            ).factory.block(
                block.addr, size=size, opt_level=0, collect_data_refs=True,
            )
        except (SimEngineError, SimTranslationError, PyVEXError) as ex:
            # Only named native decode failures mean missing evidence.
            # Programming defects must escape this boundary with their cause.
            return _NativeRelift8616(
                None,
                (
                    EntryJumpDomainRefusal8616.NATIVE_SOURCE_UNPROVED,
                    f"native re-lift of 0x{block.addr:x} failed: {ex}",
                ),
            )
        try:
            lifted_addr = _external_int_8616(
                cast(_NativeReliftBlock8616, lifted).addr,
            )
            lifted_size = _external_int_8616(
                cast(_NativeReliftBlock8616, lifted).size,
            )
            native_len = len(bytes(
                cast(Any, cast(_NativeReliftBlock8616, lifted).bytes),
            ))
        except (AttributeError, TypeError, ValueError):
            return _NativeRelift8616(
                None,
                (
                    EntryJumpDomainRefusal8616.NATIVE_SOURCE_UNPROVED,
                    "re-lifted block lacks byte or VEX surfaces",
                ),
            )
        if lifted_addr != block.addr or lifted_size != native_len:
            return _NativeRelift8616(
                None,
                (
                    EntryJumpDomainRefusal8616.NATIVE_SOURCE_UNPROVED,
                    "re-lifted block extent is incoherent with the transfer "
                    "block address",
                ),
            )
        return _NativeRelift8616(lifted, None)

    def _native_transfer_binding_8616(
        self,
        block: IRBlock,
        origin: IRInstructionOrigin8616,
        decoded: DecodedRelativeEdge,
    ) -> tuple[EntryJumpDomainRefusal8616, str] | None:
        """Bind the decoded carrier to the re-lifted native block tail.

        The decoded edge is only a claim: this stage re-lifts the exact
        native block span ``block.addr .. decoded.next_head`` through the
        supplied project source authority and requires the re-lifted tail
        bytes to equal the supplied encoding exactly, the jumpkind to be
        ``Ijk_Boring``, the statement count to equal the imported terminal
        position, and the re-lifted ``next`` expression to read the same
        recorded temporary. No caller-provided tag or copied provenance
        record can substitute for any of these facts; a missing source
        authority is ``NATIVE_SOURCE_UNPROVED``, never assumed.
        """
        if not self.terms.consume(1):
            return (
                EntryJumpDomainRefusal8616.BUDGET_EXCEEDED,
                "native transfer binding budget exhausted",
            )
        relifted = self._native_relift_8616(block, decoded)
        if relifted.failure is not None:
            return relifted.failure
        lifted = cast(_NativeReliftBlock8616, relifted.lifted)
        native_bytes = bytes(cast(Any, lifted.bytes))
        offset = decoded.head - block.addr
        if (
            offset < 0
            or offset + decoded.encoded_size != len(native_bytes)
            or native_bytes[offset:] != decoded.encoding
        ):
            return (
                EntryJumpDomainRefusal8616.TRANSFER_FACT_MISMATCH,
                f"decoded bytes {decoded.encoding.hex()} do not equal the "
                f"native terminal encoding at 0x{decoded.head:x}",
            )
        native_vex = lifted.vex
        if (
            not isinstance(native_vex, pyvex.IRSB)
            or native_vex.jumpkind != "Ijk_Boring"
        ):
            return (
                EntryJumpDomainRefusal8616.TRANSFER_FACT_MISMATCH,
                "re-lifted block is not a boring near-transfer terminal",
            )
        if len(native_vex.statements) != origin.statement_index:
            return (
                EntryJumpDomainRefusal8616.TRANSFER_FACT_MISMATCH,
                f"re-lifted statement count {len(native_vex.statements)} "
                f"does not match the imported terminal position "
                f"{origin.statement_index}",
            )
        native_next = native_vex.next
        if (
            not isinstance(native_next, pyvex.expr.RdTmp)
            or native_next.tmp != origin.block_next_tmp
        ):
            return (
                EntryJumpDomainRefusal8616.TRANSFER_FACT_MISMATCH,
                "re-lifted block-next expression does not read the "
                "recorded temporary",
            )
        return None

    def evaluate(
        self,
        candidate: PendingTerminalJump8616,
        block: IRBlock,
        solution: SegmentStateSolution8616,
        entry_cs: SegmentRegisterState,
        reachable: frozenset[int],
        blocks_by_addr: Mapping[int, IRBlock],
    ) -> bool:
        """Settle one reachable candidate: admit, refuse, or defer.

        Returns True when the candidate is settled this iteration; an
        unreachable transfer block defers for a later fixpoint round.
        """
        decoded = candidate.decoded
        block_addr = candidate.block_addr
        if block_addr not in reachable:
            return False
        terminal = block.instrs[-1]
        origin = _block_next_origin_8616(terminal, block_addr)
        if (
            terminal.op != "JMP"
            or terminal.addr != decoded.head
            or not _word_jump_form_8616(decoded)
            or origin is None
            or not _transfer_operand_bound_8616(terminal, origin, decoded)
        ):
            self.refuse(
                candidate,
                EntryJumpDomainRefusal8616.TRANSFER_FACT_MISMATCH,
                "decoded transfer does not bind to the imported "
                "block-next terminal JMP",
                block_addr,
            )
            return True
        native_failure = self._native_transfer_binding_8616(
            block, origin, decoded,
        )
        if native_failure is not None:
            reason, detail = native_failure
            self.refuse(candidate, reason, detail, block_addr)
            return True
        self.ledger.record(
            EntryJumpDomainStage8616.TRANSFER,
            "native_bound",
            f"jmp 0x{decoded.head:x} encoding equals the re-lifted "
            "native terminal bytes and block-next expression",
        )
        if not self.cs_invariant(solution, blocks_by_addr, reachable, entry_cs):
            self.refuse(
                candidate,
                EntryJumpDomainRefusal8616.CS_IDENTITY_MISMATCH,
                "cs identity changes on a path inside the entry domain",
                block_addr,
            )
            return True
        self.ledger.record(
            EntryJumpDomainStage8616.SEGMENT,
            "cs_invariant",
            f"cs identity at 0x{decoded.head:x} equals entry live-in",
        )
        target = _window_invariant_target_8616(
            decoded, self.artifact.function_addr,
        )
        if target is None:
            premise_target = self._premise_window_target_8616(
                block_addr, decoded,
            )
            if premise_target is None:
                self.refuse(
                    candidate,
                    EntryJumpDomainRefusal8616.JOINT_WINDOW_UNPROVED,
                    "decoded target is not invariant across the joint "
                    "root/transfer selector window",
                    block_addr,
                )
                return True
            target, premise = premise_target
            self.admitted_invocations[decoded.head] = premise
            self.admitted[decoded.head] = target
            self.block_targets[block_addr] = target
            self.ledger.record(
                EntryJumpDomainStage8616.TRANSFER,
                "admitted",
                f"jmp 0x{decoded.head:x} targets 0x{target:x} under a "
                "source-bound invocation premise",
            )
            return True
        self.admitted[decoded.head] = target
        self.block_targets[block_addr] = target
        self.ledger.record(
            EntryJumpDomainStage8616.TRANSFER,
            "admitted",
            f"jmp 0x{decoded.head:x} targets 0x{target:x} under the "
            "entry fetch domain",
        )
        return True

    def _premise_window_target_8616(
        self, block_addr: int, decoded: DecodedRelativeEdge,
    ) -> tuple[int, Real16InvocationDomain8616] | None:
        """Discharge one transfer through a bound invocation premise.

        Consulted only when the joint fetch-window bound cannot keep the
        decoded target invariant. The resolver must return a complete
        source-bound premise for this exact artifact surface; the premise
        is consumed through the typed discharge check bound to this exact
        block and jump head, and the retained premise is kept on the
        admission for application-time replay.
        """
        resolver = self.invocation_resolver
        if resolver is None or self.project is None:
            return None
        premise = resolver(decoded.head)
        if premise is None:
            return None
        block = next(
            (
                candidate
                for candidate in self.artifact.blocks
                if candidate.addr == block_addr
            ),
            None,
        )
        if block is None:
            return None
        from .real16_invocation_domain import (
            real16_invocation_discharges_8616,
            same_real16_entry_scope_8616,
        )

        if self.invocation_scope is not None and not same_real16_entry_scope_8616(
            premise, self.invocation_scope,
        ):
            return None
        target = decoded.next_head + decoded.displacement
        if not real16_invocation_discharges_8616(
            premise,
            project=self.project,
            block=block,
            callsite_addr=decoded.head,
            target_addr=target,
        ):
            return None
        if self.invocation_scope is None:
            self.invocation_scope = premise
        return target, premise

    def fixpoint(self) -> None:
        """Iterate stages 3-5 until no candidate remains or progress stops."""
        open_candidates = dict(self.pending)
        while open_candidates and self.iterations < self.budget.max_iterations:
            self.iterations += 1
            current_blocks = _patched_blocks_8616(
                self.artifact.blocks, self.block_targets,
            )
            current_blocks = self._call_preservation_view_8616(current_blocks)
            current_by_addr = {block.addr: block for block in current_blocks}
            region = _reachable_blocks_8616(
                current_by_addr, self.artifact.function_addr,
            )
            transfer_blocks = frozenset(open_candidates) | frozenset(
                self.block_targets,
            )
            failure = self.path_interference(
                current_by_addr, region, transfer_blocks,
            )
            if failure is not None:
                reason, detail = failure
                self.ledger.record(
                    EntryJumpDomainStage8616.PATH, "refused", detail,
                )
                self.refuse_all(open_candidates, reason, detail)
                open_candidates.clear()
                return
            reachable = (
                region.reachable if region is not None else frozenset()
            )
            if self.iterations == 1:
                self.ledger.record(
                    EntryJumpDomainStage8616.PATH,
                    "classified",
                    f"{len(reachable)} reachable blocks carry closed control",
                )
            solution, entry_cs = self.entry_cs_state(current_blocks)
            if solution is None:
                self.refuse_all(
                    open_candidates,
                    EntryJumpDomainRefusal8616.BUDGET_EXCEEDED,
                    "deterministic segment-solve budget exhausted",
                )
                open_candidates.clear()
                return
            if (
                entry_cs is None
                or entry_cs.origin is not SegmentOrigin.PROVEN
            ):
                self.refuse_all(
                    open_candidates,
                    EntryJumpDomainRefusal8616.ENTRY_FETCH_UNPROVED,
                    "entry cs identity is not a proven fetch domain",
                )
                open_candidates.clear()
                return
            progressed = False
            for block_addr in sorted(open_candidates):
                candidate = open_candidates[block_addr]
                if not self.terms.consume(1):
                    self.exhausted = True
                    break
                if self.evaluate(
                    candidate,
                    current_by_addr[block_addr],
                    solution,
                    entry_cs,
                    reachable,
                    current_by_addr,
                ):
                    del open_candidates[block_addr]
                    progressed = True
            if self.exhausted or not progressed:
                break
        leftover_reason = (
            EntryJumpDomainRefusal8616.BUDGET_EXCEEDED
            if self.exhausted or self.iterations >= self.budget.max_iterations
            else EntryJumpDomainRefusal8616.PATH_INCOMPLETE
        )
        detail = (
            "deterministic fixpoint budget exhausted before discharge"
            if leftover_reason is EntryJumpDomainRefusal8616.BUDGET_EXCEEDED
            else "transfer block never became reachable from the entry domain"
        )
        self.refuse_all(open_candidates, leftover_reason, detail)
        open_candidates.clear()

    def reverify(self) -> None:
        """Re-verify admissions under the final published edge set.

        The published graph is revalidated end to end — typed path closure
        (block refusals, exterior successor edges, scalar-effect closure)
        and the rerun segment solver's ``cs`` identity — under the same
        deterministic term budget as the fixpoint. Any break revokes every
        admission with a typed refusal; nothing is silently kept because an
        earlier CS-state join happened to pass.
        """
        if not self.admitted:
            return
        final_blocks = _patched_blocks_8616(
            self.artifact.blocks, self.block_targets,
        )
        final_blocks = self._call_preservation_view_8616(final_blocks)
        final_by_addr = {block.addr: block for block in final_blocks}
        region = _reachable_blocks_8616(
            final_by_addr, self.artifact.function_addr,
        )
        failure = self.path_interference(
            final_by_addr, region, frozenset(self.block_targets),
        )
        if failure is None:
            solution, entry_cs = self.entry_cs_state(final_blocks)
            if solution is None:
                failure = (
                    EntryJumpDomainRefusal8616.BUDGET_EXCEEDED,
                    "final-graph segment revalidation exceeded the "
                    "deterministic term budget",
                )
            elif (
                region is None
                or entry_cs is None
                or entry_cs.origin is not SegmentOrigin.PROVEN
                or not self.cs_invariant(
                    solution, final_by_addr, region.reachable, entry_cs,
                )
            ):
                failure = (
                    EntryJumpDomainRefusal8616.CS_IDENTITY_MISMATCH,
                    "published edge set no longer preserves entry "
                    "cs identity",
                )
        if failure is None:
            return
        reason, detail = failure
        self.ledger.record(
            EntryJumpDomainStage8616.PATH, "refused", detail,
        )
        for head in sorted(self.admitted):
            block_addr = next(
                addr for addr, cand in self.pending.items()
                if cand.decoded.head == head
            )
            self.refuse(self.pending[block_addr], reason, detail, block_addr)
        self.admitted.clear()
        self.block_targets.clear()

    def product(self) -> EntryJumpDomainProof8616:
        """Close the run into the frozen proof product.

        Every admission retains the full conditional-dependency set the
        final revalidated view consumed: the published edge set was
        verified under that surrogate view end to end, so each admitted
        jump is conditional on all of it — an unrelated-looking call on
        the shared reachable region still shaped the same cs invariant.
        """
        dependencies = tuple(
            self.call_dependencies[callsite]
            for callsite in sorted(self.call_dependencies)
        )
        return EntryJumpDomainProof8616(
            function_addr=self.artifact.function_addr,
            source_binding=self.binding,
            admitted=tuple(
                AdmittedTerminalJump8616(
                    block_addr=next(
                        addr for addr, cand in self.pending.items()
                        if cand.decoded.head == head
                    ),
                    head=head,
                    target=target,
                    invocation=self.admitted_invocations.get(head),
                    call_dependencies=dependencies,
                    invocation_scope=self.invocation_scope,
                )
                for head, target in sorted(self.admitted.items())
            ),
            refusals=tuple(self.refusals),
            ledger=tuple(self.ledger.entries),
            stats=EntryJumpDomainStats8616(
                raw_fact_count=self.raw_count,
                normalized_fact_count=self.normalized,
                classified_fact_count=self.normalized,
                materialized_count=len(self.admitted),
                failure_count=len(self.refusals),
            ),
            terms_consumed=self.terms.consumed,
            iterations=self.iterations,
            call_preservations=self.call_preservations,
            invocation_scope=self.invocation_scope,
        )


def prove_entry_jump_domains_8616(
    artifact: IRFunctionArtifact,
    evidence_by_block: Mapping[int, TerminalJumpEvidence8616],
    *,
    project: object | None = None,
    budget: EntryJumpDomainBudget8616 | None = None,
    call_preservations: tuple[EntryDomainCallPreservation8616, ...] = (),
    invocation_resolver: Callable[
        [int], Real16InvocationDomain8616 | None
    ] | None = None,
) -> EntryJumpDomainProof8616:
    """Prove pending terminal jumps against the function-entry fetch domain.

    ``project`` is the required native source authority: each decoded
    carrier is bound to the real mapped bytes and re-lifted ``next``
    expression of its transfer block before it may discharge. Callers
    without that authority get an honest ``NATIVE_SOURCE_UNPROVED`` refusal
    for every candidate — a standalone artifact alone cannot prove that a
    supplied encoding is the native one.

    Each candidate must survive five stages: the native root fetch head is a
    decoded entry block; the block/instruction census is complete; typed
    control edges reach the transfer with no unproved call, CS write, or
    opaque terminal on any path; the rerun segment solver proves CS identity
    unchanged from the entry state at every reachable instruction; and the
    decoded transfer facts bind to the imported JMP — its recorded
    block-``next`` origin, its symbolic operand identity, and the re-lifted
    native bytes — with a joint-window-invariant target. Candidates failing
    any stage keep their default refusal.

    ``call_preservations`` carries exact per-callsite CS-preservation
    evidence bound to this identical artifact's block and instruction
    objects. Only a still-complete proof replaces its call with the proved
    segment-boundary writes for the gate and solver views; every other call
    keeps the default CALL_ON_PATH refusal. The retained chain — in-flight
    caller object identity, decoded native callsite entry, operand target
    binding, and the callee's registered artifact coverage plus segment
    effect closure — is revalidated at every consumption and again under
    final re-verification, each consult charged one deterministic term.

    ``invocation_resolver`` maps one pending jump head to a complete
    source-bound caller-domain premise (``Real16InvocationDomain8616``)
    or ``None``; it is consulted only when the joint fetch-window bound
    cannot keep the decoded target invariant. A premise that discharges is
    retained on the admission record and replayed end to end by
    ``apply_entry_jump_domain_8616``.
    """
    pending = collect_pending_terminal_jumps_8616(evidence_by_block)
    binding = EntryJumpDomainSourceBinding8616(
        function_addr=artifact.function_addr,
        block_count=len(artifact.blocks),
        digest=_source_digest_8616(artifact.function_addr, artifact.blocks),
        pending=tuple(pending[addr] for addr in sorted(pending)),
    )
    run = _ProofRun8616(
        artifact,
        pending,
        raw_count=len(evidence_by_block),
        normalized=len(pending),
        project=project,
        binding=binding,
        budget=budget or EntryJumpDomainBudget8616(),
        call_preservations=call_preservations,
        invocation_resolver=invocation_resolver,
    )
    if pending and not _native_source_available_8616(project):
        run.refuse_all(
            pending,
            EntryJumpDomainRefusal8616.NATIVE_SOURCE_UNPROVED,
            "no loader-linear x86-16 native source authority was supplied; "
            "a decoded carrier alone cannot prove native bytes",
        )
    elif pending and run.stage_entry() and run.stage_census():
        run.fixpoint()
        run.reverify()
    run.ledger.record(
        EntryJumpDomainStage8616.TRANSFER,
        "closed",
        f"{len(run.admitted)} jumps discharged, "
        f"{len(run.refusals)} refusals retained",
    )
    return run.product()


def _application_admission_failure_8616(
    proof: EntryJumpDomainProof8616,
    root: int,
    artifact_blocks: tuple[IRBlock, ...],
    invocation_scope: Real16InvocationDomain8616 | None = None,
) -> str | None:
    """Check every published edge against its unique decoded pending transfer.

    Source membership alone cannot bind a target: a changed admission may
    retain the original block and instruction head. Reuse the same entry
    window theorem that issued the target, and reject duplicate block
    admissions before the patch loop could silently overwrite an edge. An
    admission discharged by a retained invocation premise is instead
    revalidated through the premise's own end-to-end replay, bound to the
    consuming artifact's identical block object and the recorded jump head
    and target.
    """
    pending: dict[tuple[int, int], PendingTerminalJump8616] = {}
    for recorded in proof.source_binding.pending:
        key = (recorded.block_addr, recorded.decoded.head)
        if key in pending:
            return "recorded pending candidate is ambiguous"
        pending[key] = recorded
    blocks_by_addr = {block.addr: block for block in artifact_blocks}
    seen_blocks: set[int] = set()
    for jump in proof.admitted:
        candidate = pending.get((jump.block_addr, jump.head))
        if candidate is None:
            return (
                f"admitted jump at 0x{jump.head:x} is not backed by a "
                "recorded pending candidate"
            )
        if jump.block_addr in seen_blocks:
            return "multiple admitted jumps claim the same terminal block"
        seen_blocks.add(jump.block_addr)
        dependency_failure = _call_dependency_failure_8616(
            jump, proof, artifact_blocks, invocation_scope,
        )
        if dependency_failure is not None:
            return dependency_failure
        target = _window_invariant_target_8616(candidate.decoded, root)
        if (
            not _word_jump_form_8616(candidate.decoded)
            or type(jump.target) is not int
        ):
            return "admitted target does not match its decoded entry-window transfer"
        if target != jump.target and not _premise_redischarges_8616(
            jump, blocks_by_addr.get(jump.block_addr),
        ):
            return (
                "admitted target does not match its decoded "
                "entry-window transfer"
            )
    if (
        not proof.stats.closed
        or len(proof.admitted) != proof.stats.materialized_count
        or len(proof.refusals) != proof.stats.failure_count
    ):
        return "proof accounting does not close over its admissions and refusals"
    return None


def _source_call_dependencies_8616(
    proof: EntryJumpDomainProof8616,
    blocks: tuple[IRBlock, ...],
    scope: Real16InvocationDomain8616 | None,
) -> tuple[EntryDomainCallPreservation8616, ...] | None:
    """Reconstruct the complete CALL census from the exact applying source.

    All source calls must close before application. This intentionally refuses
    an unproved off-path call too: retained dependencies cannot authenticate a
    reduced caller surface or omit a source row by deleting its record.
    """
    expected: list[EntryDomainCallPreservation8616] = []
    consumed: set[int] = set()
    for block in blocks:
        for instruction in block.instrs:
            if instruction.op != "CALL":
                continue
            records = tuple(
                record for record in proof.call_preservations
                if record.block is block and record.instruction is instruction
            )
            if len(records) != 1:
                return None
            record = records[0]
            if record.callsite_addr != instruction.addr or id(record) in consumed:
                return None
            consumed.add(id(record))
            if not record.complete_for(scope) or "cs" not in record.preserved_registers_for(scope):
                return None
            if record.required_scope is not None:
                expected.append(record)
    if len(consumed) != len(proof.call_preservations):
        return None
    return tuple(sorted(expected, key=lambda record: record.callsite_addr))


def _call_dependency_failure_8616(
    jump: AdmittedTerminalJump8616,
    proof: EntryJumpDomainProof8616,
    blocks: tuple[IRBlock, ...],
    invocation_scope: Real16InvocationDomain8616 | None,
) -> str | None:
    """Replay the source census and require one common explicitly consumed scope."""
    from .real16_invocation_domain import same_real16_entry_scope_8616

    scope = proof.invocation_scope
    if not same_real16_entry_scope_8616(jump.invocation_scope, scope):
        return "admission does not retain the common consuming entry"
    if scope is not None and not same_real16_entry_scope_8616(invocation_scope, scope):
        return "conditional admission requires its explicit consuming entry"
    if (
        jump.invocation is not None
        and not same_real16_entry_scope_8616(jump.invocation, scope)
    ):
        return "jump transfer and conditional calls require different entries"
    expected = _source_call_dependencies_8616(proof, blocks, scope)
    if expected is None or len(expected) != len(jump.call_dependencies):
        return "retained dependencies do not close over the source CALL census"
    for record, dependency in zip(expected, jump.call_dependencies, strict=True):
        if type(dependency) is not _ScopedCallDependency8616:
            return "retained call dependency is not a typed scope projection"
        if dependency.record is not record or dependency.callsite_addr != record.callsite_addr:
            return "retained dependency is duplicated, foreign, or out of census order"
        if not same_real16_entry_scope_8616(dependency.scope, scope):
            return "retained dependency does not share the consuming entry"
    return None


def _premise_redischarges_8616(
    jump: AdmittedTerminalJump8616, block: IRBlock | None,
) -> bool:
    """Replay a retained invocation premise against its admission record.

    The premise retained on the admission must still be complete — its own
    ``complete`` property re-derives the whole evidence chain, including a
    chained parent caller premise — and it must still discharge the
    recorded callsite head and target against the consuming artifact's
    identical block object. A window-discharged admission retains no
    premise, so any target drift there stays refused.
    """
    premise = jump.invocation
    if premise is None or block is None:
        return False
    from .real16_invocation_domain import (
        Real16InvocationDomain8616,
        real16_invocation_discharges_8616,
    )

    if not isinstance(premise, Real16InvocationDomain8616):
        return False
    if not premise.complete:
        return False
    return real16_invocation_discharges_8616(
        premise,
        project=premise.project,
        block=block,
        callsite_addr=jump.head,
        target_addr=jump.target,
    )


def apply_entry_jump_domain_8616(
    artifact: IRFunctionArtifact, proof: EntryJumpDomainProof8616,
    *, invocation_scope: Real16InvocationDomain8616 | None = None,
) -> EntryJumpDomainApplication8616:
    """Materialize admitted targets into successors, operands, and refusals.

    Application is bound to the exact input the proof consumed, and the
    consuming artifact supplies its own root: ``artifact.function_addr``
    must equal the proved root recorded in the source binding, so a proof
    cannot discharge onto an artifact whose function root moved after the
    proof ran — the proof's own recorded root is never trusted as the
    current one. The artifact's blocks must then recompute the recorded
    canonical source digest — every instruction field, captured temporary
    identity, block refusal, successor edge, and the block set's
    membership and order — and every admitted edge must be uniquely backed
    by a recorded pending candidate with the same decoded entry-window
    target. Any mismatch returns a typed
    ``STALE_INPUT`` non-result with the input blocks unmodified and an
    ``APPLICATION_INPUT_STALE`` refusal; a proof that cleared no candidate
    returns ``EMPTY`` with the input unchanged. Only on ``APPLIED`` does a
    discharged jump add its proven loader-linear target to the block's
    successor set, rewrite the retained JMP operand to the same proven
    constant the importer would have emitted, and remove only the specific
    ``SELECTOR_WINDOW_UNPROVED`` refusal the proof discharged. No other
    refusal or instruction is touched.
    """
    binding = proof.source_binding
    stale_detail: str | None = None
    if binding.function_addr != proof.function_addr:
        stale_detail = (
            f"proof root 0x{proof.function_addr:x} is inconsistent with "
            f"its recorded binding root 0x{binding.function_addr:x}"
        )
    elif artifact.function_addr != binding.function_addr:
        stale_detail = (
            f"consuming artifact root 0x{artifact.function_addr:x} does "
            f"not match the proved function root "
            f"0x{binding.function_addr:x}"
        )
    elif (
        binding.block_count != len(artifact.blocks)
        or binding.digest
        != _source_digest_8616(artifact.function_addr, artifact.blocks)
    ):
        stale_detail = (
            "supplied blocks do not recompute the proof's recorded "
            "source binding"
        )
    else:
        stale_detail = _application_admission_failure_8616(
            proof, artifact.function_addr, artifact.blocks, invocation_scope,
        )
    if stale_detail is not None:
        return EntryJumpDomainApplication8616(
            status=EntryJumpDomainApplicationStatus8616.STALE_INPUT,
            blocks=artifact.blocks,
            applied=(),
            refusals=(
                IRRefusal(
                    EntryJumpDomainRefusal8616.APPLICATION_INPUT_STALE.value,
                    stale_detail,
                    None,
                ),
            ),
        )
    if not proof.admitted:
        return EntryJumpDomainApplication8616(
            status=EntryJumpDomainApplicationStatus8616.EMPTY,
            blocks=artifact.blocks,
            applied=(),
            refusals=(),
        )
    admitted_by_block = {jump.block_addr: jump for jump in proof.admitted}
    patched: list[IRBlock] = []
    for block in artifact.blocks:
        jump = admitted_by_block.get(block.addr)
        if jump is None:
            patched.append(block)
            continue
        instrs = tuple(
            IRInstr(
                op=instr.op,
                dst=instr.dst,
                args=(
                    (IRValue(MemSpace.CONST, const=jump.target, size=4),)
                    if instr.op == "JMP" and instr.addr == jump.head
                    else instr.args
                ),
                size=instr.size,
                addr=instr.addr,
                call_stack_effect=instr.call_stack_effect,
                origin=instr.origin,
            )
            for instr in block.instrs
        )
        patched.append(IRBlock(
            addr=block.addr,
            instrs=instrs,
            refusals=tuple(
                refusal for refusal in block.refusals
                if not (
                    refusal.kind
                    == TerminalJumpRefusalReason8616
                    .SELECTOR_WINDOW_UNPROVED.value
                    and refusal.block_addr == block.addr
                )
            ),
            successor_addrs=tuple(sorted(
                {*block.successor_addrs, jump.target}
            )),
        ))
    return EntryJumpDomainApplication8616(
        status=EntryJumpDomainApplicationStatus8616.APPLIED,
        blocks=tuple(patched),
        applied=proof.admitted,
        refusals=(),
        invocation_scope=proof.invocation_scope,
    )
