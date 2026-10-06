"""Source-bound intake of uncatalogued single-block near-RET leaf callees.

Layer: tools/dosunit real-mode comparator intake.
Responsibility: admit an uncatalogued callee only from actual caller CALL
bytes re-verified against loaded memory.  The caller transfer record must be
a direct near CALL whose bytes decode to the requested full loader-linear
target; the callee body is boundedly decoded from that target through the
first terminal near RET (single straight-line block, no alternate exits,
no nested control, no interrupts, no port I/O or dirty helpers), then
lowered through the existing full-state SSA path with the exact consumed
body size — never the scan bound — and admitted only when
``complete_leaf_block`` accepts the single resulting part.

Intake is boundary recovery only.  It forges neither caller provenance nor a
whole-call proof: saved-return-frame equality and caller-CS restoration
remain the obligations of ``real16_call_execution``/``real16_call_boundary``
when the admitted parts are composed by the parent.  Symbols, names,
signatures, low-16-bit searches and rendered text never establish identity.
Forbidden: guessing a target, widening the scan budget into a body size, or
publishing a receipt before the source bytes are re-read and re-verified.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from importlib.metadata import version
from pathlib import Path
from typing import Any, NoReturn

import angr
import pyvex

import tools.dosunit.straightline_ssa as S
from tools.dosunit import ssa_provenance
from tools.dosunit.binary_environment import (
    EnvironmentEffect,
    decoded_port_effects,
    external_effects,
    requires_environment_contract,
)
from tools.dosunit.callee_proof_scope import complete_leaf_block
from tools.dosunit.flat32_proof_report import loaded_image_identity
from tools.dosunit.proof_contracts import FactCounters
from tools.dosunit.real16_call_contracts import Real16CallRefusal
from tools.dosunit.real16_call_evidence import block_source, block_transfer, part_delta, part_entry_linear
from tools.dosunit.real16_call_frames import CallFrameKind, decoded_call_frame
from tools.dosunit.real16_entry_domain import Real16EntryDomain, code_entry_domain


class IntakeStatus(StrEnum):
    """Verdict of a single uncatalogued-callee intake attempt."""

    ADMITTED = "admitted"
    REFUSED = "refused"


class IntakeRefusalReason(StrEnum):
    """Typed reason an intake request failed closed.

    Every reason names the precise evidence boundary that could not be
    established; callers must not string-parse details to recover semantics.
    """

    IMAGE_IDENTITY_MISSING = "image_identity_missing"
    CALLER_PART_MISSING = "caller_part_missing"
    CALLER_PART_AMBIGUOUS = "caller_part_ambiguous"
    SOURCE_CALL_NOT_ADMITTED = "source_call_not_admitted"
    CALL_RECORD_INCOMPLETE = "call_record_incomplete"
    CALL_BYTES_MISMATCH = "call_bytes_mismatch"
    CALL_OPCODE_UNSUPPORTED = "call_opcode_unsupported"
    CALL_TARGET_MISMATCH = "call_target_mismatch"
    TARGET_NOT_SOURCE_BOUND = "target_not_source_bound"
    TRANSFER_INCONSISTENT = "transfer_inconsistent"
    TARGET_LOW16_COLLISION = "target_low16_collision"
    TARGET_ALREADY_CATALOGUED = "target_already_catalogued"
    TARGET_DOMAIN_UNMAPPED = "target_domain_unmapped"
    BODY_LIFT_FAILED = "body_lift_failed"
    BODY_INCOMPLETE = "body_incomplete"
    BODY_TRAP_EXITS = "body_trap_exits"
    BODY_ALTERNATE_EXITS = "body_alternate_exits"
    BODY_NESTED_CALL = "body_nested_call"
    BODY_INTERRUPT = "body_interrupt"
    BODY_INDIRECT_CONTROL = "body_indirect_control"
    BODY_BRANCH = "body_branch"
    BODY_UNTERMINATED = "body_unterminated"
    BODY_ENVIRONMENT_EFFECT = "body_environment_effect"
    BODY_TERMINAL_NOT_NEAR_RET = "body_terminal_not_near_ret"
    BODY_DECODE_GAP = "body_decode_gap"
    BODY_BYTES_MISMATCH = "body_bytes_mismatch"
    BODY_BUDGET_EXCEEDED = "body_budget_exceeded"
    LOWERING_REFUSED = "lowering_refused"
    LEAF_INCOMPLETE = "leaf_incomplete"
    FULL_STATE_MISSING = "full_state_missing"
    SOURCE_CHANGED = "source_changed"


@dataclass(frozen=True)
class IntakeBudget:
    """Hard bounds on the body scan; the scan bound is never the body size."""

    max_body_bytes: int = 0x100
    max_instructions: int = 32
    max_assignments_per_function: int = 512
    max_lift_block_ms: int = 10000


@dataclass(frozen=True)
class IntakeRequest:
    """Source-bound intake request supplied by the parent composer.

    ``target_linear`` must be the full loader-linear control destination the
    parent resolved from the caller's actual CALL transfer; intake refuses
    unless it equals the transfer's recorded ``raw`` and the decoded CALL
    bytes recomputed from loaded memory.
    """

    project: angr.Project
    document: Mapping[str, Any]
    caller_function_key: str
    caller_block_delta: int
    target_linear: int


@dataclass(frozen=True)
class CallSiteEvidence:
    """Durable record of the verified caller CALL instruction."""

    function_id: str
    part_id: str
    delta: int
    site_linear: int
    site_ip: int
    size: int
    bytes_hex: str
    frame_kind: CallFrameKind
    displacement: int
    computed_target: int
    fallthrough_linear: int
    segment_para: int

    def to_dict(self) -> dict[str, Any]:
        """Serialize the call-site evidence with normalized hex fields."""
        return {
            "function_id": self.function_id,
            "part_id": self.part_id,
            "delta": f"0x{self.delta:04x}",
            "site_linear": f"0x{self.site_linear:05x}",
            "site_ip": f"0x{self.site_ip:04x}",
            "size": self.size,
            "bytes": self.bytes_hex,
            "frame_kind": self.frame_kind.value,
            "displacement": self.displacement,
            "computed_target": f"0x{self.computed_target:05x}",
            "fallthrough_linear": f"0x{self.fallthrough_linear:05x}",
            "segment_para": f"0x{self.segment_para:04x}",
        }


@dataclass(frozen=True)
class BodyEvidence:
    """Durable record of the decoded callee body at the exact target."""

    target_linear: int
    entry_ip: int
    segment_para: int
    size: int
    bytes_hex: str
    sha256: str
    instruction_count: int
    terminal_opcode: int

    def to_dict(self) -> dict[str, Any]:
        """Serialize the body evidence with normalized hex fields."""
        return {
            "target_linear": f"0x{self.target_linear:05x}",
            "entry_ip": f"0x{self.entry_ip:04x}",
            "segment_para": f"0x{self.segment_para:04x}",
            "size": self.size,
            "bytes": self.bytes_hex,
            "sha256": self.sha256,
            "instruction_count": self.instruction_count,
            "terminal_opcode": f"0x{self.terminal_opcode:02x}",
        }


@dataclass(frozen=True)
class IntakeReceipt:
    """Durable provenance receipt for one admitted (or attempted) intake.

    ``size_origin`` states that the body size was derived from verified
    source-bound terminal control closure, not declared by any catalog.
    """

    image_sha256: str
    loaded_image: dict[str, Any]
    semantic_sha256: str
    model: str
    packages: dict[str, str]
    selector_domain: Real16EntryDomain
    exe: str
    loader: dict[str, Any]
    document_id: str | None
    function_id: str
    call_site: CallSiteEvidence
    body: BodyEvidence
    output_regs: tuple[str, ...]
    leaf_complete: bool
    effects: tuple[EnvironmentEffect, ...]
    counts: dict[str, int]
    size_origin: str = "terminal_control_closure"

    def to_dict(self) -> dict[str, Any]:
        """Serialize the receipt to a JSON-stable document."""
        return {
            "image_sha256": self.image_sha256,
            "loaded_image": dict(self.loaded_image),
            "semantic_sha256": self.semantic_sha256,
            "model": self.model,
            "packages": dict(self.packages),
            "selector_domain": asdict(self.selector_domain),
            "exe": self.exe,
            "loader": dict(self.loader),
            "document_id": self.document_id,
            "function_id": self.function_id,
            "call_site": self.call_site.to_dict(),
            "body": self.body.to_dict(),
            "output_regs": list(self.output_regs),
            "leaf_complete": self.leaf_complete,
            "effects": [effect.value for effect in self.effects],
            "counts": dict(self.counts),
            "size_origin": self.size_origin,
        }


@dataclass(frozen=True)
class IntakeRefusal:
    """Typed refusal with the precise failed boundary and evidence counts."""

    reason: IntakeRefusalReason
    detail: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the refusal to a JSON-stable document."""
        return {"reason": self.reason.value, "detail": dict(self.detail)}


@dataclass(frozen=True)
class IntakeResult:
    """Outcome of one intake attempt: admitted parts plus receipt, or refusal."""

    status: IntakeStatus
    function: dict[str, Any] | None = None
    parts: tuple[dict[str, Any], ...] = ()
    receipt: IntakeReceipt | None = None
    refusal: IntakeRefusal | None = None
    counters: FactCounters = field(default_factory=FactCounters)

    def __post_init__(self) -> None:
        """Reject a status without its materialized receipt/refusal and counters."""
        if self.counters.raw_fact_count <= 0 or not self.counters.closed():
            raise ValueError("intake result lacks materialized evidence counters")
        if self.status is IntakeStatus.ADMITTED:
            if self.receipt is None or not self.parts or self.refusal is not None:
                raise ValueError("admitted intake requires parts and an exclusive receipt")
            if not self.receipt.leaf_complete or self.counters.failure_count:
                raise ValueError("admitted intake contains incomplete or failed evidence")
        elif self.refusal is None or self.receipt is not None or not self.counters.failure_count:
            raise ValueError("refused intake requires a failed-evidence record")

    @property
    def admitted(self) -> bool:
        """Whether a complete leaf was admitted with a durable receipt."""
        return self.status is IntakeStatus.ADMITTED

    def to_dict(self) -> dict[str, Any]:
        """Serialize the outcome; parts themselves remain document-shaped."""
        return {
            "status": self.status.value,
            "function": self.function,
            "parts": list(self.parts),
            "receipt": None if self.receipt is None else self.receipt.to_dict(),
            "refusal": None if self.refusal is None else self.refusal.to_dict(),
            "counters": asdict(self.counters),
        }


class _IntakeAbort(Exception):
    """Owned control-flow abort carrying a typed intake refusal."""

    def __init__(self, reason: IntakeRefusalReason, **detail: Any) -> None:  # noqa: ANN401
        super().__init__(reason.value)
        self.refusal = IntakeRefusal(reason=reason, detail=detail)


def _abort(reason: IntakeRefusalReason, **detail: Any) -> NoReturn:  # noqa: ANN401
    """Raise the owned abort for one typed refusal boundary."""
    raise _IntakeAbort(reason, **detail)


# Legacy prefixes that may precede the primary opcode of a decoded instruction.
_LEGACY_PREFIX_BYTES = frozenset({0xF0, 0xF2, 0xF3, 0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0x66, 0x67})
# Unconditional/conditional branch opcodes; only reachable as non-Ret exits.
_BRANCH_OPCODES = frozenset({0xE9, 0xEA, 0xEB, *range(0x70, 0x80), 0xE0, 0xE1, 0xE2, 0xE3})
# Interrupt-family opcodes that end a block with call-like control.
_INTERRUPT_OPCODES = frozenset({0xCC, 0xCD, 0xCE, 0xF1})
# Near RET opcodes; retf (CA/CB) and iret (CF) lift as Ijk_Ret but are far or
# interrupt returns and must not be admitted as a near leaf terminal.
_NEAR_RET_OPCODES = frozenset({0xC2, 0xC3})


def _effective_opcode(machine_code: bytes) -> int | None:
    """Return the primary opcode byte after legacy prefixes, or None."""
    index = 0
    while index < len(machine_code) and machine_code[index] in _LEGACY_PREFIX_BYTES:
        index += 1
    return machine_code[index] if index < len(machine_code) else None


def _instruction_bytes(record: Mapping[str, Any]) -> bytes | None:
    """Parse the hex byte record of one decoded instruction exactly."""
    raw = record.get("bytes")
    if not isinstance(raw, str) or not raw:
        return None
    try:
        return bytes.fromhex(raw)
    except ValueError:
        return None


def _near_call_target(site_linear: int, raw: bytes, operand_size: int) -> int | None:
    """Recompute full loaded control from exact bytes and all fetching selectors.

    Unsupported prefix/width or selector-dependent control stays unresolved.
    Wrapping belongs to architectural IP/EIP, not loader coordinates.
    """
    from angr_platforms.X86_16.relative_control_edge import (
        DecodedRelativeEdge,
        decode_relative_edge,
        invariant_relative_destination,
    )

    edge = decode_relative_edge(site_linear, raw, source="callee_intake")
    if (not isinstance(edge, DecodedRelativeEdge) or not edge.is_call
            or edge.width.value != operand_size * 8):
        return None
    target: int | None = invariant_relative_destination(edge).target
    return target



def _resolve_document_identity(
    request: IntakeRequest,
) -> tuple[Path, str]:
    """Bind the request to a binary image identity; refuse when unverifiable."""
    exe_value = request.document.get("exe") if isinstance(request.document, Mapping) else None
    exe_text = exe_value if isinstance(exe_value, str) and exe_value else ""
    if not exe_text:
        filename = request.project.filename
        exe_text = filename if isinstance(filename, str) else ""
    if not exe_text:
        _abort(IntakeRefusalReason.IMAGE_IDENTITY_MISSING, field="document.exe")
    exe_path = Path(exe_text)
    try:
        digest: str = S._file_sha256(exe_path)
    except OSError as error:
        _abort(IntakeRefusalReason.IMAGE_IDENTITY_MISSING, exe=str(exe_path), error=str(error))
    return exe_path, digest


def _loader_identity(project: angr.Project) -> tuple[dict[str, Any], int]:
    """Capture loader architecture/base facts; refuse when the mapping is absent."""
    main_object = project.loader.main_object
    linked_base = main_object.linked_base
    mapped_base = main_object.mapped_base
    if not isinstance(linked_base, int) or not isinstance(mapped_base, int):
        _abort(IntakeRefusalReason.IMAGE_IDENTITY_MISSING, field="loader.main_object")
    # Dynamic angr boundary: dosunit injects optional lifter-mode metadata into Project.
    mode = getattr(project, "_dosunit_lifter_mode", "")
    loader = {
        "arch": project.arch.name,
        "mode": str(mode),
        "linked_base": f"0x{linked_base:05x}",
        "mapped_base": f"0x{mapped_base:05x}",
    }
    return loader, linked_base


def _caller_call_part(request: IntakeRequest) -> dict[str, Any]:
    """Find the unique caller part ending at the requested block delta."""
    functions = request.document.get("functions") if isinstance(request.document, Mapping) else None
    if not isinstance(functions, list):
        _abort(IntakeRefusalReason.CALLER_PART_MISSING, field="document.functions")
    matched: list[dict[str, Any]] = []
    for part in functions:
        if not isinstance(part, dict):
            continue
        function = part.get("function")
        function = function if isinstance(function, dict) else {}
        if request.caller_function_key not in {function.get("id"), function.get("name")}:
            continue
        if part_delta(part) == request.caller_block_delta:
            matched.append(part)
    if not matched:
        _abort(
            IntakeRefusalReason.CALLER_PART_MISSING,
            function=request.caller_function_key,
            delta=f"0x{request.caller_block_delta:04x}",
        )
    if len(matched) != 1:
        _abort(
            IntakeRefusalReason.CALLER_PART_AMBIGUOUS,
            function=request.caller_function_key,
            delta=f"0x{request.caller_block_delta:04x}",
            matched=len(matched),
        )
    return matched[0]


def _verified_call_bytes(
    request: IntakeRequest,
    part: dict[str, Any],
) -> tuple[int, int, int, bytes]:
    """Require an admitted direct_call whose recorded bytes match loaded memory."""
    source = block_source(part)
    if source.get("jumpkind") != "Ijk_Call" or block_transfer(part).get("kind") != "direct_call":
        _abort(
            IntakeRefusalReason.SOURCE_CALL_NOT_ADMITTED,
            jumpkind=source.get("jumpkind"),
            transfer_kind=block_transfer(part).get("kind"),
        )
    instructions = source.get("instructions")
    last = instructions[-1] if isinstance(instructions, list) and instructions else None
    if not isinstance(last, dict):
        _abort(IntakeRefusalReason.CALL_RECORD_INCOMPLETE, field="source.instructions")
    address_value = last.get("address")
    address = address_value if isinstance(address_value, dict) else {}
    site_linear = S._optional_int(address.get("linear"))
    site_ip = S._optional_int(address.get("ip"))
    call_size = S._optional_int(last.get("size"))
    call_bytes = _instruction_bytes(last)
    if site_linear is None or site_ip is None or call_size is None or call_size <= 0:
        _abort(IntakeRefusalReason.CALL_RECORD_INCOMPLETE, field="source.instructions[-1]")
    if call_bytes is None or len(call_bytes) != call_size:
        _abort(
            IntakeRefusalReason.CALL_RECORD_INCOMPLETE,
            field="source.instructions[-1].bytes",
            declared=call_size,
            encoded=None if call_bytes is None else len(call_bytes),
        )
    loaded = S._loader_bytes(request.project, site_linear, call_size)
    if loaded is None or loaded != call_bytes:
        _abort(
            IntakeRefusalReason.CALL_BYTES_MISMATCH,
            site_linear=f"0x{site_linear:05x}",
            recorded=call_bytes.hex(),
            loaded=None if loaded is None else loaded.hex(),
        )
    return site_linear, site_ip, call_size, call_bytes


def _consistent_call_transfer(
    part: dict[str, Any],
    site_linear: int,
    call_size: int,
    call_bytes: bytes,
) -> tuple[CallFrameKind, int, int]:
    """Recompute the near target and require transfer and fallthrough consistency."""
    try:
        frame = decoded_call_frame(part)
    except Real16CallRefusal as error:
        _abort(IntakeRefusalReason.CALL_OPCODE_UNSUPPORTED, detail=error.detail)
    if frame not in {CallFrameKind.NEAR16, CallFrameKind.NEAR32}:
        _abort(IntakeRefusalReason.CALL_OPCODE_UNSUPPORTED, frame=frame.value)
    computed = _near_call_target(site_linear, call_bytes, frame.offset_bytes)
    transfer = block_transfer(part)
    value = transfer.get("target")
    target = value if isinstance(value, dict) else {}
    raw = S._optional_int(target.get("raw"))
    low16 = S._optional_int(target.get("low16"))
    if raw is None or low16 is None:
        _abort(IntakeRefusalReason.TRANSFER_INCONSISTENT, field="transfer.target")
    if computed is None or computed != raw:
        _abort(
            IntakeRefusalReason.CALL_TARGET_MISMATCH,
            computed=None if computed is None else f"0x{computed:05x}",
            recorded=f"0x{raw:05x}",
        )
    if low16 != raw & 0xFFFF:
        _abort(
            IntakeRefusalReason.TRANSFER_INCONSISTENT,
            raw=f"0x{raw:05x}",
            low16=f"0x{low16:04x}",
        )
    value = transfer.get("fallthrough")
    fallthrough = value if isinstance(value, dict) else {}
    fallthrough_linear = S._optional_int(fallthrough.get("linear"))
    if fallthrough_linear is None or fallthrough_linear != site_linear + call_size:
        _abort(
            IntakeRefusalReason.TRANSFER_INCONSISTENT,
            field="transfer.fallthrough.linear",
            recorded=None if fallthrough_linear is None else f"0x{fallthrough_linear:05x}",
            expected=f"0x{site_linear + call_size:05x}",
        )
    return frame, computed, fallthrough_linear


def _verify_call_site(request: IntakeRequest, part: dict[str, Any]) -> CallSiteEvidence:
    """Bind the admitted direct_call record to the actual loaded CALL bytes."""
    site_linear, site_ip, call_size, call_bytes = _verified_call_bytes(request, part)
    frame, computed, fallthrough_linear = _consistent_call_transfer(part, site_linear, call_size, call_bytes)
    function_value = part.get("function")
    function = function_value if isinstance(function_value, dict) else {}
    entry_value = part.get("entry")
    entry = entry_value if isinstance(entry_value, dict) else {}
    segment_para = S._optional_int(entry.get("cs"))
    if segment_para is None:
        _abort(IntakeRefusalReason.CALL_RECORD_INCOMPLETE, field="entry.cs")
    return CallSiteEvidence(
        function_id=str(function.get("id") or function.get("name") or request.caller_function_key),
        part_id=str(part.get("id") or ""),
        delta=request.caller_block_delta,
        site_linear=site_linear,
        site_ip=site_ip,
        size=call_size,
        bytes_hex=call_bytes.hex(),
        frame_kind=frame,
        displacement=int.from_bytes(call_bytes[len(call_bytes) - frame.offset_bytes :], "little", signed=True),
        computed_target=computed,
        fallthrough_linear=fallthrough_linear,
        segment_para=segment_para,
    )


def _check_target_domain(
    request: IntakeRequest,
    call_site: CallSiteEvidence,
    linked_base: int,
) -> int:
    """Bind the requested target and derive the callee entry offset in the caller domain."""
    if request.target_linear != call_site.computed_target:
        _abort(
            IntakeRefusalReason.TARGET_NOT_SOURCE_BOUND,
            requested=f"0x{request.target_linear:05x}",
            computed=f"0x{call_site.computed_target:05x}",
        )
    catalog_entries: dict[int, set[str]] = {}
    for part in request.document.get("functions", []) or []:
        if not isinstance(part, dict):
            continue
        entry = part_entry_linear(part)
        function_value = part.get("function")
        function = function_value if isinstance(function_value, dict) else {}
        function_id = str(function.get("id") or function.get("name") or "")
        if entry is None or not function_id:
            continue
        catalog_entries.setdefault(entry, set()).add(function_id)
    if request.target_linear in catalog_entries:
        _abort(
            IntakeRefusalReason.TARGET_ALREADY_CATALOGUED,
            target=f"0x{request.target_linear:05x}",
            owners=sorted(catalog_entries[request.target_linear]),
        )
    collisions = {
        f"0x{entry:05x}": sorted(ids)
        for entry, ids in catalog_entries.items()
        if entry != request.target_linear and entry & 0xFFFF == request.target_linear & 0xFFFF
    }
    if collisions:
        _abort(
            IntakeRefusalReason.TARGET_LOW16_COLLISION,
            target=f"0x{request.target_linear:05x}",
            low16=f"0x{request.target_linear & 0xFFFF:04x}",
            collisions=collisions,
        )
    function_base = linked_base + (call_site.segment_para << 4)
    entry_ip = request.target_linear - function_base
    if not 0 <= entry_ip <= 0xFFFF:
        _abort(
            IntakeRefusalReason.TARGET_DOMAIN_UNMAPPED,
            target=f"0x{request.target_linear:05x}",
            function_base=f"0x{function_base:05x}",
            segment_para=f"0x{call_site.segment_para:04x}",
        )
    return entry_ip


def _classify_terminal_opcode(opcode: int | None, jumpkind: str) -> None:
    """Raise the typed refusal for a non-RET terminal instruction kind."""
    if opcode in {0xE8, 0x9A}:
        _abort(IntakeRefusalReason.BODY_NESTED_CALL, jumpkind=jumpkind, opcode=opcode)
    if opcode in _INTERRUPT_OPCODES:
        _abort(IntakeRefusalReason.BODY_INTERRUPT, jumpkind=jumpkind, opcode=opcode)
    if opcode == 0xFF:
        _abort(IntakeRefusalReason.BODY_INDIRECT_CONTROL, jumpkind=jumpkind, opcode=opcode)
    if opcode is not None and opcode in _BRANCH_OPCODES:
        _abort(IntakeRefusalReason.BODY_BRANCH, jumpkind=jumpkind, opcode=opcode)
    _abort(IntakeRefusalReason.BODY_UNTERMINATED, jumpkind=jumpkind, opcode=opcode)


def _lift_body_block(
    request: IntakeRequest,
    budget: IntakeBudget,
    *,
    exe_path: Path,
    exe_digest: str,
) -> S.LiftedBlock:
    """Lift one bounded block at the target; a lift timeout is a budget refusal."""
    if budget.max_body_bytes <= 0 or budget.max_instructions <= 0:
        _abort(IntakeRefusalReason.BODY_BUDGET_EXCEEDED, counter="budget_invalid")
    probe = S._loader_bytes(request.project, request.target_linear, 1)
    if not probe:
        _abort(
            IntakeRefusalReason.TARGET_DOMAIN_UNMAPPED,
            target=f"0x{request.target_linear:05x}",
        )
    try:
        return S._lift_vex_block_cached(
            project=request.project,
            exe_path=exe_path,
            exe_digest=exe_digest,
            start=request.target_linear,
            size=budget.max_body_bytes,
            opt_level=0,
            cache_document=None,
            cache_stats={"hits": 0, "misses": 0, "writes": 0, "errors": 0},
            max_lift_block_ms=budget.max_lift_block_ms,
        )
    except TimeoutError as error:
        _abort(IntakeRefusalReason.BODY_BUDGET_EXCEEDED, counter="lift_ms", error=str(error))


def _check_body_terminal(lifted: S.LiftedBlock, target_linear: int) -> None:
    """Require a complete block ending in a terminal near RET with no exits."""
    irsb = lifted.irsb
    if not isinstance(irsb, pyvex.IRSB) or irsb.statements is None:
        _abort(IntakeRefusalReason.BODY_LIFT_FAILED, field="complete_vex_irsb")
    instructions = lifted.instructions
    if not instructions:
        _abort(IntakeRefusalReason.BODY_INCOMPLETE, target=f"0x{target_linear:05x}")
    if instructions[0].get("linear") != target_linear:
        _abort(
            IntakeRefusalReason.BODY_DECODE_GAP,
            expected=f"0x{target_linear:05x}",
            first=instructions[0].get("linear"),
        )
    exits = [statement for statement in irsb.statements if isinstance(statement, pyvex.stmt.Exit)]
    if exits:
        kinds = sorted({str(item.jumpkind) for item in exits})
        if any(kind.startswith("Ijk_Sig") for kind in kinds):
            _abort(IntakeRefusalReason.BODY_TRAP_EXITS, exits=kinds)
        _abort(IntakeRefusalReason.BODY_ALTERNATE_EXITS, exits=kinds)
    jumpkind = irsb.jumpkind
    last_opcode = _effective_opcode(_instruction_bytes(instructions[-1]) or b"")
    if jumpkind != "Ijk_Ret":
        _classify_terminal_opcode(last_opcode, jumpkind)
    if last_opcode not in _NEAR_RET_OPCODES:
        _abort(
            IntakeRefusalReason.BODY_TERMINAL_NOT_NEAR_RET,
            opcode=last_opcode,
            jumpkind=jumpkind,
        )
    if requires_environment_contract(irsb):
        _abort(IntakeRefusalReason.BODY_ENVIRONMENT_EFFECT, boundary="dirty_helper")


def _check_decoded_effects(data: bytes, linear: int, index: int) -> None:
    """Consume the shared binary port classification with complete decoding."""
    effects = decoded_port_effects(data, linear, mode_bits=16)
    if effects is None:
        _abort(IntakeRefusalReason.BODY_DECODE_GAP, instruction=index)
    if effects:
        _abort(IntakeRefusalReason.BODY_ENVIRONMENT_EFFECT, instruction=index,
               effects=sorted(effect.value for effect in effects))


def _walk_body_instructions(
    request: IntakeRequest,
    lifted: S.LiftedBlock,
    budget: IntakeBudget,
) -> bytes:
    """Verify contiguous coverage and effect-free opcodes; return exact bytes."""
    body_parts: list[bytes] = []
    cursor = request.target_linear
    for index, record in enumerate(lifted.instructions):
        linear = record.get("linear")
        size = record.get("size")
        data = _instruction_bytes(record)
        if type(linear) is not int or type(size) is not int or size <= 0 or data is None:
            _abort(IntakeRefusalReason.BODY_INCOMPLETE, instruction=index)
        if len(data) != size:
            _abort(IntakeRefusalReason.BODY_DECODE_GAP, instruction=index, size=size, bytes=len(data))
        if linear != cursor:
            _abort(
                IntakeRefusalReason.BODY_DECODE_GAP,
                instruction=index,
                expected=f"0x{cursor:05x}",
                actual=f"0x{linear:05x}",
            )
        _check_decoded_effects(data, linear, index)
        body_parts.append(data)
        cursor += size
        if index + 1 > budget.max_instructions:
            _abort(
                IntakeRefusalReason.BODY_BUDGET_EXCEEDED,
                counter="instructions",
                limit=budget.max_instructions,
            )
    body = b"".join(body_parts)
    if len(body) > budget.max_body_bytes:
        _abort(
            IntakeRefusalReason.BODY_BUDGET_EXCEEDED,
            counter="body_bytes",
            limit=budget.max_body_bytes,
        )
    irsb_size = lifted.irsb.size
    if type(irsb_size) is not int or irsb_size != len(body):
        _abort(
            IntakeRefusalReason.BODY_INCOMPLETE,
            irsb_size=irsb_size,
            decoded=len(body),
        )
    loaded = S._loader_bytes(request.project, request.target_linear, len(body))
    if loaded is None or loaded != body:
        _abort(
            IntakeRefusalReason.BODY_BYTES_MISMATCH,
            target=f"0x{request.target_linear:05x}",
            decoded=body.hex(),
            loaded=None if loaded is None else loaded.hex(),
        )
    return body


def _decode_leaf_body(
    request: IntakeRequest,
    budget: IntakeBudget,
    *,
    exe_path: Path,
    exe_digest: str,
) -> tuple[bytes, list[dict[str, Any]], int]:
    """Bounded-decode one straight-line block through the first terminal near RET."""
    lifted = _lift_body_block(request, budget, exe_path=exe_path, exe_digest=exe_digest)
    _check_body_terminal(lifted, request.target_linear)
    body = _walk_body_instructions(request, lifted, budget)
    return body, lifted.instructions, len(body)


def _catalog_record(
    request: IntakeRequest,
    call_site: CallSiteEvidence,
    entry_ip: int,
    body_size: int,
) -> dict[str, Any]:
    """Build the exact-size catalog record consumed by ``_lower_function``.

    The record is intake-scoped evidence plumbing: ``size`` is the consumed
    body length, not a declared catalog extent, and ``entry`` maps the full
    loader-linear target into the caller's segment/offset domain.
    """
    module = str(request.document.get("module") or "module")
    function_id = f"{module}:binary_intake_{request.target_linear:05x}"
    return {
        "id": function_id,
        "names": [f"binary_intake_{request.target_linear:05x}"],
        "entry": {
            "kind": "module_relative",
            "segment": f"seg_{call_site.segment_para:04x}",
            "segment_para": f"0x{call_site.segment_para:04x}",
            "offset": f"0x{entry_ip:04x}",
        },
        "return_kind": "near",
        "size": body_size,
        "safe_traps": [],
        "sources": ["binary_callee_intake"],
    }


def _lower_leaf(
    request: IntakeRequest,
    budget: IntakeBudget,
    record: dict[str, Any],
    *,
    exe_path: Path,
    exe_digest: str,
    linked_base: int,
    body: bytes,
) -> list[dict[str, Any]]:
    """Lower the body through ``_lower_function`` and verify the single leaf."""
    output_regs = tuple(S.INTERNAL_STATE_REGS)
    parts, refusals, _blocks_lifted = S._lower_function(
        project=request.project,
        linked_base=linked_base,
        exe_path=exe_path,
        exe_digest=exe_digest,
        cache_document=None,
        cache_stats={"hits": 0, "misses": 0, "writes": 0, "errors": 0},
        function=record,
        segment_paragraphs={},
        output_regs=output_regs,
        source_ir=str(request.document.get("source_ir") or "vex"),
        max_blocks_per_function=1,
        max_insns_per_function=budget.max_instructions,
        max_assignments_per_function=budget.max_assignments_per_function,
        scan_limit=budget.max_body_bytes,
        follow_call_fallthrough=False,
        max_lift_block_ms=budget.max_lift_block_ms,
    )
    if refusals:
        _abort(IntakeRefusalReason.LOWERING_REFUSED, refusals=list(refusals))
    if len(parts) != 1:
        _abort(IntakeRefusalReason.LEAF_INCOMPLETE, parts=len(parts))
    part = parts[0]
    if not complete_leaf_block(part):
        _abort(IntakeRefusalReason.LEAF_INCOMPLETE, part_id=str(part.get("id") or ""))
    if part_entry_linear(part) != request.target_linear:
        _abort(
            IntakeRefusalReason.LEAF_INCOMPLETE,
            entry=part_entry_linear(part),
            target=f"0x{request.target_linear:05x}",
        )
    outputs = part.get("outputs")
    missing = sorted(set(S._ssa_register_widths()) - set(outputs if isinstance(outputs, dict) else {}))
    if missing:
        _abort(IntakeRefusalReason.FULL_STATE_MISSING, missing=missing)
    effects = external_effects({"assignments": part.get("assignments"), "outputs": part.get("outputs")})
    if effects:
        _abort(
            IntakeRefusalReason.BODY_ENVIRONMENT_EFFECT,
            effects=sorted(effect.value for effect in effects),
        )
    source = block_source(part)
    digest = hashlib.sha256(body).hexdigest()
    if (
        S._optional_int(source.get("machine_code_size")) != len(body)
        or S._optional_int(source.get("function_machine_code_size")) != len(body)
        or source.get("machine_code_sha256") != digest
        or source.get("function_machine_code_sha256") != digest
    ):
        _abort(
            IntakeRefusalReason.LEAF_INCOMPLETE,
            machine_code_size=source.get("machine_code_size"),
            function_machine_code_size=source.get("function_machine_code_size"),
        )
    lowered_parts: list[dict[str, Any]] = parts
    return lowered_parts


def intake_uncatalogued_leaf(
    request: IntakeRequest,
    *,
    budget: IntakeBudget | None = None,
) -> IntakeResult:
    """Admit an uncatalogued near-RET leaf callee from source-bound CALL bytes.

    The request must name a caller part inside ``request.document`` whose last
    instruction is an admitted direct near CALL; its bytes are re-read from
    loaded memory, the recomputed target must equal both the transfer record
    and ``request.target_linear``, and the body at that target must decode to
    one complete near-RET block within ``budget``.  Success returns the
    lowered leaf parts and a durable receipt; any evidence gap returns a
    typed refusal instead of guessing.  This performs no whole-call
    equivalence, saved-return-frame, or CS-restoration proof.
    """
    budget = IntakeBudget() if budget is None else budget
    try:
        exe_path, exe_digest = _resolve_document_identity(request)
        identity = ssa_provenance.begin_lowering(exe_path)
        image = loaded_image_identity(request.project)
        if identity.binary_hash != exe_digest:
            _abort(IntakeRefusalReason.SOURCE_CHANGED, boundary="initial_identity")
        selector_domain = code_entry_domain(request.target_linear)
        if selector_domain is None:
            _abort(IntakeRefusalReason.TARGET_DOMAIN_UNMAPPED, target=request.target_linear)
        loader, linked_base = _loader_identity(request.project)
        part = _caller_call_part(request)
        call_site = _verify_call_site(request, part)
        entry_ip = _check_target_domain(request, call_site, linked_base)
        body, instructions, body_size = _decode_leaf_body(request, budget, exe_path=exe_path, exe_digest=exe_digest)
        record = _catalog_record(request, call_site, entry_ip, body_size)
        parts = _lower_leaf(
            request,
            budget,
            record,
            exe_path=exe_path,
            exe_digest=exe_digest,
            linked_base=linked_base,
            body=body,
        )
        # Re-read the source before publication; a changed image never ships.
        if (
            S._loader_bytes(request.project, call_site.site_linear, call_site.size)
            != bytes.fromhex(call_site.bytes_hex)
            or S._loader_bytes(request.project, request.target_linear, body_size) != body
            or ssa_provenance.begin_lowering(exe_path) != identity
            or loaded_image_identity(request.project) != image
        ):
            _abort(
                IntakeRefusalReason.SOURCE_CHANGED,
                target=f"0x{request.target_linear:05x}",
                site=f"0x{call_site.site_linear:05x}",
            )
        receipt = IntakeReceipt(
            image_sha256=exe_digest,
            loaded_image=image,
            semantic_sha256=identity.semantic_hash,
            model=ssa_provenance.REAL16_MODEL,
            packages={name: version(name) for name in ssa_provenance.SSA_PACKAGES},
            selector_domain=selector_domain,
            exe=str(exe_path),
            loader=loader,
            document_id=(str(request.document.get("id")) if request.document.get("id") is not None else None),
            function_id=str(record["id"]),
            call_site=call_site,
            body=BodyEvidence(
                target_linear=request.target_linear,
                entry_ip=entry_ip,
                segment_para=call_site.segment_para,
                size=body_size,
                bytes_hex=body.hex(),
                sha256=hashlib.sha256(body).hexdigest(),
                instruction_count=len(instructions),
                terminal_opcode=_effective_opcode(_instruction_bytes(instructions[-1]) or b"") or 0,
            ),
            output_regs=tuple(S.INTERNAL_STATE_REGS),
            leaf_complete=True,
            effects=(),
            counts={
                "instructions": len(instructions),
                "exit_edges": 0,
                "lowered_parts": len(parts),
                "lowering_refusals": 0,
                "source_revalidations": 2,
            },
        )
        return IntakeResult(
            status=IntakeStatus.ADMITTED,
            function=record,
            parts=tuple(parts),
            receipt=receipt,
            counters=FactCounters(1, 1, 1, 1, 0),
        )
    except _IntakeAbort as abort:
        return IntakeResult(status=IntakeStatus.REFUSED, refusal=abort.refusal,
                            counters=FactCounters(1, 1, 1, 1, 1))
