"""Bounded returning DOS/BIOS service effects for the real16 symbolic terminal slice.

Layer: dosunit symbolic program proof.
Responsibility: own the ordered returning-service event type, the live IVT
authentication, frame-alias range declaration and low-half register effects
for the declared ``INT 21h/AH=30h AL=00`` version query and the declared
``INT 10h/AH=0Fh`` video-state query inside the bounded terminal comparison.
Every admission check reuses the concrete contract owners —
``program_version_query``, ``version_event_data``, ``vector_bytes``,
``video_dispatch_refusal`` and ``video_query_event_data`` — and produces
typed ``TerminalRefusal`` evidence; unsupported selectors, prefixed or
wrapping frames, frame aliasing, unproved live vector bytes and missing
policies refuse rather than guess. A declared service model is a visible
environment premise, never real DOS/BIOS proof: the events record exactly
the caller-declared response bytes, and the upper register halves, every
flag and every segment are preserved by leaving the SSA versions untouched.
The module also owns the verification census — a complete, unique, ordered
derivation of executed returning-service boundaries from the authenticated
block receipts and the declared selectors — so a trace's retained receipts
must answer every executed boundary, never a caller-supplied subset.
``ProgramEnvironment`` is imported under ``TYPE_CHECKING`` only, so this
module stays free of the native lifter chain and the census controls can
run before the parent proof release.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

import capstone
from capstone import x86_const as decoded_ids

from tools.dosunit import straightline_ssa as S
from tools.dosunit.proof_contracts import FactCounters
from tools.dosunit.real16_program_memory import ProgramMemoryLayout
from tools.dosunit.real16_program_model import ProgramEventKind
from tools.dosunit.real16_program_vectors import (
    DOS_VECTOR,
    DOS_VECTOR_RANGE,
    VECTOR_BYTES,
    VectorRefusal,
    vector_bytes,
)
from tools.dosunit.real16_program_version import (
    VERSION_FUNCTION,
    VersionAnswered,
    VersionPolicy,
    VersionRefused,
    program_version_query,
    version_event_data,
)
from tools.dosunit.real16_program_video import (
    VIDEO_FUNCTION,
    VIDEO_VECTOR,
    VideoQueryPolicy,
    video_query_event_data,
)
from tools.dosunit.real16_program_video_boundary import (
    VIDEO_VECTOR_RANGE,
    VideoDispatchRefusal,
    video_dispatch_refusal,
)
from tools.dosunit.real16_replay_model import LinearRange
from tools.dosunit.terminal_memory_effects import (
    TerminalRefusal,
    TerminalRefusalKind,
    const_eval,
)
from tools.dosunit.terminal_native_decode import (
    DEFAULT_NATIVE_LIMITS,
    NativeDecodeLimits,
    decode_terminal_block,
)

if TYPE_CHECKING:
    from tools.dosunit.real16_program_boot import ProgramEnvironment


@dataclass(frozen=True, slots=True)
class TerminalServiceEvent:
    """One ordered returning-service observation under the declared model.

    ``kind`` and ``data`` are the observable receipt — the same payload the
    concrete replay reports for the declared policy — while ``address``,
    ``vector`` and ``function`` retain the native dispatch site for
    stale-evidence verification. Events are compared in execution order:
    a repeated, removed or reordered call is a different observable history.
    """

    kind: ProgramEventKind
    address: int
    vector: int
    function: int
    data: bytes


@dataclass(frozen=True, slots=True)
class ReturningService:
    """One applied returning-service dispatch and its native continuation.

    ``fallthrough`` is the exact linear address of the instruction after the
    ``CD vector`` boundary; ``fallthrough_ip`` is the CS-relative offset the
    service leaves in IP — the same value the entry frame pushes. Both are
    derived from proved concrete coordinates only.
    """

    event: TerminalServiceEvent
    fallthrough: int
    fallthrough_ip: int


def declared_frame_aliases(environment: ProgramEnvironment) -> tuple[tuple[LinearRange, str], ...]:
    """Return the live-vector ranges a service frame may never overwrite.

    Mirrors the concrete ``_service_frame`` guards: a declared DOS vector
    policy binds slot 0x21, and either declared video policy binds slot
    0x10. Each range carries the exact typed refusal detail the concrete
    dispatch reports.
    """
    aliases: list[tuple[LinearRange, str]] = []
    if environment.vector_policy is not None:
        aliases.append((DOS_VECTOR_RANGE, VectorRefusal.FRAME_ALIAS.value))
    if environment.video_policy is not None or environment.video_state_policy is not None:
        aliases.append((VIDEO_VECTOR_RANGE, VideoDispatchRefusal.FRAME_ALIAS.value))
    return tuple(aliases)


_STORE_ADDRESS_MODULUS = 1 << 32
"""Modulus of the SSA store-address domain.

``_z3_store`` resizes every store address to 32 bits and indexes bytes
with 32-bit ``BitVecVal`` offsets, so a store's byte positions are
``(base + index) mod _STORE_ADDRESS_MODULUS`` — not unbounded integer
arithmetic.
"""


def live_ivt_bytes(
    mem_version: S.SsaExpr,
    address: int,
    initial_bytes: Callable[[int, int], bytes | None],
) -> bytes | None:
    """Derive the effective ``VECTOR_BYTES`` at ``address`` under the current memory.

    Admitted query domain: ``address`` is a nonnegative linear base whose
    half-open range ``[address, address + VECTOR_BYTES)`` stays inside
    the 32-bit store-address modulus — every caller passes a proved low
    IVT slot, so anything else is outside the declared contract and
    refuses.

    Store byte positions follow the SSA memory semantics exactly —
    ``_z3_store`` truncates each address to 32 bits and indexes bytes
    modulo ``_STORE_ADDRESS_MODULUS`` — so a proved base is truncated the
    same way, and a store whose byte range still wraps the modulus
    boundary while queried bytes are unresolved refuses rather than
    claim disjointness over an interval that cannot express the wrapped
    tail; splitting coverage across the boundary is deliberately not
    modeled. Store data must be byte-addressable: ``_z3_store`` rejects
    ``width % 8 != 0`` terms, and a zero-width term is equally malformed,
    so any such store anywhere in the walked chain is unproved — the
    same malformed-chain stance as the ``mem_input`` root check.

    Newest stores win, exactly as concrete execution observes them: a
    store whose proved concrete range still reaches an unresolved vector
    byte must carry proved concrete data or the live bytes are
    unprovable. A store that cannot touch an unresolved byte — proved
    disjoint, or overlapping only bytes newer stores already covered —
    needs no data proof, and once every vector byte is covered the
    remaining older stores cannot change the answer, so the walk only
    has to reach the shared input root. Bytes no store covered resolve
    to the declared initial bytes. ``None`` means unproved — an
    out-of-domain query range, a malformed store term, a possibly
    overlapping symbolic store address over unresolved bytes, a store
    range wrapping the 32-bit boundary, symbolic store data covering an
    unresolved byte, a non-``mem_input`` chain root or undeclared
    initial coverage — and every caller turns it into a typed refusal.
    """
    if not 0 <= address <= _STORE_ADDRESS_MODULUS - VECTOR_BYTES:
        return None
    data = bytearray(VECTOR_BYTES)
    covered = [False] * VECTOR_BYTES
    expr = mem_version
    while expr.op in {"storele", "storebe"}:
        width_bytes = _store_data_bytes(expr)
        if width_bytes is None:
            return None
        if not all(covered):
            span = _concrete_span(expr, width_bytes)
            if span is None:
                return None
            base, end = span
            if _store_reaches_unresolved(base, end, address, covered):
                value = const_eval(expr.args[2])
                if value is None:
                    return None
                _apply_store_bytes(expr, base, value, address, data, covered)
        expr = expr.args[0]
    if expr.op != "mem_input":
        return None
    return _resolve_uncovered(data, covered, address, initial_bytes)


def _store_data_bytes(expr: S.SsaExpr) -> int | None:
    """Return the store's byte width, or ``None`` when the term is malformed.

    ``_z3_store`` rejects non-byte-addressable data widths with
    ``DosUnitError``; a ``width % 8 != 0`` or zero-width store term
    cannot be produced by the admitted semantics, so the chain is
    malformed and the live bytes are unproved.
    """
    width = int(expr.args[2].width)
    if width <= 0 or width % 8 != 0:
        return None
    return width // 8


def _concrete_span(expr: S.SsaExpr, width_bytes: int) -> tuple[int, int] | None:
    """Return ``(base, end)`` for a store's proved range, or ``None`` to refuse.

    The SSA store semantics truncate the address term to 32 bits
    (``_resize_z3`` unsigned), and every stored byte is addressed modulo
    ``_STORE_ADDRESS_MODULUS``; this helper applies the same truncation,
    then refuses — rather than splits — a range that would cross the
    modulus boundary, since the wrapped tail may hit queried bytes the
    plain half-open interval would miss. ``None`` also marks a symbolic
    (unproved) base.
    """
    base = const_eval(expr.args[1])
    if base is None:
        return None
    base %= _STORE_ADDRESS_MODULUS
    end = base + width_bytes
    if end > _STORE_ADDRESS_MODULUS:
        return None
    return base, end


def _store_reaches_unresolved(
    base: int, end: int, address: int, covered: list[bool]
) -> bool:
    """Return whether one non-wrapping store still touches an unresolved byte.

    The caller guarantees ``[base, end)`` does not wrap the 32-bit
    modulus boundary, so a plain half-open interval is exact. ``True``
    means at least one byte inside ``[address, address + VECTOR_BYTES)``
    is written by this store and not already covered by a newer store,
    so the store's data term must be proved concrete.
    """
    lo = max(base, address)
    hi = min(end, address + VECTOR_BYTES)
    return any(not covered[at - address] for at in range(lo, hi))


def _apply_store_bytes(
    expr: S.SsaExpr,
    base: int,
    value: int,
    address: int,
    data: bytearray,
    covered: list[bool],
) -> None:
    """Copy one proved store's still-unresolved bytes into ``data``.

    Newest stores win: only bytes inside the queried range that no newer
    store covered are written, in the store's declared endness.
    """
    width_bytes = expr.args[2].width // 8
    for index in range(width_bytes):
        offset = index if expr.op == "storele" else width_bytes - 1 - index
        at = base + offset
        if address <= at < address + VECTOR_BYTES and not covered[at - address]:
            data[at - address] = (value >> (index * 8)) & 0xFF
            covered[at - address] = True


def _resolve_uncovered(
    data: bytearray,
    covered: list[bool],
    address: int,
    initial_bytes: Callable[[int, int], bytes | None],
) -> bytes | None:
    """Fill still-uncovered bytes from the declared initial state.

    ``None`` means at least one uncovered byte has no declared initializer,
    so the live vector bytes are unproved.
    """
    for index in range(VECTOR_BYTES):
        if covered[index]:
            continue
        initial = initial_bytes(address + index, 1)
        if initial is None:
            return None
        data[index] = initial[0]
    return bytes(data)


def check_dos_vector(
    *,
    environment: ProgramEnvironment,
    layout: ProgramMemoryLayout,
    mem_version: S.SsaExpr,
    initial_bytes: Callable[[int, int], bytes | None],
) -> None:
    """Authenticate the declared external DOS entry before any INT21 dispatch.

    Without a declared ``vector_policy`` no declared memory may cover slot
    0x21 — the concrete ``POLICY_REQUIRED`` boundary. With one, the declared
    entry must be external to the program arena and the live vector bytes —
    through any prefix stores — must still encode it exactly.
    """
    policy = environment.vector_policy
    if policy is None:
        if any(
            region.overlaps(DOS_VECTOR_RANGE.address, VECTOR_BYTES)
            for region in layout.ranges
        ):
            raise TerminalRefusal(
                TerminalRefusalKind.UNSUPPORTED_ENVIRONMENT,
                VectorRefusal.POLICY_REQUIRED.value,
            )
        return
    arena_start = environment.psp_segment * 16
    if arena_start <= policy.dos_entry.linear() < arena_start + len(environment.allocation):
        raise TerminalRefusal(
            TerminalRefusalKind.UNSUPPORTED_ENVIRONMENT, VectorRefusal.OWNED_HANDLER.value
        )
    live = live_ivt_bytes(mem_version, DOS_VECTOR_RANGE.address, initial_bytes)
    if live is None:
        raise TerminalRefusal(
            TerminalRefusalKind.SERVICE_GUARD_UNPROVED,
            "live DOS vector bytes are not proved under the declared state",
        )
    if live != vector_bytes(policy.dos_entry):
        raise TerminalRefusal(
            TerminalRefusalKind.UNSUPPORTED_ENVIRONMENT, VectorRefusal.DOS_REDIRECTED.value
        )


def check_video_vector(
    *,
    policy: VideoQueryPolicy,
    environment: ProgramEnvironment,
    mem_version: S.SsaExpr,
    initial_bytes: Callable[[int, int], bytes | None],
) -> None:
    """Authenticate the declared external BIOS entry before an INT10 dispatch.

    Reuses ``video_dispatch_refusal`` against the effective live vector
    bytes: a program-owned entry or a redirected slot refuses with the
    concrete refusal detail; unproved live bytes are a guard refusal.
    """
    live = live_ivt_bytes(mem_version, VIDEO_VECTOR_RANGE.address, initial_bytes)
    if live is None:
        raise TerminalRefusal(
            TerminalRefusalKind.SERVICE_GUARD_UNPROVED,
            "live BIOS vector bytes are not proved under the declared state",
        )
    failure = video_dispatch_refusal(
        policy,
        live,
        arena_start=environment.psp_segment * 16,
        arena_size=len(environment.allocation),
    )
    if failure is not None:
        raise TerminalRefusal(TerminalRefusalKind.UNSUPPORTED_ENVIRONMENT, failure.value)


def version_answer(*, policy: VersionPolicy, state: S._IrsbLowerState) -> VersionAnswered:
    """Admit one INT21/AH=30 query under the declared policy.

    The AL selector must be proved concrete under the declared seed;
    ``program_version_query`` then decides admission, and its typed refusal
    becomes an ``UNDECLARED_SERVICE`` rather than an emulated DOS error.
    """
    selector = const_eval(S.SsaExpr("trunc", 8, (state.reg_versions["ax"],)))
    if selector is None:
        raise TerminalRefusal(
            TerminalRefusalKind.SERVICE_GUARD_UNPROVED,
            "AL selector is not proved under the declared state",
        )
    result = program_version_query(policy, selector=selector)
    if isinstance(result, VersionRefused):
        raise TerminalRefusal(
            TerminalRefusalKind.UNDECLARED_SERVICE, result.refusal.value
        )
    return result


def apply_version_effect(state: S._IrsbLowerState, answered: VersionAnswered) -> None:
    """Install the documented AX/BX/CX low halves, preserving upper halves.

    The 386 high halves live in separate SSA registers, so writing the low
    halves alone models the concrete ``(reg & 0xFFFF0000) | answer`` writes;
    flags and segments are untouched exactly as the declared contract
    requires.
    """
    state.reg_versions["ax"] = S.SsaExpr("const", 16, value=answered.ax)
    state.reg_versions["bx"] = S.SsaExpr("const", 16, value=answered.bx)
    state.reg_versions["cx"] = S.SsaExpr("const", 16, value=answered.cx)


def apply_video_effect(state: S._IrsbLowerState, policy: VideoQueryPolicy) -> None:
    """Install AL=mode, AH=columns and BH=page, preserving every other bit.

    The term form keeps the prior BL and the separate ``ebx_hi`` storage,
    matching the concrete ``(ebx & 0xFFFF00FF) | page << 8`` write.
    """
    state.reg_versions["ax"] = S.SsaExpr(
        "const", 16, value=(policy.columns << 8) | policy.mode
    )
    bx = state.reg_versions["bx"]
    state.reg_versions["bx"] = S.SsaExpr(
        "or",
        16,
        (
            S.SsaExpr("and", 16, (bx, S.SsaExpr("const", 16, value=0x00FF))),
            S.SsaExpr("const", 16, value=policy.page << 8),
        ),
    )


def version_event(site_address: int, policy: VersionPolicy) -> TerminalServiceEvent:
    """Record the declared DOS version receipt at one dispatch site."""
    return TerminalServiceEvent(
        ProgramEventKind.DOS_VERSION,
        site_address,
        DOS_VECTOR,
        VERSION_FUNCTION,
        version_event_data(policy),
    )


def video_event(site_address: int, policy: VideoQueryPolicy) -> TerminalServiceEvent:
    """Record the declared BIOS video-state receipt at one dispatch site."""
    return TerminalServiceEvent(
        ProgramEventKind.BIOS_VIDEO_QUERY,
        site_address,
        VIDEO_VECTOR,
        VIDEO_FUNCTION,
        video_query_event_data(policy),
    )


@dataclass(frozen=True, slots=True)
class ServiceBlockEnding:
    """One admitted block receipt's verified native ending.

    Verification maps each byte-authenticated ``TerminalBlockReceipt`` into
    this boundary view; the census re-derives the tail encoding from the
    retained image bytes, never from trace tags.
    """

    address: int
    size: int
    jumpkind: str
    next_target: int | None


@dataclass(frozen=True, slots=True)
class ReturningBoundary:
    """One executed returning-service boundary in block-receipt order.

    ``receipt`` is the payload the declared environment must produce for
    the boundary's vector — the same bytes the concrete event owners
    report — so a retained event is valid only as the positional answer
    to one census entry.
    """

    site: int
    vector: int
    function: int
    kind: ProgramEventKind
    receipt: bytes


_MIDDLE_JUMPKINDS = frozenset({"Ijk_Boring", "Ijk_Call"})
"""Jumpkinds an honest acyclic walk may carry before its closing block."""


def _stale_census(detail: str) -> TerminalRefusal:
    """Name a retained-evidence authentication failure consistently."""
    return TerminalRefusal(TerminalRefusalKind.STALE_EVIDENCE, detail)


def _native_interrupt_boundary(
    block: ServiceBlockEnding, read: Callable[[int, int], bytes | None],
    limits: NativeDecodeLimits,
) -> tuple[int, int] | TerminalRefusal | None:
    """Authenticate an INT ending from complete decoded instructions and bytes."""
    if not 0 < block.size <= limits.max_block_bytes:
        return _stale_census("block receipt exceeds native decoding budget")
    code = read(block.address, block.size)
    if code is None or len(code) != block.size:
        return _stale_census("block receipt lacks complete initialized bytes")
    try:
        instructions = decode_terminal_block(code, block.address, mode=capstone.CS_MODE_16, limits=limits)
    except TerminalRefusal as error:
        return _stale_census(f"block receipt cannot be decoded: {error}")
    transfers = (capstone.CS_GRP_INT, capstone.CS_GRP_CALL, capstone.CS_GRP_RET,
                 capstone.CS_GRP_IRET, capstone.CS_GRP_JUMP)
    if any(instruction.group(group) for instruction in instructions[:-1] for group in transfers):
        return _stale_census("block receipt crosses an earlier native control transfer")
    final = instructions[-1]
    if final.id == decoded_ids.X86_INS_INT:
        encoding = bytes(final.bytes)
        if block.jumpkind != "Ijk_Call" or len(encoding) != 2 or encoding[0] != 0xCD:
            return _stale_census("native INT disagrees with retained transfer or supported encoding")
        return final.address, encoding[1]
    if block.jumpkind == "Ijk_Call" or any(final.group(group) for group in transfers[:-1]):
        return _stale_census("retained service boundary is not an admitted native INT")
    return _ordinary_successor_refusal(block, final)


def _ordinary_successor_refusal(
    block: ServiceBlockEnding, final: capstone.CsInsn,
) -> TerminalRefusal | None:
    """Authenticate ordinary fallthrough/direct-jump edges before the census."""
    if block.next_target is None:
        return None  # Fault outcome and fault-site evidence are checked separately.
    expected = final.address + final.size
    if final.group(capstone.CS_GRP_JUMP):
        operands = final.operands
        if final.id != decoded_ids.X86_INS_JMP or len(operands) != 1 or operands[0].type != decoded_ids.X86_OP_IMM:
            return _stale_census("ordinary successor lacks a supported native direct-jump target")
        expected = int(operands[0].imm)
    if block.next_target != expected:
        return _stale_census("ordinary successor disagrees with native instruction semantics")
    return None


def _closing_interrupt_refusal(
    block: ServiceBlockEnding, site: int, vector: int, *,
    terminal_site: int | None, terminal_target: int | None, fault_outcome: bool,
) -> TerminalRefusal | None:
    """Authenticate the closing interrupt against the terminal or fault outcome."""
    if fault_outcome:
        if block.next_target is not None or vector not in (DOS_VECTOR, VIDEO_VECTOR):
            return _stale_census("fault boundary claims a successor or unsupported dispatch")
        return None
    if terminal_site is None:
        return _stale_census("trace closes on a boundary its outcome does not declare")
    if vector != DOS_VECTOR or site != terminal_site or block.next_target != terminal_target:
        return _stale_census("closing native INT does not bind the declared DOS termination site")
    return None


def _declared_returning_boundary(
    site: int, vector: int, *, version_policy: VersionPolicy | None,
    video_policy: VideoQueryPolicy | None,
) -> ReturningBoundary | TerminalRefusal:
    """Project one authenticated returning vector through its declared contract."""
    if vector == DOS_VECTOR and version_policy is not None:
        return ReturningBoundary(
            site, vector, VERSION_FUNCTION, ProgramEventKind.DOS_VERSION,
            version_event_data(version_policy),
        )
    if vector == VIDEO_VECTOR and video_policy is not None:
        return ReturningBoundary(
            site, vector, VIDEO_FUNCTION, ProgramEventKind.BIOS_VIDEO_QUERY,
            video_query_event_data(video_policy),
        )
    return _stale_census(f"executed INT at {hex(site)} lacks a declared returning contract")


def _census_block(
    block: ServiceBlockEnding, native: tuple[int, int] | None, *, is_last: bool,
    version_policy: VersionPolicy | None, video_policy: VideoQueryPolicy | None,
    terminal_site: int | None, terminal_target: int | None, fault_outcome: bool,
) -> ReturningBoundary | TerminalRefusal | None:
    """Classify one byte-authenticated block without trusting its transfer tag."""
    if native is None:
        if is_last and terminal_site is not None:
            return _stale_census("declared terminal outcome lacks its native interrupt")
        if not is_last and block.jumpkind not in _MIDDLE_JUMPKINDS:
            return _stale_census("middle block has a non-admitted transfer")
        return None
    site, vector = native
    if is_last:
        return _closing_interrupt_refusal(
            block, site, vector, terminal_site=terminal_site,
            terminal_target=terminal_target, fault_outcome=fault_outcome,
        )
    if block.next_target != site + 2:
        return _stale_census("returning native INT does not continue at its exact fallthrough")
    return _declared_returning_boundary(
        site, vector, version_policy=version_policy, video_policy=video_policy,
    )


def returning_service_census(
    endings: tuple[ServiceBlockEnding, ...],
    read: Callable[[int, int], bytes | None],
    *,
    version_policy: VersionPolicy | None,
    video_policy: VideoQueryPolicy | None,
    terminal_site: int | None,
    terminal_target: int | None,
    fault_outcome: bool,
    limits: NativeDecodeLimits = DEFAULT_NATIVE_LIMITS,
) -> tuple[ReturningBoundary, ...] | TerminalRefusal:
    """Derive every returning INT from bounded native decode in execution order.

    Retained transfer tags alone cannot admit or suppress a service. Decode
    each complete block from authenticated bytes, reject hidden earlier control
    transfers, and require exact instruction-aligned INT endings and successor
    continuity. The declared native terminal/fault closes the census. Receipts
    are checked separately against this independently derived denominator.
    """
    if not endings or len(endings) > limits.max_blocks:
        return _stale_census("block census is empty or exceeds the existing block budget")
    if fault_outcome and terminal_site is not None:
        return _stale_census("trace claims a processor fault and terminal site together")
    boundaries: list[ReturningBoundary] = []
    for index, block in enumerate(endings):
        is_last = index == len(endings) - 1
        if not is_last and block.next_target != endings[index + 1].address:
            return _stale_census("block does not continue to its recorded successor")
        native = _native_interrupt_boundary(block, read, limits)
        if isinstance(native, TerminalRefusal):
            return native
        boundary = _census_block(
            block, native, is_last=is_last, version_policy=version_policy,
            video_policy=video_policy, terminal_site=terminal_site,
            terminal_target=terminal_target, fault_outcome=fault_outcome,
        )
        if isinstance(boundary, TerminalRefusal):
            return boundary
        if boundary is not None:
            boundaries.append(boundary)
    return tuple(boundaries)


def verify_returning_receipts(
    events: tuple[TerminalServiceEvent, ...],
    endings: tuple[ServiceBlockEnding, ...],
    read: Callable[[int, int], bytes | None],
    *,
    version_policy: VersionPolicy | None,
    video_policy: VideoQueryPolicy | None,
    terminal_site: int | None,
    terminal_target: int | None,
    fault_outcome: bool,
    outputs: int,
    counters: FactCounters,
    limits: NativeDecodeLimits = DEFAULT_NATIVE_LIMITS,
) -> TerminalRefusal | None:
    """Require the retained receipts to answer the executed-boundary census.

    The census — re-derived from the authenticated block evidence and the
    declared selectors — fixes the denominator: exactly one receipt per
    executed returning boundary, in receipt order, with its site, vector,
    function, kind and declared payload all re-derived rather than trusted.
    Count equality plus positional binding refutes removed, duplicated,
    reordered, mis-sited and mis-payloaded receipt lists alike, while
    legitimate repeated dispatches keep their per-occurrence receipts. The
    closed fact counters must also re-derive from the admitted evidence —
    ``raw``/``normalized`` count every block plus every boundary, the
    outcome is the one extra classified fact, every boundary and output
    must materialize, and nothing may fail silently — so a forged counter
    set refuses as ``STALE_EVIDENCE``.
    """
    census = returning_service_census(
        endings,
        read,
        version_policy=version_policy,
        video_policy=video_policy,
        terminal_site=terminal_site,
        terminal_target=terminal_target,
        fault_outcome=fault_outcome,
        limits=limits,
    )
    if isinstance(census, TerminalRefusal):
        return census
    if len(events) != len(census):
        return TerminalRefusal(
            TerminalRefusalKind.STALE_EVIDENCE,
            f"returning-service census admits {len(census)} executed boundaries "
            f"but the trace retains {len(events)} receipts",
        )
    for index, (event, boundary) in enumerate(zip(events, census, strict=True)):
        if (
            event.address != boundary.site
            or event.vector != boundary.vector
            or event.function != boundary.function
            or event.kind is not boundary.kind
        ):
            return TerminalRefusal(
                TerminalRefusalKind.STALE_EVIDENCE,
                f"receipt {index} does not bind the executed boundary at "
                f"{hex(boundary.site)}",
            )
        if event.data != boundary.receipt:
            return TerminalRefusal(
                TerminalRefusalKind.STALE_EVIDENCE,
                f"receipt at {hex(boundary.site)} does not re-derive from the "
                "declared environment",
            )
    evidence = len(endings) + len(census)
    expected = FactCounters(
        raw_fact_count=evidence,
        normalized_fact_count=evidence,
        classified_fact_count=evidence + 1,
        materialized_count=outputs + len(census),
        failure_count=0,
    )
    if counters != expected:
        return TerminalRefusal(
            TerminalRefusalKind.STALE_EVIDENCE,
            "trace fact counters do not re-derive from the admitted evidence census",
        )
    return None
