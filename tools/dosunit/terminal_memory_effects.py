"""Memory-effect admission at the symbolic terminal intake boundary.

Layer: dosunit symbolic program proof.
Responsibility: own the typed refusal vocabulary for the bounded terminal
comparison and audit every memory effect a lifted native region produces —
stores AND loads — at intake time, before any output term is materialized or
compared. Loads live inside register, temporary and store-value terms whether
or not a compared output reaches them, so the audit walks the complete
lowering state; discarded and dead reads are concrete fault obligations, not
optional evidence. Each ``loadle``/``loadbe`` address and each
``storele``/``storebe`` destination must be proved concrete under the
declared seed and admitted by the lane's declared readable/writable domain —
unproved coordinates and undeclared accesses are typed refusals, matching the
concrete replays' unmapped-access faults. The auditor also records which
proved reads reach the shared initial memory, so the comparison can verify
the concrete boot pair actually satisfies the declared initial-data relation
instead of assuming it.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import StrEnum

from tools.dosunit import straightline_ssa as S


class TerminalRefusalKind(StrEnum):
    """Typed bounded-admission failures; each names a distinct missing proof."""

    BOOT_CONTRACT = "boot_contract_refused"
    UNSUPPORTED_ENVIRONMENT = "unsupported_environment_contract"
    LIFT = "native_lift_incomplete"
    DECODE = "native_decode_incomplete"
    INSTRUCTION_SCOPE = "instruction_scope_refused"
    ENVIRONMENT_EFFECT = "environment_effect_refused"
    CONDITIONAL_CONTROL = "conditional_control"
    INDIRECT_CONTROL = "indirect_control"
    CALL_BOUNDARY = "call_boundary"
    RETURN_NOT_TERMINAL = "return_not_terminal"
    LOOP_BOUNDARY = "loop_boundary"
    CONTROL_ESCAPE = "control_escape"
    FAULT_BOUNDARY = "fault_boundary"
    BLOCK_LIMIT = "block_limit"
    UNDECLARED_SERVICE = "undeclared_service"
    SERVICE_ENCODING = "service_encoding_mismatch"
    SERVICE_GUARD_UNPROVED = "service_guard_unproved"
    INTERRUPT_FRAME = "interrupt_frame_refused"
    STACK_ARGUMENT = "exit_argument_undeclared"
    UNPROVED_POINTER = "unproved_pointer"
    FAULT_GUARD_UNPROVED = "fault_guard_unproved"
    UNDECLARED_READ = "undeclared_read"
    UNDECLARED_WRITE = "undeclared_write"
    CODE_WRITE = "code_write_refused"
    UNSUPPORTED_IR = "unsupported_ir"
    STALE_EVIDENCE = "stale_native_bytes_or_identity"


class TerminalRefusal(Exception):
    """One typed admission failure; the trace dies with this reason."""

    def __init__(self, kind: TerminalRefusalKind, detail: str) -> None:
        """Bind the refusal to its kind and evidence detail."""
        super().__init__(f"{kind.value}:{detail}")
        self.kind = kind
        self.detail = detail


_CONST_BINOPS: dict[str, Callable[[int, int, int], int]] = {
    "add": lambda a, b, w: (a + b) & ((1 << w) - 1),
    "sub": lambda a, b, w: (a - b) & ((1 << w) - 1),
    "mul": lambda a, b, w: (a * b) & ((1 << w) - 1),
    "and": lambda a, b, w: a & b & ((1 << w) - 1),
    "or": lambda a, b, w: (a | b) & ((1 << w) - 1),
    "xor": lambda a, b, w: (a ^ b) & ((1 << w) - 1),
    "shl": lambda a, b, w: (a << b) & ((1 << w) - 1),
    "lshr": lambda a, b, w: (a >> b) & ((1 << w) - 1),
    "ashr": lambda a, b, w: (_const_sign_extend(a, w) >> b) & ((1 << w) - 1),
}

_UNSIGNED_COMPARISONS: dict[str, Callable[[int, int], bool]] = {
    "eq": lambda a, b: a == b,
    "ne": lambda a, b: a != b,
    "ult": lambda a, b: a < b,
    "ule": lambda a, b: a <= b,
    "ugt": lambda a, b: a > b,
    "uge": lambda a, b: a >= b,
}

_SIGNED_COMPARISONS: dict[str, Callable[[int, int], bool]] = {
    "slt": lambda a, b: a < b,
    "sle": lambda a, b: a <= b,
    "sgt": lambda a, b: a > b,
    "sge": lambda a, b: a >= b,
}

_COMPARISON_OPS: frozenset[str] = frozenset(
    (*_UNSIGNED_COMPARISONS, *_SIGNED_COMPARISONS)
)


def _const_sign_extend(value: int, bits: int) -> int:
    """Reinterpret a masked ``bits``-wide constant as signed."""
    return value - (1 << bits) if value >= (1 << (bits - 1)) else value


def _const_trunc_div(dividend: int, divisor: int) -> int:
    """Signed division truncated toward zero, matching ``sdiv`` semantics."""
    quotient = abs(dividend) // abs(divisor)
    return -quotient if (dividend < 0) != (divisor < 0) else quotient


def _const_division(expr: S.SsaExpr, width_mask: int) -> int | None:
    """Evaluate one defined division or remainder term.

    Undefined division is never totalized: a zero or unproved divisor makes
    the term unprovable and every caller treats that as a typed refusal or
    an already unreachable path.
    """
    left, right = (const_eval(arg) for arg in expr.args[:2])
    if left is None or right is None:
        return None
    if expr.op in {"udiv", "urem"}:
        if right == 0:
            return None
        quotient = left // right if expr.op == "udiv" else left % right
        return quotient & width_mask
    left_signed = _const_sign_extend(left, int(expr.args[0].width))
    right_signed = _const_sign_extend(right, int(expr.args[1].width))
    if right_signed == 0:
        return None
    quotient = _const_trunc_div(left_signed, right_signed)
    remainder = left_signed - quotient * right_signed
    return (quotient if expr.op == "sdiv" else remainder) & width_mask


def _const_comparison(expr: S.SsaExpr) -> int | None:
    """Evaluate one unsigned or signed comparison term to a truth bit."""
    left, right = (const_eval(arg) for arg in expr.args[:2])
    if left is None or right is None:
        return None
    if expr.op in _SIGNED_COMPARISONS:
        left = _const_sign_extend(left, int(expr.args[0].width))
        right = _const_sign_extend(right, int(expr.args[1].width))
        return int(_SIGNED_COMPARISONS[expr.op](left, right))
    return int(_UNSIGNED_COMPARISONS[expr.op](left, right))


def _const_unary(expr: S.SsaExpr, width_mask: int) -> int | None:
    """Evaluate one coercion or bitwise-not term over a proved child."""
    inner = const_eval(expr.args[0])
    if inner is None:
        return None
    if expr.op == "sext":
        return _const_sign_extend(inner, int(expr.args[0].width)) & width_mask
    if expr.op == "not":
        return (~inner) & width_mask
    return inner & width_mask


def const_eval(expr: S.SsaExpr) -> int | None:
    """Evaluate a term built only of constants; symbolic stays unproved.

    Under the declared concrete register seed, frame addresses, selectors,
    fault guards and stack-argument coordinates are proved by this evaluator
    or refused as unproved — never guessed. Memory-derived terms return
    ``None``. Division operators are defined only for a proved nonzero
    divisor: a zero divisor is not totalized into a bogus value — the term is
    unprovable and every caller treats it as a typed refusal or an already
    unreachable path.
    """
    width_mask = (1 << int(expr.width)) - 1
    if expr.op == "const":
        return int(expr.value or 0) & width_mask
    if expr.op in {"zext", "trunc", "sext", "not"}:
        return _const_unary(expr, width_mask)
    if expr.op == "concat":
        left, right = (const_eval(arg) for arg in expr.args[:2])
        return None if left is None or right is None else (left << expr.args[1].width) | right
    if expr.op in _CONST_BINOPS:
        left, right = (const_eval(arg) for arg in expr.args[:2])
        if left is None or right is None:
            return None
        return _CONST_BINOPS[expr.op](left, right, int(expr.width))
    if expr.op in {"udiv", "urem", "sdiv", "srem"}:
        return _const_division(expr, width_mask)
    if expr.op in _COMPARISON_OPS:
        return _const_comparison(expr)
    return None


def overlay_bytes(
    layers: Iterable[Iterable[tuple[int, bytes]]], address: int, size: int
) -> bytes | None:
    """Compose the concrete initial bytes at ``[address, address+size)``.

    ``layers`` are chunk tables in priority order — the first layer covering
    a byte wins, mirroring the concrete replay's write order (later loader
    writes overlay earlier ones, so callers pass the last-written layer
    first). ``None`` means at least one byte has no declared initializer and
    is genuinely unconstrained in the boot contract.
    """
    if size <= 0:
        return b""
    out = bytearray(size)
    covered = [False] * size
    for chunks in layers:
        for start, data in chunks:
            lo = max(address, start)
            hi = min(address + size, start + len(data))
            for offset in range(lo, hi):
                index = offset - address
                if not covered[index]:
                    out[index] = data[offset - start]
                    covered[index] = True
    return bytes(out) if all(covered) else None


def check_memory_writes(
    mem_version: S.SsaExpr, admit: Callable[[int, int], None]
) -> None:
    """Audit every symbolic store on the final memory version.

    Each ``storele``/``storebe`` node's address must be proved concrete under
    the declared seed and admitted by ``admit`` — symbolic destinations,
    undeclared memory and code-range writes are typed refusals, matching the
    concrete replays' write gates.
    """
    expr = mem_version
    while expr.op in {"storele", "storebe"}:
        address = const_eval(expr.args[1])
        size = expr.args[2].width // 8
        if address is None:
            raise TerminalRefusal(
                TerminalRefusalKind.UNPROVED_POINTER,
                "memory store destination is not proved concrete",
            )
        admit(address, size)
        expr = expr.args[0]
    if expr.op != "mem_input":
        raise TerminalRefusal(
            TerminalRefusalKind.UNSUPPORTED_IR, "memory chain does not end at the shared input"
        )


@dataclass(frozen=True, slots=True)
class InitialReadSite:
    """One proved read of shared initial memory.

    ``initialized`` is this lane's concrete initial bytes at the site —
    ``None`` when the boot contract leaves the range unconstrained. The
    comparison requires the other lane's concrete bytes to agree exactly;
    anything else falsifies the shared-initial-memory premise.
    """

    address: int
    size: int
    initialized: bytes | None


class MemoryReadAuditor:
    """Audit every memory read a lowered region produces at effect intake.

    The shared input memory is symbolic, so a load always produces a term —
    the concrete program still faults when the address is unmapped. Walking
    the full lowering state after each block (temps, register versions, the
    memory chain and the lowered successor) catches live, intermediate and
    discarded reads identically: unproved addresses refuse as
    ``UNPROVED_POINTER``, unadmitted ranges refuse through the lane's
    ``admit`` callback, and proved reads reaching the initial memory are
    recorded as :class:`InitialReadSite` evidence for the cross-boot
    initial-data check.
    """

    def __init__(
        self,
        *,
        admit: Callable[[int, int], None],
        initial_bytes: Callable[[int, int], bytes | None],
    ) -> None:
        """Bind the lane's readable-domain admission and byte resolver."""
        self._admit = admit
        self._initial_bytes = initial_bytes
        # Keep each referent alive: integer IDs alone can be reused after a
        # block discards its temporary expressions, hiding a later read.
        self._seen: dict[int, S.SsaExpr] = {}
        self._sites: dict[tuple[int, int], bytes | None] = {}

    def audit_state(self, state: S._IrsbLowerState, *extra: S.SsaExpr | None) -> None:
        """Audit every term the just-lowered block introduced into the state."""
        terms: tuple[S.SsaExpr | None, ...] = (
            *state.temp_defs.values(),
            *state.reg_versions.values(),
            state.mem_version,
            state.ip_expr,
            *extra,
        )
        for term in terms:
            if term is not None:
                self.audit_term(term)

    def audit_term(self, expr: S.SsaExpr) -> None:
        """Audit every load reachable from one lowered term, once each."""
        if id(expr) in self._seen:
            return
        self._seen[id(expr)] = expr
        for arg in expr.args:
            self.audit_term(arg)
        if expr.op in {"loadle", "loadbe"}:
            self._admit_load(expr)

    def _admit_load(self, expr: S.SsaExpr) -> None:
        """Require a proved concrete address inside the declared read domain."""
        address = const_eval(expr.args[1])
        if address is None:
            raise TerminalRefusal(
                TerminalRefusalKind.UNPROVED_POINTER,
                "memory load address is not proved concrete",
            )
        size = expr.width // 8
        self._admit(address, size)
        for start, length in self._initial_ranges(expr.args[0], address, size):
            self._sites.setdefault((start, length), self._initial_bytes(start, length))

    @staticmethod
    def _initial_ranges(
        mem_version: S.SsaExpr, address: int, size: int
    ) -> tuple[tuple[int, int], ...]:
        """Retain precisely the read lanes not overwritten by earlier stores.

        One overlapping store does not initialize a whole wider load. Walk
        the store chain and subtract its byte coverage, keeping every remaining
        lane bound to the boot pair's initial-data relation.
        """
        uncovered = [(address, address + size)]
        expr = mem_version
        while expr.op in {"storele", "storebe"}:
            store_address = const_eval(expr.args[1])
            if store_address is None:
                raise TerminalRefusal(
                    TerminalRefusalKind.UNPROVED_POINTER,
                    "cannot establish read initialization through a symbolic store",
                )
            store_size = expr.args[2].width // 8
            uncovered = _subtract_store_coverage(uncovered, store_address, store_size)
            if not uncovered:
                return ()
            expr = expr.args[0]
        if expr.op != "mem_input":
            raise TerminalRefusal(
                TerminalRefusalKind.UNSUPPORTED_IR,
                "read memory chain does not end at the shared input",
            )
        return tuple((start, end - start) for start, end in uncovered)

    def initial_sites(self) -> tuple[InitialReadSite, ...]:
        """Return the deduplicated proved initial-memory reads, sorted."""
        return tuple(
            InitialReadSite(address, size, initialized)
            for (address, size), initialized in sorted(self._sites.items())
        )


def _subtract_store_coverage(
    ranges: list[tuple[int, int]], address: int, size: int
) -> list[tuple[int, int]]:
    """Subtract one concrete store from disjoint half-open read intervals."""
    remaining: list[tuple[int, int]] = []
    store_end = address + size
    for start, end in ranges:
        if end <= address or store_end <= start:
            remaining.append((start, end))
            continue
        if start < address:
            remaining.append((start, address))
        if store_end < end:
            remaining.append((store_end, end))
    return remaining
