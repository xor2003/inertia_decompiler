"""Exact-byte near-relative control evidence.

Layer: frontend control semantics.
Responsibility: retain immutable instruction bytes and derived relative-edge
facts, projecting architectural and loaded destinations through the shared
coordinate owner. Neither CS nor a concrete CFG target is guessed.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256
from typing import NoReturn

from .control_coordinates import (
    ControlAddressDomain,
    ControlWidth,
    CoordinateConstant,
    CoordinateValue,
    architectural_offset,
    linear_continuation,
    relative_offset,
)


class RelativeEdgeForm(StrEnum):
    """Typed near-relative control form decoded from complete bytes."""

    JMP_REL8 = "jmp_rel8"
    JCC_REL8 = "jcc_rel8"
    LOOP_REL8 = "loop_rel8"
    JCXZ_REL8 = "jcxz_rel8"
    CALL_REL16 = "call_rel16"
    JMP_REL16 = "jmp_rel16"
    JCC_REL16 = "jcc_rel16"
    CALL_REL32 = "call_rel32"
    JMP_REL32 = "jmp_rel32"
    JCC_REL32 = "jcc_rel32"


class RelativeEdgeRefusalReason(StrEnum):
    """Bounded reason a complete byte string is not a supported edge."""

    EMPTY_ENCODING = "empty_encoding"
    UNSUPPORTED_PREFIX = "unsupported_prefix"
    UNSUPPORTED_FORM = "unsupported_form"
    LENGTH_MISMATCH = "length_mismatch"


# Non-displacement byte count (prefix plus opcode) and displacement width
# for each supported form. Encoded size is prefix bytes + displacement bytes.
_FORM_LAYOUT: dict[RelativeEdgeForm, tuple[int, int]] = {
    RelativeEdgeForm.JMP_REL8: (1, 8),
    RelativeEdgeForm.JCC_REL8: (1, 8),
    RelativeEdgeForm.LOOP_REL8: (1, 8),
    RelativeEdgeForm.JCXZ_REL8: (1, 8),
    RelativeEdgeForm.CALL_REL16: (1, 16),
    RelativeEdgeForm.JMP_REL16: (1, 16),
    RelativeEdgeForm.JCC_REL16: (2, 16),
    RelativeEdgeForm.CALL_REL32: (2, 32),
    RelativeEdgeForm.JMP_REL32: (2, 32),
    RelativeEdgeForm.JCC_REL32: (3, 32),
}

_CONDITIONAL_FORMS: frozenset[RelativeEdgeForm] = frozenset({
    RelativeEdgeForm.JCC_REL8,
    RelativeEdgeForm.LOOP_REL8,
    RelativeEdgeForm.JCXZ_REL8,
    RelativeEdgeForm.JCC_REL16,
    RelativeEdgeForm.JCC_REL32,
})

_CALL_FORMS: frozenset[RelativeEdgeForm] = frozenset({
    RelativeEdgeForm.CALL_REL16,
    RelativeEdgeForm.CALL_REL32,
})

# Prefix bytes the contract does not accept at all. 0x66 is handled
# separately because it is supported only before E8/E9 and 0F 80..8F.
_UNSUPPORTED_PREFIX_BYTES: frozenset[int] = frozenset({
    0xF0, 0xF2, 0xF3, 0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0x67,
})


def _unprefixed_form(opcode: int) -> RelativeEdgeForm | None:
    """Return the unprefixed relative form of one opcode byte, if any."""
    if opcode == 0xEB:
        return RelativeEdgeForm.JMP_REL8
    if 0x70 <= opcode <= 0x7F:
        return RelativeEdgeForm.JCC_REL8
    if opcode in (0xE0, 0xE1, 0xE2):
        return RelativeEdgeForm.LOOP_REL8
    if opcode == 0xE3:
        return RelativeEdgeForm.JCXZ_REL8
    if opcode == 0xE8:
        return RelativeEdgeForm.CALL_REL16
    if opcode == 0xE9:
        return RelativeEdgeForm.JMP_REL16
    return None


def _classify_jcc16(encoding: bytes) -> RelativeEdgeForm | RelativeEdgeRefusalReason:
    """Classify a 0F-leading encoding as Jcc rel16 or a refusal."""
    if len(encoding) < 2:
        return RelativeEdgeRefusalReason.LENGTH_MISMATCH
    if not 0x80 <= encoding[1] <= 0x8F:
        return RelativeEdgeRefusalReason.UNSUPPORTED_FORM
    if len(encoding) != 4:
        return RelativeEdgeRefusalReason.LENGTH_MISMATCH
    return RelativeEdgeForm.JCC_REL16


def _classify_dword(encoding: bytes) -> RelativeEdgeForm | RelativeEdgeRefusalReason:
    """Classify a 66-leading encoding as rel32 or a refusal."""
    if len(encoding) < 2:
        return RelativeEdgeRefusalReason.LENGTH_MISMATCH
    opcode = encoding[1]
    if opcode == 0x0F:
        if len(encoding) < 3:
            return RelativeEdgeRefusalReason.LENGTH_MISMATCH
        if not 0x80 <= encoding[2] <= 0x8F:
            return RelativeEdgeRefusalReason.UNSUPPORTED_FORM
        if len(encoding) != 7:
            return RelativeEdgeRefusalReason.LENGTH_MISMATCH
        return RelativeEdgeForm.JCC_REL32
    if opcode not in (0xE8, 0xE9):
        # 0x66 before any other opcode (including the rel8 family) is
        # outside the supported contract, not a guessed rel8-with-prefix.
        return RelativeEdgeRefusalReason.UNSUPPORTED_PREFIX
    if len(encoding) != 6:
        return RelativeEdgeRefusalReason.LENGTH_MISMATCH
    return RelativeEdgeForm.CALL_REL32 if opcode == 0xE8 else RelativeEdgeForm.JMP_REL32


def _classify_encoding(encoding: bytes) -> RelativeEdgeForm | RelativeEdgeRefusalReason:
    """Map complete instruction bytes to a supported form or refusal."""
    if not encoding:
        return RelativeEdgeRefusalReason.EMPTY_ENCODING
    lead = encoding[0]
    if lead in _UNSUPPORTED_PREFIX_BYTES:
        return RelativeEdgeRefusalReason.UNSUPPORTED_PREFIX
    if lead == 0x66:
        return _classify_dword(encoding)
    if lead == 0x0F:
        return _classify_jcc16(encoding)
    form = _unprefixed_form(lead)
    if form is None:
        return RelativeEdgeRefusalReason.UNSUPPORTED_FORM
    prefix_len, displacement_bits = _FORM_LAYOUT[form]
    if len(encoding) != prefix_len + displacement_bits // 8:
        return RelativeEdgeRefusalReason.LENGTH_MISMATCH
    return form


@dataclass(frozen=True, slots=True)
class RelativeEdgeRefusal:
    """Typed non-result retaining the exact bytes that failed to decode.

    A refusal is evidence of "no supported form", never a guessed default.
    ``head``, ``encoding`` and ``source`` preserve the caller's input
    identity so receipts can attribute the refusal to its exact bytes.
    """

    reason: RelativeEdgeRefusalReason
    head: int
    encoding: bytes
    source: str | None = None


@dataclass(frozen=True, slots=True)
class RelativeEdgeTargets:
    """One CS-domain evaluation of a decoded edge's architectural effects.

    Offsets are architectural IP/EIP values wrapped at the edge's operand
    width. Controls are full-width loaded destinations composed with CS by
    the authoritative coordinate owner.
    """

    taken_offset: CoordinateValue
    fallthrough_offset: CoordinateValue
    taken_control: CoordinateValue
    fallthrough_control: CoordinateValue


@dataclass(frozen=True, slots=True)
class DecodedRelativeEdge:
    """Immutable exact-byte near-relative control edge.

    ``head`` is the instruction head coordinate in the caller-declared
    control domain (loader-linear for LOADER_LINEAR, an architectural
    offset for ARCHITECTURAL_OFFSET). ``encoding`` retains the complete
    input bytes verbatim. ``width`` is the architectural operand wrap width
    derived from those bytes, and ``displacement`` is the signed
    displacement derived once from them. ``source`` is an opaque identity
    label retained for receipts; it is never interpreted as semantics.

    The edge stores no resolved target integer and no CS value: targets
    exist only as the projections below, evaluated under an explicit CS.
    """

    head: int
    encoding: bytes
    form: RelativeEdgeForm
    width: ControlWidth
    displacement: int
    source: str | None = None

    def __post_init__(self) -> None:
        """Re-derive every stored invariant from the retained bytes."""
        if type(self.head) is not int:
            raise TypeError("head must be an int coordinate")
        if not 0 <= self.head <= 0xFFFFFFFF:
            raise ValueError("head requires an unsigned32 control coordinate")
        if type(self.encoding) is not bytes:
            raise TypeError("encoding must be exact bytes")
        if _classify_encoding(self.encoding) is not self.form:
            raise ValueError("encoding bytes do not match declared form")
        prefix_len, displacement_bits = _FORM_LAYOUT[self.form]
        expected_width = ControlWidth.DWORD if displacement_bits == 32 else ControlWidth.WORD
        if self.width is not expected_width:
            raise ValueError("operand width inconsistent with form")
        displacement = int.from_bytes(self.encoding[prefix_len:], "little", signed=True)
        if displacement != self.displacement:
            raise ValueError("displacement inconsistent with encoding")

    @property
    def encoded_size(self) -> int:
        """Return the complete instruction length in bytes."""
        return len(self.encoding)

    @property
    def next_head(self) -> int:
        """Return the head coordinate of the next instruction, same domain."""
        return self.head + len(self.encoding)

    @property
    def displacement_bits(self) -> int:
        """Return the encoded displacement width in bits."""
        return _FORM_LAYOUT[self.form][1]

    @property
    def is_conditional(self) -> bool:
        """Return whether the form has an architecturally live untaken edge."""
        return self.form in _CONDITIONAL_FORMS

    @property
    def is_call(self) -> bool:
        """Return whether the form is a near call."""
        return self.form in _CALL_FORMS

    @property
    def encoding_digest(self) -> str:
        """Return a stable digest of the exact bytes for receipts."""
        return sha256(self.encoding).hexdigest()

    def fallthrough_offset(
        self, cs: CoordinateValue, constant: CoordinateConstant, *,
        domain: ControlAddressDomain = ControlAddressDomain.LOADER_LINEAR,
    ) -> CoordinateValue:
        """Return the architectural IP/EIP of the untaken edge, wrapped."""
        return architectural_offset(
            self.next_head, cs, self.width, constant, domain=domain,
        )

    def taken_offset(
        self, cs: CoordinateValue, constant: CoordinateConstant, *,
        domain: ControlAddressDomain = ControlAddressDomain.LOADER_LINEAR,
    ) -> CoordinateValue:
        """Return the architectural IP/EIP of the taken edge, wrapped."""
        return relative_offset(self.next_head, cs, self.displacement, self.width, constant, domain=domain)

    def fallthrough_control(
        self, cs: CoordinateValue, constant: CoordinateConstant, *,
        domain: ControlAddressDomain = ControlAddressDomain.LOADER_LINEAR,
    ) -> CoordinateValue:
        """Return the full-width loaded destination of the untaken edge."""
        offset = self.fallthrough_offset(cs, constant, domain=domain)
        return linear_continuation(
            cs, offset, self.width, constant,
            control_width=ControlWidth.DWORD, domain=domain,
        )

    def taken_control(
        self, cs: CoordinateValue, constant: CoordinateConstant, *,
        domain: ControlAddressDomain = ControlAddressDomain.LOADER_LINEAR,
    ) -> CoordinateValue:
        """Return the full-width loaded destination of the taken edge."""
        offset = self.taken_offset(cs, constant, domain=domain)
        return linear_continuation(
            cs, offset, self.width, constant,
            control_width=ControlWidth.DWORD, domain=domain,
        )

    def project(
        self, cs: CoordinateValue, constant: CoordinateConstant, *,
        domain: ControlAddressDomain = ControlAddressDomain.LOADER_LINEAR,
    ) -> RelativeEdgeTargets:
        """Evaluate all four edge destinations under one explicit CS."""
        fallthrough = self.fallthrough_offset(cs, constant, domain=domain)
        taken = self.taken_offset(cs, constant, domain=domain)
        return RelativeEdgeTargets(
            taken_offset=taken,
            fallthrough_offset=fallthrough,
            taken_control=linear_continuation(
                cs, taken, self.width, constant,
                control_width=ControlWidth.DWORD, domain=domain,
            ),
            fallthrough_control=linear_continuation(
                cs, fallthrough, self.width, constant,
                control_width=ControlWidth.DWORD, domain=domain,
            ),
        )


def decode_relative_edge(
    head: int, encoding: bytes, *, source: str | None = None,
) -> DecodedRelativeEdge | RelativeEdgeRefusal:
    """Decode complete instruction bytes into a typed edge or a refusal.

    ``head`` is the instruction head coordinate in the caller's control
    domain; it is retained, not interpreted. ``encoding`` must be the
    complete instruction bytes only: a recognized form with missing or
    trailing bytes refuses as LENGTH_MISMATCH. ``source`` is an opaque
    identity label retained verbatim.
    """
    if type(head) is not int or type(encoding) is not bytes:
        raise TypeError("relative edge requires an integer head and exact bytes")
    if not 0 <= head <= 0xFFFFFFFF:
        raise ValueError("head requires an unsigned32 control coordinate")
    raw = encoding
    classified = _classify_encoding(raw)
    if isinstance(classified, RelativeEdgeRefusalReason):
        return RelativeEdgeRefusal(
            reason=classified, head=head, encoding=raw, source=source,
        )
    prefix_len, displacement_bits = _FORM_LAYOUT[classified]
    displacement = int.from_bytes(raw[prefix_len:], "little", signed=True)
    width = ControlWidth.DWORD if displacement_bits == 32 else ControlWidth.WORD
    return DecodedRelativeEdge(
        head=head, encoding=raw, form=classified,
        width=width, displacement=displacement, source=source,
    )


type RelativeEdgeDecode = DecodedRelativeEdge | RelativeEdgeRefusal


class RelativeDestinationVerdict(StrEnum):
    """Whether exact relative bytes select one full loaded target for all fetch CS."""

    PROVEN = "proven"
    EMPTY_FETCH_DOMAIN = "empty_fetch_domain"
    SELECTOR_DEPENDENT = "selector_dependent"


@dataclass(frozen=True, slots=True)
class RelativeDestination:
    """Constant-time selector-interval evidence, without a native IR binding claim."""

    verdict: RelativeDestinationVerdict
    target: int | None
    selector_min: int
    selector_max: int


def _concrete_projection_only(value: object, width: object) -> NoReturn:
    """Reject accidental symbolic input at the concrete interval boundary."""
    raise TypeError(f"expected concrete coordinate, received {value!r}:{width!r}")


def invariant_relative_destination(edge: DecodedRelativeEdge) -> RelativeDestination:
    """Project a decoded edge under every CS capable of fetching its head.

    WORD offsets are modular *inside* CS, never in loader coordinates.
    Fetch selectors form an interval whose base span is less than 65536.
    Across that interval the WORD destination is a monotone step function:
    base + ((next + displacement - base) mod 65536). Equal endpoint values
    therefore prove invariance without enumerating selectors. DWORD
    composition cancels the base modulo 2**32, so its endpoints also agree.
    This proves byte coordinates only; consumers must separately bind IR.
    """
    minimum = max(0, (edge.head - 0xFFFF + 15) // 16)
    maximum = min(0xFFFF, edge.head // 16)
    if minimum > maximum:
        return RelativeDestination(RelativeDestinationVerdict.EMPTY_FETCH_DOMAIN, None, minimum, maximum)
    first = edge.taken_control(minimum, _concrete_projection_only)
    last = edge.taken_control(maximum, _concrete_projection_only)
    if not isinstance(first, int) or not isinstance(last, int):
        raise TypeError("concrete selector projection produced a symbolic destination")
    if first != last:
        return RelativeDestination(RelativeDestinationVerdict.SELECTOR_DEPENDENT, None, minimum, maximum)
    return RelativeDestination(RelativeDestinationVerdict.PROVEN, first, minimum, maximum)
