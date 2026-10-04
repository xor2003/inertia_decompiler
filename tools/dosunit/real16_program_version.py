"""Bounded opt-in DOS INT21/AH=30 AL=00 version-query contract for initialized MZ replay.

Layer: dosunit concrete execution contracts.
Responsibility: declare the typed policy, outcome records, pure admission
logic, identity projection and manifest parsing for the DOS version-query
service available to whole-program replay. The contract is an explicit
synthetic environment declaration: the caller states the exact AL=major,
AH=minor, BH=OEM, BL:CX=serial24 response a query observes. Nothing here
models an actually installed DOS, and the declared fields are bounded
caller-supplied data, never proof of real DOS behavior. An accepted query's
response effect is the three documented low-half register updates and
the checked fallthrough IP; the executor preserves the upper halves of
EAX/EBX/ECX, every flag and segment. Architectural INT stack writes are
modeled separately before the service response. Concrete execution
evidence only, never symbolic proof. This module performs no guest writes
itself.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

# INT21/AH=30 is Get DOS Version; AL=00 is the only admitted selector. Other
# AL subfunctions (version flags, OEM-dependent variants) are never modeled.
VERSION_FUNCTION: int = 0x30
VERSION_SELECTOR: int = 0x00

# DOS 2.0 introduced the documented return convention (minor in AH, OEM in
# BH, 24-bit serial in BL:CX); a declared major below 2 would publish a
# minor/serial whose meaning the contract does not define.
MINIMUM_MAJOR: int = 2

# BL:CX carries a 24-bit serial: BL holds bits 16..23, CX bits 0..15.
SERIAL_MASK: int = 0xFFFFFF

# The deterministic report payload for one answered query:
# vector, function, selector, major, minor, oem, then serial little-endian.
VERSION_EVENT_BYTES: int = 9

_U8_MAX: int = 0xFF
_U16_MAX: int = 0xFFFF


def _checked_u8(value: int, name: str, minimum: int = 0) -> int:
    """Validate one 8-bit domain field, rejecting bool masquerades."""
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= _U8_MAX:
        raise ValueError(f"{name} must be an 8-bit unsigned integer >= {minimum}")
    return value


def _checked_u16(value: int, name: str) -> int:
    """Validate one 16-bit domain field, rejecting bool masquerades."""
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= _U16_MAX:
        raise ValueError(f"{name} must be a 16-bit unsigned integer")
    return value


def _checked_u24(value: int, name: str) -> int:
    """Validate one 24-bit serial field, rejecting bool masquerades."""
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= SERIAL_MASK:
        raise ValueError(f"{name} must be a 24-bit unsigned integer")
    return value


class VersionRefusal(StrEnum):
    """Typed reason one declared version query was refused; never hidden."""

    UNSUPPORTED_SELECTOR = "unsupported_version_selector"


@dataclass(frozen=True, slots=True)
class VersionPolicy:
    """Explicit caller-declared version response; no field is inferred.

    ``major``/``minor`` are the AL/AH bytes, ``oem`` the BH byte and
    ``serial`` the 24-bit BL:CX value the declared contract reports for one
    AL=00 query. ``major`` is bounded below at 2 because the documented
    response convention does not exist for DOS 1.x. Every field is plain
    bounded integer data; the policy is immutable and carries no runtime
    state, so one declared policy answers every admitted query identically.
    """

    major: int
    minor: int
    oem: int
    serial: int

    def __post_init__(self) -> None:
        """Bind the declared response to the documented byte/serial domains."""
        _checked_u8(self.major, "version major", MINIMUM_MAJOR)
        _checked_u8(self.minor, "version minor")
        _checked_u8(self.oem, "version oem")
        _checked_u24(self.serial, "version serial")


@dataclass(frozen=True, slots=True)
class VersionAnswered:
    """One completed query; the declared low-half effect on AX/BX/CX.

    ``ax`` carries (minor << 8) | major, ``bx`` carries (oem << 8) | the
    serial's top byte and ``cx`` the serial's low word. Installing these is
    the caller's obligation alongside preserving every other register bit,
    flag and segment. The response adds no writes beyond the INT entry frame.
    """

    ax: int
    bx: int
    cx: int

    def __post_init__(self) -> None:
        """Bind the record to the 16-bit low-half register domain."""
        _checked_u16(self.ax, "answered ax")
        _checked_u16(self.bx, "answered bx")
        _checked_u16(self.cx, "answered cx")


@dataclass(frozen=True, slots=True)
class VersionRefused:
    """One refused query; the executor must stop, never emulate a DOS error."""

    selector: int
    refusal: VersionRefusal

    def __post_init__(self) -> None:
        """Retain a typed refusal, never a text status."""
        _checked_u8(self.selector, "version selector")
        if not isinstance(self.refusal, VersionRefusal):
            raise ValueError("refused version query requires a typed VersionRefusal")


type VersionCallResult = VersionAnswered | VersionRefused


def program_version_query(policy: VersionPolicy, *, selector: int) -> VersionCallResult:
    """Admit one INT21/AH=30-shaped query under the declared policy.

    ``selector`` is the caller's AL value; only AL=00 (Get DOS Version) is
    admitted — every other selector returns ``VersionRefused`` with
    ``UNSUPPORTED_SELECTOR``. A non-``VersionPolicy`` policy or a malformed
    selector — non-integer, bool or outside the 8-bit AL domain — raises
    ``ValueError``. The answer derives deterministically from the immutable
    policy: AX gets (minor << 8) | major, BX gets (oem << 8) | the serial's
    top byte, CX gets the serial's low word. This function performs no
    writes; installing the low halves and advancing IP is the caller's
    obligation, as is preserving the upper register halves, all flags and
    segments. Architectural INT entry writes belong to the execution owner.
    """
    if not isinstance(policy, VersionPolicy):
        raise ValueError("version service requires a declared VersionPolicy")
    _checked_u8(selector, "version selector")
    if selector != VERSION_SELECTOR:
        return VersionRefused(selector, VersionRefusal.UNSUPPORTED_SELECTOR)
    return VersionAnswered(
        ax=(policy.minor << 8) | policy.major,
        bx=(policy.oem << 8) | (policy.serial >> 16),
        cx=policy.serial & _U16_MAX,
    )


def version_event_data(policy: VersionPolicy) -> bytes:
    """Return the deterministic 9-byte report payload for one answered query.

    The payload is vector, function, selector, then the declared major,
    minor and OEM bytes, then the 24-bit serial little-endian — the complete
    declared response so a report reader never needs to re-derive it.
    """
    if not isinstance(policy, VersionPolicy):
        raise ValueError("version event data requires a declared VersionPolicy")
    return (
        bytes((0x21, VERSION_FUNCTION, VERSION_SELECTOR, policy.major, policy.minor, policy.oem))
        + policy.serial.to_bytes(3, "little")
    )


def version_receipt_complete(data: bytes) -> bool:
    """Reject malformed service, selector or response domains in retained events."""
    return (
        type(data) is bytes
        and len(data) == VERSION_EVENT_BYTES
        and data[:3] == bytes((0x21, VERSION_FUNCTION, VERSION_SELECTOR))
        and data[3] >= MINIMUM_MAJOR
    )



def version_policy_document(policy: VersionPolicy | None) -> dict[str, object] | None:
    """Project the declared response into deterministic identity/report data."""
    if policy is None:
        return None
    if not isinstance(policy, VersionPolicy):
        raise ValueError("version document requires a declared VersionPolicy or None")
    return {
        "service": "int21_30_al00",
        "major": policy.major,
        "minor": policy.minor,
        "oem": policy.oem,
        "serial24": policy.serial,
        "scope": "caller-declared version response bytes; no installed-DOS claim",
    }


def _integer(value: object, name: str) -> int:
    """Accept explicit JSON integers/hex strings, never bool or float aliases."""
    if type(value) is int:
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError as error:
            raise ValueError(f"{name}: invalid integer") from error
    raise ValueError(f"{name}: expected integer")


def _object(value: object, keys: set[str], name: str) -> dict[str, object]:
    """Require exactly the declared JSON members, without ignored fields."""
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError(f"{name}: expected exactly {sorted(keys)}")
    return value


def parse_version_policy(value: object) -> VersionPolicy | None:
    """Read an explicit ``dos_version`` object; absence keeps the refusal.

    The object must declare exactly ``major``, ``minor``, ``oem`` and
    ``serial24`` — unknown or missing fields are malformed, and each value
    must be an explicit integer or hexadecimal string inside its declared
    domain (8-bit fields, 24-bit serial, major >= 2). ``None`` declares "no
    version service" and every query refuses.
    """
    if value is None:
        return None
    declared = _object(value, {"major", "minor", "oem", "serial24"}, "dos_version")
    return VersionPolicy(
        _integer(declared["major"], "dos_version major"),
        _integer(declared["minor"], "dos_version minor"),
        _integer(declared["oem"], "dos_version oem"),
        _integer(declared["serial24"], "dos_version serial24"),
    )
