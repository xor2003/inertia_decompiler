"""Explicit device-information responses for initialized real16 replay.

Layer: dosunit concrete execution contracts.
Responsibility: admit only INT21/AX4400 queries for declared stable handles,
retain their exact response words and reject unknown handles/subfunctions.
Responses describe a caller-declared environment, not inferred host devices.
Handle creation, close, duplication and setting device information are outside
this immutable policy; the execution owner must continue refusing those calls.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

MAX_DEVICE_HANDLES: int = 256
DEVICE_QUERY_PREFIX: bytes = bytes((0x21, 0x44, 0))
DEVICE_RECEIPT_BYTES: int = 7


def _word(value: object, field: str) -> int:
    """Reject bool, coercions and values outside a guest register word."""
    if type(value) is not int or not 0 <= value <= 0xFFFF:
        raise ValueError(f"{field} must be an unsigned integer word")
    return value


@dataclass(frozen=True, slots=True)
class DeviceInformation:
    """One stable DOS handle and its explicitly declared successful DX answer."""

    handle: int
    information: int

    def __post_init__(self) -> None:
        """Check both public fields without guessing device-bit meanings."""
        _word(self.handle, "device handle")
        _word(self.information, "device information")


@dataclass(frozen=True, slots=True)
class DeviceInfoPolicy:
    """Bounded immutable answers for preexisting handles; absent is unknown.

    A successful query clears CF and writes only DX, leaving AX and all other
    registers/flags intact. Architectural INT frame writes belong to replay.
    Missing handles refuse rather than inventing DOS error 6. Other IOCTL
    subfunctions refuse rather than silently changing this declared state.
    """

    handles: tuple[DeviceInformation, ...]

    def __post_init__(self) -> None:
        """Require a bounded unique typed inventory with canonical order."""
        if type(self.handles) is not tuple or not 1 <= len(self.handles) <= MAX_DEVICE_HANDLES:
            raise ValueError("device information needs 1..256 declared handles")
        if any(not isinstance(item, DeviceInformation) for item in self.handles):
            raise ValueError("device information requires typed handle records")
        if len({item.handle for item in self.handles}) != len(self.handles):
            raise ValueError("duplicate device information handle")
        object.__setattr__(self, "handles", tuple(sorted(self.handles, key=lambda item: item.handle)))


class DeviceInfoRefusal(StrEnum):
    """Explicit service boundaries; these are not emulated DOS error returns."""

    UNKNOWN_HANDLE = "undeclared_device_information_handle"
    SUBFUNCTION = "unsupported_device_information_subfunction"


def program_device_query(
    policy: DeviceInfoPolicy, *, selector: int, handle: int,
) -> DeviceInformation | DeviceInfoRefusal:
    """Resolve one declared success without accessing host descriptors."""
    if type(selector) is not int or not 0 <= selector <= 255:
        raise ValueError("device subfunction must be a byte")
    _word(handle, "device handle")
    if selector != 0:
        return DeviceInfoRefusal.SUBFUNCTION
    for item in policy.handles:
        if item.handle == handle:
            return item
    return DeviceInfoRefusal.UNKNOWN_HANDLE


def device_info_event_data(answer: DeviceInformation) -> bytes:
    """Retain the queried handle and complete response with the service selector."""
    return DEVICE_QUERY_PREFIX + answer.handle.to_bytes(2, "little") + answer.information.to_bytes(2, "little")


def device_info_receipt_complete(data: bytes) -> bool:
    """Reject truncated or differently selected service receipts."""
    return type(data) is bytes and len(data) == DEVICE_RECEIPT_BYTES and data[:3] == DEVICE_QUERY_PREFIX


def device_info_policy_document(policy: DeviceInfoPolicy | None) -> dict[str, object] | None:
    """Serialize the canonical explicit handle inventory for identity and CLI."""
    if policy is None:
        return None
    return {"handles": [{"handle": item.handle, "information": item.information} for item in policy.handles]}


def parse_device_info_policy(value: object) -> DeviceInfoPolicy | None:
    """Read exact declared words; no implicit standard handles or host probes."""
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {"handles"}:
        raise ValueError("dos_device_info requires exactly handles")
    rows = value["handles"]
    if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_DEVICE_HANDLES:
        raise ValueError("dos_device_info handles must contain 1..256 records")
    handles: list[DeviceInformation] = []
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"handle", "information"}:
            raise ValueError("device information record needs handle and information")
        handles.append(DeviceInformation(_word(row["handle"], "handle"), _word(row["information"], "information")))
    return DeviceInfoPolicy(tuple(handles))
