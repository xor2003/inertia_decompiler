"""Layer: Frontend / explicit DOS runtime contracts.

Responsibility: bind the bounded DOSBox INT21 entry premise to one exact PSP,
with explicit serialization and no inferred backend profile.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class DosBoxInt21EntryPolicy8616:
    """Explicit premise for DOSBox's version/resize register-save prologue."""

    psp_segment: int

    def __post_init__(self) -> None:
        """Require an exact nonzero real-mode PSP word."""
        if type(self.psp_segment) is not int or not 1 <= self.psp_segment <= 0xFFFF:
            raise ValueError("DOSBox entry PSP must be a nonzero unsigned word")


def dosbox_entry_policy_document(policy: DosBoxInt21EntryPolicy8616 | None) -> dict[str, object] | None:
    """Serialize the explicit premise without manufacturing a default."""
    if policy is None:
        return None
    return {"kind": "dosbox_int21_register_save_v1", "psp_segment": policy.psp_segment}


def parse_dosbox_entry_policy(value: object) -> DosBoxInt21EntryPolicy8616 | None:
    """Parse only the bounded named premise and its exact declared PSP."""
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {"kind", "psp_segment"}:
        raise ValueError("DOSBox entry policy requires kind and psp_segment")
    if value["kind"] != "dosbox_int21_register_save_v1":
        raise ValueError("unsupported DOSBox entry policy kind")
    psp = value["psp_segment"]
    if type(psp) is not int:
        raise ValueError("DOSBox entry PSP must be an integer")
    return DosBoxInt21EntryPolicy8616(psp)


def dosbox_entry_policy_matches(policy: object, psp_segment: int) -> bool:
    """Require absent premise or one exact typed and PSP-bound declaration."""
    return policy is None or (type(policy) is DosBoxInt21EntryPolicy8616
                              and policy.psp_segment == psp_segment)
