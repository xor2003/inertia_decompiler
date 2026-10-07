"""Exact block-local register-snapshot view evidence for word transport.

Layer: Widening.
Responsibility: own the typed producer/view coherence contract for
``REG.source_tmp`` snapshot reads. A snapshot is earned only by a block-local
``MOV t?, <current REG>`` producer at the same word width; the retained view
keeps the source register's name and its SSA version at capture time — never
a TMP definition version and never the register name alone. Reads resolve
through the retained capture: missing or out-of-block producers, non-MOV or
unknown producers, register or version mismatches, and decorated views all
refuse closed. The captured word survives later writes to the source register;
TMP producer scope stays strictly block-local.
Consumes alias-proven storage identity.
Do not join values from rendered text, cosmetic shape, postprocess, or CLI/reporting evidence.
"""

from __future__ import annotations

from dataclasses import dataclass

from inertia.ir.core import IRValue, MemSpace
from inertia.semantics.register_value_preservation import register_value_projection_8616

from .entry_word_transport_contracts import (
    EntryWordTransportRefusal8616,
)
from .entry_word_transport_contracts import (
    EntryWordTransportRefusalKind8616 as Refusal,
)


@dataclass(frozen=True, slots=True)
class SnapshotCapture8616:
    """The exact register view one block-local TMP producer captured.

    ``register_version`` is the source register's SSA version at the producer
    site — distinct from the TMP's own definition version. ``word`` freezes
    whether that view carried the proven entry word when captured.
    """

    register: str
    register_version: int
    word: bool


def snapshot_capture_view_8616(source: IRValue) -> tuple[str, int] | None:
    """The producer view of a plain current-register MOV source, if exact.

    Only an undecorated current ``REG`` operand earns a capture: a nested
    snapshot view, displaced/indexed/decorated operand, or non-register source
    earns none, so later reads through that producer refuse.
    """
    if source.space is not MemSpace.REG or source.name is None:
        return None
    if source.version is None:
        return None
    if register_value_projection_8616(source.name, source.name) != (0, 16):
        return None
    if source.source_tmp is not None or source.offset or source.index is not None:
        return None
    if source.index_shift or source.expr or source.const is not None:
        return None
    if source.call_output is not None or source.size != 2:
        return None
    return source.name.lower(), source.version


def captured_word_8616(
    capture: SnapshotCapture8616 | None,
    value: IRValue,
) -> tuple[bool, EntryWordTransportRefusal8616 | None]:
    """Resolve a captured-register read through retained producer evidence.

    Every incoherent view refuses with a typed reason rather than falling
    back to the current register by name: an absent or non-capture producer,
    a register mismatch, or a version mismatch each fails independently.
    """
    if capture is None:
        return False, EntryWordTransportRefusal8616(
            Refusal.UNSUPPORTED_OPERAND,
            "snapshot producer absent or not a register capture",
        )
    if value.name is None or capture.register != value.name.lower():
        return False, EntryWordTransportRefusal8616(
            Refusal.UNSUPPORTED_OPERAND,
            "captured register differs from the snapshot view",
        )
    if capture.register_version != value.version:
        return False, EntryWordTransportRefusal8616(
            Refusal.STALE_TMP_VERSION,
            "snapshot view version differs from retained producer",
        )
    return capture.word, None
