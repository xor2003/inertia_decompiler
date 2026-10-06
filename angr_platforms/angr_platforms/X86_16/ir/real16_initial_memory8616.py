"""Source-authenticated immutable initialized bytes for invocation LOADs.

Layer: IR.
Responsibility: project the declared ProgramBoot memory initialization order
without granting authority to project loader padding or guessed DOS fields.
Owns typed Value, Address, Condition, instruction facts, and lossless normalization.
Do not perform alias-state ownership, widening, lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting work here.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, cast

from .real16_declared_interrupt8616 import declared_environment_digest_8616


@dataclass(frozen=True, slots=True)
class InvocationInitialMemory8616:
    """One derivation's immutable initialized chunks, later chunks overlay first.

    Produced only after source reconstruction; consumers must rebuild this
    snapshot on every proof replay so mutated boot declarations cannot inherit
    prior constants. The relocated image overlays the explicitly declared arena
    exactly as concrete ProgramBoot execution does. ROM is intentionally absent.
    """

    chunks: tuple[tuple[int, bytes], ...]

    def byte_at(self, address: int) -> int | None:
        """Read one explicitly initialized conventional byte, never page padding."""
        if type(address) is not int or not 0 <= address < 0xA0000:
            return None
        for base, data in reversed(self.chunks):
            if base <= address < base + len(data):
                return data[address - base]
        return None


class _InitialLayout8616(Protocol):
    """Cross-layer declared layout, identical to the service-digest boundary."""

    chunks: tuple[tuple[int, bytes], ...]


class _InitialEnvironment8616(Protocol):
    """Authenticated boot environment's existing memory-layout projection."""

    def memory_layout(self) -> _InitialLayout8616:
        """Return exact initialized bytes, excluding implicit page padding."""
        ...


def _valid_chunks_8616(chunks: tuple[tuple[int, bytes], ...]) -> bool:
    """Require a bounded immutable disjoint conventional-memory declaration."""
    if not chunks or len(chunks) > 34:
        return False
    end = 0
    for base, data in sorted(chunks):
        if type(base) is not int or type(data) is not bytes or not data:
            return False
        if base < end or base + len(data) > 0xA0000:
            return False
        end = base + len(data)
    return True


def invocation_initial_memory_8616(
    environment: object,
    environment_digest: str | None,
    image_chunks: tuple[tuple[int, bytes], ...],
) -> InvocationInitialMemory8616 | None:
    """Project initialized bytes only after the caller authenticates boot source.

    The invocation owner must first reproduce the boot and independently bind
    relocated image chunks to retained MZ bytes. This adapter uses the existing
    declared-service layout protocol and its exact byte digest; it never imports
    a concrete dosunit implementation or reads arbitrary project memory. Static
    or incomplete declarations supply no digest and yield no LOAD constants.
    """
    if environment_digest is None or declared_environment_digest_8616(environment) != environment_digest:
        return None
    # The existing digest already validates this cross-layer protocol. Access
    # errors after that validation are contract errors and must remain loud.
    chunks = cast(_InitialEnvironment8616, environment).memory_layout().chunks
    if not _valid_chunks_8616(chunks) or not _valid_chunks_8616(image_chunks):
        return None
    return InvocationInitialMemory8616(chunks + image_chunks)
