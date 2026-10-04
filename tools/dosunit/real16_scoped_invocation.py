"""Bind one declared ProgramBoot to a loaded project for scoped IR intake.

Layer: dosunit program intake.
Responsibility: authenticate the retained MZ source, the declared boot
contract and the project's mapped image bytes for one caller-supplied
``ProgramBoot``, derive the bounded Frontend invocation inventory rooted
at the header entry — independent of any optional function catalog — and
install the typed ``Real16InvocationSource8616`` only after the complete
preparation succeeds. Every refused preparation clears the project's
invocation-source slot so a rejected input can never leave a new or stale
authority installed. This owner performs no IR recovery, publishes no
artifact, changes no call-prefix or stack semantics, and leaves universal
publication and refusal untouched.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import StrEnum
from functools import partial
from typing import Protocol, cast

from angr_platforms.X86_16.analysis_helpers import (
    resolve_direct_call_target_from_instruction_8616,
)
from angr_platforms.X86_16.frontend_direct_callsite_index import (
    DirectCallTargetResolver8616,
)
from angr_platforms.X86_16.frontend_invocation_inventory import (
    InvocationInventory8616,
    InvocationInventoryBudget8616,
    build_invocation_inventory_8616,
)
from angr_platforms.X86_16.ir.entry_domain_call_preservation import (
    Real16InvocationSource8616,
    install_real16_invocation_source_8616,
)
from angr_platforms.X86_16.mz_invocation_source import mz_invocation_source_8616

from tools.dosunit.real16_program_boot import ProgramBoot, program_from_mz_bytes

__all__ = [
    "DeclaredInvocationInstall8616",
    "DeclaredInvocationStatus8616",
    "install_declared_invocation_source_8616",
    "recompute_declared_program_boot_8616",
]


class DeclaredInvocationStatus8616(StrEnum):
    """Typed outcome of one declared ProgramBoot install preparation."""

    INSTALLED = "installed"
    BOOT_TYPE_REFUSED = "boot_type_refused"
    BOOT_RECOMPUTE_REFUSED = "boot_recompute_refused"
    BOOT_STALE_REFUSED = "boot_stale_refused"
    SOURCE_PROJECTION_REFUSED = "source_projection_refused"
    PROJECT_SURFACE_REFUSED = "project_surface_refused"
    IMAGE_MISMATCH_REFUSED = "image_mismatch_refused"
    INVENTORY_REFUSED = "inventory_refused"


@dataclass(frozen=True, slots=True)
class DeclaredInvocationInstall8616:
    """Typed install receipt: the retained authority exists only when installed.

    ``source`` is the installed ``Real16InvocationSource8616`` and
    ``inventory`` the closed Frontend corpus it was bound to; both are
    present only for ``INSTALLED``. ``refusal_addr`` names the exact byte
    or head coordinate whose check refused. A refused receipt always
    carries ``source is None`` because the project slot was cleared.
    """

    status: DeclaredInvocationStatus8616
    source: Real16InvocationSource8616 | None
    inventory: InvocationInventory8616 | None
    entry_linear: int | None
    boot_sha256: str | None
    refusal_addr: int | None

    @property
    def installed(self) -> bool:
        """Return whether a typed authority was installed this call."""
        return bool(
            self.status is DeclaredInvocationStatus8616.INSTALLED
            and self.source is not None
        )


class _LoaderMemorySurface8616(Protocol):
    """Third-party loader memory used for mapped-byte authentication."""

    def load(self, addr: int, size: int) -> object:
        """Return the mapped bytes for one linear range."""
        ...


class _LoaderSurface8616(Protocol):
    """Third-party loader boundary consumed by byte authentication."""

    memory: _LoaderMemorySurface8616


class _ProjectSurface8616(Protocol):
    """Minimal project surface required for image authentication."""

    loader: _LoaderSurface8616


def recompute_declared_program_boot_8616(boot: object) -> object:
    """Re-derive an equal ``ProgramBoot`` from its retained MZ bytes.

    This is the ``boot_recompute`` authority installed with the source
    record. ``code_ranges`` participate only under the declared scope,
    mirroring the boot object's own source check so a whole-image scope
    recomputes to the identical synthesized range.
    """
    if type(boot) is not ProgramBoot:
        raise TypeError("declared boot recompute requires a typed ProgramBoot")
    declared_boot = boot
    declared = (
        declared_boot.image.code_ranges
        if declared_boot.image.code_scope == "declared"
        else ()
    )
    result: object = program_from_mz_bytes(
        declared_boot.source,
        declared_boot.environment,
        code_ranges=tuple(declared),
    )
    return result


def _clear_and_refuse_8616(
    project: object,
    status: DeclaredInvocationStatus8616,
    *,
    inventory: InvocationInventory8616 | None = None,
    entry_linear: int | None = None,
    boot_sha256: str | None = None,
    refusal_addr: int | None = None,
) -> DeclaredInvocationInstall8616:
    """Clear the project slot so no stale authority survives a refusal."""
    install_real16_invocation_source_8616(project, None)
    return DeclaredInvocationInstall8616(
        status=status,
        source=None,
        inventory=inventory,
        entry_linear=entry_linear,
        boot_sha256=boot_sha256,
        refusal_addr=refusal_addr,
    )


def _project_memory_8616(project: object) -> _LoaderMemorySurface8616 | None:
    """Return the project loader memory surface without inventing one."""
    try:
        return cast(_ProjectSurface8616, project).loader.memory
    except AttributeError:
        return None


def _authenticated_image_bytes_8616(
    memory: _LoaderMemorySurface8616, boot: ProgramBoot
) -> int | None:
    """Verify loader bytes equal the boot image, returning a mismatch address.

    Every declared ``(address, bytes)`` chunk must read back identically
    from the project's mapped memory; an unloadable or unequal range is
    reported at its chunk address, ``None`` means full agreement. Chunk
    shape is already bound: the source-projection check requires
    ``chunks == ((module_base, module),)`` before this runs.
    """
    for address, chunk in boot.image.chunks:
        try:
            loaded = memory.load(address, len(chunk))
        except (AttributeError, KeyError, OSError, TypeError, ValueError):
            return address
        if not isinstance(loaded, (bytes, bytearray, memoryview)) or loaded != chunk:
            return address
    return None


def install_declared_invocation_source_8616(
    project: object,
    boot: object,
    *,
    extra_entries: Iterable[int] = (),
    budget: InvocationInventoryBudget8616 | None = None,
    direct_target_resolver: DirectCallTargetResolver8616 | None = None,
) -> DeclaredInvocationInstall8616:
    """Authenticate one declared ProgramBoot and install its invocation source.

    Preparation order is fixed so the earliest dishonesty wins: the boot
    must be a typed ``ProgramBoot``, recompute to an equal object from its
    retained source, agree with the independent ``mz_invocation_source_8616``
    header/module projection (including the entry-in-module contract the
    boot factory does not enforce), and match the project's mapped image
    bytes exactly. Only then is the bounded inventory rooted at the
    header-derived entry built and the typed record installed.
    ``extra_entries`` may add caller-proven corpus roots (for example a
    catalog), but the MZ entry is always included independently.
    """
    install_real16_invocation_source_8616(project, None)
    if type(boot) is not ProgramBoot:
        return _clear_and_refuse_8616(project, DeclaredInvocationStatus8616.BOOT_TYPE_REFUSED)
    declared_boot = boot
    try:
        recomputed = recompute_declared_program_boot_8616(boot)
    except (TypeError, ValueError, KeyError, AttributeError):
        return _clear_and_refuse_8616(project, DeclaredInvocationStatus8616.BOOT_RECOMPUTE_REFUSED)
    if type(recomputed) is not ProgramBoot or recomputed != declared_boot:
        return _clear_and_refuse_8616(project, DeclaredInvocationStatus8616.BOOT_STALE_REFUSED)
    try:
        projection = mz_invocation_source_8616(declared_boot.source, declared_boot.image.load_segment)
    except (TypeError, ValueError):
        return _clear_and_refuse_8616(project, DeclaredInvocationStatus8616.SOURCE_PROJECTION_REFUSED)
    points_reproduced = (
        projection.entry_linear == declared_boot.entry.linear()
        and projection.stack_segment == declared_boot.stack.segment
        and projection.stack_offset == declared_boot.stack.offset
        and projection.file_sha256 == declared_boot.image.file_sha256
    )
    if (
        not projection.complete
        or not points_reproduced
        or declared_boot.image.chunks != ((projection.module_base, projection.module),)
    ):
        return _clear_and_refuse_8616(project, DeclaredInvocationStatus8616.BOOT_STALE_REFUSED)
    memory = _project_memory_8616(project)
    if memory is None:
        return _clear_and_refuse_8616(
            project,
            DeclaredInvocationStatus8616.PROJECT_SURFACE_REFUSED,
            entry_linear=declared_boot.entry.linear(),
            boot_sha256=declared_boot.boot_sha256,
        )
    mismatch = _authenticated_image_bytes_8616(memory, declared_boot)
    if mismatch is not None:
        return _clear_and_refuse_8616(
            project,
            DeclaredInvocationStatus8616.IMAGE_MISMATCH_REFUSED,
            entry_linear=declared_boot.entry.linear(),
            boot_sha256=declared_boot.boot_sha256,
            refusal_addr=mismatch,
        )
    entry_linear = declared_boot.entry.linear()
    resolver: DirectCallTargetResolver8616 = (
        partial(resolve_direct_call_target_from_instruction_8616, project)
        if direct_target_resolver is None
        else direct_target_resolver
    )
    inventory = build_invocation_inventory_8616(
        project,
        entry_linear,
        extra_entries=extra_entries,
        budget=budget,
        direct_target_resolver=resolver,
    )
    if not inventory.ready or inventory.callsite_index is None:
        return _clear_and_refuse_8616(
            project,
            DeclaredInvocationStatus8616.INVENTORY_REFUSED,
            inventory=inventory,
            entry_linear=entry_linear,
            boot_sha256=declared_boot.boot_sha256,
            refusal_addr=inventory.refusal_addr,
        )
    source = Real16InvocationSource8616(
        boot=declared_boot,
        boot_recompute=recompute_declared_program_boot_8616,
        callsite_index=inventory.callsite_index,
    )
    install_real16_invocation_source_8616(project, source)
    return DeclaredInvocationInstall8616(
        status=DeclaredInvocationStatus8616.INSTALLED,
        source=source,
        inventory=inventory,
        entry_linear=entry_linear,
        boot_sha256=declared_boot.boot_sha256,
        refusal_addr=None,
    )
