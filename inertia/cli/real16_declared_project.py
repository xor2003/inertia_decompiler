"""Layer: CLI/fallback/reporting.

Responsibility: bind explicit conditional real16 input to an exact MZ load.
Environment and service semantics remain with the canonical dosunit owners.
"""

from __future__ import annotations

import io
from pathlib import Path
from typing import Protocol, cast

import angr

from inertia.cli.mz_static_intake import MzStaticIntakeRequest8616
from inertia.frontend.x86_16.load_dos_mz import DOSMZ
from tools.dosunit.catalog.real16_declared_input import read_declared_real16_input_8616
from tools.dosunit.catalog.real16_scoped_invocation import recompute_declared_program_boot_8616


class _DeclaredProjectMarker8616(Protocol):
    """Explicit slots on the third-party project carrying deferred authority."""

    _inertia_mz_static_invocation_request_8616: MzStaticIntakeRequest8616
    _inertia_real16_declared_input_path_8616: Path


def declared_input_path_8616(project: object) -> Path | None:
    """Read optional declaration provenance from the third-party project.

    Rebuilds re-read and authenticate the named file; this accessor grants
    neither a cached declaration nor a reusable proof.
    """
    # Dynamic third-party angr boundary: undeclared projects have no marker.
    value = getattr(project, "_inertia_real16_declared_input_path_8616", None)
    if value is None or isinstance(value, Path):
        return value
    raise TypeError("project declaration provenance must be a Path")


def build_declared_project_8616(
    binary: Path,
    declaration_path: Path,
    *,
    force_blob: bool,
    base_addr: int,
    entry_point: int,
) -> angr.Project:
    """Load source-bound conditional input without loader fallback or inference.

    Supplied coordinates must already agree with the canonical boot. The
    mapped image is checked before the deferred request becomes visible.
    No inventory, native census or universal proof is minted here.
    """
    if force_blob:
        raise ValueError("declared real16 input requires the DOS MZ backend")
    source = binary.read_bytes()
    if not DOSMZ.is_compatible(io.BytesIO(source)):
        raise ValueError("declared real16 input requires a plain DOS MZ image")
    declaration = read_declared_real16_input_8616(declaration_path, source)
    boot = declaration.boot
    load_base = boot.image.load_segment << 4
    # CLI policy supplies a paragraph; isolated CLE rebuilds supply a linear
    # linked_base, which may also be below 64K. The declaration owns the one
    # actual load address, so accept only its exact two coordinate projections.
    if base_addr not in (boot.image.load_segment, load_base) or entry_point != boot.entry.linear():
        raise ValueError("load coordinates differ from the declared real16 boot")
    project = angr.Project(
        binary,
        auto_load_libs=False,
        main_opts={"backend": "dos_mz", "base_addr": load_base},
        simos="DOS",
    )
    main_object = project.loader.main_object
    if not isinstance(main_object, DOSMZ) or main_object.mz_load_segment != boot.image.load_segment:
        raise ValueError("loaded backend differs from the declared real16 boot")
    if project.entry != boot.entry.linear():
        raise ValueError("loaded entry differs from the declared real16 boot")
    for address, data in boot.image.chunks:
        if project.loader.memory.load(address, len(data)) != data:
            raise ValueError("mapped image differs from the declared real16 source")
    marker = cast(_DeclaredProjectMarker8616, project)
    marker._inertia_mz_static_invocation_request_8616 = MzStaticIntakeRequest8616(
        source=source,
        declared_boot=boot,
        declared_boot_recompute=recompute_declared_program_boot_8616,
        declared_services=declaration.services,
        function_entries=declaration.function_entries,
    )
    marker._inertia_real16_declared_input_path_8616 = declaration_path.resolve()
    return project
