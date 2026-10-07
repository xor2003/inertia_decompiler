"""Layer: validation frontend.

Responsibility: load complete i386 executable images for SSA comparison.
"""

from __future__ import annotations

from pathlib import Path

import angr

from tools.dosunit.architectures.flat32_pe_loader import InclusivePE


def load_flat32_project(exe_path: Path, *, perform_relocations: bool = True) -> angr.Project:
    """Force PE/ELF loading and preserve the inclusive PE end and relocation policy."""
    with exe_path.open("rb") as stream:
        magic = stream.read(4)
    if magic[:2] == b"MZ":
        project = angr.Project(
            str(exe_path), auto_load_libs=False,
            main_opts={"backend": InclusivePE, "max_mapped_bytes": 64 * 1024 * 1024},
            load_options={"perform_relocations": perform_relocations},
        )
    else:
        project = angr.Project(str(exe_path), auto_load_libs=False, main_opts={"backend": "elf"})
    if project.arch.name != "X86":
        raise ValueError(f"expected i386, found {project.arch.name}: {exe_path}")
    return project
