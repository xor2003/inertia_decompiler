"""Select shared GP storage for the generated SORTD behavior gate.

Layer: Tooling/gates.
Responsibility: use Lowering's explicit ABI for every compiled translation unit,
without inferring storage from generated C or altering generated function bodies.
"""

from __future__ import annotations

from pathlib import Path

from angr_platforms.X86_16.lowering.gp_word_runtime import (
    DEFAULT_GP_RUNTIME_ABI_8616 as DEFAULT_GP_RUNTIME_ABI_8616,
)
from angr_platforms.X86_16.lowering.gp_word_runtime import (
    GPRegisterRuntimeABI8616,
    coherent_gp_runtime_definitions_8616,
    coherent_gp_runtime_header_8616,
)


def prepare_sortd_gp_runtime(
    build_dir: Path, fixture: Path, abi: GPRegisterRuntimeABI8616,
) -> tuple[Path, tuple[str, ...]]:
    """Return one runtime source and compiler flags shared by all consumers."""
    if not isinstance(abi, GPRegisterRuntimeABI8616):
        raise ValueError(f"expected GPRegisterRuntimeABI8616, got {abi!r}")
    if abi is GPRegisterRuntimeABI8616.SCALAR:
        return fixture, ()
    header = build_dir / "inertia_gp_runtime.h"
    header.write_text(coherent_gp_runtime_header_8616(), encoding="ascii")
    runtime = build_dir / "inertia_gp_runtime.c"
    runtime.write_text(
        coherent_gp_runtime_definitions_8616() + fixture.read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    return runtime, ("-include", str(header.resolve()))
