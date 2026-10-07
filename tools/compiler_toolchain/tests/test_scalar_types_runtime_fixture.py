"""Durable contracts for the scalar-types runtime acceptance fixture."""

from pathlib import Path

import tools.compiler_toolchain.build_msc6_examples as build_msc6_examples
import tools.compiler_toolchain.verify_msc_example_runtime_gate as verify_msc_example_runtime_gate

REPO_ROOT = Path(__file__).resolve().parents[3]
HIGH_BIT_MIX_CHECK = "if (mix_uc(64, 0) != (unsigned char)128)"


def test_scalar_types_harnesses_require_unsigned_high_bit_return() -> None:
    """Every scalar runtime projection must reject a signed-byte mix result."""
    source = (REPO_ROOT / "examples" / "msc6_constructs" / "scalar_types_io.c").read_text(encoding="ascii")

    assert HIGH_BIT_MIX_CHECK in source
    assert HIGH_BIT_MIX_CHECK in build_msc6_examples.SCALAR_TYPES_HARNESS_MAIN
    assert HIGH_BIT_MIX_CHECK in verify_msc_example_runtime_gate.SCALAR_TYPES_HARNESS_MAIN
