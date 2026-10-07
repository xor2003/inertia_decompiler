#!/usr/bin/env python3
"""Corpus validation script: Test Item 5 (BYTEOPS byte-register correctness).

Layer: Tooling/gates.
Responsibility: preserve the existing validate_item5_byteops tool behavior.
"""

import sys
from pathlib import Path

# Add workspace to path
REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT))


def test_byteops_decompilation():  # noqa: ANN201
    """Test BYTEOPS.COD decompilation for byte-register correctness."""
    import archinfo

    from decompile import Project, decompile_one

    cod_file = REPO_ROOT / "cod" / "default" / "BYTEOPS.COD"

    if not cod_file.exists():
        print(f"ERROR: {cod_file} not found")
        return False

    print(f"[*] Loading {cod_file}")
    try:
        project = Project(cod_file, arch=archinfo.ArchX86(), auto_load_libs=False)
    except Exception as e:
        print(f"ERROR loading project: {e}")
        return False

    # Decompile main or first function
    print("[*] Decompiling BYTEOPS...")
    try:
        result = decompile_one(project, project.entry, timeout=5)
        decompiled_src = result.text if hasattr(result, "text") else str(result)

        print("\n=== DECOMPILED OUTPUT ===")
        print(decompiled_src)
        print("=== END OUTPUT ===\n")

        # Check for success criteria
        checks = {
            "has_a_operations": "a = a -" in decompiled_src or "a = a*" in decompiled_src,
            "has_b_operations": "b = b /" in decompiled_src or "b = b %" in decompiled_src,
            "no_synthetic_ax": "ax_" not in decompiled_src,
            "no_synthetic_bx": "bx_" not in decompiled_src,
            "has_printf": "printf" in decompiled_src,
        }

        print("\n[*] Validation Results:")
        all_pass = True
        for check_name, result in checks.items():
            status = "✓ PASS" if result else "✗ FAIL"
            print(f"  {status}: {check_name}")
            if not result:
                all_pass = False

        return all_pass

    except Exception as e:
        print(f"ERROR during decompilation: {e}")
        import traceback

        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = test_byteops_decompilation()
    sys.exit(0 if success else 1)
