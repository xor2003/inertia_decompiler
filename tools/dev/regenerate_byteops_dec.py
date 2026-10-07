#!/usr/bin/env python3
"""Regenerate the BYTEOPS.dec file with the current bounded_live decompilation output.

Layer: Tooling/gates.
Responsibility: preserve the existing regenerate_byteops_dec tool behavior.
"""

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT))

import decompile  # noqa: E402

_COD_DIR = _ROOT / "cod"
_DEC_OUTPUT_PATH = _ROOT / ".codex_automation/evidence_subset/cod/default/BYTEOPS.dec"


def regenerate_byteops_dec() -> bool:  # noqa: D103
    proc_path = _COD_DIR / "default" / "BYTEOPS.COD"

    # Extract the function from COD
    entries = decompile.extract_cod_function_entries(proc_path, "_main", "NEAR")
    proc_code, synthetic_globals = decompile.join_cod_entries_with_synthetic_globals(entries)

    # Build project and CFG
    project = decompile._build_project_from_bytes(proc_code, base_addr=0x1000, entry_point=0x1000)
    cfg = project.analyses.CFGFast(
        start_at_entry=False,
        function_starts=[project.entry],
        regions=[(project.entry, project.entry + len(proc_code))],
        normalize=True,
        force_complete_scan=False,
    )
    function = cfg.functions[project.entry]
    cod_metadata = decompile.extract_cod_proc_metadata(proc_path, "_main", "NEAR")

    # Decompile the function
    status, text = decompile._decompile_function(
        project,
        cfg,
        function,
        timeout=30,
        api_style="modern",
        binary_path=proc_path,
        cod_metadata=cod_metadata,
        synthetic_globals=synthetic_globals,
    )

    if status != "ok":
        print(f"ERROR: Decompilation failed with status '{status}': {text}", file=sys.stderr)
        return False

    # Generate the .dec file content with proper formatting
    dec_content = f"""/* loading: {proc_path} */
/* procedures recovered: 1 */
/* == 1/1 BYTEOPS.COD :: _main [NEAR] == */
{text}
"""

    # Write the .dec file
    _DEC_OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    _DEC_OUTPUT_PATH.write_text(dec_content, encoding="utf-8")
    print(f"✓ Regenerated {_DEC_OUTPUT_PATH}")
    print("\nGenerated content preview (first 1500 chars):")
    print("=" * 80)
    print(dec_content[:1500])
    if len(dec_content) > 1500:
        print("... (truncated)")
    print("=" * 80)
    return True


if __name__ == "__main__":
    success = regenerate_byteops_dec()
    sys.exit(0 if success else 1)
