from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from tools.dev.check_sortd_sidecar_free import EXPECTED_SORTD_FUNCTION_ADDRS

REPO_ROOT = Path(__file__).resolve().parents[2]
SORTD_EXE = REPO_ROOT / "SORTD.EXE"
INVENTORY_SCRIPT = REPO_ROOT / "scripts" / "indexed_address_parity_inventory.py"


def test_sortd_sidecar_free_inventory_matches_reviewed_migration_baseline() -> None:
    result = subprocess.run(
        [sys.executable, str(INVENTORY_SCRIPT), str(SORTD_EXE)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["closed"] is True
    assert payload["exact"] is False
    assert tuple(report["function_addr"] for report in payload["functions"]) == EXPECTED_SORTD_FUNCTION_ADDRS
    stats = payload["stats"]
    # Effective segment identity excludes BP-based stack accesses from the
    # legacy DS inventory without changing authoritative Alias fact totals.
    assert stats == {
        "alias_failure_count": 1,
        "alias_materialized_count": 35,
        "alias_only_count": 4,
        "alias_only_no_legacy_count": 4,
        "access_failure_count": 1,
        "access_materialized_count": 35,
        "alias_copy_failure_count": 6,
        "alias_copy_materialized_count": 2,
        "classified_fact_count": 36,
        "coalesced_fact_count": 11,
        "copy_failure_count": 5,
        "copy_materialized_count": 3,
        "copy_raw_fact_count": 8,
        "divergent_function_count": 1,
        "duplicate_key_count": 0,
        "exact_function_count": 19,
        "failure_count": 1,
        "function_count": 20,
        "global_indexed_count": 31,
        "identity_conflict_count": 0,
        "legacy_only_alias_refusal_count": 0,
        "legacy_only_count": 0,
        "legacy_only_ir_refusal_count": 0,
        "legacy_only_no_ir_count": 0,
        "matched_key_count": 31,
        "materialized_count": 35,
        "normalized_fact_count": 36,
        "normalized_key_count": 66,
        "pointer_relative_count": 4,
        "raw_fact_count": 47,
        "raw_key_count": 66,
    }
    assert tuple(
        (
            report["function_addr"],
            site["source_instr_addr"],
            site["destination_instr_addr"],
            site["source_base_offset"],
            site["destination_base_offset"],
        )
        for report in payload["functions"]
        for site in report["alias_copy_sites"]
    ) == (
        (0x10678, 0x106A9, 0x106B2, 0x08F0, 0x0B4C),
        (0x10808, 0x10871, 0x1087A, 0x0B4A, 0x0B4C),
    )
