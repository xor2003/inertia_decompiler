"""Layer: comparator conditional target evidence.

Responsibility: apply the existing explicit value-relocation premise to bounded
returning targets, keeping this evidence separate from strict table lemmas.
"""

from __future__ import annotations

from typing import Any

from tools.comparator.global_layout_checks import check_global_layout
from tools.comparator.table_target_checks import _returning_block
from tools.dosunit.compare import straightline_ssa as S


def check_normalized_targets(
    original_image: bytes, candidate_image: bytes, correspondence: dict[int, int],
    normalization: dict[int, int],
) -> dict[str, Any]:
    """Compare target effects under the same declared premise as the MSC8 lane.

    This is value rewriting, not a derived live-memory or alias relation. The
    result never satisfies strict target lemmas or grants whole-function credit.
    Calls retain their unnormalized return-address checks during composition.
    """
    layout = check_global_layout(normalization)
    if not normalization or len(set(normalization.values())) != len(normalization):
        raise ValueError("target normalization requires a nonempty injective address map")
    pairs: list[dict[str, Any]] = []
    for original_address, candidate_address in sorted(correspondence.items()):
        left, original = _returning_block(original_image, original_address)
        right, candidate = _returning_block(candidate_image, candidate_address)
        row: dict[str, Any] = {"original": original, "candidate": candidate, "status": "incomplete"}
        if left is not None and right is not None:
            right["_constant_normalization"] = dict(normalization)
            right["_constant_normalization_reasons"] = dict.fromkeys(normalization, "global_reloc")
            proof = S._compare_functions(left, right, timeout_ms=1000)
            row["solver_result"] = proof
            row["status"] = {"passed": "conditional", "failed": "mismatch"}.get(proof["status"], "incomplete")
        pairs.append(row)
    statuses = {row["status"] for row in pairs}
    status = ("mismatch" if "mismatch" in statuses else
              "conditional" if statuses == {"conditional"} else "incomplete")
    return {
        "status": status, "scope": "value_relocated_returning_target_blocks", "pairs": pairs,
        "function_equivalence_proved": False,
        "assumptions": {"kind": "conditional_value_relocation", "proved": False,
                        "relocations": {hex(k): hex(v) for k, v in sorted(normalization.items())},
                        "map_sha256": layout["map_sha256"]},
        "pending_conditions": ["derive the live-memory and alias relation behind value rewriting",
                               "compose the relation with root prefix and all target paths",
                               "preserve related memory through writes and external effects"],
    }


def attach_normalized_table_checks(report: dict[str, Any], original: bytes, candidate: bytes) -> None:
    """Reuse the sealed report premise; retain original target and root verdicts."""
    premise = report.get("proof_contract", {}).get("global_normalization")
    if not premise or not premise.get("relocations"):
        return
    normalization = {int(k, 0): int(v, 0) for k, v in premise["relocations"].items()}
    for row in report["results"]:
        for check in row.get("partial_table_checks", []):
            strict = check.get("target_block_checks")
            if strict is None or strict["status"] == "checked":
                continue
            if len(set(normalization.values())) != len(normalization):
                check["normalized_target_checks"] = {
                    "status": "incomplete", "reason": "noninjective_global_relocation_map",
                    "function_equivalence_proved": False,
                }
                continue
            pairs = {int(pair["original"]["address"], 0): int(pair["candidate"]["address"], 0)
                     for pair in strict["pairs"]}
            check["normalized_target_checks"] = check_normalized_targets(original, candidate, pairs, normalization)
