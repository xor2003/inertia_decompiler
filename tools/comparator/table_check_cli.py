"""Layer: comparator CLI.

Responsibility: publish reproducible partial table checks independently of full
function proofs; structural success never enters the function coverage count.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from tools.comparator.table_checks import check_target_tables, read_target_table
from tools.comparator.table_dispatch_checks import check_dispatch_pair


def main(argv: list[str] | None = None) -> int:
    """Check a declared pair of tables and retain their source and map digests."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--original-exe", type=Path, required=True)
    parser.add_argument("--candidate-exe", type=Path, required=True)
    parser.add_argument("--original-table", type=lambda text: int(text, 0), required=True)
    parser.add_argument("--candidate-table", type=lambda text: int(text, 0), required=True)
    parser.add_argument("--original-count", type=int, required=True)
    parser.add_argument("--candidate-count", type=int, required=True)
    parser.add_argument("--original-dispatch", type=lambda text: int(text, 0))
    parser.add_argument("--candidate-dispatch", type=lambda text: int(text, 0))
    parser.add_argument("--target-map", type=Path, required=True,
                        help='JSON list of {"original":"0x...", "candidate":"0x..."} target pairs')
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if (args.original_dispatch is None) != (args.candidate_dispatch is None):
        parser.error("dispatch checks require both --original-dispatch and --candidate-dispatch")
    map_bytes = args.target_map.read_bytes()
    pairs = json.loads(map_bytes)
    if not isinstance(pairs, list):
        raise ValueError("target map must be a list of address pairs")
    correspondence: dict[int, int] = {}
    for pair in pairs:
        if not isinstance(pair, dict) or set(pair) != {"original", "candidate"}:
            raise ValueError("target map entries require original and candidate addresses")
        left, right = int(pair["original"], 0), int(pair["candidate"], 0)
        if left in correspondence:
            raise ValueError("duplicate original target in correspondence")
        correspondence[left] = right
    original_image, candidate_image = args.original_exe.read_bytes(), args.candidate_exe.read_bytes()
    original = read_target_table(original_image, args.original_table, args.original_count)
    candidate = read_target_table(candidate_image, args.candidate_table, args.candidate_count)
    result = check_target_tables(original, candidate, correspondence)
    if args.original_dispatch is not None:
        dispatch = check_dispatch_pair(original_image, candidate_image, original, candidate,
                                       args.original_dispatch, args.candidate_dispatch)
        result["dispatch_check"] = dispatch
        if result["status"] != "mismatch" and dispatch["status"] != "checked":
            result["status"] = dispatch["status"]
    result["target_map_sha256"] = hashlib.sha256(map_bytes).hexdigest()
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(f"{result['status']}: {result['checked_entries']} table entries checked; function proof pending")
    return 0 if result["status"] == "checked" else 1


if __name__ == "__main__":
    raise SystemExit(main())
