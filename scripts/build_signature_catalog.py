#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from signature_catalog import build_signature_catalog


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Recursively import .pat/.obj/.lib signatures into one deduplicated PAT catalog.",
    )
    parser.add_argument("roots", nargs="+", type=Path, help="Root directories or files to import.")
    parser.add_argument(
        "--output",
        required=True,
        type=Path,
        help="Output PAT catalog path.",
    )
    parser.add_argument(
        "--no-recursive",
        action="store_true",
        help="Only inspect the immediate directory entries of each root.",
    )
    parser.add_argument(
        "--flair-root",
        type=Path,
        default=Path("/home/xor/ida77/flair77"),
        help="Path to the FLAIR tool root used for local plb conversion.",
    )
    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=None,
        help="Optional cache directory for temporary/generated PATs.",
    )
    args = parser.parse_args(argv)

    result = build_signature_catalog(
        args.roots,
        args.output,
        recursive=not args.no_recursive,
        flair_root=args.flair_root,
        cache_dir=args.cache_dir,
    )
    print(f"output: {result.output_path}")
    print(f"inputs: {result.input_count}")
    print(f"imported_modules: {result.imported_module_count}")
    print(f"unique_modules: {result.unique_module_count}")
    print(f"duplicate_modules: {result.duplicate_module_count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
