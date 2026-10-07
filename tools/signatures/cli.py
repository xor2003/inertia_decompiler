#!/usr/bin/env python3
"""Build compiler/library signature catalogs as optional decompiler evidence.

Layer: Tooling/gates.
Responsibility: build optional signature catalogs without making signatures semantic proof.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT: Path = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.signatures.flair_paths import flair_signature_root  # noqa: E402
from tools.signatures.signature_catalog import build_signature_catalog  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    """Build an optional signature catalog from the command arguments."""
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
        default=flair_signature_root(),
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
