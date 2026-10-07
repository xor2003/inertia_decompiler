#!/usr/bin/env python3
"""Import external compiler pattern files into local signature catalogs.

Layer: Tooling/gates.
Responsibility: import optional compiler patterns without making signatures semantic proof.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.signatures.signature_catalog import build_signature_catalog  # noqa: E402

DEFAULT_COMPILERS_ROOT = Path("/home/xor/inertia_player/dos_compilers")


def _default_input_roots() -> tuple[Path, ...]:
    if not DEFAULT_COMPILERS_ROOT.exists():
        return ()
    return tuple(child for child in sorted(DEFAULT_COMPILERS_ROOT.iterdir()) if child.is_dir())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Import PAT/OBJ/LIB patterns into the repo-global PAT file.")
    parser.add_argument("inputs", nargs="*", type=Path, help="PAT/OBJ/LIB files or directories to import.")
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("signature_catalogs/imported_patterns.pat"),
        help="Output PAT file. Defaults to signature_catalogs/imported_patterns.pat.",
    )
    args = parser.parse_args(argv)

    repo_root = REPO_ROOT
    output_path = args.output if args.output.is_absolute() else (repo_root / args.output)
    cache_dir = repo_root / "signature_catalogs" / ".signature_catalog_cache"
    input_roots = tuple(args.inputs) if args.inputs else _default_input_roots()
    if not input_roots:
        raise SystemExit("no input roots found")
    result = build_signature_catalog(input_roots, output_path, recursive=True, cache_dir=cache_dir)
    print(
        f"wrote {result.output_path} "
        f"inputs={result.input_count} unique_modules={result.unique_module_count} "
        f"duplicates={result.duplicate_module_count}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
