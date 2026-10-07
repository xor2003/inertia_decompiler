#!/usr/bin/env python3
"""Bundle compiler signature catalogs as optional evidence artifacts.

Layer: Tooling/gates.
Responsibility: package optional signature catalogs without making signatures semantic proof.
"""

from __future__ import annotations

import argparse
import pickle
import shutil
import sys
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tools.signatures.omf_pat import load_cached_pat_regex_specs  # noqa: E402
from tools.signatures.signature_catalog import build_signature_catalog  # noqa: E402

DEFAULT_COMPILERS_ROOT = Path("/home/xor/inertia_player/dos_compilers")
DEFAULT_BUNDLE_DIR = REPO_ROOT / "signature_catalogs"
DEFAULT_CATALOG_NAME = "all_compilers.pat"
DEFAULT_CACHE_DIRNAME = ".signature_catalog_cache"
DEFAULT_BUNDLE_NAME = "all_compilers_catalog_bundle.zip"


def _default_input_roots() -> tuple[Path, ...]:
    if not DEFAULT_COMPILERS_ROOT.exists():
        return ()
    return tuple(child for child in sorted(DEFAULT_COMPILERS_ROOT.iterdir()) if child.is_dir())


def _zip_tree(bundle_path: Path, root: Path) -> None:
    with zipfile.ZipFile(bundle_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            arcname = path.relative_to(root)
            zf.write(path, arcname=str(arcname))


def main(argv: list[str] | None = None) -> int:
    """Build and package one optional compiler signature-catalog bundle."""
    parser = argparse.ArgumentParser(
        description="Build all-compilers PAT catalog + cache and package them into a shareable zip bundle."
    )
    parser.add_argument("inputs", nargs="*", type=Path, help="Compiler roots; default: all under dos_compilers.")
    parser.add_argument(
        "--bundle-dir",
        type=Path,
        default=DEFAULT_BUNDLE_DIR,
        help="Output directory for PAT/cache and zip bundle.",
    )
    parser.add_argument(
        "--catalog-name",
        type=str,
        default=DEFAULT_CATALOG_NAME,
        help="PAT filename inside bundle-dir.",
    )
    parser.add_argument(
        "--bundle-name",
        type=str,
        default=DEFAULT_BUNDLE_NAME,
        help="Zip bundle filename inside bundle-dir.",
    )
    args = parser.parse_args(argv)

    input_roots = tuple(args.inputs) if args.inputs else _default_input_roots()
    if not input_roots:
        raise SystemExit("no compiler roots found")

    bundle_dir = args.bundle_dir if args.bundle_dir.is_absolute() else (REPO_ROOT / args.bundle_dir)
    bundle_dir.mkdir(parents=True, exist_ok=True)
    catalog_path = bundle_dir / args.catalog_name
    cache_dir = bundle_dir / DEFAULT_CACHE_DIRNAME
    cache_dir.mkdir(parents=True, exist_ok=True)

    result = build_signature_catalog(input_roots, catalog_path, recursive=True, cache_dir=cache_dir)
    specs = load_cached_pat_regex_specs(catalog_path, cache_dir)
    snapshot_path = bundle_dir / "catalog_specs.pickle"
    snapshot_path.write_bytes(pickle.dumps(specs, protocol=pickle.HIGHEST_PROTOCOL))

    staging = bundle_dir / ".bundle_staging"
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True, exist_ok=True)
    shutil.copy2(catalog_path, staging / catalog_path.name)
    shutil.copy2(snapshot_path, staging / snapshot_path.name)
    # Matcher zip path needs only catalog + precompiled specs snapshot.
    # Raw per-input cache artifacts are not required inside bundle.

    bundle_path = bundle_dir / args.bundle_name
    _zip_tree(bundle_path, staging)
    shutil.rmtree(staging, ignore_errors=True)

    print(
        f"bundle={bundle_path} "
        f"catalog={catalog_path} "
        f"inputs={result.input_count} "
        f"unique_modules={result.unique_module_count} "
        f"cached_specs={len(specs)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
