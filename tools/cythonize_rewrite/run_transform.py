"""Layer: Tooling/cythonize.

Responsibility: apply the pure-mode Cython rewrite to every module under the
target package, in place. Files stay valid CPython (``import cython`` uses the
wheel shim when interpreted) and compile to native extensions when cythonized.

Usage:
  python tools/cythonize_rewrite/run_transform.py inertia \
      --manifest .cache/cython-bench/manifest.json [--jobs 8] [--check] \
      [--only inertia/ir/foo.py]
"""

from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from transform import transform_source, mixin_demoted_class_names  # noqa: E402


def _module_name(root: pathlib.Path, path: pathlib.Path) -> str:
    """Dotted module name for ``path`` under package ``root``."""
    rel = path.relative_to(root.parent)
    return ".".join(rel.with_suffix("").parts)


def _work(args: tuple[str, str, dict, bool]) -> tuple[str, dict, str | None]:
    """Transform one file; returns (path, stats, error).

    In check mode (``dry=True``) the transformed output is compared but
    never written — ``stats["would_write"]`` replaces ``written``.
    """
    path_s, source, rec, dry = args
    stats: dict = {}
    try:
        out = transform_source(source, rec, stats)
    except Exception as exc:  # noqa: BLE001 - codemod reports per-file errors
        return path_s, stats, f"{type(exc).__name__}: {exc}"
    if out != source:
        if dry:
            stats["would_write"] = 1
        else:
            pathlib.Path(path_s).write_text(out)
            stats["written"] = 1
    return path_s, stats, None


def main() -> None:
    """Rewrite all modules under the package root in place."""
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("root", type=pathlib.Path)
    ap.add_argument("--manifest", type=pathlib.Path, required=True)
    ap.add_argument("--jobs", type=int, default=8)
    ap.add_argument("--check", action="store_true", help="parse only, no writes")
    ap.add_argument("--only", type=pathlib.Path, help="single file mode")
    ap.add_argument(
        "--files", type=pathlib.Path, nargs="+",
        help="explicit file list (instead of scanning root)",
    )
    ap.add_argument("--report", type=pathlib.Path)
    args = ap.parse_args()

    manifest = json.loads(args.manifest.read_text())
    modules = manifest["modules"]
    mixin_demoted = mixin_demoted_class_names(modules)

    paths = (
        [args.only]
        if args.only
        else sorted(args.files)
        if args.files
        else sorted(args.root.rglob("*.py"))
    )
    tasks: list[tuple[str, str, dict]] = []
    skipped: dict[str, str] = {}
    for path in paths:
        module = _module_name(args.root, path)
        rec = modules.get(module, {})
        if rec.get("cython_name_collision"):
            skipped[str(path)] = "cython_name_collision"
            continue
        if module in mixin_demoted:
            rec = {**rec, "mixin_demoted": sorted(mixin_demoted[module])}
        source = path.read_text(errors="replace")
        tasks.append((str(path), source, rec, args.check))

    errors: dict[str, str] = {}
    totals: dict = {}
    if args.jobs <= 1:
        results = [_work(t) for t in tasks]
    else:
        with mp.Pool(args.jobs) as pool:
            results = pool.map(_work, tasks, chunksize=8)
    for path_s, stats, err in results:
        for k, v in stats.items():
            totals[k] = totals.get(k, 0) + v
        if err:
            errors[path_s] = err

    report = {"totals": totals, "errors": errors, "skipped": skipped}
    if args.report:
        args.report.write_text(json.dumps(report, indent=1, sort_keys=True) + "\n")
    print(json.dumps({"files": len(tasks), "totals": totals,
                      "errors": len(errors), "skipped": len(skipped)},
                     indent=1, sort_keys=True))


if __name__ == "__main__":
    main()
