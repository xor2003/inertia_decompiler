"""Layer: Tooling/cythonize.

Responsibility: re-run the per-file ``cython`` check on a subset of paths
listed in a prior errors manifest, writing a fresh errors manifest.

Usage:
  python tools/cythonize_rewrite/recheck.py <errors_in.json> <errors_out.json> [jobs]
"""

from __future__ import annotations

import json
import multiprocessing as mp
import sys

from build_all import _check_one


def main() -> int:
    src, dst = sys.argv[1], sys.argv[2]
    jobs = int(sys.argv[3]) if len(sys.argv) > 3 else 8
    paths = list(json.load(open(src)))
    with mp.Pool(jobs) as pool:
        results = pool.map(_check_one, paths, chunksize=2)
    errors = {p: e for p, e in results if e}
    ok = sum(1 for _, e in results if e is None)
    json.dump(errors, open(dst, "w"), indent=1)
    print(f"rechecked={len(results)} ok={ok} still_failing={len(errors)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
