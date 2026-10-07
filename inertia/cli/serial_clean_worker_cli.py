"""Layer: CLI/fallback/reporting.

Responsibility: enter one isolated serial function worker through the typed CLI core.
Forbidden: owning decompiler semantics, source-backed recovery, or postprocess semantic repair.
"""

from __future__ import annotations

import cProfile
import os
import sys
from pathlib import Path

from inertia.cli.cache_runtime_contract import (
    WORKER_CPROFILE_ENV_8616,
    WORKER_IN_PROCESS_PROFILE_ENV_8616,
)
from inertia.cli.cli_core import main as _core_main


def _worker_profile_path_8616(raw_path: str) -> Path:
    """Expand the process placeholder in one explicit worker profile path."""
    return Path(raw_path.replace("{pid}", str(os.getpid()))).expanduser()


def main(argv: list[str] | None = None) -> int:
    """Run one clean worker, optionally recording opt-in cProfile evidence."""
    raw_profile_path = os.environ.get(WORKER_CPROFILE_ENV_8616, "").strip()
    if not raw_profile_path:
        return int(_core_main(argv))
    os.environ[WORKER_IN_PROCESS_PROFILE_ENV_8616] = "1"
    profile_path = _worker_profile_path_8616(raw_profile_path)
    profile_path.parent.mkdir(parents=True, exist_ok=True)
    profiler = cProfile.Profile()
    try:
        return int(profiler.runcall(_core_main, argv))
    finally:
        profiler.dump_stats(profile_path)
        print(f"[profile] clean worker cProfile: {profile_path}", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
