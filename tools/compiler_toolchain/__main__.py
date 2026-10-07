"""Run the manifest-selected compiler coverage command.

Layer: Tooling/CLI.
Responsibility: expose the shared suite without changing its acceptance policy.
"""

from __future__ import annotations

from tools.compiler_toolchain.compiler_coverage_suite import main

if __name__ == "__main__":
    raise SystemExit(main())
