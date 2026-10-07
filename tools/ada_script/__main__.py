"""Layer: ADA command entry.

Responsibility: expose the standalone analyzer as ``python -m tools.ada_script``.
"""

from __future__ import annotations

from tools.ada_script.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
