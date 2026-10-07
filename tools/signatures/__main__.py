"""Run the shared optional signature catalog command.

Layer: Tooling/CLI.
Responsibility: expose the catalog builder through the package command.
"""

from __future__ import annotations

from tools.signatures.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
