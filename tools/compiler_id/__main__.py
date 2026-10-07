"""Run the compiler-identification tool as a package.

Layer: Tooling/optional evidence.
Responsibility: retain one implementation of command-line report behavior.
"""

from __future__ import annotations

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
