"""Compiler identification command entry point.

Layer: Tooling/optional evidence.
Responsibility: invoke the classification report through its canonical owner.
"""

from __future__ import annotations

from .report import main as main

if __name__ == "__main__":
    raise SystemExit(main())
