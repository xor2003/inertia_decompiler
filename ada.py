#!/usr/bin/env python3
"""Layer: CLI entry point.

Responsibility: expose the merged ada_script disassembler and shared signatures.
"""

from __future__ import annotations

from tools.ada_script.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
