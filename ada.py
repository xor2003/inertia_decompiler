#!/usr/bin/env python3
"""Command wrapper for the standalone annotated DOS-disassembly CLI.

Layer: Tooling/gates.
Responsibility: expose the standalone annotated DOS-disassembly CLI without owning analysis semantics.
"""

from __future__ import annotations

from tools.ada_script.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
