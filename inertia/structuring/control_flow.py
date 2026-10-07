"""Compatibility exports for control-flow structuring helpers.

Layer: Structuring.
Responsibility: owns CFG shape, loops, switches, and structured condition lowering from proven
IR/semantic evidence.
Do not perform alias-state ownership, widening, type/materialization recovery,
rewrite cleanup, postprocess, or CLI/reporting work here.
"""

from __future__ import annotations

from inertia.structuring.decompiler_structuring_stage import *  # noqa: F403
