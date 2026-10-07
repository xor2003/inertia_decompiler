"""Pipeline governance package exports.

Layer: Pipeline governance.
Responsibility: owns runtime ordering, invariant checks, hard failures, and final emission gates.
Do not recover semantic facts or perform IR, alias, widening,
lowering/materialization, structuring, rewrite, postprocess, or CLI/reporting
work here.
"""

from __future__ import annotations
