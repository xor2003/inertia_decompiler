"""Compatibility export for the canonical alias model implementation.

Layer: Alias.
Responsibility: Owns storage identity and alias-state ownership.
Dynamic boundary: compatibility re-export only; canonical alias_model_impl owns
the literal public API.
Do not perform lowering, structuring, rewrite, postprocess, or CLI/reporting
work here.
"""

from __future__ import annotations

from .alias_model_impl import *  # noqa: F403
from .alias_model_impl import __all__ as __all__
