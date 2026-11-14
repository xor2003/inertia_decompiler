# cython: language_level=3, infer_types=True
"""Layer: frontend package boundaries.

Responsibility: expose project-owned decompiler namespace without eager pipeline startup.
"""

from __future__ import annotations
import cython
