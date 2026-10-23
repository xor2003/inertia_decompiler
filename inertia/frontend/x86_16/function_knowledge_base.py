"""Resolve the knowledge base that actually owns an angr Function.

Layer: Frontend/angr compatibility.
Responsibility: validate originating function-manager/project identity for consumers.
This module does not reparent functions, merge knowledge bases or infer semantics.
"""

from __future__ import annotations

from typing import Protocol, cast

from angr import KnowledgeBase
from angr.knowledge_plugins.functions.function_manager import FunctionManager


class _FunctionOwnerBoundary8616(Protocol):
    """Required ownership field at the third-party angr Function boundary."""

    _function_manager: FunctionManager | None


def function_knowledge_base_8616(project: object, function: object) -> KnowledgeBase:
    """Require the exact originating function KB and matching project identity."""
    manager = cast(_FunctionOwnerBoundary8616, function)._function_manager
    if manager is None:
        raise ValueError("function ownership requires an originating function manager")
    kb = manager._kb
    if kb._project is not project:
        raise ValueError("function manager belongs to a different project")
    return kb
