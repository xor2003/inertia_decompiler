"""Shared repository test configuration.

Layer: Test infrastructure.
Responsibility: activate component ownership for unit and artifact tests.
"""

from __future__ import annotations

pytest_plugins: list[str] = ["tools.dev.pytest_components", "tools.dev.pytest_workspace", "tools.dev.pytest_runtime"]
