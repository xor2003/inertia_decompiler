"""Shared repository test configuration.

Layer: Test infrastructure.
Responsibility: activate component ownership for unit and artifact tests.
"""

from __future__ import annotations

pytest_plugins: list[str] = ["pytest_components"]
