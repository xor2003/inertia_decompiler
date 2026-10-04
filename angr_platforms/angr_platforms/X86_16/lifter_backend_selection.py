"""Layer: Frontend/runtime package initialization.

Responsibility: activate the required default lifter backend before transitive imports.
This import boundary owns the sole startup activation; selection rules live in
lifter_backend and instruction semantics remain in the authoritative .py source.
"""

from __future__ import annotations

import sys
from typing import Any, cast

from .lifter_backend import LifterBackend, activate_lifter_backend

# Python's package module/__path__ contract is a dynamic import-system boundary.
_package_path: list[str] = cast(Any, sys.modules[__package__]).__path__
VEX_BACKEND: LifterBackend = activate_lifter_backend(_package_path)
