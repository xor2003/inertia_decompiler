"""Layer: Frontend/runtime package initialization.

Responsibility: activate the required default lifter backend before transitive imports.
This import boundary owns the sole startup activation; selection rules live in
lifter_backend and instruction semantics remain in the authoritative .py source.
"""

from __future__ import annotations

from inertia.frontend.x86_16.lifter_backend import LifterBackend
from inertia.frontend.x86_16.lifter_import import selected_lifter_backend

VEX_BACKEND: LifterBackend = selected_lifter_backend()
