"""Layer: Tooling/type checking.

Responsibility: type the external pure-Python annotation API used by the lifter.
These marker objects describe compiler storage, not guest-value Python types.
"""

from collections.abc import Callable

int: object
bint: object

def locals[**P, R](**types: object) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Preserve the callable contract when declaring compiler-local storage."""
