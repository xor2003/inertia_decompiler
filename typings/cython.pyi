"""Layer: Tooling/type checking.

Responsibility: type the external pure-Python annotation API used by the
accelerated modules. These marker objects describe compiler storage, not
guest-value Python types. Decorators preserve the wrapped contract exactly;
``declare`` stays opaque because the annotated binding site carries the type.
"""

from collections.abc import Callable
from typing import Any, TypeVar

int: object
bint = bool

_T = TypeVar("_T")
_F = TypeVar("_F", bound=Callable[..., Any])


def declare(t: object = ..., value: object = ..., **kwargs: object) -> Any:
    """Return the initializer the compiler binds to declared storage."""


def cfunc(func: _F) -> _F:
    """Preserve the callable contract for a module-private compiled function."""

def ccall(func: _F) -> _F:
    """Preserve the callable contract for a fast-call compiled function."""

def cclass(cls: type[_T]) -> type[_T]:
    """Preserve the class contract for a compiled extension type."""

def locals[**P, R](**types: object) -> Callable[[Callable[P, R]], Callable[P, R]]:
    """Preserve the callable contract when declaring compiler-local storage."""
