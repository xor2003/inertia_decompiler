"""Layer: dosunit native guest engine construction.

Responsibility: create Unicorn engines whose TCG translation arena is bounded
before the first lazy engine operation; refuse loudly when the installed
binding cannot honour the bound instead of silently keeping the default
~1 GiB virtual reservation.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from unicorn.unicorn_py3.unicorn import Uc, UcError
else:
    try:
        from unicorn.unicorn_py3.unicorn import Uc, UcError
    except ImportError:
        Uc = None  # type: ignore[assignment, misc]
        UcError = RuntimeError  # type: ignore[assignment, misc]

# libunicorn reserves about 1 GiB of virtual address space per engine for its
# TCG translation arena on 64-bit hosts. Measured on this binding (2.1.4):
# +1,050,532 KiB VmSize for ~4 MiB RSS, reserved lazily at the first engine
# operation (mem_map), with a native exit(1) — not a Python exception — when
# the reservation cannot fit the process address-space limit. The bound below
# keeps each engine's arena at 16 MiB; measured guest observables are
# unchanged on the 16- and 32-bit replay/control paths.
DEFAULT_TCG_BUFFER_BYTES: int = 16 << 20


class EngineArenaRefusal(RuntimeError):
    """The installed Unicorn binding could not honour the bounded arena."""


def _apply_arena_bound(guest: Uc, tcg_buffer_bytes: int) -> Uc:
    """Bound a constructed engine's TCG arena before its first operation.

    libunicorn reserves the translation buffer lazily; UC_CTL_TCG_BUFFER_SIZE
    applied here takes effect before that reservation. A binding that lacks
    the ctl surface, rejects the write or read (UcError, cause retained), or
    reports an effective size above the request is refused loudly; this
    function never returns an engine that kept a larger arena.
    """
    # Dynamic third-party boundary: the ctl surface is optional across unicorn builds.
    set_size = getattr(guest, "ctl_set_tcg_buffer_size", None)
    # Dynamic third-party boundary: same optional ctl surface for the readback.
    get_size = getattr(guest, "ctl_get_tcg_buffer_size", None)
    if not callable(set_size) or not callable(get_size):
        raise EngineArenaRefusal("installed unicorn binding lacks TCG buffer-size controls")
    try:
        guest.ctl_set_tcg_buffer_size(tcg_buffer_bytes)
        effective = guest.ctl_get_tcg_buffer_size()
    except UcError as exc:
        raise EngineArenaRefusal(
            f"unicorn rejected TCG buffer bound {tcg_buffer_bytes}"
        ) from exc
    if effective <= 0 or effective > tcg_buffer_bytes:
        raise EngineArenaRefusal(
            f"unicorn reports TCG buffer {effective} bytes, above bound {tcg_buffer_bytes}"
        )
    return guest


def make_guest(arch: int, mode: int, *, tcg_buffer_bytes: int = DEFAULT_TCG_BUFFER_BYTES) -> Uc:
    """Create a bounded-arena engine; see the module docstring for the policy."""
    if Uc is None:
        raise EngineArenaRefusal("unicorn backend is not importable")
    if tcg_buffer_bytes <= 0:
        raise EngineArenaRefusal(f"tcg_buffer_bytes must be positive, got {tcg_buffer_bytes}")
    return _apply_arena_bound(Uc(arch, mode), tcg_buffer_bytes)
