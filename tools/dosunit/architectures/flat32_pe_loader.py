"""Layer: dosunit CLE PE loader compatibility boundary.

Responsibility: retain the inclusive final mapped byte before CLE relocations
and bound mapped-image construction. The installed PE constructor truncates at
max_addr - min_addr, losing one byte. This adapter corrects that loader span,
never SSA semantics, and refuses incompatible memory mutations explicitly.
"""
from __future__ import annotations

from typing import Any, cast

from cle import Clemory
from cle.backends.pe.pe import PE


# Installed CLE has no PE stub; only this third-party inheritance boundary is
# dynamic. Owned constructor fields, arguments and image results stay typed.
class InclusivePE(PE):  # type: ignore[misc]
    """A bounded loader adapter for the installed third-party PE constructor.

    CLE calls the image builder during construction, then applies relocation
    records after this backend returns. The corrected seed is therefore in
    place before imports and base relocations can read or modify its last byte.
    Dynamic constructor arguments are confined to this third-party boundary.
    """

    memory: Clemory
    """CLE backend memory, initialized before root binding and relocation."""

    def __init__(self, *args: object, max_mapped_bytes: int, **kwargs: object) -> None:
        """Keep upstream parsed metadata and repair only its inclusive seed span."""
        if type(max_mapped_bytes) is not int or max_mapped_bytes <= 0:
            raise ValueError("PE mapped-byte allowance must be a positive integer")
        self._owned_allowance: int = max_mapped_bytes
        self._owned_seed: bytes = b""
        # CLE supplies heterogeneous backend options, including its evolving
        # debug callback arguments. Preserve that third-party keyword boundary.
        super().__init__(*args, **cast(Any, kwargs))
        seed = self._owned_seed
        if not seed:
            raise ValueError("PE constructor did not materialize its bounded image")
        last = len(seed) - 1
        if last in self.memory:
            if self.memory.load(0, len(seed)) != seed:
                raise ValueError("PE constructor changed initialized bytes before relocation")
        else:
            backers = tuple(self.memory.backers())
            if len(backers) != 1 or backers[0][0] != 0 or bytes(backers[0][1]) != seed[:-1]:
                raise ValueError("PE constructor omitted more than its inclusive final byte")
            # VEX concrete_load reads one contiguous backer. Appending a new
            # one-byte backer repairs ordinary reads but still truncates decode.
            # This is still backend construction: the loader has not bound its
            # root view or applied relocations. Build its one contiguous seed
            # through public APIs; installed CLE remove_backer also misindexes
            # an exact start and cannot safely replace the existing backer.
            corrected = Clemory(self.arch)
            corrected.add_backer(0, seed)
            self.memory = corrected

    def _get_memory_mapped_image(self, max_virtual_address: int = 0x100000000) -> bytes:
        """Build exactly the bounded inclusive span, including declared zero tails."""
        span = self.max_addr - self.min_addr + 1
        if not 0 < span <= self._owned_allowance:
            raise ValueError("PE declared mapped span exceeds the loader allowance")
        mapped = super()._get_memory_mapped_image(max_virtual_address=max_virtual_address)
        seed = bytes(mapped[:span]).ljust(span, b"\0")
        self._owned_seed = seed
        return seed
