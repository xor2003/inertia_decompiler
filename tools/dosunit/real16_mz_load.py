"""Real MZ image loading for real16 concrete replay.

Layer: dosunit concrete execution.
Responsibility: parse DOS MZ headers, apply relocation records against an
explicit load segment through the shared Frontend source owner, and fingerprint the file bytes, relocated image and
relocation records. The loaded image is the only memory seed; there is no
emulated DOS environment, PSP or operating-system service.

"""

from __future__ import annotations

import hashlib

from angr_platforms.X86_16.mz_load_source import (
    MAX_MZ_RELOCATIONS as MAX_MZ_RELOCATIONS,
)
from angr_platforms.X86_16.mz_load_source import (
    MzExe as MzExe,
)
from angr_platforms.X86_16.mz_load_source import (
    parse_mz as parse_mz,
)
from angr_platforms.X86_16.mz_load_source import (
    relocate_mz_load_module,
)

from tools.dosunit.model import canonical_json_bytes
from tools.dosunit.real16_replay_model import LINEAR_LIMIT, LinearRange, Real16Image

_relocate = relocate_mz_load_module

DEFAULT_LOAD_SEGMENT: int = 0x1000



def image_from_mz_bytes(
    data: bytes,
    *,
    load_segment: int = DEFAULT_LOAD_SEGMENT,
    code_ranges: tuple[LinearRange, ...] = (),
) -> Real16Image:
    """Relocate an MZ image at ``load_segment`` and fingerprint the result.

    ``code_ranges`` are physical addresses of declared instruction bytes;
    when omitted the entire loaded image is declared executable and the scope
    is recorded as ``whole_image``. The BSS paragraph count from ``minalloc``
    is retained so callers can map it as zeroed memory.
    """
    if not 0 <= load_segment <= 0xFFFF:
        raise ValueError("load segment must be a 16-bit paragraph value")
    exe = parse_mz(data)
    base = load_segment * 16
    relocated = relocate_mz_load_module(exe, load_segment)
    if base + len(relocated) + exe.minalloc * 16 > LINEAR_LIMIT:
        raise ValueError("relocated image plus BSS exceeds the real-mode address space")
    scope = "declared"
    ranges = code_ranges
    if not ranges:
        ranges = (LinearRange(base, len(relocated)),)
        scope = "whole_image"
    if any(
        region.address < base or region.address + region.size > base + len(relocated)
        for region in ranges
    ):
        raise ValueError("declared code range must lie inside relocated image bytes")
    reloc_digest = hashlib.sha256(canonical_json_bytes(list(exe.relocations))).hexdigest()
    image_digest = hashlib.sha256(
        base.to_bytes(4, "little") + len(relocated).to_bytes(4, "little") + relocated
    ).hexdigest()
    return Real16Image(
        chunks=((base, relocated),),
        code_ranges=ranges,
        load_segment=load_segment,
        image_size=len(relocated),
        bss_size=exe.minalloc * 16,
        file_sha256=hashlib.sha256(data).hexdigest(),
        image_sha256=image_digest,
        reloc_sha256=reloc_digest,
        code_scope=scope,
    )
