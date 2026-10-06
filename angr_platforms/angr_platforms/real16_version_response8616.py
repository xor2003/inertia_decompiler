"""Single-owner contract for the declared DOS version-service response.

Layer: Frontend/runtime package surface — shared service contract.
Responsibility: own exactly once the documented INT 21h / AH=30h / AL=00h
service identity and response encoding that two consumers project: the
dosunit canonical ``program_version_query`` owner and the invocation
census's declared-service revalidation. This module is pure data and one
pure function — it imports nothing beyond the standard library and must
stay importable without initializing angr or the ``X86_16`` platform
package. Nothing here asserts an installed DOS: the constants name the
declared contract shape and the function encodes caller-declared policy
fields into the documented response words.

"""

from __future__ import annotations

__all__ = [
    "INT21_VERSION_FUNCTION_8616",
    "INT21_VERSION_MINIMUM_MAJOR_8616",
    "INT21_VERSION_SELECTOR_8616",
    "INT21_VERSION_SERIAL_MASK_8616",
    "INT21_VERSION_VECTOR_8616",
    "version_response_words_8616",
]

# INT 21h is the DOS service vector this declared contract binds.
INT21_VERSION_VECTOR_8616: int = 0x21

# AH=30h is Get DOS Version; AL=00h is the only admitted selector. Other
# AL subfunctions are never modeled by either consumer.
INT21_VERSION_FUNCTION_8616: int = 0x30
INT21_VERSION_SELECTOR_8616: int = 0x00

# DOS 2.0 introduced the documented return convention (minor in AH, OEM in
# BH, 24-bit serial in BL:CX); a declared major below 2 would publish a
# response whose meaning the contract does not define.
INT21_VERSION_MINIMUM_MAJOR_8616: int = 2

# BL:CX carries a 24-bit serial: BL holds bits 16..23, CX bits 0..15.
INT21_VERSION_SERIAL_MASK_8616: int = 0xFFFFFF


def version_response_words_8616(
    major: int, minor: int, oem: int, serial: int
) -> tuple[int, int, int]:
    """Project the documented AH=30h response words from declared policy.

    ``ax`` is ``(minor << 8) | major``, ``bx`` is ``(oem << 8) |`` the
    serial's top byte and ``cx`` the serial's low word — the single
    documented encoding both the dosunit mint and the census-side
    expectation derive from a declared policy. The caller is responsible
    for admitting only bounded fields (8-bit majors/minor/oem, 24-bit
    serial, ``major >= 2``); this function performs no admission checks
    and no writes.
    """
    return (
        (minor << 8) | major,
        (oem << 8) | (serial >> 16),
        serial & 0xFFFF,
    )
