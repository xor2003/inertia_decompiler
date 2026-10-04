"""Layer: test support.
Responsibility: own replay capture fixture fixture contracts and evidence.
"""
from __future__ import annotations

from tools.dosunit.flat32_replay_model import (
    ReplayImage,
)
from tools.dosunit.real16_replay_model import (
    Real16Image,
)

SEED = "0x6d3676656374"  # fixed cohort seed ("m6vect"); same seed, same bytes


INSTRUCTION_LIMIT = 10000


MAX_COHORT_VECTORS = 16


FUZZ_COUNT = 6


TRACE_CAP = 4096


R16_LOAD = 0x1000


R16_SS = 0x7000


R16_SP = 0x0100


R16_TRAP_OFF = 0x8000  # inside entry CS, outside image bytes


R16_CALLEE = 0x000C


R16_SPIN = 0x0032


R16_CODE_SIZE = 0x0034


R16_ARRAY = 0x0200


R16_OUT = 0x0300


R16_IMAGE_SIZE = 0x0320


R16_SENTINEL = 0xDEAD


F32_TEXT = 0x401000


F32_DATA = 0x402000


F32_ESP = 0x28000


F32_CALLEE = 0x401011


F32_SPIN = 0x401038


F32_OUT = 0x402020


F32_DATA_SIZE = 0x40


F32_SENTINEL = 0xDEAD


_R16_CODE = bytes.fromhex(
    "bb 00 02"          # 0x00 mov bx,0x0200
    "b9 04 00"          # 0x03 mov cx,0x0004
    "e8 03 00"          # 0x06 call +3 -> 0x0c
    "c3"                # 0x09 ret (through harness frame)
    "90 90"             # 0x0a pad
    "31 c0"             # 0x0c callee: xor ax,ax
    "03 07"             # 0x0e loop: add ax,[bx]
    "83 c3 02"          # 0x10 add bx,2
    "e2 f9"             # 0x13 loop -7 -> 0x0e
    "a3 00 03"          # 0x15 mov [0x0300],ax
    "81 fa ad de"       # 0x18 cmp dx,0xdead
    "75 02"             # 0x1c jne +2 -> 0x20
    "0f a2"             # 0x1e cpuid (undeclared machine input)
    "c3"                # 0x20 ret
)


_R16_MUT_OFFSET = 0x0E  # `03 07` add -> `2b 07` sub


_F32_CODE = bytes.fromhex(
    "bb 00 20 40 00"    # +0x00 mov ebx,0x402000
    "b9 04 00 00 00"    # +0x05 mov ecx,4
    "e8 02 00 00 00"    # +0x0a call +2 -> 0x11
    "c3"                # +0x0f ret
    "90"                # +0x10 pad
    "31 c0"             # +0x11 callee: xor eax,eax
    "03 03"             # +0x13 loop: add eax,[ebx]
    "83 c3 04"          # +0x15 add ebx,4
    "e2 f9"             # +0x18 loop -7 -> 0x13
    "a3 20 20 40 00"    # +0x1a mov [0x402020],eax
    "81 fa ad de 00 00"  # +0x1f cmp edx,0xdead
    "75 02"             # +0x25 jne +2 -> 0x29
    "0f a2"             # +0x27 cpuid (undeclared machine input)
    "c3"                # +0x29 ret
)


_F32_MUT_OFFSET = 0x13  # `03 03` add -> `2b 03` sub


def real16_image_bytes(*, mutated: bool) -> bytes:
    """Assemble the real16 load-module bytes for the fixture pair."""
    code = bytearray(_R16_CODE)
    if mutated:
        code[_R16_MUT_OFFSET] = 0x2B
    image = code.ljust(R16_SPIN, b"\x90") + bytes.fromhex("eb fe")
    image = image.ljust(R16_ARRAY, b"\x00") + bytes.fromhex("05 00 03 00 02 00 01 00")
    return (image.ljust(R16_OUT, b"\x00") + bytes(2)).ljust(R16_IMAGE_SIZE, b"\x00")


def flat32_code_bytes(*, mutated: bool) -> bytes:
    """Assemble the flat32 .text bytes for the fixture pair."""
    code = bytearray(_F32_CODE)
    if mutated:
        code[_F32_MUT_OFFSET] = 0x2B
    return code.ljust(F32_SPIN - F32_TEXT, b"\x90") + bytes.fromhex("eb fe")


def flat32_data_bytes() -> bytes:
    """Assemble the flat32 .data bytes: four dwords plus the output cell."""
    data = b"".join(word.to_bytes(4, "little") for word in (5, 3, 2, 1))
    return data.ljust(F32_DATA_SIZE, b"\x00")


def real16_mz_wrap(image: bytes) -> bytes:
    """Wrap one assembled load module in a minimal valid MZ header."""
    reloc_pos = 0x1C
    header_size = ((reloc_pos + 15) // 16) * 16
    file_size = header_size + len(image)
    blocks, lastsize = divmod(file_size, 512)
    if lastsize:
        blocks += 1
    header = bytearray(header_size)
    header[0:2] = b"MZ"
    header[0x02:0x04] = lastsize.to_bytes(2, "little")
    header[0x04:0x06] = blocks.to_bytes(2, "little")
    header[0x08:0x0A] = (header_size // 16).to_bytes(2, "little")
    header[0x0C:0x0E] = (0xFFFF).to_bytes(2, "little")
    header[0x0E:0x10] = (0x0080).to_bytes(2, "little")
    header[0x10:0x12] = (0xFFFE).to_bytes(2, "little")
    header[0x18:0x1A] = reloc_pos.to_bytes(2, "little")
    return bytes(header) + image


def real16_mz_bytes(*, mutated: bool) -> bytes:
    """Assemble the fixture MZ image (no relocations)."""
    return real16_mz_wrap(real16_image_bytes(mutated=mutated))


def flat32_pe_wrap(text: bytes, data: bytes) -> bytes:
    """Wrap given .text/.data bytes in the test-support minimal PE32 builder."""
    import flat32_replay_test_support as support

    return support._pe32(
        [
            (b".text\0\0\0", len(text), 0x1000, 0x200, 0x60000020, text),
            (b".data\0\0\0", F32_DATA_SIZE, 0x2000, 0x400, 0xC0000040, data),
        ]
    )


def flat32_pe_bytes(*, mutated: bool) -> bytes:
    """Assemble the fixture PE32 image."""
    return flat32_pe_wrap(flat32_code_bytes(mutated=mutated), flat32_data_bytes())


def real16_load_image(image: bytes) -> Real16Image:
    """Relocate assembled load-module bytes into the replay image contract."""
    from tools.dosunit.real16_mz_load import image_from_mz_bytes
    from tools.dosunit.real16_replay_model import LinearRange

    return image_from_mz_bytes(
        real16_mz_wrap(image), load_segment=R16_LOAD,
        code_ranges=(LinearRange(R16_LOAD * 16, R16_CODE_SIZE),),
    )


def flat32_pe_image(text: bytes, data: bytes) -> ReplayImage:
    """Snapshot given .text/.data bytes into the replay image contract."""
    import flat32_replay_test_support as support

    return support._pe_image(
        [
            (b".text\0\0\0", len(text), 0x1000, 0x200, 0x60000020, text),
            (b".data\0\0\0", F32_DATA_SIZE, 0x2000, 0x400, 0xC0000040, data),
        ]
    )
