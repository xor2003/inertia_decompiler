"""Layer: comparator structural evidence.

Responsibility: bind declared target tables to canonical i386 indexed indirect
CALL/JMP operands. This establishes operand shape, not incoming register values.
"""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass

from tools.comparator.table_checks import TableCheckStatus, TargetTable, read_pe_bytes


@dataclass(frozen=True)
class TableDispatch:
    """Decoded seven-byte FF /2 or /4 with SIB index and absolute displacement."""

    address: int
    table_address: int
    index_register: str
    scale: int
    transfer: str
    instruction_bytes: str


def read_table_dispatch(image: bytes, address: int) -> TableDispatch | None:
    """Decode exact unprefixed near DWORD indexed CALL/JMP forms from PE bytes.

    Other encodings remain incomplete evidence. In particular a base register,
    address/operand-size prefix or absent index cannot masquerade as this form.
    No disassembly strings or symbol names participate in recognition.
    """
    raw = read_pe_bytes(image, address, 7, executable=True)
    if raw[0] != 0xFF or raw[1] not in (0x14, 0x24):
        return None
    sib = raw[2]
    index = (sib >> 3) & 7
    if sib & 7 != 5 or index == 4:
        return None
    registers = ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi")
    return TableDispatch(address, int.from_bytes(raw[3:7], "little"), registers[index],
                         1 << (sib >> 6), "call" if raw[1] == 0x14 else "jump", raw.hex())


def check_dispatch_pair(
    original_image: bytes, candidate_image: bytes, original_table: TargetTable,
    candidate_table: TargetTable, original_site: int, candidate_site: int,
) -> dict[str, object]:
    """Check table binding, DWORD stride and identical index/transfer shape.

    Register changes are reported as shape mismatches; a later relational proof
    may establish their equivalence. Equal names never prove equal live values.
    Source hashes prevent mixing a table receipt with another image's dispatch.
    """
    images_match = (hashlib.sha256(original_image).hexdigest() == original_table.image_sha256
                    and hashlib.sha256(candidate_image).hexdigest() == candidate_table.image_sha256)
    if not images_match:
        raise ValueError("dispatch images do not match table evidence")
    original = read_table_dispatch(original_image, original_site)
    candidate = read_table_dispatch(candidate_image, candidate_site)
    checks: dict[str, bool] = {}
    status = TableCheckStatus.INCOMPLETE
    if original is not None and candidate is not None:
        checks = {
            "original_table_binding": original.table_address == original_table.address,
            "candidate_table_binding": candidate.table_address == candidate_table.address,
            "dword_stride": original.scale == candidate.scale == 4,
            "index_register_shape": original.index_register == candidate.index_register,
            "transfer_kind": original.transfer == candidate.transfer,
        }
        status = TableCheckStatus.CHECKED if all(checks.values()) else TableCheckStatus.MISMATCH
    return {
        "status": status.value, "scope": "dispatch_operand_shape", "checks": checks,
        "original": None if original is None else asdict(original),
        "candidate": None if candidate is None else asdict(candidate),
        "pending_conditions": ["declared instruction sites are reachable instruction boundaries",
                               "index live-value equivalence and reachable index domain"],
    }


def check_dispatch_binding(
    original_image: bytes, candidate_image: bytes, original_table: TargetTable,
    candidate_table: TargetTable, original_site: int, candidate_site: int,
) -> dict[str, object]:
    """Bind native operands without assuming anything about paired index values.

    Only a consumer proving the actual selection guards may use this weaker
    structural lemma. The original strict register-shape evidence is retained.
    """
    shape = check_dispatch_pair(original_image, candidate_image, original_table, candidate_table,
                                original_site, candidate_site)
    checks = shape["checks"]
    required = ("original_table_binding", "candidate_table_binding", "dword_stride", "transfer_kind")
    complete = isinstance(checks, dict) and all(checks.get(name) is True for name in required)
    return {**shape, "status": TableCheckStatus.CHECKED if complete else shape["status"],
            "scope": "dispatch_operand_binding", "strict_shape": shape,
            "pending_conditions": ["exact composed selection guards must be proved for every slot"]}
