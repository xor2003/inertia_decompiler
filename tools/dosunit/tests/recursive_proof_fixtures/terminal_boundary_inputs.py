"""Actual MZ first-MiB-boundary recursive joint fixtures (binary-derived).

Layer: test support.
Responsibility: build immutable, source-bound joint inputs whose bootstrap CALL
target stays inside the first MiB while its saved-return terminal coordinate
crosses ``0x100000``, plus a nearby positive companion whose terminal stays
inside.  Every artifact is derived from exact file bytes; nothing here asserts
a proof outcome.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import angr
import inertia.frontend.x86_16.simos_86_16  # noqa: F401
from inertia.frontend.x86_16.load_dos_mz import DOSMZ  # noqa: F401
from tools.dosunit.tests.recursive_proof_fixtures.image_bound_inputs import Inputs, _proposal
from tools.dosunit.tests.recursive_proof_fixtures.real16_joint_system import build_real16_joint_system
from tools.dosunit.tests.test_dosunit_tool import _edge_function, _mz_exe

import tools.dosunit.compare.straightline_ssa as S
from tools.dosunit.compare.real16_call_contracts import initial_state
from tools.dosunit.compare.real16_call_evidence import group_functions
from tools.dosunit.recursive_proofs.loaded_byte_image_binding import bind_real16_mz
from tools.dosunit.recursive_proofs.loaded_byte_relation import propose_loaded_byte_relation
from tools.dosunit.recursive_proofs.loaded_byte_relation_proof import prove_loaded_byte_relation

# Physical geometry shared by both fixtures.  ``load_segment = 0xFF00`` maps
# the relocated image at physical 0xFF000; the entry selector is 0xFFFF, so
# image offsets >= 0xFF0 are reached as CS-relative IP values.
LOAD_SEGMENT: int = 0xFF00
BOUNDARY_CS: int = 0xFFFF
RECURSIVE_OFFSET: int = 0x0FF0
RECURSIVE_CODE: bytes = bytes.fromhex("e8fdffc3")  # call -3 (self at ip 0); ret
STACK_SS: int = 0x0280  # header field: SS register = (0xFF00 + 0x0280) & 0xFFFF = 0x0180
STACK_SP: int = 0xFFFE
IMAGE_SIZE: int = 0x1001  # covers the continuation byte at physical 0x100000


def _image(*, bootstrap_offset: int, call_rel: int, tag_byte: int) -> bytes:
    """Compose one immutable load image; one inert byte separates the sides."""
    image = bytearray([0x90] * IMAGE_SIZE)
    image[0x000] = tag_byte
    image[RECURSIVE_OFFSET:RECURSIVE_OFFSET + len(RECURSIVE_CODE)] = RECURSIVE_CODE
    image[bootstrap_offset:bootstrap_offset + 3] = b"\xe8" + (call_rel & 0xFFFF).to_bytes(2, "little")
    image[bootstrap_offset + 3] = 0xC3
    return bytes(image)


def _document(tmp_path: Path, tag: str, *, bootstrap_offset: int, call_rel: int,
              tag_byte: int, load_segment: int = LOAD_SEGMENT) -> dict[str, Any]:
    """Lower an actual MZ file under a dos_mz project at the matching base."""
    file = bytearray(_mz_exe(_image(bootstrap_offset=bootstrap_offset, call_rel=call_rel,
                                    tag_byte=tag_byte),
                             minalloc=0))
    file[0x0E:0x10] = STACK_SS.to_bytes(2, "little")
    file[0x10:0x12] = STACK_SP.to_bytes(2, "little")
    entry_ip = (bootstrap_offset - ((BOUNDARY_CS - load_segment) << 4)) & 0xFFFF
    file[0x14:0x16] = entry_ip.to_bytes(2, "little")
    file[0x16:0x18] = ((BOUNDARY_CS - load_segment) & 0xFFFF).to_bytes(2, "little")
    path = tmp_path / f"{tag}.exe"
    path.write_bytes(bytes(file))
    project = angr.Project(
        str(path),
        auto_load_libs=False,
        main_opts={"backend": "dos_mz", "base_addr": load_segment << 4},
        simos="DOS",
    )
    cast(Any, project)._dosunit_lifter_mode = "dos_mz"  # dynamic third-party project boundary
    functions = [_edge_function("bootstrap", "bootstrap", offset=bootstrap_offset, size=4),
                 _edge_function("recursive", "recursive", offset=RECURSIVE_OFFSET,
                                size=len(RECURSIVE_CODE))]
    catalog = {"schema": "dosunit.functions.v1", "id": f"functions:{tag}", "module": f"{tag}.exe",
               "program_kind": "mz_exe", "functions": functions, "diagnostics": []}
    return S.lower_straightline_ssa_document(exe_path=path, functions_catalog=catalog,
                                             output_regs=tuple(S.INTERNAL_STATE_REGS),
                                             max_blocks_per_function=32, follow_call_fallthrough=True,
                                             lifter_project=project)


def make_terminal_inputs(tmp_path: Path, *, bootstrap_offset: int, call_rel: int,
                         load_segment: int = LOAD_SEGMENT,
                         tag_bytes: tuple[int, int] = (0x90, 0x91)) -> Inputs:
    """Derive every proof input from the exact files, never from metadata."""
    docs = [_document(tmp_path, tag, bootstrap_offset=bootstrap_offset, call_rel=call_rel,
                      tag_byte=tag_byte, load_segment=load_segment)
            for tag, tag_byte in zip(("a", "b"), tag_bytes, strict=True)]
    system = build_real16_joint_system(docs[0], docs[1], "recursive")
    loads = tuple(bind_real16_mz(Path(doc["exe"]).read_bytes(), load_segment=load_segment)
                  for doc in docs)
    initialized = prove_loaded_byte_relation(
        propose_loaded_byte_relation(loads[0].binding.snapshot, loads[1].binding.snapshot))
    groups = [group_functions(doc) for doc in docs]
    bootstrap = tuple(S._compose_block_outputs(group["bootstrap"].blocks[0],
                      group["bootstrap"].blocks[0]["outputs"], initial_state()) for group in groups)
    requests = []
    for side in range(2):
        rows = [_proposal(loads[side], step.original_address if side == 0 else step.candidate_address,
                          step.original if side == 0 else step.candidate) for step in system.steps]
        rows.append(_proposal(loads[side], loads[side].binding.entry, bootstrap[side]))
        requests.append(tuple(rows))
    return Inputs(system, (loads[0], loads[1]), initialized,
                  (bootstrap[0], bootstrap[1]), (requests[0], requests[1]))


def make_terminal_wrap_inputs(tmp_path: Path) -> Inputs:
    """Bootstrap at 0xFFFFD calls 0xFFFF0; saved-return terminal is 0x100000."""
    return make_terminal_inputs(tmp_path, bootstrap_offset=0xFFD, call_rel=-0x10)


def make_terminal_inside_inputs(tmp_path: Path) -> Inputs:
    """Companion: bootstrap at 0xFFFFC calls 0xFFFF0; terminal stays 0xFFFFF."""
    return make_terminal_inputs(tmp_path, bootstrap_offset=0xFFC, call_rel=-0xF)
