"""Initialized program bytes cannot disappear behind shared-memory proofs."""

import hashlib
from pathlib import Path

import pytest
from tools.dosunit.tests.test_dosunit_tool import _edge_function, _mz_exe

from tools.dosunit.contracts.binary_initial_state import InitialImageReason, compare_initial_images
from tools.dosunit.contracts.proof_contracts import ProofStatus
from tools.dosunit.compare.real16_binary_compare import compare_binary16


def _identity(data: bytes) -> dict:
    return {"sha256": hashlib.sha256(data).hexdigest(), "byte_count": len(data),
            "architecture": "X86", "width": 32, "loader": "Elf",
            "mapped_base": 0x400000, "linked_base": 0x400000, "entry": 0x401000}


def test_initialized_image_identity_is_a_separate_obligation():
    image = _identity(b"original initialized bytes")
    relation = compare_initial_images(image, image)
    assert relation.status is ProofStatus.PROVED
    assert relation.to_document(ProofStatus.UNKNOWN)["initialized_function_status"] == "unknown"
    changed = compare_initial_images(image, _identity(b"changed initialized bytes"))
    assert changed.status is ProofStatus.UNKNOWN
    assert changed.reason is InitialImageReason.RELATION_REQUIRED
    assert changed.to_document(ProofStatus.PROVED)["initialized_function_status"] == "unknown"
    assert changed.counters.failure_count == 1


@pytest.mark.parametrize("field,value", [("sha256", ""), ("sha256", "z" * 64),
                                        ("byte_count", 0), ("entry", True), ("loader", None)])
def test_incomplete_image_identity_refuses(field, value):
    image = _identity(b"program")
    image[field] = value
    result = compare_initial_images(image, image)
    assert result.status is ProofStatus.UNKNOWN
    assert result.reason is InitialImageReason.MISSING


def test_equal_hash_without_equal_loader_coordinates_refuses():
    image = _identity(b"program")
    relocated = {**image, "mapped_base": 0x500000}
    assert compare_initial_images(image, relocated).status is ProofStatus.UNKNOWN


def test_changed_initialized_global_leaves_binary_memory_obligation(tmp_path: Path):
    code = bytes.fromhex("a14005c3")  # MOV AX,[DS:0540]; RET
    paths = []
    for name, value in (("original", 1), ("candidate", 2)):
        image = bytearray(0x600)
        image[0x200:0x204] = code
        image[0x540:0x542] = value.to_bytes(2, "little")
        path = tmp_path / (name + ".exe")
        path.write_bytes(_mz_exe(bytes(image)))
        paths.append(path)
    catalog = {"schema": "dosunit.functions.v1", "id": "functions:test", "module": "demo.exe",
               "program_kind": "mz_exe", "diagnostics": [], "functions": [
                   _edge_function("demo.exe:read", "read", offset=0x200, size=len(code)),
               ]}
    original = compare_binary16(paths[0], paths[0], catalog, catalog)
    assert original["status"] == "proved", original["proof"]
    assert original["initial_image_relation"]["status"] == "proved"
    modified = compare_binary16(paths[0], paths[1], catalog, catalog)
    # Function code remains equal for a shared arbitrary memory input; each
    # executable's own initialized global does not share that input relation.
    assert modified["status"] == "proved", modified["proof"]
    assert modified["proof_scope"] == "requested_functions_over_shared_input_memory"
    relation = modified["initial_image_relation"]
    assert relation["status"] == "unknown"
    assert relation["initialized_function_status"] == "unknown"
    assert relation["startup_and_environment_proved"] is False



def _mapped_project(chunks):
    """Use real CLE mapped backers with stable loader metadata."""
    from types import SimpleNamespace

    import archinfo
    from cle.memory import Clemory

    arch = archinfo.ArchX86()
    memory = Clemory(arch)
    for address, data in chunks:
        memory.add_backer(address, data)
    main = SimpleNamespace(mapped_base=0x400000, linked_base=0x400000)
    return SimpleNamespace(arch=arch, entry=0x400000,
                           loader=SimpleNamespace(memory=memory, main_object=main))


def test_flat32_image_identity_ignores_backer_fragmentation():
    """Equal mapped bytes have equal identities across CLE cache layouts."""
    from tools.dosunit.reporting.flat32_proof_report import loaded_image_identity

    whole = _mapped_project(((0x400000, b"abcd"),))
    split = _mapped_project(((0x400000, b"ab"), (0x400002, b"cd")))
    assert loaded_image_identity(whole) == loaded_image_identity(split)
    split.loader.memory.store(0x400002, b"X")
    assert loaded_image_identity(whole) != loaded_image_identity(split)


@pytest.mark.parametrize("chunks", [((0x400000, b"ab"), (0x400003, b"cd")),
                                   ((0x400001, b"abcd"),)])
def test_flat32_image_identity_retains_holes_and_coordinates(chunks):
    """Identical concatenated bytes do not erase missing or shifted mappings."""
    from tools.dosunit.reporting.flat32_proof_report import loaded_image_identity

    whole = _mapped_project(((0x400000, b"abcd"),))
    changed = _mapped_project(chunks)
    assert loaded_image_identity(whole) != loaded_image_identity(changed)
