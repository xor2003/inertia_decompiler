"""A real bounded CS table stays conditional on its caller and memory."""

import hashlib
import io
from dataclasses import replace

import angr
import pytest

from inertia.frontend.x86_16.arch_86_16 import Arch86_16
from inertia.frontend.x86_16.declared_function_entry import DeclaredEntryMemory8616, admit_declared_function_entry_8616
from inertia.frontend.x86_16.frontend_direct_callsite_index import build_boundary_direct_callsite_index_8616
from inertia.frontend.x86_16.frontend_function_boundary import exact_function_range_boundary_8616
from inertia.ir import invocation_indirect_target as owner
from inertia.ir import real16_invocation_domain as census
from inertia.ir.invocation_indirect_target import discover_invocation_indirect_target_8616
from inertia.lowering.analysis_helpers import resolve_direct_call_target_from_instruction_8616
from tests.ir.test_declared_function_entry_domain import _recompute, _world
from tools.dosunit.runtime.real16_program_boot import program_from_mz_bytes
from tools.dosunit.runtime.real16_replay_model import LinearRange

pytestmark = pytest.mark.decompiler

SWITCH = bytes.fromhex(
    "558bec8b56048bda83fb037719d1e32effa73903"
    "b80a00eb148bc2051400ebf78bc2d1e0ebf1"
    "8bc205fbffebea5dc31e03230323032a03"
)


def _fixture(argument: int, *, table: bool = True, known_argument: bool = True):
    """Declare a genuine CALL prefix, without declaring callee effects."""
    _, original, old = _world()
    setup = b"\xb8" + argument.to_bytes(2, "little") if known_argument else bytes.fromhex("a10008")
    caller = setup + bytes.fromhex("50e8e30259c3")
    image = bytearray(0x350)
    image[:2] = bytes.fromhex("0f0b")
    image[0x20:0x20 + len(caller)] = caller
    image[0x70] = 0xC3
    image[0x30A:0x30A + len(SWITCH)] = SWITCH
    header = bytearray(original.source[:32])
    length = len(header) + len(image)
    header[2:4] = (length % 512).to_bytes(2, "little")
    header[4:6] = ((length + 511) // 512).to_bytes(2, "little")
    header[12:14] = (0x500).to_bytes(2, "little")
    environment = replace(original.environment, allocation=bytes(0x5000))
    boot = program_from_mz_bytes(bytes(header + image), environment, code_ranges=(
        LinearRange(0x1000, 2), LinearRange(0x1020, len(caller)), LinearRange(0x1070, 1),
        LinearRange(0x130A, 47),
    ))
    module = boot.image.chunks[0][1]
    project = angr.Project(io.BytesIO(module), main_opts={
        "backend": "blob", "arch": Arch86_16(), "base_addr": 0x1000, "entry_point": 0x1000,
    }, auto_load_libs=False)
    boundary = exact_function_range_boundary_8616(project, 0x1020, 0x1020 + len(caller))
    assert boundary is not None
    artifact = census.real16_native_census_import_8616(project, boundary)
    assert artifact is not None
    digest = census.declared_environment_digest_8616(environment)
    spec = replace(
        old.admission.spec, source_sha256=hashlib.sha256(boot.source).hexdigest(),
        relocated_sha256=hashlib.sha256(module).hexdigest(),
        native_sha256=hashlib.sha256(caller).hexdigest(), environment_sha256=digest,
        range_end=0x1020 + len(caller), registers=(("ds", 0x100), ("sp", 0x80), ("ss", 0x200)),
        memory=(DeclaredEntryMemory8616(0x2080, bytes.fromhex("7000")),
                *((DeclaredEntryMemory8616(0x1339, SWITCH[-8:]),) if table else ())),
    )
    admission = admit_declared_function_entry_8616(
        spec, source=boot.source, loaded_module=module, environment_sha256=digest,
    )
    link = census.DeclaredFunctionEntryLink8616(admission, artifact, boundary)
    invocation = census.prove_real16_declared_function_entry_domain_8616(
        project, link, 0x1024, boot=boot, boot_recompute=_recompute,
    )
    assert invocation.complete, invocation.failure
    index = build_boundary_direct_callsite_index_8616(
        boundary, direct_target_resolver=lambda instruction: resolve_direct_call_target_from_instruction_8616(project, instruction),
    )
    return invocation, index.for_target(0x130A)[0]


@pytest.mark.parametrize("argument,target", [(0, 0x131E), (1, 0x1323), (2, 0x1323), (3, 0x132A)])
def test_native_table_singleton_from_declared_prefix(argument: int, target: int) -> None:
    invocation, decoded = _fixture(argument)
    result = discover_invocation_indirect_target_8616(invocation, decoded)
    assert result is not None
    assert result.target == target
    assert result.invocation is invocation
    assert result.instruction_addr == 0x1319


@pytest.mark.parametrize("mutation", ["missing_table", "native", "scope", "table", "default", "unknown_index", "foreign_call"])
def test_unknown_or_mutated_premise_never_supplies_table_target(mutation: str) -> None:
    invocation, decoded = _fixture(
        4 if mutation == "default" else 2, table=mutation != "missing_table",
        known_argument=mutation != "unknown_index",
    )
    if mutation == "native":
        invocation.project.loader.memory.store(0x1319, b"\x90")
    elif mutation == "scope":
        object.__setattr__(invocation, "failure_count", 1)
    elif mutation == "table":
        invocation.project.loader.memory.store(0x133D, b"\xff")
    elif mutation == "foreign_call":
        decoded = replace(decoded, callsite_addr=decoded.callsite_addr + 1)
    assert discover_invocation_indirect_target_8616(invocation, decoded) is None


def test_replaced_native_import_producer_refuses(monkeypatch: pytest.MonkeyPatch) -> None:
    invocation, decoded = _fixture(2)

    def replaced(*args: object, **kwargs: object) -> object:
        raise AssertionError("substituted producer must not execute")

    monkeypatch.setattr(owner, "_block_to_ir", replaced)
    assert discover_invocation_indirect_target_8616(invocation, decoded) is None


@pytest.mark.parametrize("mutation", ["native", "seed"])
def test_mutation_during_final_invocation_replay_refuses(monkeypatch: pytest.MonkeyPatch, mutation: str) -> None:
    """A successful replay Boolean does not protect an earlier captured value."""
    invocation, decoded = _fixture(2)
    original = census.Real16InvocationDomain8616.complete.fget
    assert original is not None
    import inspect

    def complete(self):
        result = original(self)
        caller = inspect.currentframe().f_back
        if self is invocation and caller.f_code is owner._seal.__code__:
            if mutation == "native":
                self.project.loader.memory.store(0x1319, b"\x90")
            else:
                object.__setattr__(self, "callsite_call_state", (("cs", 0x100), ("ss", 0x200)))
        return result

    monkeypatch.setattr(census.Real16InvocationDomain8616, "complete", property(complete))
    assert discover_invocation_indirect_target_8616(invocation, decoded) is None
