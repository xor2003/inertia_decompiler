"""Storage-class refusal at the call-return bridge cleanup boundary."""

from itertools import count
from types import SimpleNamespace

import pytest
from angr.analyses.decompiler.structured_codegen.c import CAssignment, CStatements, CVariable
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable
from inertia.frontend.x86_16.arch_86_16 import Arch86_16

from inertia.structuring.call_return_conditions import _remove_redundant_return_bridge_8616


@pytest.mark.parametrize("stack_destination", (True, False))
def test_return_bridge_removal_requires_stack_destination(stack_destination):
    """Only a matching stack destination permits removing the old bridge."""
    arch = Arch86_16()
    codegen = SimpleNamespace(project=SimpleNamespace(arch=arch), cstyle_null_cmp=False,
                              next_node_idx=count().__next__, next_ident=lambda name: name)
    word = SimTypeShort(False).with_arch(arch)
    offset, size = arch.registers["ax"]
    register = CVariable(SimRegisterVariable(offset, size), variable_type=word, codegen=codegen)
    stack = CVariable(SimStackVariable(-2, 2, base="bp"), variable_type=word, codegen=codegen)
    destination = stack if stack_destination else register
    call_assignment = CAssignment(stack, register, codegen=codegen)
    bridge = CAssignment(stack, register, codegen=codegen)
    root = CStatements([call_assignment, bridge], codegen=codegen)

    _remove_redundant_return_bridge_8616(root, destination, (offset, size), call_assignment)

    assert root.statements == ([call_assignment] if stack_destination else [call_assignment, bridge])
