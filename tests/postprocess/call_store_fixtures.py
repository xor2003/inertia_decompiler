"""Construct explicitly typed stack stores for call-consumer regressions.

Layer: Tests.
Responsibility: supply known word widths independently of address arithmetic.
"""

from angr.analyses.decompiler.structured_codegen import c
from angr.sim_type import SimTypeShort


def word_dereference(address: c.CExpression, *, codegen: c.CStructuredCodeGenerator) -> c.CUnaryOp:
    """Model a native word lvalue without deriving width from its address."""
    lvalue = c.CUnaryOp("Dereference", address, codegen=codegen)
    # Codegen stores the resolved access type here; pointer arithmetic alone
    # does not establish how many bytes a machine store writes.
    lvalue._type = SimTypeShort(False).with_arch(codegen.project.arch)
    return lvalue


def ss_word_store(
    codegen: c.CStructuredCodeGenerator,
    segment: c.CExpression,
    displacement: int,
    value: c.CExpression,
) -> c.CAssignment:
    """Build the legacy probe-carrier address with an explicit word store."""
    def constant(number: int) -> c.CConstant:
        return c.CConstant(number, SimTypeShort(False), codegen=codegen)

    segment_base = c.CBinaryOp("Shl", segment, constant(4), codegen=codegen)
    offset = c.CBinaryOp(
        "Sub", c.CDirtyExpression("vvar_85", codegen=codegen), constant(-displacement), codegen=codegen
    )
    address = c.CBinaryOp("Add", segment_base, offset, codegen=codegen)
    return c.CAssignment(word_dereference(address, codegen=codegen), value, codegen=codegen)
