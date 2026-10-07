"""Conversion-corruption controls for the staged carry/borrow SSA repair.

Contract under test: ``definition_for_8616`` is identity-only (a captured
``source_tmp`` read with no pending ``active_unary``); ``conversion_source_8616``
consumes exactly the typed conversion its caller requests after width proof;
``dependency_arithmetic_sites_8616`` traverses authenticated conversions for
dependency only. Each control proves refusal when the typed conversion
evidence is corrupted and preservation only when the projection is exact.
"""
from dataclasses import replace

import pytest
from inertia.ir.core import IRActiveUnary8616, IRInstr, IRValue, MemSpace

from inertia.semantics.carry_borrow_contracts import (
    CarryBorrowConversion8616,
    CarryBorrowDefinitionSite8616,
    CarryBorrowKind8616,
)
from inertia.semantics.carry_borrow_ssa import (
    conversion_source_8616,
    definition_for_8616,
    dependency_arithmetic_sites_8616,
)


def _site(
    instr_index: int,
    op: str,
    dst_size: int,
    args: tuple[IRValue, ...],
    instr_size: int | None = None,
) -> CarryBorrowDefinitionSite8616:
    dst = IRValue(MemSpace.TMP, name=f"t{instr_index}", size=dst_size, source_tmp=instr_index)
    return CarryBorrowDefinitionSite8616(
        block_addr=0x1000,
        instr_index=instr_index,
        instruction=IRInstr(
            op=op,
            dst=dst,
            args=args,
            size=dst_size if instr_size is None else instr_size,
            addr=0x1000,
        ),
    )


def _definitions(*sites: CarryBorrowDefinitionSite8616) -> dict[int, CarryBorrowDefinitionSite8616]:
    return {site.instruction.dst.source_tmp: site for site in sites}


def _sub_site() -> CarryBorrowDefinitionSite8616:
    return _site(
        40,
        "Iop_Sub16",
        2,
        (IRValue(MemSpace.REG, name="ax", size=2), IRValue(MemSpace.CONST, const=1, size=2)),
    )


def _and_site() -> CarryBorrowDefinitionSite8616:
    return _site(
        39,
        "Iop_And16",
        2,
        (IRValue(MemSpace.CONST, const=1, size=2),) * 2,
    )


def _narrow_site(operand_tmp: int = 39, unary_op: str = "Iop_16to1") -> CarryBorrowDefinitionSite8616:
    """MOV t41 = <op>(t39): pending unary wrapper as the MOV source."""
    operand = IRValue(MemSpace.TMP, name="mask", size=2, expr=("Iop_And16",), source_tmp=operand_tmp)
    wrapper = IRValue(
        MemSpace.TMP,
        name="mask",
        size=1,
        expr=(unary_op,),
        active_unary=IRActiveUnary8616(unary_op, operand, 1),
    )
    return _site(41, "MOV", 1, (wrapper,))


def _extend_site() -> CarryBorrowDefinitionSite8616:
    """MOV t42 = 1Uto16(t41): pending extend wrapper as the MOV source."""
    operand = IRValue(MemSpace.TMP, name="mask", size=1, expr=("Iop_16to1",), source_tmp=41)
    wrapper = IRValue(
        MemSpace.TMP,
        name="mask",
        size=2,
        expr=("Iop_1Uto16",),
        active_unary=IRActiveUnary8616("Iop_1Uto16", operand, 16),
    )
    return _site(42, "MOV", 2, (wrapper,))


def test_conversion_source_returns_authenticated_operand() -> None:
    definitions = _definitions(_sub_site(), _and_site(), _narrow_site())
    operand = conversion_source_8616(
        definitions[41], CarryBorrowConversion8616.NARROW_TO_BIT, definitions
    )
    assert operand is not None and operand.source_tmp == 39
    resolved = definition_for_8616(operand, definitions)
    assert resolved is not None and resolved.instr_index == 39


def test_conversion_source_proves_captured_one_bit_operand() -> None:
    definitions = _definitions(_sub_site(), _and_site(), _narrow_site())
    operand = conversion_source_8616(
        _extend_site(), CarryBorrowConversion8616.WIDEN_BIT_TO_WORD, definitions
    )
    assert operand is not None and operand.source_tmp == 41


def test_definition_for_resolves_only_pinned_identity() -> None:
    definitions = _definitions(_sub_site(), _and_site(), _narrow_site())
    pinned = IRValue(MemSpace.TMP, name="mask", size=1, expr=("Iop_16to1",), source_tmp=41)
    site = definition_for_8616(pinned, definitions)
    assert site is not None and site.instr_index == 41
    wrapper = definitions[41].instruction.args[0]
    assert definition_for_8616(wrapper, definitions) is None


def test_pending_conversion_reaches_arithmetic_in_dependency_walk() -> None:
    definitions = _definitions(_sub_site(), _and_site(), _narrow_site())
    operand = definitions[41].instruction.args[0].active_unary.operand
    seed = IRValue(MemSpace.TMP, name="mask", size=1, source_tmp=41)
    sites = dependency_arithmetic_sites_8616(
        seed, definitions, CarryBorrowKind8616.SUB_WITH_BORROW
    )
    assert sites == ()
    pinned = replace(operand, source_tmp=40)
    sites = dependency_arithmetic_sites_8616(
        IRValue(
            MemSpace.TMP,
            name="mask",
            size=1,
            expr=("Iop_16to1",),
            active_unary=IRActiveUnary8616("Iop_16to1", pinned, 1),
        ),
        definitions,
        CarryBorrowKind8616.SUB_WITH_BORROW,
    )
    assert tuple(site.instr_index for site in sites) == (40,)


def test_dependency_walk_drops_unauthenticated_wrapper() -> None:
    definitions = _definitions(_sub_site(), _and_site(), _narrow_site())
    operand = IRValue(MemSpace.TMP, name="mask", size=2, expr=("Iop_And16",), source_tmp=40)
    not_wrapper = IRValue(
        MemSpace.TMP,
        name="mask",
        size=2,
        expr=("Iop_Not16",),
        active_unary=IRActiveUnary8616("Iop_Not16", operand, 16),
    )
    assert (
        dependency_arithmetic_sites_8616(
            not_wrapper, definitions, CarryBorrowKind8616.SUB_WITH_BORROW
        )
        == ()
    )


def test_dependency_walk_refuses_active_plus_pinned_before_capture() -> None:
    definitions = _definitions(_sub_site(), _and_site(), _narrow_site())
    operand = IRValue(MemSpace.TMP, name="mask", size=2, expr=("Iop_And16",), source_tmp=39)
    corrupt = IRValue(
        MemSpace.TMP,
        name="mask",
        size=1,
        expr=("Iop_16to1",),
        source_tmp=40,
        active_unary=IRActiveUnary8616("Iop_16to1", operand, 1),
    )
    assert (
        dependency_arithmetic_sites_8616(
            corrupt, definitions, CarryBorrowKind8616.SUB_WITH_BORROW
        )
        == ()
    )


def _extend_wrapper_with(corrupt: str) -> tuple[IRValue, CarryBorrowDefinitionSite8616]:
    """Return the corrupted extend MOV and its inner operand view."""
    site = _extend_site()
    wrapper = site.instruction.args[0]
    unary = wrapper.active_unary
    if corrupt == "not_a_conversion":
        wrapper = replace(
            wrapper, expr=("Iop_Not16",), active_unary=replace(unary, op="Iop_Not16")
        )
    elif corrupt == "wrong_result_bits":
        wrapper = replace(wrapper, active_unary=replace(unary, result_bits=8))
    elif corrupt == "expr_mismatch":
        wrapper = replace(wrapper, expr=("Iop_8Uto16",))
    elif corrupt == "operand_width_mismatch":
        wrapper = replace(
            wrapper,
            active_unary=replace(
                unary,
                operand=replace(unary.operand, size=2, expr=("Iop_And16",), source_tmp=39),
            ),
        )
    elif corrupt == "pinned_wrapper_absent_tmp":
        wrapper = replace(wrapper, source_tmp=99)
    elif corrupt == "pinned_wrapper_existing_tmp":
        wrapper = replace(wrapper, source_tmp=40)
    elif corrupt == "wrong_requested_conversion":
        pass
    site = replace(site, instruction=replace(site.instruction, args=(wrapper,)))
    return wrapper, site


@pytest.mark.parametrize(
    "corrupt",
    (
        "not_a_conversion",
        "wrong_result_bits",
        "expr_mismatch",
        "operand_width_mismatch",
        "pinned_wrapper_absent_tmp",
        "pinned_wrapper_existing_tmp",
        "wrong_requested_conversion",
    ),
)
def test_corrupted_pending_conversion_refuses(corrupt: str) -> None:
    definitions = _definitions(_sub_site(), _and_site(), _narrow_site())
    wrapper, site = _extend_wrapper_with(corrupt)
    requested = (
        CarryBorrowConversion8616.WIDEN_BYTE_TO_WORD
        if corrupt == "wrong_requested_conversion"
        else CarryBorrowConversion8616.WIDEN_BIT_TO_WORD
    )
    assert conversion_source_8616(site, requested, definitions) is None
    assert definition_for_8616(wrapper, definitions) is None


def test_missing_operand_definition_refuses() -> None:
    definitions = _definitions(_sub_site(), _and_site())
    site = _extend_site()
    assert (
        conversion_source_8616(
            site, CarryBorrowConversion8616.WIDEN_BIT_TO_WORD, definitions
        )
        is None
    )


@pytest.mark.parametrize("corrupt", ("dst_size", "instr_size"))
def test_corrupt_mov_result_width_refuses(corrupt: str) -> None:
    definitions = _definitions(_sub_site(), _and_site(), _narrow_site())
    site = _extend_site()
    instruction = site.instruction
    if corrupt == "dst_size":
        instruction = replace(
            instruction, dst=replace(instruction.dst, size=1)
        )
    else:
        instruction = replace(instruction, size=1)
    site = replace(site, instruction=instruction)
    assert (
        conversion_source_8616(
            site, CarryBorrowConversion8616.WIDEN_BIT_TO_WORD, definitions
        )
        is None
    )


def test_unsupported_inner_unary_defeats_width_proof() -> None:
    """MOV of a non-conversion unary cannot prove the operand's bit width."""
    definitions = _definitions(
        _sub_site(), _and_site(), _narrow_site(unary_op="Iop_Not16")
    )
    site = _extend_site()
    assert (
        conversion_source_8616(
            site, CarryBorrowConversion8616.WIDEN_BIT_TO_WORD, definitions
        )
        is None
    )


def test_missing_narrow_operand_never_uses_storage_width_as_producer_proof():
    site = _narrow_site(operand_tmp=999)
    assert conversion_source_8616(site, CarryBorrowConversion8616.NARROW_TO_BIT, _definitions(site)) is None
