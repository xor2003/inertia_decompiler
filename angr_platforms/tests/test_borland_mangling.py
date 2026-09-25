"""Tests for the Borland C++ mangled-name decoder."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from angr_platforms.X86_16.borland_mangling import (
    BorlandSpecial,
    BorlandTypeKind,
    demangle_borland_name,
    render_borland_signature,
)


def test_free_function_void() -> None:
    sig = demangle_borland_name("@CHECK_USER$QV")
    assert sig.name == "CHECK_USER"
    assert sig.scopes == ()
    assert sig.special is BorlandSpecial.NONE
    assert render_borland_signature(sig) == "CHECK_USER()"


def test_method_far_class_pointer() -> None:
    sig = demangle_borland_name("@M_ACTOR@FACING_ACTOR$QN7M_ACTOR")
    assert sig.scopes == ("M_ACTOR",)
    assert sig.name == "FACING_ACTOR"
    (param,) = sig.params
    assert param.kind is BorlandTypeKind.POINTER
    assert param.space == "far"
    assert param.target.class_name == "M_ACTOR"
    assert (
        render_borland_signature(sig)
        == "M_ACTOR::FACING_ACTOR(M_ACTOR far *)"
    )


def test_repeated_argument_compression() -> None:
    """T<n> is a 1-based reference to an earlier argument type."""
    sig = demangle_borland_name(
        "@M_ACTOR@CHECK_NEW_POS$QN7M_ACTORIINIT4III"
    )
    rendered = render_borland_signature(sig)
    assert rendered == (
        "M_ACTOR::CHECK_NEW_POS(M_ACTOR far *, int, int, "
        "int far *, int far *, int, int, int)"
    )
    # T4 repeats argument 4 (int far *).
    assert sig.params[4] == sig.params[3]


def test_constructor_destructor() -> None:
    ctor = demangle_borland_name("@M_ACTOR@$BCTR$QNUCNVT2")
    assert ctor.special is BorlandSpecial.CONSTRUCTOR
    assert render_borland_signature(ctor) == (
        "M_ACTOR::M_ACTOR(unsigned char far *, void far *, void far *)"
    )
    dtor = demangle_borland_name("@game_cast@$bdtr$qv")
    assert dtor.special is BorlandSpecial.DESTRUCTOR
    assert render_borland_signature(dtor) == "game_cast::~game_cast()"


def test_operator_new_delete() -> None:
    new = demangle_borland_name("@$BNEW$QUI")
    assert new.special is BorlandSpecial.OPERATOR
    assert render_borland_signature(new) == "operator new(unsigned int)"
    delete = demangle_borland_name("@$BDELE$QNV")
    assert render_borland_signature(delete) == "operator delete(void far *)"


def test_function_pointer_argument() -> None:
    """NQUC$V is a far pointer to a function taking uchar, returning void."""
    sig = demangle_borland_name("@TEXT_PAGER@$BCTR$QNUCUCNQUC$V")
    rendered = render_borland_signature(sig)
    assert rendered == (
        "TEXT_PAGER::TEXT_PAGER(unsigned char far *, unsigned char, "
        "void(far*)(unsigned char))"
    )
    fnptr = sig.params[2]
    assert fnptr.kind is BorlandTypeKind.POINTER
    assert fnptr.target.kind is BorlandTypeKind.FUNCTION
    assert fnptr.target.params[0].builtin == "char"
    assert "unsigned" in fnptr.target.params[0].quals
    assert fnptr.target.result.builtin == "void"


def test_data_member_and_vtable() -> None:
    member = demangle_borland_name("@GUI_ITEM@owner")
    assert member.special is BorlandSpecial.DATA_MEMBER
    assert render_borland_signature(member) == "GUI_ITEM::owner"
    vtable = demangle_borland_name("@GUI_ITEM@")
    assert vtable.special is BorlandSpecial.VTABLE
    assert render_borland_signature(vtable) == "GUI_ITEM::vtable"


def test_non_mangled_name_passthrough() -> None:
    sig = demangle_borland_name("_main")
    assert sig.parse_error
    assert render_borland_signature(sig) == "_main"
