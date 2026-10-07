from inertia.frontend.x86_16.instruction import SIB, InstrData, InstrFlags, ModRM, X86Instruction


def test_instruction_metadata_classes_use_slots():
    assert not hasattr(ModRM(), "__dict__")
    assert not hasattr(SIB(), "__dict__")
    assert not hasattr(InstrData(), "__dict__")
    assert not hasattr(InstrFlags(), "__dict__")


def test_x86_instruction_base_uses_slots():
    holder = X86Instruction(emu=object(), instr=InstrData(), mode32=False)
    assert not hasattr(holder, "__dict__")
    assert holder.mode32 is False


def test_nested_package_instruction_mixins_share_one_slotted_base():
    from inertia.frontend.x86_16.instr_base import InstrBase
    from inertia.frontend.x86_16.instruction import X86Instruction as NestedX86Instruction

    assert InstrBase.__mro__.count(NestedX86Instruction) == 1
