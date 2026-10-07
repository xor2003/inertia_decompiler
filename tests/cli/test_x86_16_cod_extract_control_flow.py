from inertia.frontend.x86_16.cod_extract import (
    extract_small_two_arg_cod_logic_entries,
)


def _entry(text: str, data: bytes) -> dict[str, object]:
    return {"text": text, "bytes": data}


def test_small_cod_frame_removal_preserves_branch_distances_and_existing_nops() -> None:
    entries = [
        _entry("push\tbp", b"\x55"),
        _entry("mov\tbp,sp", b"\x8b\xec"),
        _entry("cmp\tbyte ptr MOUSE,0", b"\x80\x3e\x00\x20\x00"),
        _entry("jne\tactive", b"\x75\x04"),
        _entry("mov\tsp,bp", b"\x8b\xe5"),
        _entry("pop\tbp", b"\x5d"),
        _entry("ret", b"\xc3"),
        _entry("nop", b"\x90"),
        _entry("mov\tcx,[bp+4]", b"\x8b\x4e\x04"),
        _entry("mov\tdx,[bp+6]", b"\x8b\x56\x06"),
        _entry("mov\tsp,bp", b"\x8b\xe5"),
        _entry("pop\tbp", b"\x5d"),
        _entry("ret", b"\xc3"),
    ]

    extracted = extract_small_two_arg_cod_logic_entries(entries)

    assert extracted is not None
    original_body_lengths = tuple(len(entry["bytes"]) for entry in entries[2:])
    extracted_lengths = tuple(len(entry["bytes"]) for entry in extracted)
    assert extracted_lengths == original_body_lengths
    assert any(entry["text"] == "nop" for entry in extracted)
    assert extracted[2]["bytes"] == b"\x90\x90"
    assert extracted[3]["bytes"] == b"\x90"
