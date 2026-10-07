from __future__ import annotations

from inertia.frontend.x86_16.hardware import Hardware


def test_hardware_initializes_frontend_runtime_surfaces() -> None:
    hardware = Hardware(16)

    assert hardware.mem_size == 16
    assert hardware.memory is hardware
    assert hardware.port_io == {}
    assert hardware.port_io_map == {}
    assert hardware.mem_io == {}
    assert hardware.mem_io_map == {}
