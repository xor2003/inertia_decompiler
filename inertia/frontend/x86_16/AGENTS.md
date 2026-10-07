# Frontend contracts

Root `AGENTS.md` and the real-mode edge policy remain authoritative. Start with
[README.md](README.md). Architecture storage belongs in `arch_86_16.py`;
CS-relative/loader control projection belongs in `control_coordinates.py`.
MZ/NE header, relocation and mapping evidence belongs in their loader owners;
optional resource parsing belongs in `ne_resources.py`.
Interrupt-service evidence belongs in `interrupt_contract.py`; DOS state,
interrupt hooks and calling-convention registration belong in `simos_86_16.py`.
Native backend verification belongs in `lifter_backend.py`; preserve the explicit
source-package binding and mandatory compiled default when moving build owners.
Do not introduce alias/type recovery or presentation repairs here.

Migration must preserve old/new module and class identity and architecture
registration. Check both import orders, source-hash mutation refusal, loader
behavior and installed packaging. Instruction/lifter moves additionally require
the existing Cython bundle/build and semantic controls. Preserve distinct
segments, return offsets and full-width control observations.
