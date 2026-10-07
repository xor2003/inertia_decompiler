# Instruction semantics

The instruction semantics, flag analysis, call effects, carry/borrow evidence,
and terminal-return analyses live here. Implementations retain their existing
interfaces and behavior. Historical `X86_16/semantics/` module paths are aliases
to these owners.

Private tests live in `tests/semantics/`. Tests involving lowering, widening,
validation or full decompilation move with those layers or shared integration
coverage. The IR and other layers still use their existing owners during the
remaining file moves.
