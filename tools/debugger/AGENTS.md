# Debugger ownership

Follow root `AGENTS.md`; start with [README.md](README.md).
Protocol changes belong in `gdb_client.py`, execution-control changes in
`gdb_tui.py`, presentation in `tui_widgets.py`. Backend launch remains in
`cli.py`, with root `debugger.py` as a compatibility entry. Machine semantics
must not move into this UI.

Run scoped `lint-iteration` and `tools/debugger/tests` for Python edits with
`PYTHON_JIT=1` and nice 10. Import moves also require historical module identity,
both TUI help commands, packaging and ownership checks. Keep temporary
breakpoints distinct from user breakpoints; preserve requested step counts.
Mock-client tests are static; mark actual KVM-backed execution only when used.
