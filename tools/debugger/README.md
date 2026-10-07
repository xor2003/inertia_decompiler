# DOS debugger

`gdb_client.py` owns the asynchronous GDB RSP protocol; `gdb_tui.py` owns
interactive execution controls; `tui_widgets.py` owns their presentation.
`cli.py` selects and starts the backend; the root launcher forwards to it:

```sh
PYTHON_JIT=1 nice -n 10 .venv/bin/python debugger.py GAME.EXE --backend angr
PYTHON_JIT=1 nice -n 10 .venv/bin/python -m tools.debugger.cli --help
PYTHON_JIT=1 nice -n 10 .venv/bin/python -m tools.debugger.gdb_tui --help
PYTHON_JIT=1 nice -n 10 .venv/bin/python -m pytest tools/debugger/tests -q --tb=short --durations=5
```

The TUI requires Textual. A live session requires an RSP server; protocol and
step-over unit controls use fake clients and require neither DOSBox nor KVM.
Historical `inertia_decompiler.gdb_client`, `gdb_tui` and `tui_widgets`
imports alias these owners. The historical TUI module command remains usable.
Backend execution and decompiler machine semantics remain with their existing
owners; this directory does not duplicate CPU state or instruction effects.
Installed packages expose `inertia-debugger`. Checkout launchers retain project
virtualenv selection; re-execution uses the qualified module command.
