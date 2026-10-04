# Initialized DOS program file-input comparison

`replay-program16` can explicitly admit successful INT21/AH3F reads and
INT21/AH42 seeks over preopened immutable regular-file snapshots. This is
concrete differential execution for a declared environment. It does not turn
agreement into all-input proof or emulate a general DOS filesystem.

The service follows the successful Read/LSeek register interface documented in
Microsoft's [MS-DOS system calls](https://github.com/microsoft/MS-DOS/blob/main/v2.0/source/SYSCALL.txt).
Unknown handles, unsupported seek modes, negative/overflowed positions,
undeclared buffers, code destinations and exhausted budgets refuse rather than
fabricating a DOS error response. File open/create/close, writes to regular
files, host paths, directories, devices and redirectors remain unsupported.

Add the following to an existing initialized-MZ manifest's `environment`:

```json
"input_files": {
  "files": [{"handle": 5, "bytes": "41424344", "cursor": 0}],
  "max_call_bytes": 32,
  "max_total_bytes": 4096
}
```

Absence or null keeps input services disabled. Each file supplies its complete
compact hexadecimal content and exact initial unsigned32 cursor, including
positions past EOF. Handles5..65535 must be unique; at most32 files and4MiB
aggregate content are admitted. Per-call request caps are positive and at most
65535; total served-byte caps are positive and at most4MiB. Input policy cannot
replace PSP bytes or invent the DOS handle table. Output streams remain a
separate opt-in contract for handles1/2.

Reads use BX handle, CX requested count and DS:DX destination. Successful reads
return the actual count in AX with CF clear, preserve every other register and
flag, and advance only by the actual payload length. Partial/emptyEOF preserves
unreturned buffer bytes. Empty reads do not dereference even an outside buffer.
A nonempty payload must end within its64KiB segment and the exact declared
arena; payload writes cannot overlap declared code. Guest writes and cursor
changes commit only after these checks.

Seek uses AL origin0/1/2 and signed32 CX:DX displacement from beginning/current/
end. A successful result is an unsigned32 position in DX:AX with CF clear;
other state is preserved. Refused operations do not advance the runtime state.
Each execution creates fresh cursors from the declared policy.

Reports bind file handles, byte sizes/SHA256, initial positions and caps into
boot/environment identities. Successful read/seek receipts preserve chronological
cursor transitions. Every declared handle must have a complete final position;
missing, duplicate, discontinuous or foreign receipts cannot establish agreement.
The observation contract includes final file positions, independent output
streams, exit and complete named guest memory outputs. Read chunk boundaries
are diagnostics: split reads can agree when final positions and outputs agree.
Changed initial file content/cursors describe another environment and compare
as incomplete, rather than silently changing the domain.

```sh
PYTHON_JIT=1 .venv/bin/python -m tools.dosunit.dosunit replay-program16 \
  --oracle-exe original.exe --candidate-exe rebuilt.exe \
  --environment dos-environment.json --instruction-limit 100000 \
  --out dos-program-comparison.json
```

Schemas `dosunit.real16_program_environment.v1` and
`dosunit.real16_program_replay.v1` describe structural manifests/reports; typed
parsing additionally checks numeric domains, aggregate budgets and memory/code
admission. Schema validity itself is not proof. Reports retain
`proof_status=not_established_by_execution`; exit0/1/2 means executed agreement,
mismatch or incomplete execution respectively.

This closes a bounded M6 file-input step. Representative initialized programs,
additional DOS/device and Windows services, symbolic environment closure and
release gates remain required by the original plan. Existing ELF support is
unchanged.

The combined input/output regression executes an initialized MZ file-copy
program with both policies enabled. It checks equivalent chunking across
corresponding buffers, changed stream bytes, destination and exit mutations,
handle-policy isolation, immutable snapshots and separate input/output budgets:

```sh
PYTHON_JIT=1 .venv/bin/python -m pytest -n 3 --tb=short --durations=5 \
  angr_platforms/tests/test_real16_program_file_copy.py
```

These are concrete controls under the declared synthetic service scope. They
do not establish symbolic equivalence or general DOS filesystem behavior.
