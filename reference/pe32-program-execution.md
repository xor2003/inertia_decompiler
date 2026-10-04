# Initialized PE32 program comparison

`dosunit.py replay-program32` starts actual PE32 bytes at the loaded header
entry in a fresh Unicorn i386 guest. It preserves declared initial stack bytes:
there is no manufactured caller frame, function return trap or stack zero fill.
ELF function replay is unchanged. This is independent concrete evidence for one
declared state; it never establishes a symbolic all-input proof.

The concrete replay loader scope is i386 PE32 non-DLL executables without import,
bound-import, IAT, delay-import, TLS, load-config or CLR directories. These
startup requirements refuse before CLE instead of receiving guessed state or
fake imports. Entry derivation and the relevant directories follow Microsoft's
[PE specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format).
Loaded bytes and section permissions come from the existing bounded InclusivePE
loader and flat32 permission authority. Only main-image backers are admitted.
Unmodeled headers/gaps retain denied guest access. Native startup services and
representative compiler-program execution are still open acceptance items.

The declared machine model is Unicorn's flat i386 bootstrap with zero selectors,
checked explicitly on each fresh guest. The command supplies no guest GDT/TEB/PEB;
segment writes and FS/GS memory access refuse. Ports, clock/entropy instructions,
CPU-feature queries, unmodeled register files, privileged instructions and
unknown software services also refuse. Exact initialized allocations, page
permissions and declared executable byte ranges are enforced independently;
page padding cannot supply caller data or code.

The environment schema is `dosunit.pe32_program_environment.v1`:

```json
{
  "schema": "dosunit.pe32_program_environment.v1",
  "environment": {
    "registers": {
      "eax": 0, "ebx": 0, "ecx": 0, "edx": 0,
      "esi": 0, "edi": 0, "ebp": 0,
      "esp": "0x10001000", "eflags": 2
    },
    "memory": [{
      "address": "0x10000ff8",
      "bytes": "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5",
      "access": ["read", "write"]
    }],
    "exit_address": "0x70000000"
  },
  "observations": []
}
```

All nine registers are required exactly once. Allocations supply every initial
byte and permit only explicitly declared read/write access; they cannot overlap
one another, loaded image bytes or the terminal address. ESP must anchor four
readable/writable bytes; actual pushes must also fit the declared memory. The
example bytes are one chosen test state, not an assumption about Windows memory.
Optional observations require a unique `name`, positive `size`, and both
`oracle_address` and `candidate_address` inside initialized bytes. Names/sizes
provide cross-program correspondence; collecting them cannot change execution.
Metadata, mapping, file and aggregate observation work are bounded by the shared
64MiB flat32 limits. Schemas check structure; typed parsers additionally check
numeric domains, overlap, byte budgets and binary-derived loader requirements.

`exit_address` is an explicit synthetic terminal-service assumption. At that
address the executor reads a 32-bit exit argument at `[ESP+4]` and terminates
without returning. It does not infer an API from names or instructions, bind
imports, or emulate general Windows services. A single inert fetchable gateway
byte is installed outside loaded/data bytes; its instruction is never executed.
A program must reach this declared boundary under the declared ABI. An ordinary
RET alone has no established complete program outcome.

```sh
PYTHON_JIT=1 .venv/bin/python dosunit.py replay-program32 \
  --oracle-exe original.exe --candidate-exe changed.exe \
  --environment pe-environment.json --instruction-limit 100000 \
  --out pe-program-comparison.json
```

Report schema: `dosunit.pe32_program_replay.v1`. Exit0 means tested agreement;
exit1 means a complete exit/output mismatch or termination versus a captured
CPU fault; exit2 means incomplete execution. Registers and final memory writes
remain diagnostic. Process comparison observes the full 32-bit exit and every
named output. Equal faults, truncation, missing outputs and unsupported access
cannot agree. Native backend initialization failure is typed `unavailable`;
missing backend packages raise a cause-preserving command error.

Both inputs and the environment are read as immutable snapshots and rechecked
before report publication. Boot construction rejects stale entry/image/state
identities; reports bind loaded bytes, permissions, declared initial state and
terminal policy. `proof_status` remains `not_established_by_execution`.

Routine controls execute serialized PE images with the actual independent
backend: initialized stack preservation, full-width exit, changed internal
registers, output/exit corruptions, faults, loops, startup-directory refusal,
exact allocation checks, unavailable backend, stale identities and snapshot
mutation. This bounded capability does not close original M6 corpus, files,
service/device coverage or M7 release acceptance.

## Symbolic terminal comparison

`compare-terminal32` separately lifts actual binary bytes and compares the
bounded acyclic transition to the declared PE32 exit gateway. Use the same environment
format above, with no named replay observations or custom code-range projection:
this proof compares the complete modeled terminal state and memory effects.

```sh
env PYTHON_JIT=1 nice -n 10 .venv/bin/python -m tools.dosunit.dosunit \
  compare-terminal32 --oracle-exe original.exe --candidate-exe rebuilt.exe \
  --environment environment.json --out terminal-proof.json
```

The report schema is `dosunit.symbolic_terminal_compare.v1`. Equality is
`status=conditional`, retaining environment and initial-memory assumptions;
`execution_status=not_run` never substitutes for independent replay. Changed
modeled effects produce counterexamples. Unproved pointers, dead faulting reads,
unsupported services/control and budgets produce explicit non-results.
Exit codes0/1/2 mean conditional equality/counterexample/non-result. Optional
`--solver-timeout-ms` may reduce the existing15-second solver budget, not enlarge
it. All input files are rechecked before publication. This command does not
prove arbitrary program termination or general operating-system behavior.

The symbolic lane additionally accepts explicitly declared no-argument,
DWORD-returning import services in `environment.services`. Each item declares
`dll`, `name`, `address`, `result`, `volatile` and `flags`. Actual import-directory
identities and readable non-executable IAT slots must bind every declaration;
only authenticated indirect CALL/JMP routes consume it. DLL case is normalized,
export-name case is preserved. Undeclared, ordinal, bound or delayed imports
refuse. See the [service declaration and example](dosunit-execution-spec.md#declared-pe32-import-services).

Ordered calls remain observable even if their return values are discarded.
Opaque responses are fresh per occurrence and paired only across corresponding
invocations. State, memory and residual return-address writes remain observed.
These are synthetic environment assumptions, not proved Windows implementations;
`replay-program32` continues to refuse them. Optional bounded divide-error
comparison retains a separate no-handler/fault-site premise. Other unsupported
services, exceptions and internal-call shapes remain explicit non-results.
