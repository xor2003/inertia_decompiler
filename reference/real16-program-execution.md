# Initialized MZ program comparison

`dosunit.py replay-program16` runs each program from its MZ header entry and
stack in a fresh Unicorn guest. It installs no synthetic caller frame. This is
concrete evidence for the declared initial state, independent of SSA/Z3 proof.

The initial environment supplies every byte of the allocated arena, including
the PSP and uninitialized storage. The relocated load module overwrites only
its loaded bytes at PSP+16 paragraphs. DS/ES start at the PSP; CS:IP and SS:SP
come from the header. All other integer registers, EFLAGS, FS and GS are
explicit. The arena must satisfy the header allocation bounds and remain below
the conventional-memory ceiling. Segment-addition wrap refuses.

The default service contract admits only DOS INT21/AH4C termination. AL becomes
the exit code; there is no return to the program. This convention is documented
in Microsoft's [MS-DOS4 Programmer's Reference](https://www.pcjs.org/documents/books/mspl13/msdos/dosref40/).
Other DOS/BIOS services, device I/O and undeclared memory accesses remain visible
refusals. No file, output-device, allocation-service or asynchronous model is
implied by this command. Symbolic comparators retain their existing independent
environment-admission contracts.

Every admitted unprefixed `INT 21h` leaves the architectural six-byte entry
frame below SS:SP: saved next IP, CS and incoming FLAGS. Returning summaries
restore SP but retain those memory bytes; even an output service reading that
range sees the new frame. Exit retains the frame in named memory observations;
its register diagnostics remain at the intercepted callsite rather than an
invented DOS handler address. This execution model is bound into result identity
as `real16_int21_stack_v1`.

The frame must lie in declared writable RAM and outside executable code.
Stack/fallthrough wrap, prefixed interrupt encodings, and service writes into
their own live return frame refuse. A refused service may retain its already
executed INT entry writes; it never becomes complete agreement. No transient
handler code or asynchronous interrupt behavior is inferred.

An explicit `environment.dos_vectors` declaration enables AH35 queries and AH25
updates against the **live** interrupt vector table. For example:

```json
{"dos_entry": {"segment": 84, "offset": 33}}
```

These example coordinates come from a captured native environment; they are
not defaults or inferred library identities. Supply all 1024 initial IVT bytes
through `extra_memory`. Queries read current guest bytes, including prior raw
stores or vector updates. Updates write DS:DX into the requested slot. Queries
preserve EBX's upper half, and both services preserve flags and unowned registers.
Exact before/after slot receipts participate in concrete comparison.

Before every modeled DOS call, slot21 must still point to the declared external
entry, which must lie outside the program's allocation. Narrow code-range
declarations cannot hide a program-owned handler. AH25 redirection refuses
before changing the slot; a raw store that redirects it blocks the next DOS
summary. Writing the same pointer back is allowed. Stack frames overlapping slot21 and service
writes into the active return frame also refuse. Arbitrary interrupt handlers
are not executed by these summaries. Declaring even part of slot21 without a
vector policy refuses DOS summaries rather than ignoring those supplied bytes.

`environment.dos_device_info` enables successful INT21/AX4400 queries for an
explicit stable handle inventory:

```json
{"handles": [{"handle": 4, "information": 32770}]}
```

The exact returned word goes into DX and CF clears; AX, upper EDX and every
other register/flag bit survive. The normal INT entry frame remains observable.
The example response is a declaration, not a default or a host-device probe.
Unknown handles refuse rather than inventing a DOS invalid-handle error.
Other IOCTL selectors, handle creation/close/duplication and device-state changes
remain unsupported. The inventory is bounded to256 unique handle records;
canonical order and every response bind boot/execution identities. Complete
query/response receipts participate in comparison even if code later overwrites
DX. Absent/null policy leaves these queries refused.

`environment.bios_video` optionally supplies a **static, declared** INT10/AH0F
response and its external service entry:

```json
{"mode": 3, "columns": 80, "page": 0, "entry": {"segment": 84, "offset": 16}}
```

These are example declaration values, never detected firmware or defaults.
The exact four INT10 vector bytes at physical0040 must be explicitly supplied
in initial memory and still match `entry` when the query executes. A handler
inside the program allocation, a changed vector, a prefixed INT, or a stack
frame overlapping either declared service vector refuses before applying the
response. Successful queries update only AL/AH/BH, preserve all other register
and flag bits, and leave the architectural six-byte interrupt frame visible.
The five-byte query receipt retains vector/function/mode/columns/page even if
code overwrites those registers. Policy fields bind boot and execution identity.
Absent/null policy refuses queries. Other video services and arbitrary BIOS
handlers remain unsupported. Agreement under this declaration is concrete
environment-dependent execution evidence; it does not prove installed BIOS
behavior or all-input binary equivalence.

`environment.bios_video_state` separately enables unprefixed INT10/AH1B/BX0:

```json
{"static_state": {"segment": 49152, "offset": 10854}, "dcc": 8,
 "colours": 16, "pages": 8, "scanline": 2, "misc": 33, "memory": 3,
 "entry": {"segment": 84, "offset": 16}}
```

All fields are explicit declarations, not defaults. The 64-byte response uses
the declared static fields and live BDA bytes at physical0449–0466 and0484–0486;
the rows byte is incremented modulo256. The exact table layout follows the
functionality-state service, including its zero-filled reserved fields.
The executor updates only AL to1Bh and writes the table at checked ES:DI.
Uninitialized bytes, offset wrap, output overlap with code, IVT, BDA sources or
the INT frame, and frame overlap with BDA sources refuse. Both video policies,
when supplied, must declare the same unchanged external vector entry.
Nonzero BX and prefixed INT instructions remain unsupported. A complete68-byte
receipt retains the service selector and all64 response bytes, even if later
instructions overwrite the table or registers. Every policy field binds both
boot and environment identities. The returned static-state pointer does not
map ROM: reading undeclared ROM remains a refusal. This is an explicit bounded
environment model, not execution of an installed BIOS handler.

`environment.rom` optionally declares immutable firmware data. It is null or a
nonempty list of at most16 objects with exact `segment`, `offset`, `data_hex`
members. Regions must be disjoint, fit their logical64KiB offset domains and
lie wholly in physicalC0000–FFFFF. All bytes must be explicit; video/MMIO memory
A0000–BFFFF, gaps and page padding are never implied by a declaration. Regions
are canonically ordered for identity while retaining their segmented coordinates.
No ROM signature, firmware identity or interrupt-handler correctness is inferred.

ROM grants CPU data reads and bounded DOS output-source reads only. Pages are
read-only and non-executable; execution scope remains the loaded program code.
Guest writes produce a typed `read_only_write` refusal. DOS file-read buffers,
BIOS table destinations and interrupt frames still require writable RAM; a
refused file read does not advance the file cursor. Declared ROM does not enlarge
the DOS allocation, add default bytes or bypass code-write checks. Every ROM
byte binds boot and environment identity, and stale derived chunks/coverage/pages
are rejected before execution. Each replay maps a fresh instance. The public
report retains the declaration as `contract.read_only_rom`.

An explicit `environment.dos_resize` declaration optionally enables a
**single final-block Kvikdos allocator profile** for INT21/AH4A:

```json
{"profile": "kvikdos_single_tail", "segment": 256,
 "mcb_hex": "5a9201009f0000b24b56314b50523047"}
```

This profile requires the native loader's fixed PSP0100 block; the bytes are
not defaulted or inferred. Supply the actual initial MCB bytes and complete arena
from the declared PSP to the conventional ceiling A0000. The MCB occupies the
explicit preceding paragraph and becomes guest-visible memory. Initial type,
owner, size, previous-size and native signature must validate against the
allocation. The declaration is included in both boot and environment identity.

The service checks live metadata on every call, writes its size field on
successful changes, clears carry, and preserves unowned registers/flags. It
models native insufficient-memory AX8/BX-largest and malformed-MCB AX7 errors.
All upper register halves survive. Shrink changes ownership, not physical
mapping: previously declared RAM remains available in real mode. Repeated
growth/shrink is stateful. Complete request/response and before/after metadata
receipts are observable and validated before concrete agreement; changed or
incomplete receipts cannot silently disappear. Other block addresses and
nonterminal MCB chains refuse because their allocator state is undeclared.
Allocation/free, general DOS allocator variants and external process state are
not supplied by this profile. Absent/null policy keeps the original refusal.

The environment JSON schema is `dosunit.real16_program_environment.v1`:

```json
{
  "schema": "dosunit.real16_program_environment.v1",
  "environment": {
    "psp_segment": "0x1000",
    "allocation_hex": "FULL INITIAL ARENA AS HEX BYTES",
    "registers": {
      "eax": 0, "ebx": 0, "ecx": 0, "edx": 0,
      "esi": 0, "edi": 0, "ebp": 0, "esp": 0, "eflags": 2
    },
    "fs": 0,
    "gs": 0
  },
  "observations": [
    {"name": "buffer", "oracle_address": "0x10200", "candidate_address": "0x10200", "size": 16}
  ]
}
```

`allocation_hex` must contain the complete paragraph-aligned allocation, at
least 256 bytes. Its values are the declared initial state, never an assumption
that DOS clears memory. ESP's upper half must be zero in this scope; its lower
half is superseded by header SP. EFLAGS must retain architectural bit1.
Each named observation requires both physical addresses and a positive size
inside the declared memory coverage. Names and sizes declare the correspondence between
outputs; adding an observation cannot change guest execution.

Final readback must contain observed bytes only. If a declared output or a
recorded write cannot be read, the executor reports the missing range and
backend cause and changes an otherwise complete outcome to `unsupported`.
Readable write fragments keep their original physical addresses; missing bytes
are never replaced with zeros. Comparing incomplete results remains incomplete.

`environment.extra_memory` optionally supplies up to 32 disjoint conventional-RAM
regions outside that allocation. Each entry names an exact segmented address
and every initial byte; for example
`{"segment":100,"offset":0,"data_hex":"41424300"}`. A region cannot wrap
its 16-bit offset or enter device memory at or above A0000h. Overlaps with another
region, the process allocation or optional allocator metadata reject even when
the supplied bytes agree; different segment:offset aliases are checked by their
physical coverage. Omission supplies no extra memory.

The same derived byte union controls CPU reads/writes, named observations and
declared file/stream buffers. Adjacent declarations permit a spanning access;
gaps and mapped-page padding remain inaccessible. Added RAM does not extend
the loader grant or executable code ranges. The MZ load still overwrites only
its module inside the original allocation. Exact extra coordinates and bytes
participate in boot/environment identities. This permits captured DOS
environment blocks without inventing bytes or treating device state as RAM.

Optional `oracle_code_ranges` and `candidate_code_ranges` contain
`{"address": integer, "size": integer}` entries. When omitted or empty, the
loaded image is the declared code scope. Code writes refuse; data-writing
programs should provide exact instruction ranges when data resides in the load
module. The executor enforces allocation bounds independently of mapped page
padding.

```sh
PYTHON_JIT=1 nice -n 10 .venv/bin/python dosunit.py replay-program16 \
  --oracle-exe original.exe --candidate-exe changed.exe \
  --environment environment.json --instruction-limit 100000 \
  --out program-comparison.json
```

The report schema is `dosunit.real16_program_replay.v1`. It retains binary and
environment snapshots, boot identities, registers, writes, events, requested
output sizes and captured output bytes. Registers and writes are machine
diagnostics; terminated-process agreement observes the DOS exit/event trace and
all declared output ranges. A different internal register allocation at exit
does not itself change the declared process observations.

| Exit code | Execution comparison |
| --- | --- |
| 0 | Both terminated, matching exit/event trace and complete declared outputs |
| 1 | Observed exit/output mismatch, or termination versus a captured CPU fault |
| 2 | Refusal, budget exhaustion, unavailable backend, equal faults or incomplete evidence |

Every report retains `proof_status=not_established_by_execution`. Equal faults
do not establish agreement, and a bare RET has no synthetic program-return
outcome. Changes to any executable or environment file during execution prevent
report publication. The whole manifest and both boot contracts validate before
either program executes.

Routine controls cover actual MZ header entry/stack, relocation and bounds,
initialized storage, equivalent changed instructions, changed exit/output,
divide faults, nontermination, software-interrupt/port refusals, code writes,
complete output accounting, snapshot changes and fresh-guest determinism.
Whole-plan representative startup/services/files/device acceptance remains open.

An optional `environment.output_streams` declares a synthetic successful-write
environment for INT21/AH40, for example:

```json
{"handles": [1, 2], "max_call_bytes": 4096, "max_total_bytes": 65536}
```

Only explicitly enabled stdout/stderr handles are admitted. CX bytes at DS:DX
are copied to independent byte streams; AX returns CX and CF clears. Other
registers and flag bits are preserved by this declared model. This is an
explicit environment assumption for concrete execution, not a model of arbitrary
DOS console, file, redirection, disk-full or partial-write behavior. Zero-byte
writes read no memory. Segment wrapping, undeclared buffers, other handles and
exceeded byte budgets refuse before memory is read. Services remain disabled
when the declaration is absent. Policy and budgets bind both environment and
boot identities.

Reports retain each write event and the enabled stream denominator. Comparison
concatenates bytes independently per handle, allowing different write chunking
while detecting different bytes or stream destinations. Cross-stream interleaving
is outside this independent-stream contract. Final DOS termination remains
mandatory; missing/foreign output receipts and incomplete executions cannot
agree. Explicit immutable preopened file reads/seeks are separately described
in [the file-input contract](real16-program-file-input.md); arbitrary file writes
and OS error behavior remain outside this model.


## Declared DOS version response

`environment.dos_version` optionally supplies all four response fields:

```json
{"major": 3, "minor": 30, "oem": 0, "serial24": 0}
```

This explicitly enables only INT21/AH30 with AL00. It sets AL/AH to major/minor,
BH to OEM and BL:CX to the 24-bit serial. The model preserves upper register
halves, other registers, flags and segments. Its response adds no memory writes
beyond the common architectural INT entry frame. Its convention follows
[Microsoft's MS-DOS Encyclopedia, Function30H](https://msarchive.pcjs.org/mspl13/msdos/encyclopedia/section5/).
Major versions below2 and other AL selectors are outside the admitted contract.
An absent/null policy leaves the interrupt refused. The values declare a
synthetic environment; they do not describe the host's installed DOS version.

The policy is included in both boot and environment identities and in the
public report's service contract. Every answered query emits a `dos_version`
receipt. Agreement requires well-formed receipts with matching response bytes
and query counts, as well as the existing exit/output obligations. Malformed
receipts produce incomplete evidence even when both sides contain the same
malformation. A wrapping service fallthrough refuses before changing registers.

This service performs constant bounded work per query and uses the existing
instruction budget. It does not enable other DOS services or weaken allocation,
fault, code-write or observation checks. The representative compiled startup
probe now gets past the version query but still refuses on a write inside its
declared whole-image code scope; this is not completed program acceptance.

The invocation-domain census can also consume this explicitly declared service.
Mint a `DeclaredInterruptService8616` with
`tools.dosunit.runtime.real16_declared_invocation8616.declared_int21_version_service_8616`,
binding the environment, caller and interrupt callsite. Pass the resulting
relation through the proof API's `declared_services` tuple; its default is empty.
The census must independently prove the AH/AL selector and revalidate the
response, preserved registers, IVT slot and environment at consumption.
Successful consumption records the `declared_interrupt_service` assumption;
it is conditional on that environment, not proof of an arbitrary DOS handler.

Prior writes overlapping the IVT slot revoke the relation. The six-byte INT
frame enters the write ledger and must not overlap instruction bytes, including
future fetches. Frame contents are not inferred: subsequent loads remain unknown.
An absent declaration, altered response, foreign environment or unsupported
selector remains a refusal. The shared response encoding lives in
`inertia.frontend.real16_version_response8616`; both execution and census derive
their response words from that owner. This API adds no KVM dependency.

## Symbolic terminal comparison

`compare-terminal16` separately lifts actual binary bytes and compares the
bounded acyclic transition to DOS INT21/AH4C. Use the same environment
format above, with no named replay observations or custom code-range projection:
this proof compares the complete modeled terminal state and memory effects.

```sh
env PYTHON_JIT=1 nice -n 10 .venv/bin/python -m tools.dosunit.dosunit \
  compare-terminal16 --oracle-exe original.exe --candidate-exe rebuilt.exe \
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

The symbolic lane admits declared INT21/AH30/AL00 (DOS version) and INT10/AH0F
(video query) before termination. Existing version/video policies supply the
responses; the live IVT route, interrupt-frame writes and exact native
fallthrough must be authenticated. Ordered events remain observable even when
response registers are dead. Other concrete replay services are not implicitly
available to this symbolic lane, and ordinary internal-call wrappers may refuse.

Bounded divide-error outcomes are compared only under an explicit no-handler
and fault-site relation; other exception classes and asynchronous delivery stay
outside the model. Reports retain event/fault evidence and the native decode
limits used during intake and verification. See the
[terminal-service contract](dosunit-execution-spec.md#79-symbolic-terminal-service-comparison)
for supported transitions, refusal boundaries and budget details.

## Invocation-scoped IR evidence

The decompiler's IR API can retain a conditional control-flow view for an
independently authenticated `Real16InvocationDomain8616`. This is a segment-state
and call-preservation capability, not a whole-function equivalence verdict or
permission to publish conditional code as a universal artifact.

`raw_x86_16_import_bundle_for_artifact_8616` authenticates a caller-held raw
artifact against native bytes. `prove_scoped_x86_16_ir_function_view_8616` takes
that bundle, the exact frontend boundary and the independently supplied
`invocation_scope`. Coverage, segment state and effect closure retain the same
source, view and scope. Their `complete_for(scope)` checks revalidate native
provenance, effective CFG edges, call dependencies and evidence counts; default
`complete` remains false for conditional results. Unknown or unrelated refusals
remain present, and transfer still consumes the original instruction objects.

Scoped callee reuse stays separate from universal registry/cache entries.
Changing native bytes, a dependency or the consuming entry invalidates the
applicable proof. Cycle/depth/work bounds still apply, and no incomplete result
is cached as a proof. A loaded MZ image alone does not establish an invocation
path: consumers must supply and preserve the source-bound entry authority.

Contract controls run in the routine unit pipeline. The slower native MZ
controls run serially with `make test-scoped-ir-native
PYTHON=./.venv/bin/python` and are a prerequisite of `test-pipeline-expanded`.
These controls do not establish that the original SORTD regression or the full
binary-equivalence release plan is complete.
