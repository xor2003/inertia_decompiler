# DOS Unit Test Tool Execution Specification

## 1. Purpose

The separate initialized-program lane is documented in
[Initialized MZ program comparison](real16-program-execution.md).
`replay-program16` uses MZ header startup and typed DOS termination under an
explicit complete initial arena. Function replay, symbolic proof and program
execution retain independent contracts and verdicts.

This document turns `reference/dosunit-plan.md` into an execution
specification.

The target is a general DOS function unit-test system that can:

- generate concrete function inputs from VEX / typed Inertia IR using Z3
- import real runtime seed data from libdosbox traces and memory dumps
- execute original DOS code in-process through a reusable KVM backend
- record original x86 output as the oracle
- compare reconstructed C, decompiled C, and reassembled ASM candidates
- report typed pass/fail/refusal results

F-15 Strike Eagle 2 is the first corpus, but the tool must remain generic for
DOS `.exe` and `.com` files.

## 2. Repository And Artifact Boundaries

### 2.1 Inertia Repository

Primary planning and integration repository:

```text
/home/xor/vextest
```

Expected new files and modules:

```text
reference/dosunit-plan.md
reference/dosunit-execution-spec.md
tools/dosunit/
tools/dosunit/dosunit.py
tools/dosunit/schemas/
tools/dosunit/adapters/
tools/dosunit/backends/
tools/dosunit/tests/
```

The exact Python package location may change during implementation, but the
tool must remain logically separate from decompiler rewrite/postprocess code.

### 2.2 KVM Backend Repository

Execution backend source:

```text
/home/xor/kvikdos/kvikdos.c
```

Required direction:

- extract reusable `libkvikdos` primitives
- keep the current `kvikdos` CLI as a wrapper
- do not put `dosunit`, VEX, Z3, manifest parsing, or function discovery into
  `kvikdos`

### 2.3 libdosbox Runtime Recorder

Runtime trace and memory dump source:

```text
/home/xor/inertia_player/libdosbox
```

Relevant existing mechanisms:

- runtime JSON from `ShadowMemory::dump()`
- memory dumps from `DumpExe1`
- code execution counts
- segment observations
- memory access summaries
- pointer evidence
- ABI summaries
- program load metadata

libdosbox remains a runtime recorder and optional real-data source. It is not
the deterministic unit-test backend.

### 2.4 F-15 First Corpus

Reconstruction project:

```text
/home/xor/tmp/f15se2-re
```

IDA project and exports:

```text
/home/xor/games/f15se2-ida
```

Important first-corpus files:

```text
/home/xor/tmp/f15se2-re/map/*.map
/home/xor/tmp/f15se2-re/map/*.tgt
/home/xor/tmp/f15se2-re/src/*.c
/home/xor/tmp/f15se2-re/src/*.asm
/home/xor/tmp/f15se2-re/build/*.exe
/home/xor/tmp/f15se2-re/bin/*.exe

/home/xor/games/f15se2-ida/egame.lst
/home/xor/games/f15se2-ida/start.lst
/home/xor/games/f15se2-ida/end.lst
/home/xor/games/f15se2-ida/start.asm
/home/xor/games/f15se2-ida/su.asm
/home/xor/games/f15se2-ida/egame.cpp
/home/xor/games/f15se2-ida/egame.h
/home/xor/games/f15se2-ida/egame.seg
```

## 3. Non-Negotiable Invariants

1. VEX/Z3 generates inputs, not the final oracle.
2. The original x86 program executed by `libkvikdos` produces expected outputs.
3. Candidate comparison is against recorded original execution.
4. Memory is represented as segmented memory in manifests and IR.
5. Linear address translation happens only at backend execution boundaries.
6. `dosunit` is generic and must not contain F-15-specific rules outside
   adapter fixtures or corpus manifests.
7. `kvikdos` remains an emulator/backend, not a unit-test orchestrator.
8. Statuses, verdicts, and refusals are typed fields, not parsed strings.
9. Unsupported cases must be refused, not silently treated as passing.
10. Runtime traces from libdosbox are seed evidence, not equivalence proof.
11. Existing Inertia semantic rules still apply: no text-based recovery, no
    rewrite-stage semantic repairs, and no guessed alias/type facts.
12. libdosbox `m2c::m` must continue to reflect live DOSBox guest memory.

## 4. End-To-End Dataflow

```text
function discovery
  -> functions catalog

original EXE bytes
  -> VEX / typed Inertia IR
  -> SSA
  -> Z3 constraints
  -> synthetic vectors

libdosbox gameplay/runtime
  -> runtime JSON + memory dumps
  -> imported real seed vectors

vectors
  -> original execution through libkvikdos
  -> oracle outputs

vectors + oracle outputs
  -> candidate execution through libkvikdos
  -> structured comparison results

original/candidate EXE bytes
  -> lifter-backed region summaries
  -> static operand/effect comparison
  -> typed argument/effect drift before runtime
```

## 5. Execution Modes

### 5.1 Oracle Recording

Command shape:

```bash
dosunit record-oracle \
  --exe original.exe \
  --vectors vectors.json \
  --out oracle.json
```

Behavior:

1. Load the original DOS program.
2. Save a clean baseline snapshot.
3. For each vector:
   - restore baseline
   - apply vector pre-state
   - install the requested trap strategy
   - run until trap, timeout, fault, or unsupported external effect
   - collect declared observables
   - write expected output into the oracle artifact

The oracle is invalid if original execution times out, faults unexpectedly, or
requires unsupported side effects.

### 5.2 Candidate Comparison

Command shape:

```bash
dosunit compare \
  --oracle-exe original.exe \
  --candidate-exe rebuilt.exe \
  --vectors vectors.with-oracle.json \
  --mapping candidate-functions.json \
  --out results.json
```

Behavior:

1. Load candidate program.
2. Save candidate baseline snapshot.
3. For each vector:
   - translate function entry through candidate mapping
   - restore candidate baseline
   - apply the same pre-state
   - execute candidate
   - collect declared observables
   - compare against oracle expected output

Comparison must be field-based. It must not compare rendered source text.

### 5.3 Trace Import

Command shape:

```bash
dosunit import-libdosbox \
  --trace EGAME.json \
  --dump EGAME.20260609-170348-233.1 \
  --meta EGAME.20260609-170348-233.1.meta.json \
  --functions functions.json \
  --out seed-vectors.json
```

Behavior:

1. Read libdosbox runtime JSON.
2. Read dump metadata if available.
3. Map runtime linear addresses back to module-relative function addresses.
4. Extract hot functions, observed segment values, access-site samples, and
   memory ranges.
5. Emit seed vectors when there is enough state for replay.
6. Emit prioritization hints when data is only aggregate.

Aggregated runtime data cannot by itself become an oracle. It can become:

- function priority
- memory observation range hints
- segment defaults
- pointer evidence hints
- ABI hypothesis hints
- vector seeds if enough concrete data exists

### 5.4 Vector Generation

Command shape:

```bash
dosunit gen-vectors \
  --exe original.exe \
  --functions functions.json \
  --strategy edge \
  --out vectors.json
```

Behavior:

1. Lift selected functions to VEX.
2. Import to typed Inertia IR.
3. Build function SSA.
4. Construct path constraints.
5. Ask Z3 for concrete inputs.
6. Emit vectors with assumptions and generation provenance.
7. Emit structured refusals for unsupported functions or paths.

Z3 output is incomplete until oracle recording succeeds.

## 6. Public `libkvikdos` API Requirement

The concrete API can be C or C-compatible C++, but it must be callable from the
`dosunit` runner without spawning a process per test vector.

### 6.1 Types

Required public state types:

```c
typedef struct DosVm DosVm;
typedef struct DosVmSnapshot DosVmSnapshot;

typedef enum DosVmStatus {
    DOSVM_STATUS_OK = 0,
    DOSVM_STATUS_TRAP,
    DOSVM_STATUS_TIMEOUT,
    DOSVM_STATUS_FAULT,
    DOSVM_STATUS_UNSUPPORTED,
    DOSVM_STATUS_BACKEND_ERROR
} DosVmStatus;

typedef enum DosTrapKind {
    DOS_TRAP_HLT = 1,
    DOS_TRAP_MISSING_MEMORY,
    DOS_TRAP_SENTINEL_IP,
    DOS_TRAP_INT3,
    DOS_TRAP_BACKEND_WATCH
} DosTrapKind;

typedef struct DosRegs16 {
    uint16_t ax;
    uint16_t bx;
    uint16_t cx;
    uint16_t dx;
    uint16_t si;
    uint16_t di;
    uint16_t bp;
    uint16_t sp;
    uint16_t ip;
    uint16_t flags;
} DosRegs16;

typedef struct DosSRegs16 {
    uint16_t cs;
    uint16_t ds;
    uint16_t es;
    uint16_t ss;
    uint16_t fs;
    uint16_t gs;
} DosSRegs16;

typedef struct DosMachineState16 {
    DosRegs16 regs;
    DosSRegs16 sregs;
} DosMachineState16;

typedef struct DosProgramInfo {
    uint16_t psp;
    uint16_t loadseg;
    uint16_t entry_cs;
    uint16_t entry_ip;
    uint16_t entry_ss;
    uint16_t entry_sp;
    uint32_t loaded_low_linear;
    uint32_t loaded_high_linear;
} DosProgramInfo;
```

### 6.2 Functions

Minimum required functions:

```c
DosVmStatus dosvm_create(DosVm **out_vm, const DosVmConfig *config);
void dosvm_destroy(DosVm *vm);

DosVmStatus dosvm_load_program(DosVm *vm,
                               const char *path,
                               const char *argv,
                               DosProgramInfo *out_info);

DosVmStatus dosvm_snapshot_create(DosVm *vm, DosVmSnapshot **out_snapshot);
DosVmStatus dosvm_snapshot_restore(DosVm *vm, const DosVmSnapshot *snapshot);
void dosvm_snapshot_destroy(DosVmSnapshot *snapshot);

DosVmStatus dosvm_get_state(DosVm *vm, DosMachineState16 *out_state);
DosVmStatus dosvm_set_state(DosVm *vm, const DosMachineState16 *state);

DosVmStatus dosvm_read_memory(DosVm *vm,
                              uint32_t linear,
                              void *out_bytes,
                              size_t size);

DosVmStatus dosvm_write_memory(DosVm *vm,
                               uint32_t linear,
                               const void *bytes,
                               size_t size);

DosVmStatus dosvm_install_trap(DosVm *vm, const DosTrapConfig *trap);

DosVmStatus dosvm_run(DosVm *vm,
                      const DosRunLimits *limits,
                      DosRunResult *out_result);
```

### 6.3 Snapshot Contents

The current Python `KvikdosSession` keeps its native VM in one dedicated child
process for the session lifetime. Strict-mode native aborts are contained in
that child and reported as `KvikdosBackendError`; later requests on the failed
session refuse. A new session creates a fresh VM. One-shot execution also
creates a fresh VM for every run. Request writes and replies share a bounded
deadline, and child diagnostics and messages are bounded. The parent validates
memory reply length; the child validates guest ranges before native unsigned
conversion and resolves snapshot tokens through its owned registry.

The current wrapper snapshots guest memory only, after a program initializes
the VM. This supports the tested restarted function-harness workflow; it does
not satisfy the general paused-program snapshot contract below. Process
containment must not be reported as full CPU, DOS-service, or file-state
snapshot isolation. Native execution controls are in
`test_dosunit_kvikdos_worker_native.py`; protocol controls run without KVM.

Before restarting a program in an existing worker, the wrapper clears retained
video/environment RAM and drains its recorded native file/dup descriptors,
including DOS overflow handles. Acquisition/release hooks in the embedded native
translation unit maintain a bounded4096-entry integer ledger (16KiB); they hold
no extra descriptors that could change DOS-visible handle numbers. VM descriptors
and unrecorded worker descriptors are preserved. Stale mapped-handle slots are
cleared without blindly closing their potentially reused descriptor numbers.
This covers the inspected native source's reachable open/dup/dup2/close surface;
adding another acquisition channel requires a corresponding ownership audit.

Ledger overflow or an inconsistent release makes reset fail with status6.
That failure persists for the worker lifetime: repeated run requests cannot
silently restore success while unknown descriptors remain. A failed close drops
the uncertain number rather than risking closure of a later unrelated owner.
Destroying the worker reclaims uncertain descriptors; persistent refusal is not
successful cleanup. These controls do not restore standard-stream redirection,
external file contents/positions or a full paused CPU/service snapshot. The
native cohort tests128 allocations across two runs and repeated refusal after
exceeding the ledger; it retains the `requires_kvm` marker and explicit resource
skip when the host descriptor limit cannot reach the exhaustion boundary.

A backend snapshot must include:

- guest memory range used by the VM
- CPU registers
- segment registers
- flags
- KVM state required for deterministic replay
- DOS service state in the backend if INT handling mutates host-side state
- mapped DOS file-handle state when enabled

Phase 1 can restrict function tests to code that does not depend on mutable
host file-system state. If that restriction is active, it must be explicit in
results.

### 6.4 Backend Determinism Requirements

The backend must support deterministic configuration for:

- time and date
- timer ticks
- keyboard state
- random uninitialized initial registers
- initial memory fill
- file-system mount paths
- DOS version responses
- unsupported device I/O behavior

Default `dosunit` mode should refuse nondeterministic device effects unless a
model is configured.

## 7. Function Invocation Specification

### 7.1 Entry Address Resolution

Function entries can be specified as:

- absolute runtime `CS:IP`
- module-relative segment:offset
- module-relative linear offset from load segment
- function name resolved through a function catalog
- candidate-mapped function name

Resolution is a typed step:

```text
manifest entry
  -> function catalog entry
  -> program load segment
  -> runtime CS:IP
```

Do not guess when more than one mapping is possible. Emit
`mapping_ambiguous`.

### 7.2 Segment Defaults

`auto` segment values are resolved from:

1. vector explicit values
2. oracle/candidate mapping metadata
3. program load metadata
4. function catalog defaults
5. libdosbox imported runtime samples

If no safe segment can be resolved, emit `segment_unresolved`.

### 7.3 Stack Setup

Before invocation:

1. Restore baseline snapshot.
2. Set `SS:SP` from vector pre-state.
3. Apply explicit stack memory bytes.
4. Push a trap return frame according to function kind.
5. Apply register and segment values.
6. Set `CS:IP` to function entry.

Stack memory in vectors must use `space: "SS"` unless an explicit segment is
required.

### 7.4 Trap Strategies

#### Near Return

Near-return functions pop only `IP`, leaving `CS` unchanged.

Allowed trap strategies:

- `same_cs_hlt_slot`: patch a manifest-provided unused offset in the same code
  segment with `HLT`, then push that offset as the return IP.
- `missing_memory_return`: push an IP that returns outside the mapped executable
  range and configure the backend to treat the resulting KVM exit as a trap.
- `backend_watch`: run with a backend return watch if available.

Preferred for Phase 1:

```text
same_cs_hlt_slot when safe slot is known
missing_memory_return for smoke tests
```

If no safe near-return trap is available, emit `trap_unavailable`.

#### Far Return

Far-return functions pop `IP` and `CS`.

Trap strategy:

- create a backend-owned trap paragraph containing `HLT`
- push trap `CS`
- push trap `IP`
- execute function
- expect `KVM_EXIT_HLT` at trap location

#### No Return / Tail Jump

For functions that tail-jump or do not return:

- observe final `CS:IP`
- enforce an instruction limit
- stop at configured control target or trap
- otherwise emit `control_unbounded`

#### Explicit HLT

If the function naturally executes HLT, distinguish:

- expected program HLT
- dosunit trap HLT

Use trap address validation.

Real16 final write snapshots contain only bytes read successfully from guest
memory. An unreadable span carries its address, size and backend cause; it must
not be filled with zeros or cause later fragments to acquire earlier addresses.
Lost write-snapshot evidence prevents complete replay/program agreement and successful
boundary capture, even when execution reached the requested return or boundary.

### 7.5 Call Handling

Supported modes:

- `whole_program`: calls execute normally in the loaded program
- `leaf_only`: refuse if a call is reached
- `stubbed`: intercept configured callees and apply summaries
- `record_calls`: execute calls but record observed direct call targets

Phase 1 should implement `leaf_only` and `whole_program`.

Stubbed calls require typed summaries:

```json
{
  "target": "sub_1234",
  "pre": { "args": [] },
  "post": {
    "regs": { "ax": "symbolic_or_concrete" },
    "memory": [],
    "stack_cleanup": 0
  }
}
```

No name-based helper substitution is allowed as proof. Summaries must be
manifest-provided or recovered from validated evidence.

### 7.6 Binary-bound recursive proof scope

The real16 `check_image_bound_real16_joint` API composes source-bound atomic
transitions, entry/frame, progress, address and normal-outcome obligations.
This symbolic API is separate from the concrete execution modes above. It
does not establish whole-program reachability, allocation or final observers.

An optional `JointSystem.environment_scope` accepts a `Real16EnvironmentScope`
containing every `EnvironmentScopeMember` once and both input binary hashes.
Changing the declaration changes the proposal identity and invalidates retained
receipts. This is an explicit machine-domain premise, never inferred from the
absence of service instructions. No CLI option is implied by this internal API.

After synchronous outcome obligations prove, missing or unbound declarations
leave the environment obligation open. A valid declaration instead appears as
one content-bound assumption per member in the shared normal-outcome and
aggregate scope verdicts. Both results remain `conditional`; an empty remaining
obligation list does not mean unconditional equality. Unsupported faults,
services and incomplete source/access evidence still refuse. All required
evidence rows and counters remain visible, including on deadline exhaustion.

### 7.7 PE32 binary-bound recursive prerequisites

`build_flat32_pe_component` proposes a same-coordinate near32 component from
actual loaded executable blocks. `bind_flat32_native_effects` independently
relifts their bytes and verifies complete modeled state. The
`check_image_bound_flat32_joint` API composes that binding, the initialized-byte
relation, declared stack/access bounds, transitions and recursive frame proofs
under one deadline. Each call requires the existing flat32 adapter context.

`Flat32AccessDomain` declares an entry ESP interval, writable stack window and
finite frame budget. Mapping permission checks and dynamic access proofs are
separate obligations; writes overlapping code, including partial overlaps,
cannot satisfy the explicit code-disjointness goal. Source and model identities
are checked independently for the native, access-domain and composite owners.

A discharged component remains `conditional`: caller entry, recursive-depth
physical backing, fault outcomes, code/physical alias scope, address model and
environment requirements remain explicit. This API does not prove arbitrary
member entry states, whole-program termination or Windows services. Undeclared
call targets, incomplete manifests, unsupported faults and exhausted budgets
remain typed non-results. Section7.10 describes the public driver opt-in.

### 7.8 Real16 public recursive component reports

`compare_binary16(..., recursive=Real16RecursiveRequest(...))` optionally
attempts initialized-entry recursive components using the same sealed lowered
documents and executable identities as the ordinary comparison. The CLI exposes
`--recursive`, `--recursive-timeout-ms` and `--recursive-closed-machine`.
The last flag declares a visible binary-bound machine premise; it does not
prove the absence of external events or admit unsupported services.

The `recursive_joint` report is separate from ordinary function obligations.
A conditional component proof must not change any member's arbitrary-entry
status, assumptions, dependencies or contract. Requested-function accounting
is unchanged. Without the opt-in the report field is null. A stale or aborted
ordinary run cannot attempt the recursive path.

The retained immutable domain scope includes both binary hashes, initialized
load coordinates, root entry, scalar-domain bounds, snapshot identities and
model/proposal identities. Reports serialize these identities rather than
reducing the theorem to a list of member names. Missing call-site evidence
refuses explicitly. The total request deadline bounds construction, loading,
domain and joint proof work; each child also retains its existing smaller cap.
Unknown solver results, missing native evidence and expired budgets remain
unknown, never conditional or proved. Ordinary-import tests cover actual MZ
self/equivalent-changed pairs, corruptions, domain exclusions and budget refusal.

### 7.9 Symbolic terminal-service comparison

`tools.dosunit.compare.symbolic_terminal.compare_symbolic_terminals` lifts actual MZ
or PE32 bytes into the shared SSA model. It compares bounded acyclic paths to
DOS INT21/AH4C or a caller-declared PE32 exit gateway. The result retains both
native traces, byte/boot/environment identities, assumptions, counters and
counterexample differences. This API is separate from concrete replay.
Public `compare-terminal16` and `compare-terminal32` commands serialize this
result as `dosunit.symbolic_terminal_compare.v1`: equality becomes conditional,
execution remains not_run, and stale inputs prevent publication.

An `equivalent` terminal result is conditional on its explicit initialized-data
and environment relation. Only the bounded divide-error fault scope below is
admitted; other faults and undeclared services remain refused. Every read,
including a discarded read, must satisfy declared permissions; partial stores
retain initial-byte obligations for uncovered lanes. Every memory write and
terminal payload is observed. Incomplete or duplicate output projections refuse.

The shared `flat32_lifting` owner supplies the same register and pure flag-helper
lowering for the terminal path and both PE32 function drivers. Adapter contexts
restore every patched SSA owner on normal and exceptional exit. Driver loader,
CFG-boundary and ELF behavior remain unchanged. This bounded API does not prove
arbitrary program termination, recursive member entry or full DOS/Windows APIs.

#### Declared returning DOS/BIOS queries

The real16 path also admits INT21/AH30/AL00 (DOS version) and INT10/AH0F
(video-state query) under explicit version/video and live-vector policies.
These are declared environment transitions, not proofs of a real DOS/BIOS
implementation. Each query retains its six-byte interrupt-frame writes,
preserves register upper halves and the declared flags/segments, applies the
declared response, and continues at the exact native fallthrough.

Ordered `service_events` remain observable even when response registers are
dead. Event verification starts at the re-derived executable entry, decodes
complete bounded instruction streams, checks native transfers/successors, and
requires exactly one event per returning boundary. Deleted, duplicated,
reordered or forged events, altered transfer tags, and hidden interrupt blocks
refuse. Bytes resembling INT inside an immediate are not instructions. The
default bounds remain eight blocks,4096bytes/block,256instructions/block.
Explicit `TerminalLimits` budgets are retained as one immutable native limit
contract and used by intake and receipt verification. Reports expose
`native_limits`; verification never silently substitutes the default limits.
Live-vector recovery skips proved disjoint symbolic stores and fully shadowed
older writes. Overlapping unknown data, unresolved addresses, malformed stores
and unmodeled address wrapping still refuse without an extra solver query.
Residual return-IP writes make differing service offsets observable; equal
result registers alone are insufficient for equivalence.

#### Declared PE32 import services

The PE environment may declare `services`, a bounded list of no-argument,
DWORD-returning synthetic contracts. Each declaration supplies `dll`, `name`,
`address`, `result`, `volatile` and `flags`. The actual PE import directory must
bind every declaration and every imported symbol exactly. DLL spelling is
case-insensitive; export spelling is case-sensitive. Ordinal, bound, delayed,
ambiguous or otherwise unsupported imports refuse. The declared gateway must
not overlap executable/image data, environment allocations or another gateway.

Example service declaration (inside `environment.services`):

```json
{"dll":"kernel32.dll","name":"GetTickCount","address":"0x70000100",
 "result":{"kind":"shared_opaque"},"volatile":["ecx","edx"],"flags":"preserved"}
```

`declared_dword` instead requires a `value`; `shared_opaque` has no value field.
The response, declared volatile registers and optional opaque flags are fresh
for each occurrence, shared only across corresponding ordered invocations.
Dead results do not erase service events. Changed event sequences, state,
memory or residual return-address writes remain observable. These contracts
are explicit assumptions, not Windows implementations. Equality stays
conditional and concrete execution remains an independent status.

Only genuine `call/jmp dword ptr [IAT]` routes consume these contracts. The IAT
must be readable non-executable data and bind the declared loaded address.
CALL fallthrough is authenticated directly from native bytes. JMP continuations
also undergo one bounded fresh native walk using the same SSA lowering and
captured limits, without materializing another document or invoking Z3. This
rejects coherent receipt edits that delete an intervening invocation and repair
its counters. Both paths retain complete ordered receipt and fact accounting.

Use the project CLI:

```sh
PYTHON_JIT=1 nice -n 10 ./.venv/bin/python -m tools.dosunit compare-terminal32 \
  --oracle-exe ORIGINAL.exe --candidate-exe REBUILT.exe \
  --environment environment.json --out comparison.json
```

The default empty service list preserves import-free behavior;
the concrete PE replay backend continues to refuse these returning services
until it has an independent execution implementation.

#### Bounded processor-fault terminals

Both terminal commands may compare a proved divide-error (#DE, vector 0) under
an explicit `stop_at_exception_no_handler` premise. This does not execute a
handler or establish that a real machine lacks one. Other fault classes,
asynchronous exceptions and handler dispatch remain outside the admitted scope.

Reports retain each lane's `outcome`, fault kind/vector, instruction address,
encoding and typed reason. Fault traces have a null service `site`; the faulting
instruction is recorded in `fault.site_address`. Fault sites compare by offset
from each declared entry, under an explicit relation. Different offsets remain
observable; absolute relocation alone is not disagreement. Prefix register and
memory effects remain observable, including a preceding nonfaulting division.

Equivalent fault terminals remain `conditional`, with no-handler and fault-site
premises. `domain.faults=compared` describes established fault equivalence, not
execution coverage. Normal-service equality and non-equivalent results use
`not_established`; execution remains `not_run`. The v1 schema retains historical
`faults=refused` reports. Schema validity checks shape and status consistency,
not machine semantics or the arithmetic fault-site relation.

### 7.10 PE32 public recursive component reports

Both MSC8 and BC5 drivers accept `--recursive` with an explicit
`--recursive-access-domain STACK_LO:STACK_HI:ESP_MIN:ESP_MAX:MAX_FRAMES`.
Fields use base-0 integers. They declare a writable stack window, allowed entry
ESP interval and frame bound; the adapter does not infer these premises.
`--recursive-timeout-ms` bounds the entire recursive attempt, while each child
stage retains its existing smaller budget. The ordinary `--timeout-ms` remains
the ordinary comparison's budget.

The opt-in adds a separate `recursive_joint` component report with schema
`dosunit.pe32_compare.recursive_joint.v1`. Ordinary requested-function rows,
statuses, assumptions and dependencies retain their meaning. Without the opt-in
this field is null. A component result cannot discharge an arbitrary-entry
member obligation.

The current recursive path requires PE32 images and same-coordinate member
ranges. Both binaries are loaded and their native effects independently
rederived. Initialized memory, stack access and frame obligations are checked.
A discharged component remains conditional with named caller-entry, depth
backing, fault, code/alias, address-model and environment requirements. This is
not a proof of Windows services or unrestricted recursion. Unsupported targets,
missing evidence, stale identities and exhausted budgets remain unknown.

Reports retain the input hashes, load entries, root, snapshot identities,
domain/model/proposal identities and declared access bounds. Selected names
remain accounted for on early refusal. Symbolic status does not claim concrete
execution. ELF retains its existing comparison path and is not admitted by the
new recursive PE32 component path.

### 7.11 Explicit real16 boot invocation source

`tools.dosunit.catalog.real16_scoped_invocation.install_declared_invocation_source_8616`
accepts a loaded project and an explicitly declared `ProgramBoot`. It checks
the retained MZ source, header entry and stack, relocated image, and mapped
loader bytes before installing the source used by scoped IR proofs. It never
infers a loader environment from a function catalog.

The frontend inventory includes the MZ header entry independently of optional
`extra_entries`, then follows decoded direct calls through closed mapped
boundaries. Missing boundaries and exhausted inventory budgets return typed
refusals. `InvocationInventoryBudget8616` defaults to 64 boundaries, 65536
census instructions and 4096 extra-root inputs (duplicates count). Root and
instruction enumeration use one overflow lookahead; they never accept a
truncated corpus. These limits do not bound prior third-party decoding work.
Inspect `receipt.installed` before consuming `receipt.source` or its
inventory. Every preparation first clears any earlier installed source; a
refusal or raised input/programming error cannot retain stale authority.

```python
from tools.dosunit.catalog.real16_scoped_invocation import install_declared_invocation_source_8616

receipt = install_declared_invocation_source_8616(project, declared_boot)
if not receipt.installed:
    raise ValueError(f"Invocation source unavailable: {receipt.status}")
```

Installation supplies evidence to the existing explicitly scoped proof path;
it is not itself an equivalence proof, does not publish conditional bodies as
universal artifacts, and does not discharge DOS-service or indirect-call
boundaries. Native adapter controls run in `make test-scoped-ir-native` and
precede the expanded pipeline.

Native lifting preserves near/far CALL effects even when binary scanning
recognizes the target as a compiler stack-allocation helper. Recognition does
not discharge the return-frame writes, segment-relative target, scratch/flag
effects, or helper failure path. Analysis summaries must prove their own
premises from retained binary evidence; they cannot replace the native CALL
merely because its address appears in the helper registry. The routine
`test_x86_16_native_helper_call_retention.py` controls cover native and IR CALL
retention and reject allocation evidence based on a low-word address alias.

## 8. Memory Model Specification

### 8.1 Manifest Spaces

Allowed memory spaces:

- `CS`
- `DS`
- `ES`
- `SS`
- `FS`
- `GS`
- `SEG`
- `LINEAR`

`SEG` requires an explicit segment value:

```json
{ "space": "SEG", "segment": "0x2345", "offset": "0x0010", "bytes": "aa" }
```

`LINEAR` is allowed only for backend/debug fixtures and imported dumps. It
must not be used as a replacement for segmented IR memory.

### 8.2 Translation

Concrete backend translation:

```text
linear = (segment << 4) + offset
```

This translation is valid only after segment values have been resolved for the
current vector and current loaded program.

### 8.3 Memory Application

Before execution:

1. Validate every memory write range is in guest addressable memory.
2. Reject overlapping writes unless bytes are identical.
3. Apply memory patches after restoring baseline.
4. Record before-bytes for all observed memory ranges.

After execution:

1. Read declared observed ranges.
2. Compute byte diffs against before-bytes.
3. Compare only declared observed ranges unless `observe.memory_writes` was
   populated by a write-tracking backend.

### 8.4 Write Observation

There are two supported write-observation modes:

- `range_diff`: compare configured observed ranges
- `backend_write_log`: compare backend-collected write events

Phase 1 can use `range_diff`.

`backend_write_log` is optional and can be implemented with KVM page
protection, emulator instrumentation, or a future backend hook.

## 9. Vector Schema Requirements

### 9.1 Required Fields

Every vector must have:

- `schema`
- `id`
- `module`
- `function`
- `source`
- `pre`
- `observe`

`expected` is null before oracle recording and required for candidate
comparison.

### 9.2 Vector ID

Vector IDs are deterministic:

```text
sha256(canonical_json_without_expected)
```

Canonical JSON means:

- sorted keys
- lowercase hex strings
- no insignificant whitespace
- stable ordering of arrays unless declared unordered

### 9.3 Source Kinds

Allowed source kinds:

- `z3`
- `libdosbox`
- `manual`
- `hybrid`

Allowed origins:

- `vex`
- `typed_ir`
- `runtime_json`
- `memory_dump`
- `per_call_snapshot`
- `manual_fixture`

### 9.4 Expected Output Fields

Expected output must include:

- run status
- final registers requested by `observe.regs`
- final segment registers requested by `observe.sregs`
- masked flags
- memory observations
- return/control-flow outcome if requested
- call observations if requested

Example:

```json
{
  "status": "trapped",
  "regs": { "ax": "0x0001" },
  "sregs": { "ds": "0x2000" },
  "flags": { "value": "0x0203", "mask": "0x08d5" },
  "memory": [
    {
      "space": "DS",
      "offset": "0x0200",
      "before": "00112233",
      "after": "00119933",
      "diff": [{ "offset": 2, "before": "22", "after": "99" }]
    }
  ],
  "return": { "kind": "near", "trap": "same_cs_hlt_slot" },
  "calls": []
}
```

## 10. Result Schema Requirements

### 10.1 Top-Level Fields

```json
{
  "schema": "dosunit.result.v1",
  "run_id": "...",
  "vector_id": "...",
  "module": "...",
  "function": "...",
  "oracle_exe": "...",
  "candidate_exe": "...",
  "status": "passed",
  "verdict": {
    "kind": "equivalent",
    "changed_fields": []
  },
  "oracle": {},
  "candidate": {},
  "diagnostics": []
}
```

### 10.2 Status Enum

Allowed statuses:

- `passed`
- `failed`
- `refused`
- `timeout`
- `faulted`
- `unsupported`
- `backend_error`

### 10.3 Verdict Enum

Allowed verdict kinds:

- `equivalent`
- `observable_mismatch`
- `oracle_unavailable`
- `candidate_unavailable`
- `mapping_unavailable`
- `unsupported_effect`
- `nondeterministic`
- `backend_failure`

### 10.4 Refusal Reasons

Allowed refusal reason codes:

- `unsupported_ir`
- `unsupported_effect`
- `unbounded_memory`
- `unbounded_indirect_control`
- `segment_unresolved`
- `mapping_ambiguous`
- `mapping_missing`
- `trap_unavailable`
- `call_unmodeled`
- `device_io_unmodeled`
- `dos_interrupt_unmodeled`
- `timeout`
- `backend_error`
- `oracle_unavailable`

## 11. Discovery Specification

### 11.1 Inputs

Discovery adapters must support:

- MZ EXE headers
- COM binary entry
- map files
- IDA LST files
- IDA ASM files
- Inertia function metadata
- manual JSON manifests

### 11.2 Function Catalog Fields

Required output:

```json
{
  "schema": "dosunit.functions.v1",
  "module": "egame.exe",
  "program_kind": "mz_exe",
  "functions": [
    {
      "id": "egame.exe:sub_155AB",
      "names": ["sub_155AB"],
      "entry": {
        "kind": "module_relative",
        "segment": "text",
        "segment_para": "0x0000",
        "offset": "0x155ab"
      },
      "return_kind": "near",
      "sources": ["ida_lst", "map"],
      "confidence": "medium",
      "size": null,
      "safe_traps": []
    }
  ]
}
```

### 11.3 Confidence Rules

Confidence values:

- `high`: at least two independent sources agree, or source has strong symbol
  and relocation evidence
- `medium`: one structured source gives plausible address
- `low`: heuristic or partial source only
- `refused`: ambiguous or contradictory

Contradictions must be retained in diagnostics, not overwritten.

## 12. VEX / Z3 Generation Specification

### 12.1 Solver Model

Use bitvectors for:

- general registers
- segment registers
- flags
- temporaries
- stack offsets
- integer memory values

Use segmented memory arrays:

```text
mem_SS[offset] -> byte
mem_DS[offset] -> byte
mem_ES[offset] -> byte
```

Do not model all memory as one flat array unless the vector explicitly uses
`LINEAR` for backend-only debug fixtures.

### 12.2 Path Strategy

Initial strategies:

- `entry`: one satisfiable input reaching function entry
- `edge`: cover discovered branch edges up to a path bound; candidate
  discovery must use the x86-16 lifter through `project.factory.block(...).vex`
  before lowering a compact branch `ConditionIR`
- `hot`: bias toward libdosbox observed hot paths
- `manual_seed`: expand from imported runtime seed states

Bounds:

- max basic blocks per path
- max loop unroll count
- max memory symbolic bytes
- max solver time per path
- max vectors per function

All bounds must be written into vector generation metadata.

For `edge`, raw VEX must not be sent directly to Z3. The lifter-backed adapter
extracts only branch-relevant condition facts, then `solver_slice.py` solves
that compact condition with lazy flag materialization. If the lifter project
cannot be loaded, the byte decoder may run as a fallback, but fallback use must
be reported in counters and each emitted vector's `source.coverage`.

### 12.2.1 Region Operand/Effect Strategy

`regions` is the static gate for checking instruction arguments over parts of a
function. It summarizes straight-line lifter-backed regions, not isolated
single instructions.

Each region records:

- function id/name
- region entry/end
- instruction mnemonic and structured operands
- operand widths and access mode
- register reads/writes
- flag reads/writes
- segmented memory reads/writes
- control exits and successors

Memory operands must stay segmented:

```text
DS:[si + 0x0004]
SS:[bp - 0x0002]
ES:[di]
```

`compare-regions` compares these summaries between original and candidate
artifacts. It must report typed mismatches for register, memory
base/index/displacement/segment, width, flag, and instruction effect drift.
Direct branch/call immediates are compared as control-target operands, not as
raw relocated candidate addresses.

### 12.2.2 Function Complexity Gate

`complexity` is the static gate that decides whether a function is small enough
to attempt as one whole-function comparison/solver part.

The gate is lifter-backed. It must use `project.factory.block(...).vex` before
reading Capstone instruction summaries, so the result follows the same decode
path as region and edge analysis.

Each function records:

- instruction count and block count
- condition/branch/jump counts
- call, interrupt, and indirect-control counts
- explicit memory read/write counts
- symbolic memory counts for register-indexed memory operands
- segment-sensitive memory counts
- flag read/write counts
- partial-register, variable-shift, mul/div, string-instruction, loop, and
  backward-branch counts
- a weighted `risk.score`
- typed blockers when the function is not simple
- risk points with address and disassembly

The first conservative simple class is `simple_whole_function`. It requires:

- no conditions, jumps, calls, interrupts, loops, backward branches, string
  instructions, or indirect control
- a return instruction
- instruction count at or below `--max-simple-insns`
- explicit symbolic memory count at or below `--max-simple-symbolic-memory`
- risk score at or below `--simple-score-threshold`

When a function passes this gate, the output includes one comparison part:

```json
{
  "kind": "whole_function",
  "function": {"id": "...", "name": "..."},
  "entry": {"cs": "0x0000", "ip": "0x0200", "linear": "0x1200"},
  "end": {"cs": "0x0000", "ip": "0x0206", "linear": "0x1206"},
  "instruction_count": 3,
  "reason": "simple_whole_function"
}
```

This gate does not replace runtime oracle comparison. It selects the functions
where a future compact VEX/AIL SSA-to-Z3 whole-function pass is expected to be
cheap enough. Functions that fail the gate remain testable through entry/edge
vectors, region comparison, and runtime replay.

`report-failures` must render `dosunit.complexity.v1` documents with:

- summary counters
- complex function names and entries
- blocker names
- compact metrics
- risk-point instruction addresses and disassembly

### 12.2.3 Straight-Line SSA Strategy

`ssa` lowers bounded straight-line function slices into compact SSA. The first
frontend adapter is VEX-backed:

```text
x86 bytes -> existing x86-16 lifter -> VEX IRSB
          -> final requested PUT(reg) outputs
          -> backward slice through VEX tmp definitions
          -> compact SSA expressions
```

VEX temps are already single assignment. The dosunit layer must not decode x86
instruction semantics. It only serializes the reachable VEX expression graph.

The compact SSA artifact records:

- source IR (`vex`)
- lifted instruction list for visibility
- input registers used by the slice
- topologically ordered assignments
- requested output register expressions
- typed refusals

The first pass supports one bounded VEX IRSB. It does not follow successor
blocks, but it does lower VEX exits into a selected-block `ip` expression.
Register outputs and a symbolic byte-array memory output are supported. VEX
loads/stores become `loadle`/`storele` or big-endian equivalents over the shared
memory input. Unsupported VEX statements/helpers, partial-register accesses
that VEX does not normalize to whole-register expressions, and functions above
the instruction bound are refused rather than guessed. Unused flag computations
and unused return-IP memory loads are dropped by the backward slice.

Lifted VEX blocks are cached on disk by default by the `ssa` CLI. Cache layout:

```text
.cache/dosunit/vex/<exe-sha256>.pickle
```

The cache file stores all lifted block entries for that EXE hash, keyed inside
the file by linear address, size bound, and VEX opt level. AIL should use the
same shape later under `ail/<exe-sha256>.pickle`.

`compare-ssa` asks Z3:

```text
exists input_regs . oracle_output != candidate_output
```

Unsat means the selected SSA outputs are equivalent for that bounded slice. Sat
means the result must include a concrete counterexample model.

When a mapping document is provided, `compare-ssa` resolves oracle functions to
candidate functions through that mapping. Unmapped oracle functions are visible
refusals by default. `--skip-unmapped` suppresses those refusals for targeted
audits. AIL should later lower into the same `dosunit.ssa.v1` schema. The
compare layer must not care whether the source was VEX or AIL.

### 12.3 Constraint Outputs

Each generated vector must include:

- source path summary
- solver bounds
- constraints count
- concrete model values
- assumptions
- refusal details if partial

### 12.4 Unsupported IR

Unsupported IR must not disappear. It must result in:

```json
{
  "status": "refused",
  "reason": "unsupported_ir",
  "detail": {
    "op": "...",
    "block": "0x...",
    "path": "..."
  }
}
```

### 12.5 Generation Counters

Each generator run must report:

- `functions_seen`
- `functions_attempted`
- `branches_seen`
- `branches_attempted`
- `paths_attempted`
- `paths_solved`
- `vectors_emitted`
- `edge_sources`
- `edge_fallback_diagnostics`
- `lifter_blocks_lifted`
- `simple_whole_functions`
- `complex_functions`
- `comparison_parts_emitted`
- `functions_lowered`
- `assignments_emitted`
- `regions_emitted`
- `instructions_summarized`
- `refusals_by_reason`
- `solver_time_ms`

For Inertia semantic integration, any semantic materialization work must keep
the existing evidence loop:

- `raw_fact_count`
- `normalized_fact_count`
- `classified_fact_count`
- `materialized_count`
- `failure_count`

## 13. libdosbox Import Specification

### 13.1 Runtime JSON Fields

Importer must understand at least:

- `Meta.DosboxLoadSeg`
- `Meta.ImageSizeBytes`
- `Code`
- `Data`
- `AccessSites`
- `PointerEvidence`
- `Jumps`
- `Abi`

### 13.2 Dump Metadata Fields

Importer must understand:

- dump filename
- PSP
- load segment
- runtime `CS:IP`
- runtime `SS:SP`
- first exec
- last exec
- exec requests

### 13.3 Address Normalization

Runtime linear address to module-relative mapping:

```text
module_linear = runtime_linear - (loadseg << 4)
```

Only use this mapping when `loadseg` and image size are known.

### 13.4 Seed Vector Eligibility

Aggregated trace data can produce a replayable vector only when:

- entry `CS:IP` is known
- segment defaults are known or can be resolved
- required stack and memory inputs are available
- memory ranges are bounded
- nondeterministic device state is absent or modeled

Otherwise produce priority hints, not replay vectors.

### 13.5 Per-Call Snapshot Extension

Required future record format:

```json
{
  "schema": "dosunit.libdosbox_call_snapshot.v1",
  "module": "EGAME.EXE",
  "function": { "cs": "0x....", "ip": "0x...." },
  "entry": {
    "regs": {},
    "sregs": {},
    "flags": "0x....",
    "stack": { "ss": "0x....", "sp": "0x....", "bytes": "..." },
    "memory": []
  },
  "exit": {
    "regs": {},
    "sregs": {},
    "flags": "0x....",
    "memory_writes": [],
    "return": {}
  }
}
```

This format can become a `dosunit.vector.v1` source with `source.kind =
"libdosbox"`.

## 14. Candidate Mapping Specification

Candidates may have different layout from original. Each candidate needs a
mapping:

```json
{
  "schema": "dosunit.mapping.v1",
  "oracle_module": "egame.exe",
  "candidate_module": "egame.exe",
  "functions": [
    {
      "oracle_id": "egame.exe:sub_155AB",
      "candidate_id": "egame.exe:egmath_func",
      "candidate_entry": {
        "kind": "module_relative",
        "segment": "text",
        "offset": "0x1234"
      }
    }
  ]
}
```

Mapping sources:

- same address
- map symbol
- IDA name
- decompiler metadata
- manual manifest

If mapping is missing, emit `mapping_missing`.

## 15. CLI Specification

### 15.1 Common Flags

All commands support:

```bash
--out PATH
--log PATH
--format json
--strict
--limit-functions N
--function NAME_OR_ID
--timeout-insns N
--seed HEX
```

### 15.2 `discover`

```bash
dosunit discover \
  --exe PATH \
  [--map PATH] \
  [--ida-listing PATH] \
  [--ida-asm PATH] \
  [--inertia-functions PATH] \
  --out functions.json
```

### 15.3 `gen-vectors`

```bash
dosunit gen-vectors \
  --exe PATH \
  --functions functions.json \
  --strategy edge \
  --max-vectors-per-function 8 \
  --solver-timeout-ms 1000 \
  --out vectors.json
```

### 15.4 `import-libdosbox`

```bash
dosunit import-libdosbox \
  --trace TRACE.json \
  [--dump DUMP.1] \
  [--meta DUMP.1.meta.json] \
  --functions functions.json \
  --out seed-vectors.json
```

### 15.5 `regions`

```bash
dosunit regions \
  --exe PATH \
  --functions functions.json \
  --max-regions-per-function 8 \
  --max-insns-per-region 32 \
  --out regions.json
```

### 15.6 `complexity`

```bash
dosunit complexity \
  --exe PATH \
  --functions functions.json \
  --max-blocks-per-function 32 \
  --max-insns-per-function 128 \
  --max-simple-insns 16 \
  --simple-score-threshold 8 \
  --max-simple-symbolic-memory 0 \
  --out complexity.json
```

### 15.7 `ssa`

```bash
dosunit ssa \
  --exe PATH \
  --functions functions.json \
  --output-reg ax \
  --output-reg bx \
  --max-blocks-per-function 64 \
  --max-insns-per-function 64 \
  --cache-dir .cache/dosunit \
  --out ssa.json
```

By default `ssa` follows direct in-function successors and direct call
fallthrough. Use `--no-follow-call-fallthrough` when a report must stop each
SSA part at call boundaries.

### 15.8 `compare-ssa`

```bash
dosunit compare-ssa \
  --oracle-ssa original.ssa.json \
  --candidate-ssa rebuilt.ssa.json \
  --mapping mapping.json \
  --solver-timeout-ms 60000 \
  --max-region-loop-unroll 0 \
  --out ssa-results.json
```

`compare-ssa` enables acyclic multi-block region equality by default. Use
`--disable-region-equality` for block-only debugging. Region equality refuses
loops at the default `--max-region-loop-unroll 0`; raising the bound permits
bounded loop exploration but does not prove loop invariants. Raw region equality
requires complete bounded paths: constant loop branches may be pruned after SSA
substitution, while symbolic paths that hit the unroll bound refuse as
`loop_bound_incomplete`. Use `--disable-connectivity` to skip edge-stitching
checks between individual SSA parts when you only want direct pairwise results.

### 15.9 `compare-regions`

```bash
dosunit compare-regions \
  --oracle-regions original.regions.json \
  --candidate-regions rebuilt.regions.json \
  --out region-results.json
```

### 15.10 `report-failures`

```bash
dosunit report-failures \
  --results region-results.json \
  --limit 50 \
  --mismatch-limit 8 \
  --out failures.md
```

The report must make failed/refused items visible without requiring direct JSON
inspection. It should include the function/region or vector id, mismatch kind,
and compact oracle/candidate values for changed operands/effects.
For complexity documents it should include blocker names and risk-point
instructions. For SSA compare documents it should include changed output
registers and any Z3 counterexample model.

### 15.11 `record-oracle`

```bash
dosunit record-oracle \
  --exe ORIGINAL.EXE \
  --vectors vectors.json \
  --out vectors.with-oracle.json
```

### 15.12 `compare`

```bash
dosunit compare \
  --candidate CANDIDATE.EXE \
  --vectors vectors.with-oracle.json \
  [--mapping mapping.json] \
  --out results.json
```

### 15.13 `summarize`

```bash
dosunit summarize \
  --results results.json \
  --out summary.txt
```

Summary must include:

- total vectors
- passed
- failed
- refused
- timeout
- faulted
- top changed fields
- top refusal reasons

## 16. Initial Implementation Phases

### Phase 0: Specification And Fixtures

Deliverables:

- this execution spec
- JSON schemas under `tools/dosunit/schemas`
- one manually written COM smoke vector
- one manually written EXE smoke vector
- sample result fixture

Definition of Done:

- schemas validate sample fixtures
- fixtures are deterministic
- no implementation is claiming semantic coverage yet

### Phase 1: `libkvikdos` Backend Extraction

Deliverables:

- `libkvikdos` build target
- `kvikdos` CLI still builds
- public backend header
- snapshot/restore API
- state get/set API
- memory read/write API
- run-until-trap API
- smoke tests

Definition of Done:

- existing `/home/xor/kvikdos` CLI tests pass
- a single process runs at least 100 repeated function invocations with
  snapshot restore
- full `AX/BX/CX/DX/SI/DI/BP/SP/IP/FLAGS` and `CS/DS/ES/SS/FS/GS` are captured
- baseline restore produces byte-identical observed memory before each vector
- timeout is deterministic and reported as `timeout`
- unexpected KVM exits are reported as `backend_error` or `faulted`

### Phase 2: Minimal `dosunit` Runner

Deliverables:

- `dosunit record-oracle`
- `dosunit compare`
- vector parser
- result writer
- field diff reporter

Definition of Done:

- identical original/candidate executable passes
- intentionally patched candidate fails with precise field diff
- unsupported trap strategy reports `refused/trap_unavailable`
- no process is spawned per vector
- result JSON validates against schema

### Phase 3: Function Discovery

Deliverables:

- MZ EXE parser
- MAP parser
- IDA LST parser
- manual JSON function catalog support
- F-15 discovery fixture

Definition of Done:

- discover functions from `/home/xor/tmp/f15se2-re/map/*.map`
- discover functions from `/home/xor/games/f15se2-ida/*.lst`
- join at least one function set for `start.exe`, `egame.exe`, and `end.exe`
- ambiguous mappings are retained as diagnostics
- function catalog validates against schema

### Phase 4: VEX/Z3 Vector Generator

Deliverables:

- VEX lifting adapter
- typed IR import bridge
- SSA path collector
- Z3 bitvector model
- vector emitter
- refusal emitter

Definition of Done:

- generates at least two branch-distinguishing vectors for a small test
  function
- emits segmented memory in vectors, not flattened memory
- refuses unsupported dirty helpers
- refuses unbounded indirect control flow
- reports generation counters
- solver output is deterministic with fixed seed and bounds

### Phase 5: libdosbox Trace Import

Deliverables:

- runtime JSON importer
- dump metadata importer
- load-segment normalizer
- access-site to observe-range mapper
- priority hint output
- seed vector output where concrete state exists

Definition of Done:

- imports `/home/xor/inertia_player/libdosbox/tmp_rt.json`
- imports a real F-15 runtime JSON if available
- maps runtime linear addresses to module-relative addresses when load segment
  is known
- refuses replay vector creation when concrete state is insufficient
- emits useful function prioritization for hot code

### Phase 6: libdosbox Per-Call Snapshot Recorder

Deliverables:

- optional libdosbox call-entry snapshot hook
- optional libdosbox call-exit snapshot hook
- bounded stack window capture
- bounded memory read/write capture
- direct `dosunit.vector.v1` export or import path

Definition of Done:

- gameplay can record at least one real function call vector
- vector replays under `libkvikdos`
- `m2c::m` still reflects live guest memory
- recorder can be disabled with zero behavior change to normal DOSBox use
- snapshot size is bounded by configuration

### Phase 7: F-15 Candidate Comparison

Deliverables:

- F-15 function catalog
- oracle vector set for selected deterministic functions
- mapping for reconstructed candidate EXEs
- comparison report

Definition of Done:

- compare original `start.exe` against rebuilt `start.exe` for at least one
  deterministic function
- compare original `egame.exe` against rebuilt `egame.exe` for at least one
  deterministic function
- compare original `end.exe` against rebuilt `end.exe` for at least one
  deterministic function
- failures identify exact observable fields
- existing F-15 `make verify` remains independent and can still be run

## 17. Overall Definition Of Done

The project is done for the first usable milestone when all of the following
are true:

1. `dosunit` can discover functions from structured inputs.
2. `dosunit` can run vectors against an original DOS executable through
   `libkvikdos` without spawning a process per vector.
3. Original x86 execution records oracle output.
4. Candidate execution compares against oracle output.
5. Result JSON uses typed statuses and typed refusal reasons.
6. Segmented memory is preserved in vectors and only translated at backend
   execution boundaries.
7. VEX/Z3 generates at least one nontrivial synthetic vector set.
8. libdosbox trace import produces at least prioritization hints and at least
   one replayable seed vector when a per-call snapshot is available.
9. F-15 first-corpus smoke comparison runs on at least one function from each
   of `start.exe`, `egame.exe`, and `end.exe`.
10. Identical executable comparison passes.
11. Deliberately mutated candidate comparison fails with precise diffs.
12. Unsupported behavior is refused, not passed.
13. Documentation explains command usage, schemas, and limitations.
14. Automated tests cover schema validation, snapshot restore, oracle
    recording, candidate comparison, and at least one refusal path.

## 18. Not Done If

The project is not done if any of these are true:

- expected output comes only from Z3 or VEX instead of original x86 execution
- vectors flatten segment spaces into one untyped linear memory model
- `kvikdos` contains `dosunit` orchestration logic
- comparison depends on rendered C or ASM text
- unsupported calls, I/O, dirty helpers, or indirect jumps silently pass
- one process is started per function vector in the normal runner
- result statuses are inferred by string parsing
- libdosbox `m2c::m` is replaced by independent shadow memory
- a function is marked passing without declared observable comparison
- tests are flaky due to timer, keyboard, filesystem, or device state

## 19. First Engineering Checklist

1. Add schema files and sample fixtures under `tools/dosunit/schemas`.
2. Split `/home/xor/kvikdos/kvikdos.c` into backend and CLI without changing
   current CLI behavior.
3. Add backend smoke test for snapshot restore.
4. Add `dosunit record-oracle` for one manual vector.
5. Add `dosunit compare` for identical executable pass and mutated executable
   fail.
6. Add MAP/LST discovery for F-15.
7. Add VEX/Z3 generator for a small leaf function.
8. Add libdosbox runtime JSON importer.
9. Add per-call snapshot recorder only after the import path is stable.

## 20. Open Decisions

These must be resolved during implementation:

- final language for `dosunit` runner: Python first is preferred for schema and
  adapter speed; C/C++ can remain backend-only
- exact `libkvikdos` public header name and build system
- first near-return trap strategy for MZ EXE code segments
- whether KVM backend will support write logs in Phase 1 or only range diffs
- first canonical F-15 original executable set for oracle recording
- how candidate mapping is maintained for decompiled C builds

Open decisions must be captured in follow-up ADRs or updates to this spec.

## Binary behavior proof commands

`z3func.py compare-binary16 --oracle-exe ORIGINAL.EXE --candidate-exe REBUILT.EXE
--oracle-functions ORIGINAL.functions.json --candidate-functions REBUILT.functions.json
--out REPORT.json` freshly lowers both real-mode images. Catalogs and optional
`--mapping` describe correspondence and bounds; proof consumes binary IR.
The report uses `dosunit.binary16_compare.v1` and the shared typed obligation
ledger. Exit zero requires every requested function to have complete leaf or
closed whole-function evidence under the reported modeled state and environment.
Missing functions, incomplete graphs, unproved callees and resource exhaustion
stay required and cannot pass. Unsupported device effects require an explicit
external relation. Register, memory or control relocation assumptions remain
conditional. The contract includes binary and loaded-image hashes, semantic
sources and model versions; changed inputs invalidate evidence.

When both sides have the same executable path, catalog and fresh binary/source
identity, one invocation may reuse its sealed lowering through a deep copy.
Each side still loads its image, seals and checks provenance, scans environment
effects, and consumes the full comparison gates. `lowering_reuse` records the
reuse per side; lowering counters describe the retained evidence, not duplicate
physical lift executions. Different paths, catalogs or identities lower separately.
No lowering result is retained between invocations.

Both comparator tracks report `proof_scope=requested_functions_over_shared_input_memory`.

The real16 command and both bundled PE32 drivers optionally accept
`--ordered-io-environment dosunit.ordered_io.scalar_in_out.v1`. The declared
`dosunit.ordered_io.v1` model covers scalar IN/OUT at 8/16/32-bit widths and assumes
identical responses to identical ordered event histories. Its architecture,
effects, widths and model identity are sealed with the caller premise. It is
not a universal device theorem. Returning callees retain the same assumption;
affected proof rows are conditional and name `unproved_ordered_io_environment`.

Admission checks that every decoded event survives in the final compared I/O
state, including reads whose returned values are dead. An unused SSA assignment
alone is insufficient. Added, removed, reordered or changed events remain
observable. Missing/malformed receipts, string I/O and unsupported services
refuse. Omitting the declaration preserves default environment refusals; wrong-lane or
conflicting ambient declarations reject before work. Real16 currently rejects
combining this declaration with initialized recursive joint proofs. Budget
limits and independent concrete-execution status remain unchanged.

Their `proof_domain` field (`dosunit.proof_domain.v1`) publishes the architecture,
operand/storage widths, machine-state calling/return contract, observed register
projection and its source, memory/flag model, outcome scope and environment.
The document is included in the contract's `abi_hash`; changing its declared
scope changes proof identity. Real16 uses the actual lowering register inventory;
flat32 publishes the backend's selected outputs, or labels an omitted backend
projection as caller-declared. Supplied malformed or contradictory output
declarations raise an error instead of silently falling back. No language ABI
is inferred. Outcome `not_established` describes unverified scope, not a proof
verdict, and never discharges an obligation. Lazy flags are evaluated exactly
for supported thunks; unsupported flag-dependent counterexamples remain refusals.
This function proof assumes related, shared input memory. The separate
`initial_image_relation` records whether each executable's own mapped initial
bytes and loader coordinates establish that relation. Equal complete loaded-image
identities discharge identity; differing or missing identities require a proved
memory relation and leave `initialized_function_status=unknown` even if function
code proves. Different hashes alone are not behavioral counterexamples: code
edits may be equivalent, but code-as-data aliasing must also be accounted for.
Startup and environmental behavior remain separate obligations.

The real16 driver retries complete acyclic direct near-call regions with actual
full-state callee inlining. The saved return word and CS preservation must be
proved before resuming the caller. Reports retain transitive whole-body hashes
and semantic identities under `backend.direct_calls`; the function catalogs and
mapping contents are part of the immutable contract. Missing body identities,
unclosed indirect targets, recursion, and unresolved aliases of
data writes with the saved return word remain explicit refusals. The near-call
fallback obeys the public solver assignment/input/store limits. Matching callee
names or entry blocks cannot establish whole-caller equivalence.

Bounded indirect calls use the composed full-width control destination to prove
complete coverage by catalog entries over every admitted input and CS alias.
Each live target must have one validated owner; its actual callee body is
composed, its return destination and caller CS restoration are proved, and its
whole-body dependency identity is retained. Guarded post-states merge only after
all arms pass. Default limits allow four live targets and sixteen discovered
candidate entries; oversized catalogs, unknown destinations, incomplete bodies,
and exhausted budgets refuse. Literal destinations need no unrelated candidate
enumeration. Unknown arm feasibility is retained rather than discarded. Reports
under `backend.direct_calls` additionally count `indirect_call_sites` and
`indirect_targets_proved`; these counts do not replace the proof verdict. A
changed far-pointer representation is not automatically equivalent: its stored
bytes, resulting return state, and all other declared observations remain visible.

Direct far16 calls additionally decode their frame from the binary instruction
bytes and recover the caller CS from the actual pushed frame, including calls
to a different relocated code segment. Return-target and selector restoration
must both prove before the caller resumes. Operand-size call variants still
require complete full-width control evidence; incomplete lowering refuses.
SSA keeps a separate 32-bit loaded `control_ip` before projecting the legacy
word `ip`. CALL continuation checks consume full control: equal low words do
not discharge RET32/RETF32 return-target obligations. The architectural entry
domain admits CS aliases satisfying `0 <= loaded_entry - 16*CS <= 0xffff`.
Callee preconditions must hold for the actual substituted post-CALL selector;
an empty selector domain cannot produce a vacuous proof.

Closed matched call-containing loops use identity relations over every modeled
register, flag, segment, memory and control component at cutpoints. Direct
acyclic callees consume the same checked CALL-frame boundary as whole-caller
inlining. Every transition, successor and return must prove; matching CALL
targets or caller bytes cannot stand in for callee effects. This synchronous
induction checks admitted arbitrary cutpoint states without iteration unrolling.
Every continuing transition additionally proves preservation of the admitted
selector domain. Full loaded control is retained at cutpoints, and graph
closure checks physical successors before any word-sized delta projection.
Differing cutpoints, recursive dependencies, missing callees, resource exhaustion
or a failed transition remain unknown. A SAT cutpoint transition can be
unreachable from the entry and is not automatically a concrete counterexample.
The public report records `ssa_z3_closed_call_loop_induction`, per-transition
verdicts, dependencies and complete fact counters when this proof succeeds.

The real16 whole-function retry also checks finite paired regions when blocks
split or merge. Binary CFG edges propose a closed bijection of cutpoints;
topology alone supplies no semantic proof. Each region contains a finite,
nonempty sequence of actual blocks. Unconditional cycles without a surviving
cutpoint refuse instead of establishing progress by assumption. Every paired
transition compares full registers, segments, flags, memory and I/O under the
declared selector domain. Continuing loaded PCs follow an explicit physical
cutpoint correspondence, and their legacy word projections must prove coherent.
Return destinations retain full physical identity. Stored code addresses and
stack slots are not relocated by this PC relation.

This path applies to call-free functions as well as checked direct-call regions.
Successful evidence uses `ssa_z3_paired_region_induction`, with per-region
verdicts, finite block membership, dependencies and fact counters in
`backend.function_proofs`. The existing `backend.direct_calls` field remains a
compatibility projection of the same authoritative retry evidence. Arbitrary
cutpoint SAT states remain unknown unless their reachability is established.
Register renaming, affine recurrence relations and stack-slot correspondence
are additional obligations; finite reblocking does not discharge them.

Real16 function-retry evidence includes `retry_budget` entries for
`loop_induction`, `paired_regions` and `macro_steps` when their deadline gates
are reached. Each entry records `required` (the non-budget gates are open),
`budget_open`, `attempted` and the observed `remaining_ms`. A stage with
`required=true`, `budget_open=false` was skipped because its deadline expired;
`required=false` denotes a non-budget skip, including an unresolved candidate.
An absent entry means that gate was not reached. The final reached macro gate
supplies its record. These observations reuse existing clock reads and do not
change stage order, proof budgets, verdicts, assumptions or counters. Refusal
details can differ when runtime determines which retries fit within the budget;
the diagnostics expose that boundary rather than treating it as a proof.

SSA register reads consume the latest version of FLAGS just as they consume
the latest general-register version. Excluding final FLAGS from the requested
outputs does not discard a flag write used by a later branch or data read.
VEX backward liveness owns removal of unused writes; output selection cannot
override that evidence. This corrects prior stale-entry-FLAGS comparisons.
ABI region composition follows the separate loaded control expression, indexes
blocks by exact physical addresses and refuses ambiguous legacy aliases. An
unrecognized continuing expression or missing branch target is an unresolved
control obligation, never a synthetic function return. This also preserves
branch exploration when the compatibility `ip` output truncates a full-width
conditional expression.

ABI input and preservation lists describe the interface; they do not establish
that other entry registers are zero or irrelevant. Undeclared registers remain
symbolic, so dependencies reaching declared returns or memory observations
remain visible. The existing ABI scaffold fixes FLAGS to `0x0202`, DS/ES to the
reported data-segment paragraph, and SS to `0x3000`, unless the manifest makes
those registers symbolic. SP remains symbolic. CS and other registers without
an explicit scaffold value are never supplied by an implicit zero default.
These are modeled entry states, not collected runtime states.

### Guarded runtime boundary capture

`tools.dosunit.runtime.real16_replay.capture` and `flat32_replay.capture` accept the
same loaded image, entry and vector as replay, plus a declared executable
boundary. They share replay's initialization and execution guards, and stop
before the boundary instruction executes. The typed capture result includes
registers, explicit requested memory observations, prefix writes, bounded fetch
trace and the caller-frame trap identity. A refused prefix, earlier return,
instruction-budget exhaustion or trace overflow is a typed non-result; it must
not seed a runtime-derived vector as though the boundary had been reached.

Capture is evidence about one executed prefix, not a proof of equivalence,
complete call-target coverage or an entry-domain theorem. Flat32 page grants
include emulator page padding. A requested observation can read that mapped
padding; its page origin does not prove that the original image or vector
declared those exact bytes. A converter must check original byte extents before
using captured observations as new patches or mappings, retain unavailable
observations explicitly, and disclose any replacement of captured return slots
by a replay harness. Register/flag domains and source identities must survive
conversion. The observation contract does not authorize arbitrary host reads.

Bounded ABI composition must complete every live path. Literal composed
conditions can prune unreachable arms; a path cut at the unroll bound refuses
with `loop_bound_incomplete`. Equality of completed prefixes cannot establish
whole-function equivalence.

The MSC8/BC5 `z3cmp32.py --mode auto` drivers use the same obligation
accounting and retry bounded call composition and finite CFG reblocking.
Call composition uses actual callee effects and proves saved return targets.
Finite indirect calls require complete proved target coverage and validated
mapped callee bodies; unknown targets, incomplete coverage and resource
exhaustion remain refusals. Recursive dependencies are not discharged by
ordinary call composition: the separate opt-in recursive-component reports
in section 7.10 retain their declared premises and conditional status.
Matched closed loops use induction rather than successful bounded exploration
as their oracle.

Flat32 call composition shares one absolute monotonic deadline across both
images, block lifting, state substitution, callee return proofs and the final
comparison. `timeout_ms` bounds the complete comparison; `total_deadline` can
tighten it, and public retries preserve their original deadline. Nested solver
calls receive only the remaining positive milliseconds: zero must never disable
the total bound. Expiry reports `compose_budget_exceeded`; cached summaries and
late materialization or solver results cannot publish success after expiry.
Standalone `summarize_with_calls` accepts an absolute `total_deadline` or
`CallCompositionLimits.max_total_seconds`; without either its historical
structural limits still apply. Non-finite deadlines refuse explicitly.
A single lift, materialization operation or in-flight solver call cannot be
interrupted internally; a boundary check rejects its late result.

Flat32 return-proof refusals retain `return_proof_failure` with the typed
solver status, comparison side, callee target, continuation and solver report.
`callsite` is the terminal CALL instruction's VEX IMark address; `call_block`
is the owning block's start and may precede argument setup. Successful
`call_sites` records use the same two address meanings. In an unsuccessful
retry this evidence is under `additional_proof_attempts.calls`; it does not
change the original refusal or turn a solver countermodel into replay evidence.
Pointer stores must prove return-slot preservation; a presumed ABI or matching
pointer shape cannot supply that proof.

Loop and call-cycle rollups require every recorded member to be unconditionally
proved. Conditional, unknown, unsupported, unrecognized or missing members
refuse and remain in the denominator. A counterexample dominates incomplete
members. The rollup creates no joint recursive/progress evidence of its own.
The summary's `evidence` publishes raw, normalized, classified, materialized
and failed fact counts for the component verdicts; refused components are
materialized evidence rather than disappearing from that denominator.

`z3func.py replay-flat32 --oracle-exe ORIGINAL --candidate-exe REBUILT
--vectors VECTORS.json --out REPORT.json` independently executes i386 loaded
images in fresh Unicorn guests. Replay agreement is execution evidence only.
Default flat32 observations include every admitted integer register (including
ECX), EFLAGS, loaded EIP and all six segment selectors. The report publishes
that complete `observables` contract; explicitly requested ABI projections in
the Python API retain the existing preserved-register/ESP requirement. Missing
or duplicate returned register evidence is incomplete. Floating-point and SIMD
register files are outside this integer replay model and refuse before their
instructions execute, rather than disappearing from the observation set.
Clock reads (RDTSC/RDTSCP), CPU-feature queries (CPUID), entropy reads
(RDRAND/RDSEED) and extended-control reads (XGETBV) also refuse before
execution: the declared integer replay inputs do not provide those machine or
environment states. The typed reason is `undeclared_machine_input`; implicit
backend defaults cannot supply matching environmental evidence.
Faults, budgets and unavailable services remain separate from proof status.
Flat32 memory observations are read-only host projections: they never create
guest mappings or grant access. File PT_LOAD/section declarations, including
explicit no-access pages, bound guest access. Loaded bytes without a file
declaration retain unsupported provenance and no implicit permission. Byte
patches seed already mapped bytes without widening guest access. Caller scratch
requires an explicit vector declaration, for example:

```json
{
  "mappings": [{"address": "0x400000", "size": 16, "access": ["read", "write"]}],
  "memory": [{"address": "0x400000", "bytes": "11000000"}],
  "observations": [{"address": "0x400000", "size": 4}]
}
```

Scratch declarations cannot request execute access or widen file permissions.
The stack window and return trap are declared harness assumptions, not inferred
loader/OS facts. Reports retain page access/provenance, the required observation
manifest and each range's captured/unmapped status and bytes. Missing, duplicate
or truncated observation evidence stays incomplete even when both sides lose
the same record. Mapping storage, repeated page claims, vector metadata and
aggregate patch/observation byte work have explicit finite budgets.
These commands establish only their declared model/function scope, not DOS or
host-service whole-program behavior.

`z3func.py replay-real16 --oracle-exe ORIGINAL.EXE --candidate-exe REBUILT.EXE
--vectors VECTORS.json --instruction-limit 100000 --out REPORT.json` executes
relocated MZ binaries in fresh independent Unicorn guests. Exit status is 0
for agreement on all selected vectors, 1 for an observed mismatch, and 2 for
incomplete execution. Reports always declare
`proof_status=not_established_by_execution`; execution cannot prove equivalence
for untested inputs. Budget exhaustion, instruction coverage gaps and unavailable
backends remain incomplete even when both sides encounter the same gap.

The manifest contains a nonempty `vectors` list with unique `id` values. Every
vector declares `oracle_entry` and `candidate_entry` as `{segment,offset}`,
`registers` (including nonzero SP), `segments`, and a caller `frame` with
`kind` (`near16` or `far16`) and a segmented `target`. Optional `high_halves`,
`memory` patches (`segment`, `offset`, hexadecimal `bytes`) and `observations`
(`segment`, `offset`, `size`) describe the initial and observed state.
Per-side `oracle_load_segment`/`candidate_load_segment` and physical
`oracle_code_ranges`/`candidate_code_ranges` may narrow the loaded-image
instruction scope. Without code ranges the whole relocated image is executable.
The entire manifest is checked before any vector executes.
Each input executable is snapshotted once into immutable bytes. Its relocated
image and reported file hash derive from that same snapshot. A final file-hash
check rejects changed inputs before writing the replay report.

Default observations retain integer registers, high halves, segments, return
IP, defined flags, writes and selected memory ranges. Explicit `observables`
and `flags_mask` narrow concrete observation only and appear in every row.
Mapped pages start zero; relocated image bytes, declared patches and the caller
frame are applied in that order. Absent registers, high halves and non-CS
segments start zero; flags default to 0x2. These initialization assumptions,
all declared vector state, loaded-image fingerprints and code ranges are
recorded in the report. Floating/vector state and unsupported environment
effects remain explicit refusals.
The shared replay machine-input contract also rejects CPUID, RDTSC/RDTSCP,
RDRAND/RDSEED and XGETBV before execution in real16 function and initialized
program replay. Neither the environment declaration nor the 386 scope supplies
their CPU, clock, entropy or extended-control inputs; operand-size overrides
do not bypass this decoded-instruction refusal.


### Register relations at finite paired cutpoints

Real16 paired-region and flat32 reblocked-CFG induction may propose a bijective,
width-preserving register permutation or invertible modular affine map from
decoded entry SSA effects. Structural
matching proposes a relation; it never proves one. Entry machine inputs remain
identical, interior candidate inputs follow the proposed map, and continuing
outputs use the inverse map. Edges back to the function entry reestablish
identity; returns retain the declared final observation contract. The solver
must discharge all initiation, preservation and exit obligations over complete
cutpoint state, including memory and control. Real16 retains segments, flags,
upper halves and I/O; flat32 retains every adapter state component at cutpoints.
Finite nonempty regions establish progress on both sides. Affine multipliers
must be odd and invertible modulo the exact register width; offsets are canonical
bit patterns. Proposal synthesis understands modular arithmetic, fixed left
shifts and low-bit projections. A shifted high-register OR arm may disappear
only when all its projected bits are identically zero; overlapping OR arms
remain opaque. Even a valid proposal must prove memory, flags and every complete
transition. Successful real16 evidence uses `ssa_z3_affine_region_induction`;
rejected attempts remain visible.

Rotated guards may use a complete finite overlapping region cover when a
disjoint partition cannot pair the CFGs. Every occurrence includes the guard's
real effects; every original block remains covered, and every composed internal
continuation must prove its exact destination. A nonempty finite transition on
both sides supplies progress. A chain cycle or unsupported graph shape refuses.

Stack-slot correspondence may use an ordered permutation of byte addresses
proposed from typed entry-store effects. Each elementary swap reads both bytes
before writing either, preserving invertibility even when addresses alias.
Interior register and memory coordinates may be combined; entry backedges and
final returns still demand identity over the complete observable state.

Saved-byte invariants are separate fixed-point proposals over live scalar
state. The original entry transition must prove initiation, and every continuing
transition must independently prove preservation before the projected interior
domain is admitted. Ordered stores retain last-write behavior for aliased facts.
Final equality includes all memory bytes, registers, flags, segments and control;
applying a projection alone never proves equality. Discovery uses bounded
binary-derived candidates, retains failed attempts, and shares the original
total solver deadline across retries. Exhaustion remains UNKNOWN. Evidence
records graph formation, coordinate attempts, invariant obligations and complete
fact counters. Real16 successful memory correspondence uses
`ssa_z3_memory_region_induction`.

Flat32 CFG lifting stops at the exact machine instruction containing the first
conditional Exit, then checks a byte-identical prefix relift. Both successors
remain reachable CFG obligations. Effects after an Exit inside that same
instruction, including unsupported REP effects, retain the adapter's refusal;
relifting cannot delete part of an instruction to obtain equality.

The shared `x86_lazy_conditions` owner models all sixteen integer branch
conditions for concrete VEX i386 COPY, ADD, SUB, ADC, SBB, LOGIC, INC and DEC
thunks. Arithmetic uses the decoded byte/word/dword operand width, including
modular carry/borrow, signed overflow and even low-byte parity. ADC/SBB consume
VEX's XOR-encoded second dependency; INC/DEC preserve the saved carry. Exact
condition admission and solver interpretation use the same typed contract.
The carry-only `x86g_calculate_eflags_c` helper uses that owner's exact
BELOW/CF projection for the same admitted operation ids. Its result is zero or
one; COPY masks all other bits, ADC/SBB retain encoded incoming carry, and
INC/DEC retain saved CF. Admission and evaluation share `carry_contract`.
Symbolic operation/condition identifiers, shifts, rotations, multiplication
and unsupported helpers remain abstract. This does not add a complete EFLAGS
materialization model or change the caller's observation contract. A SAT
result depending on an unmodeled flag helper remains inconclusive.

`ProofScope.CUTPOINT_SIMULATION` means an arbitrary internal-state SAT model
refutes the proposed simulation and produces UNKNOWN at whole-function scope.
Raw failed rows and countermodels remain visible. A complete entry-to-terminal
comparison retains COUNTEREXAMPLE. Both rejected identity and proposed-register
attempts must remain in reports; missing relations, incomplete coverage and
resource exhaustion cannot be promoted to equality. The shared register and
proof-scope owners are included in flat32 semantic-source fingerprints.

### Declared initialized-program regular-file input

The initialized real16 lane optionally admits bounded read/seek over explicit
preopened immutable file snapshots. Successful register effects, exact guest
buffer/code admission, initial-content identity and complete final cursor
accounting are specified in [the file-input contract](real16-program-file-input.md).
Unsupported files/device/services refuse. Concrete agreement never establishes
symbolic equivalence. PE32 reports retain empty file projections; no Windows
file-service capability is inferred from the shared result model.


### Native-bound real16 symbolic control proofs

Real16 loader-linear lowering records an optional `source.control_domain` fetch
window for each block. The producer requires the actual `Arch86_16` contract;
flat32 lowering emits no marker. Legacy artifacts without a marker retain their
existing literal-routing behavior and refuse the new symbolic proof path.

The control proof recomputes the fetch window from the recorded head and native
terminal, verifies the contiguous instruction bytes, size and SHA-256, and checks
the terminal's decoded destinations against the transfer metadata. Z3 proves
that the raw control term denotes a decoded destination for every admitted fetch
selector. Relocation constant rewrites are excluded from this native theorem;
they remain pair-comparison inputs. Word IP projections do not authorize a
low-word alias for a physical control address. Selector-dependent backward-wrap
transfers remain refused when no single exact destination covers the domain.

A composed conditional keeps its original predicate and proves both arms. These
control proofs establish routing only: callee effects, closed region coverage,
loop induction and complete terminal behavior remain separate obligations.
Incomplete bounded loops still refuse. No runtime trace or symbol name discharges
a control obligation.

The encoder shares a memo across the control term and current CS, bounds unique
nodes to 8,192, and rejects cycles, missing references and inconsistent input
widths. The default attempt permits at most eight total solver queries and
250 ms, tightened by an available caller deadline. Each query receives remaining
time; a late solver result refuses even without a main-thread signal timer.
Classified proofs are recorded in `control_proofs`, including failures. Every
produced normalization must be consumed after the output replacement or route
selection. Unsettled products or a failed shared `FactCounters` closure refuse
with `control_evidence_unmaterialized`; one materialized product cannot conceal
a different lost proof. Detailed attempt records are capped at 128 per ledger.


### Bounded internal leader normalization

The callee-region scanner admits a reachable target at an already retained
instruction head by re-lifting the prefix with an exact boundary, checking its
instruction addresses, sizes and bytes against retained and live source bytes,
and decoding the reachable suffix normally. A target inside an instruction
still refuses. Fresh lifts stop at already verified forward leaders; a lifter
that ignores the bound or changes bytes cannot supply a completed candidate.
Re-lifts consume the original cumulative byte/instruction budgets; no budget
increase, unbounded retry, or proof-status promotion follows. Native real16 and
stock i386 VEX controls cover the same overlapping-head case. A completed scan
is boundary evidence only; existing lowering, cycle and semantic proof gates
remain mandatory.
