# Non-Interactive, Emulation-Driven Disassembler

This project is a sophisticated, non-interactive disassembler for 16-bit DOS MZ-EXE files. It leverages both static and dynamic analysis techniques to produce high-quality, human-readable assembly listings that are compatible with MASM/UASM.

The core philosophy is to first perform a deep automatic analysis using a CPU emulator, and then allow the user to refine and correct this analysis using an IDA-compatible IDC script.

## Project Architecture

The disassembler is built on a layered, modular architecture where each component has a distinct responsibility. All components interact through a central `AnalysisDatabase`, which acts as the single source of truth for the entire state of the disassembly.

The analysis pipeline proceeds in the following order:

### 1. Layer 1: Static Loader (`mz_parser.py`)
- **Responsibility**: To parse the input MZ-EXE file and establish the initial memory layout.
- **Engine**: `pefile` library.
- **Actions**:
    - Parses the MZ header to determine entry point, segment information, and image size.
    - Loads the program's code and data into the `AnalysisDatabase`.
    - **Performs initial static analysis on the relocation table**. It uses this information to heuristically identify a data segment (`dseg`) and automatically label the targets of relocated pointers (e.g., `word_11234`).

### 2. Layer 2: Dynamic Analyzer (`emulation_analyzer.py`)
- **Responsibility**: To perform deep, automatic discovery of code, data, and functions by observing the program's behavior. This is the core of the auto-analysis.
- **Engine**: `unicorn` framework for CPU emulation.
- **Actions**:
    - Sets up a 16-bit x86 virtual machine.
    - **Executes the code starting from the entry point**.
    - **Instruction Hooking**: Intercepts every instruction to discover dynamic control flow. It resolves indirect `JMP`s and `CALL`s by reading register values at runtime, discovering code paths that static analysis would miss.
    - **Memory Hooking**: Intercepts every memory read and write. This provides definitive proof of which memory locations are used as data (variables, tables, etc.). It can distinguish between byte, word, and dword accesses.
    - **Post-Emulation Processing**: After emulation, it analyzes the collected data to:
        - Define function boundaries based on `CALL` targets and `RET` instructions.
        - Mark all memory locations accessed during emulation as data.
        - Provide default, IDA-style names for all discovered items that don't already have a name (e.g., `sub_101A0`, `byte_11250`).

### 3. Layer 3: User Override (`idc_engine.py`)
- **Responsibility**: To apply the user's domain knowledge and corrections on top of the automatic analysis.
- **Engine**: `lark` parsing library.
- **Actions**:
    - Parses a user-provided `.idc` script file.
    - Executes IDC commands (`set_name`, `create_byte`, `add_func`, etc.) which directly modify the `AnalysisDatabase`.
    - This layer allows for the correction of any mistakes made by the auto-analysis and the annotation of the listing with meaningful names and comments.

### 4. Layer 4: Output Generation (`output_generator.py`)
- **Responsibility**: To render the final, annotated state of the `AnalysisDatabase` into output files.
- **Engine**: Custom formatting logic.
- **Actions**:
    - Reads the rich data from the database.
    - Generates a MASM/UASM compatible `.asm` file, complete with `SEGMENT`, `PROC`, and `ASSUME` directives, and correctly formatted operands.
    - Generates an IDA-style `.lst` file for a detailed, human-readable view of the disassembly, including hex bytes and addresses.

### Central Component: The State (`database.py`)
- **Responsibility**: To act as the central, in-memory database for all analysis information.
- **Engine**: Python `dataclasses`.
- **Function**: It holds every piece of information about every address in the binary: whether it's code or data, its size, any labels or comments, cross-references, function boundaries, and formatting overrides. All other components read from and write to this central state, ensuring consistency throughout the pipeline.

This layered approach ensures that the final output is the product of robust static analysis, powerful dynamic analysis, and precise user guidance.
