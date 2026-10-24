# Direct native boundary, version 1

This specification defines the direct backend boundary. Installed capabilities
and qualified platforms are identified by each compiler release. Backend
contracts do not change the meaning of the separate C-backed `native` driver.

## Scope and targets

Core 0.1 is unchanged. Public Kelft gains no pointers, unsafe operations, FFI,
machine integer types, or target-dependent aggregate layouts. The production
backend, runtime builders and command driver are Kelft programs. Object emission
must be deterministic.

The direct build interface uses `--target x86_64|arm64`,
`--platform linux|windows|macos`, `--emit object|executable`. The platform defaults
to the host and emission to executable. Object emission is pure and available on
every compiler host. Linking belongs to the trusted driver, needs an explicitly
configured matching linker/SDK, and never silently falls back to C. Running also
requires a compatible native execution host. Without an available matching profile,
the public compiler must reject it. JavaScript, Wasm, C and C-backed native
commands keep their existing meaning.

| Platform | Baseline | Object | Linker | ABI |
|---|---|---|---|---|
| Linux x86_64 | Ubuntu 24.04, glibc 2.39 | ELF64 | GNU ld | System V AMD64 |
| Windows x86_64 | Windows Server 2025 | COFF | link.exe | Microsoft x64 |
| macOS x86_64 | macOS 15 | Mach-O64 | Apple ld | Darwin AMD64 |
| Linux arm64 | Ubuntu 24.04, glibc 2.39 | ELF64 | GNU ld | AAPCS64 |
| macOS arm64 | macOS 14 | Mach-O64 | Apple ld | Apple ARM64 |
| Windows arm64 | Windows 11 | COFF | link.exe | classic Windows ARM64 |

The x64 qualification baselines are Windows Server 2025 and macOS 15 Intel.
Server qualification does not establish Windows 11 desktop support. The macOS
object/deployment floor remains 14.0; deployment metadata alone does not
establish execution support on an older OS. Only target profiles with complete,
verified native qualification may be advertised as certified. Releases identify
the verified subset and list other targets as unqualified.

ARM64EC, arm64e, mobile, general FFI, optimization and a custom linker are outside
this version. HTTP, SQLite, and OIDC adapters are separate work.
Application acceptance is a separate requirement.

## Private IR

`kelft-native-ir/1` is a verified backend-private representation between validated
Core and instruction encoding. It contains named functions and control-flow
blocks, explicit eight-byte value slots with `i32`, `u8` or `ptr` machine widths,
memory operations, symbolic calls and relocatable addresses. It is not persisted
as Core, accepted as public source, or exposed through a public intrinsic.

The verifier rejects malformed widths, invalid slots, duplicate symbols or block
labels, missing terminators, unreachable blocks, undefined slot reads along any
predecessor, invalid calls, invalid offsets, and unresolved addresses. Pointer
operations are restricted to trusted builders. They are not a memory-safety proof
for arbitrary IR; only compiler-generated IR may execute. No raw instruction-byte
escape hatch is part of this IR.

Initial code uses stack slots and caller-saved scratch registers. Branches use
fixed-width displacements, with checked bounds; encoders must never truncate an
out-of-range displacement. Core lowering must preserve left-to-right evaluation,
short circuiting, evaluated inout locations, iteration snapshots, wrapping i32
arithmetic, masked shift counts, division traps, and contract diagnostics. AArch64 requires
explicit division-by-zero and signed-overflow checks.

## Ownership and runtime ABI

`kelft-native/1` functions have the platform C calling convention and four pointer
parameters: context, arguments, evaluated locations, and result storage. Inputs
are borrowed for the duration of the call; returned language values are owned.
Callers initialize result storage, own cleanup, and retain arguments until the
call returns. Aggregates never cross the platform boundary by value. Internal
slot arrays contain eight-byte machine values; their layout is private and must
not be confused with the final owned language-value representation.

Runtime builders must emit allocation accounting, checked reference counts,
iterative destruction, copy-on-write aggregates, UTF-8 strings, maps, frame
cleanup, contracts and traps. Preserve the current 256 MiB heap limit and 256-call
limit. A helper cannot transfer input ownership implicitly. Public equality is
structural, not pointer equality. Core runtime and startup are emitted from
trusted Kelft IR builders, never generated C or assembled text.

The initial Linux [owned-storage layer](native-owned-storage.md) specifies its
private headers, explicit ownership operations, pooled allocation accounting and
copy-on-write protocol. The [aggregate layer](native-aggregate.md)
adds records, tuples, arrays, evaluated index locations, snapshot iteration and
normal frame cleanup. The [enum layer](native-enum.md) adds recursive tagged values,
nested patterns and array pop without changing the calling convention. The
[graph walker](native-graph.md) compares recursive values with bounded machine
stack use and heap-budgeted overflow. Implementations must preserve full aggregate conformance and frame semantics.

OS allocation, I/O and process APIs are imported mechanisms. Host adapters
implement arguments, environment, standard streams and filesystem capabilities.
Compiler/linker authority never becomes program authority. Windows uses Unicode
APIs and checks reparse points and volume boundaries. Runtime policy intersects
the embedded maximum with the host grant and denies by default. Loading a native
object is trusted compiler work, not a capability granted to an emitted program.

Each platform adapter has an explicit import allowlist and ABI wrapper. Windows
x64 requires shadow space, stack probing, preserved registers and pdata/xdata;
Darwin and ARM64 have their own stack/unwind rules. x18 is reserved on Apple and
Windows ARM64. ELF FDE start addresses use a local text-section anchor plus the emitted body
offset, so global-symbol interposition cannot redirect them. Native stream
probes retain the full unwind table and unwind across replaced mechanisms.
Unwind records must describe actual prologues, including large
frames. Objects without these adapters/records cannot pass the platform gate.

The [filesystem adapter](native-filesystem.md) intersects caller and
emitted maximum policies for canonical paths, reads, directory creation and
writes, with descriptor traversal and replacement-race probes. The
[artifact adapter](native-artifacts.md) executes supplied Linux ELF artifacts
and optional explicitly configured JavaScript/Wasm engines.
The [process adapter](native-process.md) captures arguments in a
versioned context extension and validates execution of inserted Intent guards.
The [POSIX path adapter](native-paths.md) implements lexical dirname,
resolution and relative paths plus execution-time cwd. It confers no filesystem
or subprocess authority; canonical paths and authorized I/O remain separate requirements.

## Determinism and provenance

Native role memory contracts are versioned separately from language semantics.
The [compiled resource registry](../host/native/resource-contracts.json) selects
Linux's 1 GiB per-process virtual-address ceiling, Windows' 1 GiB aggregate job
committed-memory ceiling (also applied per process), and macOS virtual-address
ceilings of 64 GiB Intel / 512 GiB ARM64. Initial stacks remain 16 MiB; the
compiler retains its 256 MiB language heap and 600-second wall deadline. macOS
CPU limits are additional process limits, not a wall-deadline replacement.
Windows reservations and resident memory are distinct from committed memory;
the macOS ceilings provide no hard 1 GiB physical-memory guarantee.

Version 2 receipts name the target, role, measured quantity, scope, mechanism,
exact ceiling and registry hash. Optional engines require separate contracts.
Older receipts keep their original quantities and producers. Contract selection
does not certify enforcement: native readbacks, positive allocation controls,
excessive/cumulative allocation denials and supervisor lifetime controls remain
required.

Object writers use deterministic section and symbol ordering, explicit little
endian fields, checked integer arithmetic and relocation addends. Duplicate or
unresolved symbols fail. Objects include ABI/profile/policy metadata. Timestamps,
paths and build IDs cannot depend on the checkout directory or wall clock.
Debug paths, signing inputs and archive member order are normalized. macOS
ad-hoc signing is a separately pinned step with unsigned and signed hashes.

Before a toolchain can be used, inventory the exact linker, SDK/sysroot files,
OS import libraries, signing tool and flags with SHA-256 identities. Unconfigured
targets fail closed. A baseline label or an image tag alone is insufficient.
Changing any input invalidates reproducibility evidence. Record full commit and
Git tree, architecture, OS, format, runtime ABI, tool input hashes, source hashes,
all required checks, and unsigned/signed artifacts in commit-bound manifests.
Collection requires a clean tracked checkout and checks identity again afterward.

Qualification must bind compiler, semantic/ABI, isolation, package, and engine
results to the exact source, resource registry, toolchain inputs, and artifacts.
Changed implementation inputs, receipts, or inventories invalidate the claim.
Qualification records remain detached from the archives they identify;
additional records must not relabel an already reproduced package.
Application acceptance remains a separate claim.

Self-compilation requires three generations, identical later-generation objects
and executables, isolated rebuilding in paths containing spaces, dependency
inspection, and denial of Node, Wasmtime, Rust tools, C compilers and
assemblers. System linkers, SDKs and OS libraries remain dependencies.

Every target requires native hardware execution evidence. Emulation is useful
development evidence but cannot substitute for its release lane. Missing runners,
toolchain hashes, runtime features or renewed acceptance block completion.

## References

Encoding and ABI review uses the [Intel manuals](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html),
[AMD64 psABI](https://gitlab.com/x86-psABIs/x86-64-ABI),
[AAPCS64](https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst),
[PE/COFF](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format),
[Microsoft x64](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention),
[Windows ARM64](https://learn.microsoft.com/en-us/cpp/build/arm64-windows-abi-conventions),
[Mach-O headers](https://github.com/apple-oss-distributions/cctools/blob/main/include/mach-o/loader.h)
and [Apple ARM64](https://developer.apple.com/documentation/xcode/writing-arm64-code-for-apple-platforms).
