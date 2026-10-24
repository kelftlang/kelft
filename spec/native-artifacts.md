# Fixed native artifact registry

The direct Linux x86-64 runtime implements `artifact_run` for
`native-linux-x86_64-v1`, `javascript`, and `wasm`, plus the separate compiler
linker service described below. Core and public intrinsic
signatures are unchanged. The private ABI is `kelft-native-artifacts/1` and uses
the 128-byte `kelft-native-fs/3` context. Inputs are borrowed, returned stdout and
stderr are owned, and the private status result is exactly four bytes. Existing
JavaScript, Wasm, C and C-backed native commands retain their profiles.

Execute permission must be true in both the caller policy and the emitted
maximum, independently of read/write roots. Unknown targets return
`UNSUPPORTED_ARTIFACT_TARGET`. Supplied native executables must be ELF64,
little-endian x86-64 ET_EXEC images. Unsupported/malformed images and host,
exec, signal, capture, timeout and output-limit failures return
`ARTIFACT_EXECUTION_FAILED`. A legitimate exit 127 is distinct from failed exec.
Invalid child policy syntax fails closed with KRT_CAPABILITY. Child read/write
roots are individually authorized against the parent's frozen grants, normalized
and JSON-escaped. The child receives only KELFT_CAPABILITIES, with execute false.
No engine handles, PATH, Node options, credentials or compiler environment are
forwarded. This is executable-code authority for the trusted compiler/verifier;
it is not OS isolation for adversarial machine code or JavaScript.

Native artifacts are copied to a sealed memfd, executed through execveat, and
never looked up as arbitrary program names. The runtime creates private pipes,
a process group and a parent-death SIGKILL setting with a parent-identity race
check. On failure it kills the group and direct child, waits for the child, closes
owned descriptors and releases workspaces. It polls both streams, retries EINTR,
handles partial writes and bounds combined output to 16 MiB and execution to
30 seconds. UTF-8 output is required. Argument count is bounded at 4096, each
argument at 4095 bytes and total argument storage at 1 MiB. Two heap-accounted
16 MiB capture buffers plus sentinel bytes are allocated before fork; heap
exhaustion cannot abandon a running child. Trap/process-exit cleanup remains OS
termination, rather than language recovery.

## Compiler linker service

`linker-linux-x86_64-v1` is a trusted build service; it does not qualify a public
direct target. The Kelft driver supplies an independently measured, observed GNU
toolchain configuration. No reviewed release pins are created by this service.
Its binary payload contains little-endian fields:

| Offset | Field |
|---|---|
| 0 | Four bytes `KLNK` |
| 4 | u32 version, exactly 1 |
| 8 | u32 tool byte length |
| 12 | u32 object byte length |
| 16 | Tool bytes followed immediately by object bytes |

Both images need at least 64 bytes. Lengths must exactly cover the payload
without signed overflow. The tool is ELF64 little-endian x86-64 ET_EXEC or ET_DYN;
the object is ELF64 little-endian x86-64 ET_REL. Invalid bundles return an artifact
execution error before tool execution. The driver separately checks tool/runtime
hashes and the configuration identity before and after linking.

Exactly one service argument supplies the desired output path. It is retained
by the compiler and never passed to GNU ld. The tool receives only fixed static,
no-build-id and non-executable-stack flags plus sealed object and output memory
file paths. The linker child receives 64 MiB file-size and 1 GiB address-space
hard limits. Existing process-group, parent-death, 30-second wall and combined
16 MiB stdout/stderr bounds remain in force. The parent seals and checks the
complete 64-bit output size before allocating or reading it; sizes beyond 64 MiB,
including values that would truncate to a small i32, fail.

Only successful linking can publish an image. The parent validates the executable
header and uses the filesystem capability guard to write the binary. A private
writer mode marks the opened descriptor 0700 after its complete write; ordinary
public write and write-once behavior is unchanged. Existing symlinks cannot become
output targets, and a linker error leaves existing output intact. No pointer,
unsafe, FFI or public intrinsic signature is added. SDK/linker dependencies remain
explicit, and complete driver/protocol/package certification remains required.

JavaScript and Wasm engines are optional execution dependencies. Native
compilation, rebuilding and native artifact execution must work without them.
The trusted launcher reads an explicit `kelft-artifact-runtimes/1` manifest with
absolute executable/dependency paths, SHA-256 pins, version arguments and exact
version output. It checks inputs, snapshots each executable into a sealed memfd,
and checks inputs again after execution. No ambient PATH discovery or fallback
occurs. Missing engines return ARTIFACT_RUNTIME_REQUIRED and malformed/unsealed
handles return INVALID_ARTIFACT_RUNTIME. The inherited-descriptor adapter supplies
engines through private inherited descriptor keys KELFT_JAVASCRIPT_RUNTIME_FD and
KELFT_WASM_RUNTIME_FD. Their descriptors are borrowed, never closed by the
language service and never delegated to children.

The standalone Kelft `engine-run` command can instead validate the explicit
manifest and supply the measured engine bytes to private probe/JavaScript/Wasm
service profiles. The service creates and owns its sealed engine descriptor;
it never closes borrowed descriptors from the older adapter. The first private
argument carries artifact source or bounded Wasm hex and is excluded from guest
arguments. Wasm modules are bounded to 32 MiB. Packed engine bytes use a retained
immutable view, avoiding a second full engine allocation; legacy slot arrays are
converted. Optional engines and services require a separately configured host
installation and are excluded from default native packages.

Node receives the sealed JavaScript artifact on stdin with --input-type=module;
it does not need a compiler-created source path or ambient NODE_OPTIONS. The
fixed Wasm entry is `kelft-wasi artifact-exec MODULE_FD_PATH POLICY_FD_PATH -- ARGS`.
That Linux-only internal entry executes the existing Wasmtime worker in-process,
with its import allowlist, memory/output limits and read-only/read-write preopens.
The native parent supplies the deadline and process boundary. A typed proc_exit
host adapter preserves Kelft's 0..255 exit range, including 127 and 255; foreign
out-of-range import calls remain execution errors. It avoids a
self-spawn through current_exe, whose name denotes a deleted memfd. The module
and normalized policy descriptors alone survive exec; ordinary inherited
nonstandard descriptors close on exec. The existing WASI /project namespace and directory-root limitations still
apply: this internal entry uses / as its explicit host project root, so an
authorized host /out/data directory appears as /project/out/data to the guest.
JavaScript/native host paths and WASI guest paths keep their respective profile
semantics. No host-to-guest mapping or preopen-rights rule is relaxed.

OS linkers, SDKs, and libraries remain intentional dependencies. JavaScript and
Wasm execution require their separately selected engines; native compilation
and native artifact execution must work without those engines.

Engine preparation must authenticate exact executable and dependency bytes and
versions. Downloads belong to explicit preparation; subsequent builds run
offline. Missing or changed prerequisites must fail rather than select an
ambient engine. Default native packages do not include optional engines.

Verification must cover deterministic objects, real child exit/output, Unicode
arguments, pipe-capacity draining, contracts and traps, read/write delegation,
execute denial, malformed images, timeout, and output overflow. Independent ABI
probes must check result widths, ownership, descriptor counts, child reaping,
environment/descriptor separation, parent-death signaling, sealing, and injected
creation/fork/exec/capture failures. Mock copies retain production code and full
unwind sections except for deliberately replaced mechanisms.

Launcher validation must reject missing or altered executables, dependencies,
versions, targets, architectures, malformed/duplicate manifest keys, and changed
inputs after handoff. Native compiler execution must work without engine handles
or development executables on PATH. Fixture engines do not establish actual
JavaScript/Wasm execution; reports must identify the real engines used.