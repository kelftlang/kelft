# Runtime contract 0.1

`intrinsics.json` is the language-owned list of intrinsic signatures. Generated
Kelft signature tables must agree with this specification. Runtime implementation source remains backend-local.

Persistent vectors and immutable value trees implement JavaScript storage. Every
mutation creates a new value path; temporary `inout` locations update only their
explicit root. Native/Wasm allocation strategies do not change this behavior.

Filesystem operations are denied unless the trusted caller supplies read/write
roots through `KELFT_CAPABILITIES`. A build can embed an additional maximum policy;
the effective policy is the intersection. Roots and targets resolve real paths,
including symlinked existing ancestors of new files. Policy is not read from prompts.
Dangling links are resolved before authority checks. If canonicalization cannot
establish containment, including inaccessible link traversal, it traps with
`KRT_CAPABILITY`; errors from authorized file operations remain recoverable.
This adapter assumes no hostile concurrent filesystem mutation; it is not an OS
sandbox. Node's own APIs are unavailable to Kelft source except through this contract.

The trusted compiler/verifier additionally uses `artifact_run`: a versioned host
service that executes already-emitted artifacts through a fixed target registry.
It performs no lexing, parsing, typing, lowering, or code generation. Execution
authority (`execute: true`) is separate from filesystem grants and is never granted
by Intent IR v0 or delegated to child artifacts. This is full executable-code
authority, reserved for the trusted compiler/test driver. Unknown target IDs fail.
There is no arbitrary program-name/process-spawn operation in Kelft-SH. The
[direct Linux artifact registry](native-artifacts.md) supports supplied ELF64
x86-64 executables and optional pinned JavaScript/Wasm engines. Those optional
execution engines are not dependencies of native compilation or rebuilding.

The JavaScript host's fixed artifact registry supports `wasm` through an installed
Rust driver, alongside `javascript`. It never falls back between targets. The
WASI profile returns `DRIVER_REQUIRED` for `artifact_run`: external execution and
Intent fixture evidence use the [separate driver protocol](driver-protocol.md).

`utf8_decode` returns a recoverable Result; `bytes_to_string` traps on invalid UTF-8.
`create_dir` is bounded by write roots. `write_once` writes exclusively and permits
an identical-content retry, supporting content-addressed immutable ledger entries.

Filesystem paths use the current host's path rules through explicit host operations.
Recoverable filesystem errors use the language-defined codes ENOENT, EACCES, EEXIST,
ENOTDIR, EISDIR, or IO_ERROR; every adapter maps host errors into this set. EPERM is
normalized to EACCES. Permission-policy violations trap with KRT_CAPABILITY instead.
String split/replace use literal, nonoverlapping matches and preserve empty segments.
An empty separator traps with KRT_EMPTY_SEPARATOR, preventing UTF-16-based splitting.
Canonical persisted module identities use project-relative forward slashes. No
wall clock, environment lookup, randomness, or directory enumeration is exposed.
