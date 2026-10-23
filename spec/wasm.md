# Wasm backend and WASI profile 0.1

The target ID is `wasm`; its runtime profile is `wasi-preview1`. Artifacts are
WebAssembly 1 binary command modules exporting `_start` and `memory`. Imports are
exclusively functions from `wasi_snapshot_preview1`. Binary emission belongs to
the backend: it uses no WAT conversion, external assembler, LLVM, or other
code-generation framework. Wasmtime executes the already-emitted modules.

Core remains unchanged and target independent. Backend-private instructions,
value tags, memory offsets, calling conventions, and allocation headers are not
Core operations or public language types. The Kelft encoder, lowering, and embedded runtime instructions provide the
source implementation of this profile.

## Values and ownership

Scalars use tagged integer values; aggregate handles carry 32-bit linear-memory
offsets. Functions transfer owned by-value arguments and return owned values.
Borrowing runtime helpers retain returned children; callers release temporaries.
`inout` locations borrow a live root cell and own their evaluated-once path.
Forwarding extends that path without escaping the root's lifetime.

Arrays use persistent radix-32 trees; maps iterate sorted key/value tuples.
Structs, tuples, and variants contain immutable value slots. Mutations rebuild
the affected path. Loop snapshots and match temporaries remain alive through
their scopes and are released on exits, including early returns.

Strings are immutable UTF-8 views over reference-counted byte buffers. Concatenation
may append beyond every existing view, but cannot modify an existing view's length
or bytes. Slices retain backing storage. Buffers grow by copying when appending
would overlap an existing value. The allocator reuses power-of-two size classes;
storage strategies are private implementation choices.

Arithmetic, structural equality, UTF-8 validation, and language traps retain the
language specification. Main's i32 return is an exit code in 0..255; other values
trap with `KRT_EXIT`. Engine failures and resource exhaustion are infrastructure
failures, not successful fixture evidence.

## Host operations and paths

WASI paths use a POSIX guest namespace. Drivers map host directories to stable
guest paths and preserve project-relative module identities. The profile initially
supports directory capability roots within the explicit project root. The driver
rejects roots outside that boundary; it never widens a preopen to make them work.
File effects are compared using guest paths rather than host drive letters.

Filesystem calls resolve links and existing ancestors, check containment, and
intersect external grants with the artifact's embedded maximum policy. Grants
are denied by default. Read-only preopens are also enforced by the stock WASI
implementation. Recoverable errors use the shared ENOENT/EACCES/EEXIST/ENOTDIR/
EISDIR/IO_ERROR vocabulary. Policy denial traps with `KRT_CAPABILITY`.

The trusted host supplies only `KELFT_WASI_CAPABILITIES`. Its private encoding is
`1` followed by records: a kind byte (`r`, `w`, or `c`), decimal UTF-8 byte length,
`:`, and the exact path bytes. `r`/`w` grant operation roots; `c` sets the logical
working directory. Example: `1r8:/projectw7:/outputc8:/project`.
Source programs have no environment-reading or environment-writing primitive.
No network, clock, randomness, arbitrary subprocess, or FFI API is exposed.

`artifact_run` returns `DRIVER_REQUIRED` in this profile. External execution uses
the separate [driver protocol](driver-protocol.md), never proprietary Wasmtime
imports. Direct compilation and deterministic Intent inspection need no driver API.

The default module memory maximum is 1 GiB. The trusted driver bounds execution
time and captured output separately. Host-runtime resource failure withholds
successful evidence. These bounds do not claim an operating-system sandbox for
an external coding agent.
