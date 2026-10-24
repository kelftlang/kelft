# C/native profile v1

The C backend emits C17 directly from validated canonical Core. Compiler output
contains no JavaScript/Wasm interpreter or code-generation framework. Linux
x86-64 execution uses pinned Clang 21.1.8; backend-local layouts are not Core ABI.

All operands, call arguments and location keys evaluate left to right in explicit
temporaries. Boolean operators short circuit. `inout` locations retain evaluated
keys and read the current root when used. Iteration observes a collection snapshot.
Integers use unsigned intermediates for wrapping and explicit division traps.
Strings preserve UTF-8 bytes, byte ordering, and checked code-point boundaries.

Aggregates and strings use local reference counts. Mutation copies shared backing
storage before replacing a root. Each invocation owns a bounded frame of value
slots; replacing a slot releases its previous value and returning releases the
frame. Runtime allocations have a 256 MiB default total limit and calls have a
256-frame limit. Exhaustion traps as `KRT_RESOURCE`. These resource limits belong
to this runtime profile, not application meaning. Runtime traps retain the shared
`error[KRT_*]` stderr format and exit status 1.

Native host access remains deny by default. Externally granted permissions are
intersected with compiled maximum restrictions. Filesystem/process services are
implemented as narrow host mechanisms, not as additional language semantics.
Unsupported host operations must remain diagnosed or explicitly unavailable;
they cannot silently become successful results or trusted verification evidence.

Portable C generation and Linux execution are separate build steps. Native
artifacts bind compiler, C source, runtime, Clang, flags, dependency and target
hashes. Reproducibility compares artifacts within that pinned toolchain.

`kelft build file.kelft --target c -o build/program.c` emits source. The trusted
JavaScript command driver additionally implements `--target native`, invoking
the digest-pinned Clang container and writing an executable plus `.build.json`
provenance. `run --target native` executes it in a network-isolated container.
Native runtime paths refer to the Linux `/work` project mount; caller grants must
use that namespace or project-relative paths. C output supports the POSIX
filesystem intrinsics with descriptor traversal and policy checks. Delegated
`artifact_run` execution is currently unavailable in this native host profile
and returns `UNSUPPORTED_ARTIFACT_TARGET` after checking execution authority.
Native HTTP, database and OIDC commands require the subsequent service profile.
