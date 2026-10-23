# Linux POSIX paths

The direct Linux x86-64 backend implements `path_dirname`, `resolve_path`,
`path_relative`, and `current_dir`. Lexical path operations do not grant
filesystem or subprocess authority.

Private helpers use `kelft-native/1` and object metadata `pathABI:
kelft-native-paths/1`. String arguments are borrowed and returned strings owned.
Context layout and canonical Core are unchanged. Kelft private-IR builders must emit deterministic complete objects.

Lexical operations follow POSIX paths, regardless of the compiler host. A slash
separates components; backslashes are ordinary bytes. `resolve_path` removes
empty, `.` and `..` components, clamps parents at root, and removes trailing
slashes except at root. An absolute second argument replaces the base. Relative
bases resolve against the executing process's working directory. `path_relative`
compares normalized absolute paths at component boundaries, returns an empty
string for equal paths, and uses `/` between components. `path_dirname` preserves
the POSIX double-slash spelling and internal redundant separators, as the existing
JavaScript POSIX implementation does. Unicode and embedded NUL bytes survive
lexical processing. NUL does not become permission to pass an invalid OS path.

These operations do not access path contents, follow symlinks, canonicalize
filesystem objects, or grant filesystem/subprocess authority. Object generation
does not read or embed the compiler host's working directory. An absolute
`resolve_path` needs no working-directory syscall.

`current_dir` uses Linux x86-64 syscall 79 through `k_os_getcwd`, returning the
actual execution-time directory. Kernel buffer growth (`ERANGE`) retries with
doubled, heap-accounted storage. Nonpositive results, malformed lengths, missing
NUL terminators and nonabsolute results trap with `KRT_IO`; invalid UTF-8 traps
with `KRT_UTF8`. This is not a filesystem authorization check. The raw mechanism
returns the signed kernel result in exactly four result bytes, including the
terminating NUL in successful byte counts. Its register clobbers respect System V
AMD64. No libc or additional production tool dependency is introduced.

Lexical workspaces, cwd buffers and returned values count toward the existing
heap limit. Length growth is bounded before allocation; scratch storage is
released on normal returns. Traps terminate the process. Inputs, their reference
counts, call depth and caller result canaries are checked by an independent C
harness. C is a test dependency only.

Validation includes eight source fixtures, deterministic object
bytes, 4,370 deterministic Node POSIX oracle cases, six guard-page strings,
allocation failure, real cwd, long Unicode cwd, deleted cwd, invalid UTF-8 cwd,
and seven injected syscall sequences. Injection weakens only the mechanism
symbol in a test copy; code and unwind sections remain byte-identical. Production
objects retain their complete unwind metadata. Existing aggregate, stream, map
and deep-graph ABI probes run alongside these checks.

Focused checks must retain the required runtime and ABI probes and identify
their selected fixtures. Reports bind source, toolchain, and artifact hashes;
a focused pass does not establish full-corpus or platform qualification.

[Arguments and inserted Intent guards](native-process.md) are implemented and
tested separately. [Canonical paths and reads](native-filesystem.md) now have
separate authority checks. Write operations and artifact execution remain unsupported. Full native Intent integration, actual baseline isolation, standalone
driver/closure, native self-compilation and all six release lanes remain required.
