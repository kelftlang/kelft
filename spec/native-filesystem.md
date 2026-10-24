# Capability-enforced Linux filesystem access

The direct Linux x86-64 backend implements `canonical_path`,
`read_file`, `read_text`, `create_dir`, `write_file`, `write_text` and
`write_once`. Artifact execution uses the separate
[fixed registry](native-artifacts.md).

`kelft-native-fs/3` extends the unchanged 64-byte owned-storage prefix and
80-byte process prefix to 128 bytes: borrowed kernel environment at 80, owned
caller/maximum read roots at 88/96 and owned caller/maximum write roots at
104/112, intersected execute permission at 120 and zero reserved storage at 124.
Aggregate startup reserves 144 bytes, captures argv/environment before entering language code, and
zeros the policy pointers. Programs with filesystem or artifact execution effects initialize policies. Normal entry return releases all four root arrays before the existing zero
live-heap assertion. Arguments and heap helpers still need only their respective
prefixes; no public pointers or unsafe operations are introduced.

Object emission accepts an explicit canonical JSON maximum policy as its third
backend argument. It validates read/write string arrays, boolean execute,
known keys, Unicode, NUL and path lengths before emission, and records the
maximum in object metadata and read-only data. The default maximum denies all
filesystem access. Emission does not inspect caller grants, cwd or filesystem
contents. The Kelft wire test driver accepts the same optional `maximum` string.
This backend interface does not introduce a public CLI command.

At execution time, the runtime reads only `KELFT_CAPABILITIES` from the captured
environment. Missing grants deny access. Duplicate environment definitions,
unknown/duplicate JSON keys, invalid arrays, booleans, escapes or surrogate pairs,
NUL paths and trailing input fail closed. The parser handles all JSON string
escapes and whitespace, with a 1 MiB policy bound. Caller and maximum read/write roots
are canonicalized once during policy initialization and must both authorize the
canonical path at component boundaries. Replacing a grant root with a symlink
cannot redefine its authority. Write/execute
grants never supply read authority. Both file and directory roots are supported.
Program code cannot access or alter the private policy arrays. Compiler/linker
authority is not inherited.

Canonicalization uses `openat2` with `O_PATH` and `RESOLVE_NO_MAGICLINKS`, then
reads the descriptor's physical name through `/proc/self/fd`. Ordinary internal
relative/absolute symlinks work. Missing suffixes resolve against an existing
parent; dangling final links are resolved explicitly. Escaping links, link loops
and proc-style magic links are rejected. Paths have a 4095-byte bound and
canonicalization a 40-step bound, matching the existing native profile's bounded
path approach. Kernel `openat2` and mounted procfs are required; missing mechanisms
fail required native checks rather than trigger a fallback.

Before reading payload bytes, the runtime anchors a directory descriptor at the
chosen grant's parent and opens the already-authorized relative path using
`RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS`, `O_NOFOLLOW`,
`O_CLOEXEC` and `O_NONBLOCK`. Replacing a path component with a symlink after
authorization cannot redirect the read outside the grant. A replacement may
produce an I/O error. Stable symlinks work through the initial canonicalization.
Directory descriptors are private and are closed on normal success/error paths.

Reads use heap-accounted growing buffers, retry `EINTR`, preserve partial reads,
and reject oversized kernel results before using them. `read_file` returns owned
bytes including arbitrary binary data; `read_text` validates UTF-8 and preserves
NUL/BOM bytes. Normal I/O failures return the existing `ENOENT`, `EACCES`,
`EEXIST`, `ENOTDIR`, `EISDIR` or `IO_ERROR` results. Invalid text traps with
`KRT_UTF8`; heap exhaustion traps with `KRT_RESOURCE`. Traps terminate the process;
the normal cleanup assertion is not recovery from traps. Nonblocking reads from
nonregular sources may return `IO_ERROR`; this file API does not establish stream
or device behavior as part of the file API.

Trusted Kelft private-IR builders implement policy parsing, authorization, and
reads/writes. Production objects import no C runtime and link using the pinned
system linker. Validation must execute real filesystem operations, including
magic-link denial and heap exhaustion under the runtime's allocation accounting.

Independent C probes check 256 policy models, 256 read/cleanup trials, guard-page
input, 25 malformed policies, eight error mappings, borrowed inputs, owned
results, status/result canaries, and descriptor counts. Test-only weak mechanisms
inject interrupted/partial/failed/oversized reads and replace a directory with an
escaping symlink after authorization, and replace the grant root after policy
initialization. Code and complete unwind sections remain
unchanged in the mock copy. C is a test dependency only.

Writes use a descriptor walk over the authorized canonical absolute path. Every
component opens with no symlink following and beneath-directory resolution;
final file creation uses `openat2`, mode 0600, no-follow, close-on-exec and
nonblocking flags. Text writes preserve UTF-8/NUL/BOM; binary writes preserve
arbitrary bytes. Ordinary writes create or truncate without creating parents.
They retry interrupted calls, advance through partial writes, return IO_ERROR
on zero writes, reject oversized syscall results with KRT_IO, and report final
close errors. A failed ordinary write can leave a partial file, matching the
existing native profile; these operations do not promise atomic replacement.

`write_once` uses exclusive creation. An existing file additionally requires
read authority in both policies before UTF-8 comparison. Identical text succeeds;
different text or an unreadable existing file returns EEXIST, and invalid UTF-8
traps. Existing contents are never overwritten. A new exclusive file requires
write authority; execute grants confer no I/O authority.

`create_dir` recursively creates directories with mode 0700. Each missing
ancestor needs its own write authorization before any mkdir. A child-only grant
cannot create an ungranted parent. Existing directories succeed and existing
files return EEXIST. Descriptor traversal rejects links inserted after initial
canonicalization. Permission modes are verified on the container's Linux tmpfs,
independently of bind-mounted host filesystem behavior.

The independent write suite runs 256 ownership/lifetime trials, checks result
width, file/directory modes and descriptor counts, and injects interrupted,
partial, zero, oversized and failed writes, close errors, final-component and
mkdir races, and grant-root replacement. Mock copies retain the complete
production code and unwind sections. Real write fixtures reset their tree before
each native and C execution; a complete tree snapshot must agree across backends,
and outside-file contents plus explicit expected changes are checked separately.
The lowerer rejects malformed write Core before object production.

Focused checks must retain the required runtime and ABI probes and identify
their fixture selection. Reports remain bound to their actual source and tool
inputs; selected checks alone do not establish platform qualification.