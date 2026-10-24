# Process arguments and Intent guard execution

The direct Linux x86-64 backend implements `args()` and executes
compiler-inserted Intent guards from canonical Core. Target availability depends on the installation and release.

`kelft-native-process/1` extends the owned-storage context's unchanged 64-byte
prefix to 80 bytes. Offset 64 holds the i32 kernel argument count including the
program name, 68 is reserved zero, and 72 holds a borrowed argv pointer. The
aggregate startup captures the initial kernel stack before alignment, initializes
the heap prefix, and stores this process state before entering language code.
The [filesystem adapter](native-filesystem.md) extends aggregate startup to a
104-byte host context within a 128-byte stack reservation. Heap/scalar helpers and their independent 64-byte context probes
remain compatible; `k_args` specifically requires the declared process extension.
Objects record `processABI` and `startupContextBytes`; the ownership calling
convention remains `kelft-native/1`.

Trusted Kelft private-IR builders emit `k_args` and `k_process_string`. No C runtime, assembler or dynamic OS library is
added. Arguments exclude argv[0], preserve empty values, Unicode and spaces, and
return a freshly owned array of owned immutable strings. Raw kernel argument
memory remains borrowed and unchanged. Repeated calls return independent values;
ordinary aggregate copy-on-write and frame cleanup apply. Invalid UTF-8 traps
with `KRT_UTF8`. Invalid private counts/pointers and exhausted heap budgets trap
with `KRT_RESOURCE`. Lengths and allocation arithmetic are bounded. UTF-8
validation currently uses budgeted temporary byte arrays; no efficiency claim is
made for large arguments. Environments, executable paths and process authority
are not exposed by this interface.

The independent C harness verifies 256 ownership trials, 1024 arguments, 33
guard-page strings, an argv table ending at a guard page, ignored/inaccessible
argv[0], four-pointer result widths and caller canaries. Seven fatal probes cover
counts, pointers, invalid UTF-8 and allocation denial. Every full or focused
native collector additionally executes a production-linked program with an
invalid UTF-8 kernel argument. Required probes cannot disappear through fixture
selection. The 40 KB argument fixture runs natively on Linux; JavaScript comparison
on Windows omits it because of the host command-line length limit.

Intent guards execute as canonical Core, including scalar preconditions and
postconditions and nested UUID, Array, Option, Result, Map, tuple, and forwarded
`inout` checks. Failed preconditions prevent body output; failed postconditions
retain body output and terminate with `KRT_CONTRACT`. Optional preferences do
not become guards. Guard lowering must preserve the declared contracts.

Arguments and guard execution do not confer filesystem or linker authority.
Canonical paths and authorized I/O use the [filesystem contract](native-filesystem.md);
artifact execution uses the [fixed registry](native-artifacts.md). Execution of
an individual guard does not establish application acceptance.