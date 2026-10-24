# Direct native standard streams

The Linux x86-64 runtime implements `print`, `println`, and `eprint` under the
following stream contract. Target availability and platform qualification are
specified by each compiler release.

`kelft-native-streams/1` uses the unchanged `kelft-native/1` four-pointer calling
convention and 64-byte context. Each intrinsic takes one borrowed packed UTF-8
string and returns void without writing a result buffer, allocating, retaining
or releasing the input. The argument is evaluated once before output. `print`
and `println` select descriptor 1; `eprint` selects descriptor 2. `println`
writes exactly one LF after its payload, including an empty payload. NULs,
CRLFs, BOMs and Unicode normalization forms are preserved byte for byte.
Output is synchronous and unbuffered in the language runtime; these calls
complete before a subsequent explicit process exit. Calls are not transactional
or guaranteed to be atomic across processes or between stdout and stderr.

Kelft private-IR builders emit the checked write loop. A narrow
Linux mechanism emits `write` directly, returning an i32 count or negative kernel
errno through the result pointer. Nonempty output retries EINTR with the same
range, advances by positive partial counts and checks each count before pointer
arithmetic. Zero progress, an oversized count, invalid private lengths and hard
errors (including EAGAIN) trap with `KRT_IO`. Empty `print`/`eprint` calls make no
syscall, even if their descriptor is closed. Diagnostics use the existing
best-effort stderr trap path; if stderr is closed, exit 1 still occurs without a
diagnostic. These error rules do not introduce a recoverable stream
API or change the existing JavaScript, Wasm and C drivers.

The process inherits its SIGPIPE disposition. With the default disposition, a
broken pipe terminates it with SIGPIPE. With SIGPIPE ignored, `write` returns
EPIPE and the checked helper traps with `KRT_IO`. The runtime does not install
signal handlers or alter the signal mask. Other inherited-descriptor properties,
such as blocking mode, are also retained.

Core cannot select, open or redirect descriptors. There is no stdin reader,
arbitrary descriptor API, file access, subprocess execution or signal interface.
The existing empty filesystem/execute maximum remains enforced by the supported
operation set. A caller may redirect inherited stdout/stderr; this does not grant
the program filesystem paths or compiler/linker authority. The private raw write
mechanism and byte-range helper are trusted runtime interfaces, not source FFI.

Verification requires deterministic object bytes and statically linked
execution with exact output bytes. They include binary
controls, Unicode, CRLF, empty output, evaluation order, a 294912-byte payload,
and 20000-iteration cleanup under a 4096-byte heap and 128 KiB stack. A separate
C ABI probe verifies borrowed inputs, void/i32 output widths, zero allocation,
real pipe routing and preservation of stdin. A test-only weak mechanism allows
an independent C stub to inject partial writes, EINTR, zero progress, hard
errors and oversized counts into the emitted loop. Production objects remain
unchanged. All original code, FDE bytes and FDE relocations remain unchanged in the mock.
ELF writers bind FDEs to a local text-section symbol and the emitted body
offset; replacing a global function symbol cannot redirect its unwind record.
The injected mechanism calls an independent native unwinder, which must find
both the emitted stream-write frame and its print/println/eprint caller.
Fourteen required native checks cover those failures, invalid lengths,
closed descriptors, `/dev/full` and both SIGPIPE dispositions; language host
checks execute the actual linker-only program. This fault injection supplements
real execution and does not provide cross-target release evidence.

Verification reports must bind source, toolchain, fixture, original/mock object,
and ABI executable identities. Fault injection supplements real execution and
cannot establish qualification for a different target.