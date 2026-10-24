# Direct native strings

This page specifies the Linux x86-64 string runtime. Canonical Core and the
`kelft-native/1` calling convention are unchanged. Backend-private layouts are
not application APIs.

`kelft-native-strings/1` uses the existing 40-byte owned-storage header with zero
children and mode zero. The payload is packed, valid UTF-8; header offset 8 holds
the byte length. Strings have no terminator and preserve embedded NULs, BOMs,
and distinct Unicode normalization forms. The allocator accounts for the entire
allocation, including its header, slab or page overhead and unused capacity.
The maximum payload remains 268435400 bytes, subject to the context heap limit.

Values are immutable. Helper inputs are borrowed; copies, concatenation, slicing
and byte-array conversion return owned values. Literals live in deterministic
read-only object data and are copied into owned storage when evaluated. The
trusted packed-copy helpers accept validated UTF-8 bytes. Public byte-array
conversion validates its borrowed source before allocating a string. Ordinary
frame cleanup, nested aggregate retention,
pattern bindings, `inout` replacement,
array snapshots and `array_pop` use the existing ownership machinery.

The string runtime supports string literals, `+`, `==`, `!=`,
`string_len`, `string_byte`, `string_slice`, `string_find`, `string_to_bytes`,
`bytes_to_string`, `utf8_decode`, `string_from_codepoint`, `i32_to_string` and
`string_to_i32`, `string_split` and `string_replace`.
Length, indices and search results use byte offsets. Byte access checks the
range before address arithmetic. Slicing checks both ranges before checking
UTF-8 boundaries, including empty slices: an empty slice inside a multibyte
sequence traps with `KRT_UTF8_BOUNDARY`. End-of-string boundaries require no
byte read. Search accepts a starting byte offset inside a multibyte sequence,
returns the first literal match at or after it, and returns the start offset
for an empty needle. Invalid ranges trap with `KRT_BOUNDS`.

Decoding rejects stray continuation bytes, invalid leads, truncated sequences,
non-continuation bytes inside sequences, overlong encodings, surrogates, and
values above U+10FFFF. It preserves BOMs, NULs and valid noncharacters. The
validator reads `Array<u8>` slots without allocating and checks that every
required continuation byte exists before accessing one. `bytes_to_string`
traps with `KRT_UTF8` on invalid input; `utf8_decode` returns an owned
`Result<string,string>` with `Error("INVALID_UTF8")`. Only successful decoding
allocates and copies packed string bytes. The recoverable error allocates its
message and Result, subject to the ordinary heap budget. No invalid string is
created. Later source-array mutation cannot alter a decoded string.

Codepoint creation accepts Unicode scalar values 0 through 1114111, excluding
55296 through 57343. Invalid inputs trap with `KRT_UNICODE` before allocation.
The emitted builder directly encodes one through four UTF-8 bytes into a new
owned string. It does not import a C encoder or OS conversion service.

Numeric formatting returns canonical signed ASCII decimal, including
`-2147483648`, with no plus sign or leading zeros. A fixed, initialized 16-byte
private stack buffer holds at most 11 bytes. Negative accumulation and division
by ten avoid negating INT_MIN. Only the finished string is allocated, at its
actual byte length; scratch space cannot consume the heap or escape the frame.

Parsing accepts the whole grammar `-?(0|[1-9][0-9]*)`, including `-0`, and only
values in the signed i32 range. Whitespace, plus signs, leading zeros, exponents,
separators, NULs, BOMs and non-ASCII digits are rejected. Invalid input returns
`Error("INVALID_I32")`; successful parsing returns `Ok(i32)`. The trusted parser
borrows its string and allocates nothing. It checks overflow before multiplying
and subtracting a digit, using negative accumulation for INT_MIN. Inputs longer
than 11 bytes are rejected before any payload read. A private raw i32 status
cell and an i32 result use the existing four-pointer ABI; this cell is unrelated
to source `inout` descriptors and never escapes the intrinsic lowering. Lowering
allocates the owned Result and, only on failure, its error message.

Split and replace use literal, non-overlapping matches, consumed from left to
right. An empty separator traps with `KRT_EMPTY_SEPARATOR`, including an empty
source. Split preserves leading, trailing and adjacent empty fields; an empty
source with a nonempty separator produces `[""]`. Replace treats replacement
bytes literally, including `$` sequences, and does not search inserted bytes.
UTF-8 scalar sequences, BOMs, NULs and normalization forms are preserved.

The trusted match counter borrows its inputs without allocating. Split counts
matches before allocating a fixed-size owned string array, then transfers each
new copied part into that array. Replace checks positive growth against the
268435400-byte payload limit before multiplication, allocates its exact final
length, and copies source ranges and replacement bytes into that allocation.
Shrinking arithmetic is bounded by the non-overlapping source matches. Neither
operation allocates a temporary match array or repeatedly grows its result.
No-match results are owned copies. Private range-copy operations accept only
ranges and capacities established by these builders; they expose no public
pointer interface. All source arguments are evaluated once, left to right,
before the separator check. Returned parts and replacements survive retiring
their borrowed inputs and use normal aggregate/frame cleanup.

Byte-array conversion creates the existing `Array<u8>` layout, with eight bytes
per element; it does not alias the packed string. Copy, concat, slice and
conversion and validation take linear time. Search currently uses a bounded naive byte search
and can take quadratic time; split and replace repeat that search in a count
pass and a copy pass. No efficient compiler-bootstrap claim follows.

Runtime builders and lowering must produce deterministic object bytes. Independently linked
native executables check behavior, ownership exhaustion, small-stack cleanup,
deterministic linking and absence of dynamic dependencies. A separate C ABI
probe checks packed bytes, borrowed inputs, owned results, u8/i32 result writes and
allocation bounds. It covers all 256 single bytes and 65536 byte pairs, 12 scalar
boundaries plus samples across the scalar range, eight guard-page cases, and
seven invalid codepoint requests. Tight-heap source fixtures verify that invalid
input is rejected before a string allocation; 20000-iteration loops verify
cleanup of valid results, recoverable errors and codepoint results. C remains a
test reference and is absent from program linking.

Numeric ABI probes independently check 36 boundary values, every value from
-4096 through 4096, and 4096 seeded full-width samples against C decimal
formatting. They check 32 malformed strings, 12 guard-page cases, borrowed-input
preservation, owned format results and both i32 output widths. A zero-budget
context checks the allocation-free parser. Shared source fixtures also check
negative zero, exact-size formatting, Result lifetimes, argument evaluation and
20000-iteration cleanup under a 4096-byte heap ceiling and 128 KiB stack.

Transform ABI probes independently compare 11648 ternary-byte source,
separator and replacement combinations with a bounded C reference. They check
borrowed-input preservation, owned results after input retirement, match-result
width, six guard-page cases and three early traps, including multiplication
that would wrap a large replacement into a small allocation. An unmatched
replacement with an unreadable payload and large declared length verifies that
no replacement-sized allocation or payload read occurs. Shared fixtures
cover UTF-8, overlap, literal replacement, evaluated inputs, array snapshots,
pop, lifetime and heap exhaustion. 20000-iteration loops use 8192-byte budgets
for split/nested arrays and 4096 bytes for string-only replacement, with 128 KiB
stacks. The split budget accounts for both charged slab size classes.

The [standard-stream runtime](native-streams.md) provides borrowed,
allocation-free `print`, `println`, and `eprint` with checked Linux writes and
exact byte output. [Ordered maps](native-map.md) and
[recursive graphs](native-graph.md) share this storage and ownership layer.