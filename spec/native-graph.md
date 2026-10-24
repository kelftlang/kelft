# Recursive aggregate graphs

The Linux x86-64 direct backend supports finite values of
recursive and mutually recursive records, enums and generic enums, including
recursion through arrays, maps, tuples, Option and Result. Canonical Core and
the four-pointer ownership ABI remain unchanged. Public Kelft gains no pointers.
Owned values still form acyclic reference graphs, possibly with shared children;
this is recursive type support, not a cycle collector or general FFI.

Layout discovery registers a complete field/variant shape before following its
references. References to an already discovered type close the type graph rather
than recursively expanding it. Newly discovered nesting remains bounded at 64;
malformed fields, variants, type references and accesses still fail validation.
Existing immutable ownership bitmaps, evaluated locations, copy-on-write and
iterative destruction apply to recursive values without a new heap layout.

## Descriptors and equality ABI

Object metadata records `graphABI: kelft-native-graphs/1`. Each program contains a
deterministic read-only `k_graph_types` table of little-endian i32 words. A
descriptor starts with `(kind,count)`, followed by byte offsets relative to the
table base. It contains no host addresses or recursive inline layouts.

| Kind | Meaning | Offset entries |
|---|---|---|
| 0 | i32 or bool | None |
| 1 | u8 | None |
| 2 | Packed string | None |
| 3 | Record or tuple | Field type descriptors |
| 4 | Array or map storage | One element type descriptor |
| 5 | Enum | Variant payload descriptors, in tag order |
| 6 | Enum payload | Payload field type descriptors |

Primitive i32/u8/bool descriptors begin at offsets 0/8/16. Other offsets follow
deterministic layout discovery order. Enum payload descriptors include their own
header and field offsets; their data begins at object offset 48. Record/tuple
fields and array/map elements begin at 40. Ownership bitmaps remain separate.

Trusted Kelft builders emit `k_graph_equal` with argument slots
`(table pointer, table byte length, root descriptor offset, left cell pointer,
right cell pointer)`. Its inputs and all reachable values are borrowed. A scalar
cell contains exactly its scalar width; an aggregate cell contains a pointer.
The helper returns i32 0/1 and writes exactly four result bytes. It validates
descriptor size/alignment, kind, count, offsets, enum tags, required payload
extent and non-null aggregate inputs before the corresponding reads. This is a
private trusted ABI, not a validator for arbitrary forged heap objects.

Equality compares string content, selected enum payloads, record fields and
ordered array/map elements. Equal aggregate pointers can skip traversal, but
different sharing patterns do not affect the result. The compiler does not perform
recursive equality code expansion; the runtime also makes no recursive graph
comparison calls.

## Bounded traversal and ownership

The helper reserves 32 continuation frames in its fixed machine frame. Each
32-byte continuation stores two borrowed cell pointers, a descriptor offset
and the next child index. It visits one child at a time and only saves a parent
when children remain; wide arrays do not create one pending frame per element.
Last-child traversal reuses the current frame.

Overflow allocates 1032-byte payload chunks through the existing bounded heap.
Each chunk contains an owned predecessor pointer and 32 continuations. Borrowed
input pointers are never registered as owned children. Draining a chunk restores
its predecessor and releases it; both successful and unequal returns release
all remaining workspace. Normal comparisons preserve input reference counts and
live heap charge. Overflow can increase peak charge and traps with `KRT_RESOURCE`
when the existing heap budget cannot accommodate it. The 256 source-call limit
and maximum heap budget remain unchanged. Traps terminate the process.

This walker bounds machine-stack use, not total work. It does not memoize pairs
of previously compared DAG nodes, so independently allocated shared graphs can
require work proportional to their expanded traversal. These bounds alone do not establish compiler-bootstrap efficiency or native
performance.

## Verification requirements

Checks must cover recursive, mutually recursive, and generic layouts; arrays,
maps, and Option values; copy-on-write, sharing, matching, wide traversal, and
cleanup. Deep-chain comparison and destruction must remain bounded under a
small machine stack. Equality-workspace exhaustion must trap after input
construction rather than accidentally passing through an earlier failure.

Independent ABI probes must verify borrowed inputs, four-byte results,
workspace reclamation, iterative destruction, exact scalar/pointer/descriptor
reads, and rejection of truncated enums before tag access. Malformed descriptors,
extents, tags, nulls, and exhausted resources must trap. Objects and linked
executables must retain reproducible identities, including in paths with spaces.
