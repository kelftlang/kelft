# Aggregate Core

The Linux x86-64 aggregate lowerer in `selfhost/direct/aggregate.kelft` consumes
canonical Core 0.1. Objects contain the owned-storage runtime, evaluated-location
helper, entry wrapper, and source functions.

Supported values are i32, u8, bool, [immutable UTF-8 strings](native-string.md),
tuples, arrays, [ordered maps](native-map.md), recursive nested structs and
[recursive enums](native-enum.md), including instantiated generic types and builtin
Option/Result with supported payload types. Records and tuples use the private
40-byte storage header and eight bytes per declared field. Strings use packed
bytes after that header. An immutable bitmap identifies owned
aggregate fields; scalar fields are not references. Record initializer values
are evaluated in source order and stored in declaration order. Field access
retains aggregate results. Equality compares fields structurally, including
nested records, tuples, arrays, maps, strings and enum payloads; pointer identity is not language equality.

`Array<u8>` stores one byte per element; other arrays store eight bytes per
element after the storage header. Header 36 distinguishes packed byte storage
(negative, bitwise-complement capacity) from slot storage (nonnegative capacity).
Length is the payload byte count divided by the corresponding stride.
Packed allocations through nine bytes retain the former slab size class, while
keeping logical byte length and one-byte indexing; larger payloads use packed
capacity without that small-object reservation. Scalar elements use child mode 0; owned
elements use mode 1 with child count equal to length. There is no public pointer
or aggregate layout. Construction evaluates every element left to right before
allocation. Index reads retain owned elements; writes copy shared enclosing
aggregates and preserve snapshots. Indices are checked before address arithmetic.
Invalid indices and slice ranges produce `KRT_BOUNDS`.

`array_len`, `array_push`, `array_slice` and `array_pop` are implemented. Push
reuses reserved storage only when its array is uniquely owned. Growth reserves
up to twice the live payload, charges the complete allocation, copies live
elements and retains owned children. Shared arrays preserve their snapshots.
Slices copy their selected elements. Nonempty pop also copies its
remaining elements and returns an owned Option. Empty pop leaves its source and
enclosing parents unchanged. Allocation checks the maximum
element count before scaling by the storage stride and charges the existing heap budget.
Equality compares lengths and elements structurally, using emitted loops for
arrays. The [graph walker](native-graph.md) uses typed descriptors and an iterative
continuation stack for recursive and deep values.

Array `for` loops support bindings, wildcards and nested irrefutable tuple or
single-variant enum patterns. The iterable is evaluated
once and retained as an iteration snapshot; mutations, pushes and reassignment
of its source do not alter the iteration. Owned elements are retained into loop
bindings and retired on normal iteration exits, break, continue and return.

Layout validation rejects duplicate/missing/mistyped fields, malformed accesses,
excessive layout nesting and unsupported types before writing an object. Newly
discovered type nesting is limited to 64 and the existing private IR limit of 4096 slots per
function still applies. Recursive type references close the layout graph.
Iteration outside arrays/maps,
compiler-owned contract
intrinsics and host interfaces remain unsupported. Support for a particular program depends on its selected target profile.

## Ownership and cleanup

Helper and source-function arguments remain borrowed. Value parameters are
retained into owned local slots. Aggregate expression results and local bindings
have explicitly tracked owners; the function entry initializes those slots to
null, including slots in branches that may not execute. Reusing a slot retires
its previous owner. Assignments retain the replacement before releasing the old
owner, so self-assignment and shared-child replacement are safe.

Statement boundaries retire temporary owners. Lexical block exits retire local
owners; break and continue retire owners within the exited loop scope. Returns
retain the result, retire every active owner in the frame and restore call
depth. Borrowed inout roots belong to the caller and are not retired by the
callee. The existing 256-call limit and 256 MiB maximum heap ceiling remain.

The entry wrapper checks that the heap's live charge returns to zero after a
normal entry return. Conformance probes lower the heap ceiling to 4096 bytes and
repeat allocation, reassignment and calls 20,000 times, including nested loop
exits. Traps and explicit process exit terminate the process; the normal-return
assertion does not claim recovery or cleanup hooks on those paths.
The owned-array iteration fixture uses 8192 bytes because its array and records
require two slab size classes. Scalar-array push/slice cleanup still uses 4096.

## Evaluated locations

Aggregate-mode location arguments point to opaque stack descriptors. A root
descriptor contains its borrowed cell pointer at offset 0 and -1 at offset -8.
A child descriptor contains its borrowed parent descriptor pointer at 0 and
the evaluated field byte offset at -8. The negative offset follows the private
slot layout; it is not a public aggregate or foreign calling convention.
An indexed child contains -2 at offset -8 and its evaluated i32 index at -16;
its borrowed parent descriptor pointer remains at offset 0. Root and field
descriptors retain their existing two-slot representation.

Descriptors remain alive in caller frames and may be forwarded through inout
parameters. A field store evaluates its location before its right-hand side,
then resolves the descriptor against the current root. This preserves updates
when the right-hand side replaces an enclosing aggregate. Writes make each
enclosing owner unique before descending; reads leave ownership unchanged.
Snapshots and sibling fields retain their prior values.
Before a write allocates any clones, a read-only traversal validates every index
against the current root. A subsequent write traversal performs copy-on-write.
This keeps a nested bounds error ahead of clone-budget exhaustion, including
when the right-hand side shrinks or replaces the source array.

The trusted Kelft location builder emits an iterative traversal. It uses no
recursive helper calls or auxiliary heap allocation. Its conservative reverse
walk takes quadratic time in path depth; writes perform two traversals. The
existing language rejection of overlapping inout
arguments is unchanged.

## Verification requirements

Validation must cover accepted and rejected layouts, indices, patterns, and
ownership transfers before object emission. Runtime checks must cover borrowed
inputs, owned results, exact result widths, frame cleanup, snapshot isolation,
evaluated locations, allocation overflow, and small-heap exhaustion. UTF-8,
numeric, and transformation cases must include malformed input and guard-page
boundaries. Native linking must preserve deterministic objects and executables,
including paths containing spaces.

The [stream](native-streams.md), [path](native-paths.md),
[process](native-process.md), and [filesystem](native-filesystem.md) contracts
specify their additional ABI and host checks. Fault-injection copies must retain
the production code and complete unwind metadata apart from the deliberately
replaced mechanism. Testing tools do not become program runtime dependencies.
