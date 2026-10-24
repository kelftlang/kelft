# Direct enums and Option

The Linux x86-64 aggregate emitter supports recursive user enums,
instantiated generic enums, `Option<T>` and `Result<T,E>` when their payload types
are supported by the backend. The [UTF-8 string runtime](native-string.md)
also supports string payloads, including Result errors. The
[graph runtime](native-graph.md) adds recursive layouts and iterative equality. Canonical Core 0.1 and the four-pointer `kelft-native/1`
calling convention are unchanged. This representation alone does not establish target availability.

## Private representation

Object metadata identifies `kelft-native-enums/1`. Values use the existing
40-byte `kelft-owned-storage/2` header and a variant-specific payload:

| Offset | Contents |
|---|---|
| 24 | Borrowed pointer to the immutable ownership bitmap |
| 32 | Child mode 2 (mixed scalar/owned slots) |
| 40 | i32 tag in an eight-byte scalar slot |
| 48 + 8 × i | Payload argument i, stored at its machine width |

The payload byte count and child count include the tag slot. Bitmap byte 0 is
zero; each following byte is zero for scalar payloads or one for owned aggregate
payloads. The bitmap lives in the object's read-only data and remains valid for
the process lifetime. Iterative destruction and cloning use the existing mixed
layout operations. Tags and scalar data must never be treated as references.

User enum tags follow their Core declaration's variant order. Builtin tags are
Some=0, None=1, Ok=0 and Error=1. These numbers are private and do not form a public
foreign aggregate layout. Each variant allocates storage, including variants
without payloads. Different variants may have different sizes and ownership
bitmaps; no inactive union fields exist.

The trusted Kelft private-IR builder emits `k_variant_alloc(tag, arity, bitmap)`.
It checks negative tags and arities, bounds arity before adding the tag and
multiplying by eight, then calls the bounded allocator. The existing allocator
rejects a missing bitmap. Source payload expressions evaluate left to right
before allocation. Owned payloads are retained into the new object; input values
remain borrowed and the returned object is owned.

## Matching, equality and pop

Match subjects evaluate once and retain their snapshot. Variant conditions test
the tag before loading any payload, including nested variants. Tuple and Boolean
patterns compose with variant patterns. Selected arms retain owned bindings and
retire them on normal exits, return, break and continue. Pattern bindings cannot
consume their subject's ownership. The source frontend checks exhaustiveness;
an unmatched path in externally supplied Core defensively terminates with
`KRT_RESOURCE` rather than reading nonexistent fields or falling through.

Array iteration also supports nested irrefutable tuple patterns and patterns
for enums with one variant and irrefutable payloads. Refutable iteration patterns
fail validation. Equality dispatches on equal tags before comparing the selected
payloads structurally. Different variants compare unequal regardless of size.

`array_pop` resolves its evaluated location for reading. For an empty array it
returns an allocated None without cloning or replacing any enclosing owners.
For a nonempty array it retains the last element into Some, copies the remaining
elements, resolves the location for writing and replaces its array owner. This
preserves iteration snapshots, shared parents and the popped value's lifetime.

## Costs and compatibility

This is a conservative representation for correctness and portability. Nullary
variants allocate, and nonempty pop copies the remaining elements in linear
time. No efficient self-compilation or performance advantage is claimed.
Allocation and copying costs must be assessed independently of correctness. Representation changes
must preserve the ABI's ownership rules and renew object/provenance evidence.

Target support and platform qualification depend on the selected installation
and release. Storage-layout changes must preserve ownership and ABI contracts.

## Verification

Verification must cover nested tags, mixed payloads, equality,
source order, owned calls/results, snapshot mutation, generic enums, loop exits,
20,000 cleanup iterations under tight budgets, and an empty nested pop whose
shared parent cannot fit a clone in the remaining budget.

The lowerer rejects malformed enum declarations, constructors and patterns
before writing an object. The independent C ABI probe tests mixed payload
ownership, clone/release counts, nullary variants and five invalid allocation
requests. C is a test dependency only; source executables link with GNU ld alone.
Reports bind source, checkout, fixture and artifact identities and retain
`releaseEligible: false`.
