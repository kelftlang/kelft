# Ordered maps

The Linux x86-64 direct lowerer implements `Map<K,V>` for the language's four
key types: i32, u8, bool, and string. Values may use the other supported recursive
aggregate types, including nested maps. Target availability depends on the
selected installation and release.

`map_new`, `map_len`, `map_get`, `map_set` and `map_remove`, structural equality
and snapshot iteration preserve the existing Core schema and language semantics.
Integer keys sort numerically without overflow-prone subtraction. Boolean keys
sort false before true; strings compare unsigned UTF-8 bytes, preserving NULs
and normalization differences. Equal-content strings replace the existing entry.
Iteration supports the same irrefutable patterns as arrays, including a single
tuple binding or a destructured `(key,value)` pattern.

## Private layout and ownership

Object metadata records `mapLayout: kelft-native-maps/1`. A map is an owned-pointer
array of key/value tuple objects in sorted order. Each tuple uses the existing
40-byte heap header, two eight-byte field slots and a mixed-ownership bitmap.
The map array owns its entries; each entry owns its aggregate key/value fields.
Empty maps are allocated owned arrays. There is no public pointer or map layout.

Trusted Kelft builders in `selfhost/direct/map-runtime.kelft` emit
`k_map_compare`, `k_map_lower_bound` and `k_map_splice`. They use the existing four-pointer runtime ABI.
Comparison and search borrow a raw key cell and never allocate, retain, release
or modify inputs. Scalar key cells contain i32 (u8 keys are widened before
marshalling); string key cells contain a borrowed pointer. Comparison/search
return i32 and write exactly four result bytes. The scalar comparator returns
-1/0/1, and the string comparator returns a signed ordering value.

Splice borrows the map and optional entry and returns an owned array. Its index
is in `[0,length]`; removal count is zero or one and cannot exceed the remaining
entries. A null entry means deletion, otherwise it inserts one retained entry.
The existing allocation checks reject excessive output length before multiplying
by eight. These helpers are private trusted mechanisms, not general FFI.

Source lowering evaluates each location and argument once, left to right. Set
and remove resolve the evaluated location against its current root after
argument evaluation. Set builds a new entry and array, then makes enclosing
owners unique before replacing their map cell. Missing remove returns false
without allocating or cloning enclosing owners. Get returns an owned Option and
retains an aggregate value; replacing/removing its source does not invalidate it.
Updates preserve aliases, retained iteration snapshots and owned loop bindings.
Frame cleanup and the entry wrapper's zero-live-charge assertion also cover maps.

Binary search takes logarithmically many key comparisons; string comparisons
may scan their bytes. Successful updates copy array entries linearly. This
conservative representation establishes semantics; it does not claim efficient
compiler bootstrap or native performance. The [graph runtime](native-graph.md) adds recursive layouts and iterative equality.

## Verification requirements

Map checks must cover every key type, signed boundaries, Unicode/NUL ordering,
replacement and removal, structural equality, nested ownership, evaluated
locations, retained get results, snapshots, and heap exhaustion. ABI checks
must verify sorted entries, borrowed inputs, allocation-free search, owned
outputs, four-byte result writes, exact key-cell reads, reclamation, and rejection
of invalid input or growth before unsafe copying. Invalid signatures, key layouts,
and iteration patterns must fail before object emission.
