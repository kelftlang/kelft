# Owned storage foundation

`kelft-owned-storage/2` is a trusted private runtime layer for Linux x86-64.
Kelft builders in `selfhost/direct/heap.kelft` and `pool.kelft` emit verified
private IR. These storage and ownership contracts do not change public Kelft
or Core 0.1 semantics.

The owned-storage context prefix is 64 bytes: call depth at offset 0, charged live bytes at 4, peak
bytes at 8, and heap ceiling at 12, all i32, followed by six pointer heads at
offsets 16 through 56 for partially occupied slabs. Startup zeros the context
and initializes the heap ceiling
to 256 MiB. The aggregate [process adapter](native-process.md) adds an explicitly
identified extension to 80 bytes; the [filesystem layer](native-filesystem.md)
adds environment and policies through byte 103. Heap helpers still require only
this prefix. Development probes may lower it; helpers reject ceilings above
256 MiB, negative accounting and ceilings below one page.

| Header offset | Width | Meaning |
|---|---|---|
| 0 | i32 | Checked positive reference count while live |
| 4 | i32 | Number of eight-byte payload slots with ownership metadata |
| 8 | i32 | Requested payload byte length |
| 12 | i32 | Storage stride for pooled objects; mapping size for direct allocations |
| 16 | pointer | Intrusive pending-destruction link, valid only after count reaches zero |
| 24 | pointer | Immutable, process-lifetime child bitmap for mixed layouts |
| 32 | i32 | Child mode: 0 no children, 1 all pointer slots, 2 bitmap |
| 36 | i32 | Array capacity: nonnegative for slots; bitwise complement for packed bytes |
| 40 | bytes | Zero-initialized payload |

Mode 0 requires a zero child count. Modes 1/2 require the count to fit within the
payload; mode 2 requires a non-null descriptor when children exist. Descriptor
bytes identify owned pointer slots; zero marks scalar/raw slots. Descriptors are
trusted constant data, not user-provided pointers. Unused payload slots begin
null, so partially constructed objects can be destroyed. Objects form acyclic
value graphs; this layer does not collect arbitrary pointer cycles or validate
forged pointers.

Allocation checks signed arithmetic and the remaining budget before invoking
the Linux mmap mechanism. Every mapping is charged at 4096-byte granularity,
including allocator metadata, unused slots and rounding. Failure becomes
`KRT_RESOURCE`. The raw syscall
wrapper normalizes Linux error returns to null and requests read/write anonymous
memory without execute permissions. Munmap failure also traps. These narrow OS
mechanisms grant neither filesystem nor process authority. Linux mechanism
semantics follow [mmap/munmap](https://man7.org/linux/man-pages/man2/mmap.2.html)
and the [system-call ABI](https://man7.org/linux/man-pages/man2/syscall.2.html).

Each object has a hidden 16-byte prefix: its slab owner pointer at -16 and a
free-list link at -8. The link is used only while free. Allocation reserves
payload length plus 56 bytes, selecting the smallest of six strides: 64, 128,
256, 512, 1024 and 2048 bytes. Larger objects use a direct mapping, whose prefix
owner is null and whose base is 16 bytes before the object pointer.

A slab occupies one 4096-byte mapping. Its 64-byte header contains next/previous
partial-slab pointers at 0/8, the free-object head at 16, live-object count at 24,
capacity at 28, stride at 32, class index at 36 and list membership at 40. Fields
after the pointers are i32; remaining header bytes are reserved and zero.
Capacity is floor(4032/stride). Full slabs leave the partial list; freeing a slot
reinserts them. Empty slabs are removed and unmapped immediately. Doubly linked
lists allow empty slabs to be removed from any position. Direct allocations
include their prefix in page rounding; the maximum payload is 256 MiB minus 56.

Reused objects, payload and padding are cleared before their headers are
initialized. Slab occupancy includes objects pending iterative destruction,
preventing an arena from being unmapped while the destruction worklist still
references it. Accounting charges each entire slab once and returns its charge
only after successful unmapping. Fragmentation therefore consumes the same
256 MiB budget; empty slabs are not cached.

The four-pointer runtime ABI is unchanged. Allocation, retain and clone return
owned references; ordinary pointer inputs are borrowed. Explicit ownership
cleanup retires one owner through release. Null retain/release is harmless.
Retain rejects dead objects and count overflow before incrementing. Release
decrements counts and puts newly dead objects on an intrusive worklist. It scans
only owned child slots and frees each object's storage after queuing its children. Neither
deep destruction nor wide sharing requires recursive calls or auxiliary heap
allocation; live charges are returned only after successful unmapping.

Clone copies payload bytes and retains every owned child. Make-unique takes one
borrowed location containing an owned object. A unique object stays in place; a
shared object is cloned, the location receives the new owner, and the previous
owner is explicitly retired. Other snapshots and child ownership remain intact.
The [aggregate layer](native-aggregate.md) integrates these
operations with evaluated field/index locations, normal frame cleanup,
structural equality and array/map snapshot iteration. Arrays use no additional
storage header: payload bytes and the capacity marker determine length, and mode 0/1 determines whether
elements are owned children. Appending to a unique array reuses its explicitly
reserved capacity. Growth reserves up to twice the old payload, bounded by the
unchanged heap ceiling; the complete reservation is charged. Shared arrays copy
their live elements and retain owned children. Header byte length and child
count always describe live elements, and cloning copies only live bytes and
resets large spare capacity (packed clones keep their marker and the minimum small-object reservation). Packed `Array<u8>` payloads use one byte per element and child mode/count zero; header 36 is the bitwise complement of capacity, including -1 for an empty byte array. Nonnegative capacity keeps the eight-byte slot representation, including legacy byte arrays used by independent probes. For lengths through nine, byte allocation and cloning reserve eight times the logical length to preserve the former slab class in one-page error-ordering fixtures; elements remain packed, header 8 stays logical, and the full reservation is charged. Larger byte allocations reserve their byte length. Strings retain zero at header 36. All reads and writes to packed elements use byte widths, including the last byte before a guard page. Slicing and nonempty pop still copy their selected
elements. The independent array ABI probe checks growth, snapshot preservation,
borrowed element ownership, zero-budget reuse and final reclamation.
The [enum layer](native-enum.md) reuses mixed mode
with a non-reference tag slot and a separate bitmap for each variant. The
[string layer](native-string.md) stores packed immutable bytes without child
references; [ordered maps](native-map.md) use owned-pointer arrays of mixed
key/value tuple entries. The [graph runtime](native-graph.md) adds recursive
type layouts and iterative equality without changing these ownership headers.


Development conformance includes exact object parity, page-boundary accounting,
shared and mixed child layouts, copy-on-write snapshots, repeated reclamation,
all size-class boundaries, full/partial slab transitions, middle/tail unlinking,
cleared slot reuse, 300,000-node destruction under a 128 KiB stack and 64 MiB
address-space limit, checked ownership traps,
the full heap ceiling and actual mmap failure under an OS address-space limit.
Objects link with GNU ld alone, have no dynamic dependencies and reproduce in
paths containing spaces. Reports remain `releaseEligible: false`; these checks
do not certify Ubuntu 24.04, six native targets, self-hosting or acceptance.
