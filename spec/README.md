# Kelft language specification

Read the [public specification](https://www.kelft.com) online or use the bundled
pages below. Core 0.1, Intent 0.2, runtime profiles, and compiler packages identify
separate contracts. A specification snapshot alone does not establish target
availability or release qualification.

## Reading order

1. [Core language 0.1](language.md): lexical rules, grammar, types, evaluation,
   modules, mutation and errors. Core is executable deterministic source.
2. [Intent source 0.2](intent-v0.2.md): declarations, prose, formal predicates,
   entities, capabilities and reviewed authoring. Core and Intent files both
   use `.kelft`; an Intent module starts with `app` after whitespace/comments.
3. [Intent IR 0.1](intent.md), [Core IR](ir.md), and [runtime](runtime.md):
   intermediate contracts and program behavior. Declaring or checking a
   requirement is not evidence that it holds.
4. [Compatibility and glossary](compatibility.md): terminology, status and
   specification corrections.

See [source examples](examples.md) for separate Core and Intent modules.

## Target and platform contracts

| Area | Specification |
| --- | --- |
| JavaScript/runtime intrinsics | [Runtime](runtime.md), [intrinsic inventory](intrinsics.json) |
| Wasm/WASI and browser | [Wasm](wasm.md), [browser](browser.md) |
| Native execution and private backend boundary | [Native profile](native.md), [direct native](native-direct.md) |
| Native aggregate storage | [Owned storage](native-owned-storage.md), [aggregates](native-aggregate.md), [enums](native-enum.md), [maps](native-map.md), [graphs](native-graph.md) |
| Native text and host access | [Strings](native-string.md), [streams](native-streams.md), [paths](native-paths.md), [processes](native-process.md), [filesystems](native-filesystem.md), [artifacts](native-artifacts.md) |
| Service and application profiles | [Services](services.md), [application platform](application-platform.md) |
| External execution evidence | [Driver protocol](driver-protocol.md) |

Language semantics are normative; target/profile documents specify the named
profile, rather than a guarantee that every installation contains it.
Backend-private IR/ABI contracts are not portable application APIs. Consult the
compiler's capabilities and release notes for availability and tested hosts.

Prose is CC-BY-4.0; first-party copyable code examples are MIT-0; machine-readable
intrinsic data retains the software license. See the root LICENSE and licensing
inventory.
