# Specification compatibility and glossary

## Versions and authority

Core language 0.1, Intent IR 0.1, Intent source 0.2, named runtime/ABI profiles,
compiler packages and editor releases have separate version identities. The
`spec-v0.2.0` publication is a snapshot of the current specification collection,
not a statement that every underlying contract has version 0.2.0.

Normative requirements define source semantics or an explicitly named protocol.
Examples and explanations are informative. A proposal
does not expand normative support. Per-target implementation availability,
execution observations and certification are separate claims. Backend-private
contracts can change independently of portable source semantics.

Released specification snapshots are immutable. Corrections produce a new
snapshot and describe their compatibility effect. Language changes require
review and updated successful and rejected conformance cases. Editorial
corrections must preserve accepted/rejected inputs and runtime behavior.

## Source forms

All language source uses `.kelft`, UTF-8 and ASCII identifiers. The Core grammar
reserves its keywords. Intent keywords are contextual and its clause prose is
not Core syntax. Triple-quoted strings are an Intent source feature; formal
predicates use Core expressions and Core string syntax. Comments are `//` and
non-nested `/* ... */`. Compiler spans are half-open UTF-8 byte offsets; editor
display positions can use a different encoding.

## Glossary

| Term | Meaning |
| --- | --- |
| Core | Deterministic executable language, compiled without an AI provider. |
| Intent | Typed declarations of outcomes, constraints and change contracts. |
| Obligation | A requirement whose evidence or implementation may still be absent. |
| Checked | Validated source/contracts; not proof of an application's requirements. |
| Needs human | An unresolved decision blocks the requested workflow. |
| Verification | Execution of the selected trusted verification contracts. |
| Acceptance | Reviewed, input-bound promotion recorded by the authoring workflow. |
| Capability | Explicit authority bounded by host grants and compiled restrictions. |
| Profile | Named target/runtime/ABI contract and its required behavior. |
| Certification | Evidence about an exact producer/target scope, not transferred by source similarity. |

## Corrections

Report the specification version, page and section, a minimal example, expected
behavior, and relevant compiler output. Issues and pull requests are welcome;
see [contribution guidance](../CONTRIBUTING.md). Source changes and editor
highlighting do not independently redefine the language.