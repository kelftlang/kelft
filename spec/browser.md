# Browser event ABI v1

`--target wasm --runtime-profile browser-events-v1` emits a direct Wasm module
exporting `memory` and `kelft_dispatch`. Core's existing value semantics and
instruction lowering are unchanged. Filesystem and artifact effects are rejected.
The transport uses the existing standard WASI argument/output imports; all other
host operations are denied. There are no environment variables or preopened paths.

Each dispatch instantiates fresh linear memory. `args()[0]` contains one JSON input:

```json
{"schemaVersion":"0.2","state":{},"event":{"type":"initialise","data":{}}}
```

Core prints exactly one JSON transition:

```json
{"schemaVersion":"0.2","state":{},"commands":[]}
```

The generic transport validates frames and bounds input/output to 1 MiB each.
Fresh instances prevent state or key material leaking through retained linear
memory across transitions. State is explicitly returned by Core. Browser hosts
must execute transitions in a dedicated Worker with an execution deadline; direct
`executeEvent` is also exposed for finite conformance tests. The transport itself
implements no task state, authorization, synchronization, retry, or UI policy.

The platform bridge implements scoped DOM rendering, same-origin HTTP transport
and timers, intersecting grants with maximum restrictions. The separately bundled
vault implements cryptography, with Core retaining application policy. Integrated
encrypted storage, Relay rendering, and browser application acceptance require
their own verification; this transport does not establish those release gates.

Browser modules contain exactly one `kelft.capabilities.v1` custom section with
`{schemaVersion:"0.2",profile:"browser-events-v1",maximum:...}`. The maximum
contains Boolean `dom`, `timers`, `vault`, `random`, `clock`, `navigation`, and
`network:{sameOrigin,paths,methods}`. The bridge reads this section directly;
caller-supplied settings can only restrict it. Missing or malformed sections
cannot authorize effects. Pure event-transport execution remains available for
conformance testing without host effects.
