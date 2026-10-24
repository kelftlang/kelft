# External execution protocol 0.1

The Kelft compiler owns compilation, Intent validation, proposal preservation,
semantic differences, assumption handling, contract evaluation, and acceptance.
The Rust driver owns host authority, subprocess lifecycle, registry snapshots,
resource limits, and observation collection. It exposes only standard WASI to
modules and contains no Kelft compiler implementation.

## Transactions

The compiler command is `protocol prepare|finalize /control/request.json`.
Requests contain `schemaVersion`, `sessionId`, `action` (run/verify/accept), `entry`,
`target`, `runtimeProfile`, `artifactPath`, `args`, `permissions`, `intentPath`,
`policyPath`, `proposalPath`, `basePath`, `approved`, `ledger`, `parent`,
`compilerHash`, `registryHash`, `driverHash`, `runtimeIdentity`, and `limits`.

Prepare resolves and checks source and Intent, emits the candidate into `/output`,
and returns a plan containing `requestHash`, identities, limits, `report`, and
`planHash`. The report binds candidate, artifact, Intent, policy, fixture, and
dependency hashes and lists registered `executionRequests`. Compiler checks run
inside Wasm. Unresolved decisions stop with `needs-human` before execution.
Acceptance plans also bind the semantic proposal and base revision hashes when
supplied. Kelft checks preservation and requested authority during prepare, then
rechecks the exact revisions during finalize.

The driver checks the plan against its external request and immutable verifier
registry snapshot. Registered operations are `run` and `fixture`; declarations
never provide executable names or arbitrary command strings. Every operation
uses the exact prepared artifact and recorded arguments. Candidate authority is
bounded independently by external grants and the emitted maximum policy.
Candidate mounts cannot overlap private transaction state; writable mounts cannot
contain the trusted driver, compiler, or bootstrap seeds. Before finalization,
the driver rechecks the original external policy and fixture registry. Every
compiler invocation also checks the compiler's original pinned artifact hash.

Finalize reloads the request, plan, current source/Intent/policy inputs, and
`/control/evidence.json`. It recomputes artifact and input bindings, validates the
receipt, checks exact execution coverage, and evaluates the contract. Acceptance
writes the existing content-addressed ledger only after these checks pass.
Subsequent acceptance retains the existing base/proposal/preservation rules.

## Evidence

Evidence contains `schemaVersion`, `sessionId`, `planHash`, `compilerHash`,
`registryHash`, `driverHash`, `runtimeIdentity`, `results`, and `receipt`. Each result identifies the operation,
verifier, fixture and artifact hashes, status, exit, stdout/stderr hex bytes,
normalized trap category, infrastructure error, and `fileEffects` snapshots.

Hashes use SHA-256 over raw artifact bytes or canonical JSON as specified by the
field. `planHash` hashes the plan without its own field. The receipt is
`hmac-sha256:` plus the HMAC-SHA256 digest of canonical evidence JSON without
`receipt`. The 32-byte session key is available only to the compiler through
`/control/session.key`. Candidates receive neither that mount nor execution
authority. Session metadata is excluded from compiler artifact bytes.

Missing, duplicated, substituted, malformed, stale, unauthenticated, timed-out,
or resource-failed mandatory observations cannot authorize acceptance. Fixture
stdout, stderr, and exit expectations are evaluated by Kelft. Optional fixture
`fileEffects` must exactly match the recorded before/after snapshot; when absent,
Intent fixture execution must leave writable files unchanged. Snapshot entries
identify directories, symlinks, or file hashes and bytes without following links.

Fixture defaults: 30 seconds, 1 GiB Wasm memory, and 1 MiB each of stdout/stderr.
Compiler phases: 300 seconds and 64 MiB each of stdout/stderr. Limits and runtime
identity belong to trusted configuration and are recorded in evidence/provenance.
The external driver remains a trusted collector; a valid receipt is not a formal
proof that observations are truthful or that the compiler is correct.
