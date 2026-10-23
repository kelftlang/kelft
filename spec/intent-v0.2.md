# Kelft 0.2: intent-first, code-optional programming

This specification extends, rather than replaces, Kelft-SH 0.1 and Intent IR 0.1.
This document defines the semantic-envelope programming model and its
implementation contract. A declaration is not evidence that its
requirement holds. Unsupported verification and execution remain explicit.

## Source and grammar

Source uses UTF-8, ASCII identifiers, `.kelft`, braces, newline-delimited clauses,
`//` and non-nested `/* */` comments. Semicolons can terminate clauses. Core syntax
and reserved identifiers remain unchanged. Intent keywords are contextual.
Strings use Core escapes; triple-quoted strings permit literal newlines. CRLF is
normalized to LF in multiline strings. String contents otherwise remain exact.

```ebnf
intent_module = "app" identifier "{" { declaration | clause } "}" ;
declaration = named_block | behavior | endpoint | scenario | event_policy | roles | capability ;
named_block = ("context" | "entity" | "reference" | "feature"
            | "unknown" | "build" | "change") identifier block ;
behavior = "behavior" identifier [ parameters [ "->" core_type ] ] block ;
endpoint = "endpoint" identifier block ;
scenario = "scenario" (identifier | string) block ;
event_policy = "when" prose block ;
roles = "roles" block ;
capability = "capability" [ identifier ] block ;
block = "{" { declaration | clause | field } "}" ;
parameters = "(" [ [ "inout" ] identifier [ ":" core_type ]
             { "," [ "inout" ] identifier [ ":" core_type ] } ] ")" ;
field = identifier ":" domain_type [ "where" refinement ] terminator ;
domain_type = core_type [ "?" ] | identifier "|" identifier { "|" identifier } ;
clause = keyword [ identifier ":" ] (string | prose | formal) terminator ;
formal = "(" core_expression ")" ;
terminator = NEWLINE | ";" | lookahead("}") ;
```

Clause keywords are `intent`, `must`, `ensures`, `prefer`, `may`, `given`, `and`,
`when`, `then`, `eventually`, `source`, `applies`, `decision`, `because`, `image`,
`match`, `allow`, `deny`, `ask`, `blocks`, `use`, `implementation`, `ownership`,
`preserve`, `evolve`, `change`, `require`, `verify`, `target`, `agent`, `tool`,
`method`, `path`, `request`, `response`, `status`, `error`, and `extensible`.
Bare names are permitted only inside `roles`. Entity fields are unique. Named
declarations are unique in their containing scope. Labels are unique per scope.
Anonymous capability blocks have the fixed local identity `capability`.

Parenthesized requirements always parse as Core expressions. Syntax errors do not
fall back to prose. Formal syntax validation is separate from type checking and
verification; unresolved names and unavailable evaluators cannot produce evidence.
Behavior signatures may omit types during progressive refinement, but executable
bindings must have fully resolved matching types before acceptance.

Typed behaviors additionally accept Core `inout` parameters and `-> type` after
the parameter list. A declared signature without a return type remains incomplete
for ABI verification. `result` is reserved for a non-void behavior's postconditions;
it is not available in preconditions. Formal predicates must have Boolean type.
The `signatures` command emits resolved parameter modes/types and return types,
with the domain type declarations needed to compare implementation ABIs.

The deterministic `models` output contains executable Boolean precondition and
postcondition predicates. Validation descends through tuples, arrays, maps,
options, results and entity fields before aliases erase UUID constraints. Both
inputs and resulting values must satisfy domain validation. Preferences are
type checked but do not become mandatory guards. Formal expressions cannot use
host effects, mutation, process output, process exit or environment arguments.

Core `check`, `ir`, `build` and `run` accept `--intent declarations.kelft`.
For every explicitly bound, completely typed behavior, the compiler compares the
resolved implementation ABI and domain shapes, then inserts a compiler-owned
wrapper into canonical Core. All calls, including recursive calls, pass through
the wrapper. It validates inputs and hard preconditions, invokes the unchanged
implementation once, then validates outputs and postconditions. Failed guards
terminate with `error[KRT_CONTRACT]` identifying the behavior and stage. A
postcondition failure does not undo external effects; transactional service
handlers must roll back their transaction. Unbound behaviors retain outstanding
implementation and verification obligations. Guard insertion does not grant
capabilities or change source ownership.

An optional `--bindings FILE` accompanies `--intent`. It contains an array of
`{scope,path,symbol,ownership}` records: qualified declaration identity,
project-relative Core path, function name, and `human|ai|shared` ownership.
Resolution records may bind unbound behaviors/endpoints, but cannot override a
source binding or change declared ownership. They are reviewed implementation
metadata, not a replacement Intent graph. Synthesis may propose AI bindings
only within its existing file allowlist. Trusted configuration can supply manual
bindings, with the same ownership protection as source bindings.

The v0.2 authoring envelope additionally permits `implementationBindings` and
`proposedTests`; older envelopes remain readable. A proposed test has a stable
`id`, `requirements` containing existing obligation identities, and a fixture
`{args,stdout,stderr,exit}`. Proposed tests initially supply no evidence.
`register-tests PROPOSAL --hash REVIEW_HASH --tests ID,ID` explicitly registers
reviewed tests, executes them, and issues a new review hash. Acceptance requires
that new hash and reruns the tests. Existing trusted and accepted tests remain
mandatory; generated tests cannot replace them. Changing trusted registrations
requires explicit `approvedVerificationChanges` in operator configuration.

An `endpoint name` block is permitted inside `feature api`. It requires one each
of `method GET|POST|PUT|PATCH|DELETE`, `path "/absolute/path"`, `request Entity|void`,
`response Entity|void`. A quoted `implementation "./core.kelft::handler"` is
optional; an unbound endpoint remains an implementation obligation.
`status 200` is the default success status; `extensible response` explicitly opens
the response schema. `error code: 403 ErrorEntity` declares a named error contract.
Error clauses directly in `feature api` are defaults inherited by its endpoints;
an endpoint may explicitly replace a default with the same name. The resolved
error contracts participate in preservation exactly as local declarations do.
Success statuses are 200–299 or 301/302/303/307/308. Status 204 and redirects
require `response void`; redirects require an empty body and a safe Location.
Request and response types resolve to declared entities, whose fields and reachable
domain definitions participate in API comparison. Parameter names use `{identifier}`.
Paths cannot overlap for the same method: `/tasks/{id}` and `/tasks/current` are
ambiguous and rejected, including during compatible evolution. A new route cannot
intercept callers of an accepted route.
Endpoint ownership follows behavior ownership. The deterministic `contracts`
command emits domain and endpoint manifests, retaining declared root types so
`void` and an empty object cannot be confused. Extraction alone does not prove that
the implementation routes or responds according to the manifest.

### Executable wire boundaries

`wire-models SOURCE --json-module RELATIVE --wire-module RELATIVE` emits trusted
Core routing metadata, request/response/error validators and canonical JSON
serializers. Both frontends produce identical source. This output is derived from
declarations, never from a provider's IR. The shared bounded Core runtime supports
Text/string, UUID, i32, u8, bool, void, entity alternatives, entities, Array, Map,
tuples, Option and Result, recursively. Unsupported types produce K0716 (or an
earlier Core type diagnostic) rather than accepting arbitrary values.

Entities are JSON objects. Required fields must exist; optional fields may be
absent or null. Unknown fields fail, except at an explicitly extensible response
root; nested entities remain closed. Alternatives are strings. Arrays and tuples
are JSON arrays. Maps are arrays of `[key,value]` pairs with unique scalar keys.
Results are exactly `{"ok": value}` or `{"error": value}`. Options use null for
None and the inner value for Some, except when the inner type itself admits null
(Option or void), when Some is exactly `{"some": value}`. Integers are canonical
decimal values in their Core ranges. Refinements and nested UUIDs are validated.
Malformed JSON, duplicate keys, excess depth and resource limits fail recoverably.

The native gateway selects reviewed endpoint handlers with ABI
`(state:JSON.Value,event:JSON.Value)->JSON.Value`. It keeps contract identity
outside handler-owned state across completion events. Paths, query fields and JSON
bodies merge without collisions. Only scalar query/path values are converted;
all merged inputs must pass the declared request validator. Invalid inputs emit
the declared 400 Problem contract (`code` and `message`); if that contract is not
declared, the boundary fails closed. The gateway checks every terminal success or
error response, including serialization, content type and redirect safety. Invalid
handler output traps before delivery and rolls back open host transactions.
Undeclared HTTP routes return a transport 404, and only explicitly reviewed public
asset routes bypass entity serialization. Handlers cannot escape to undeclared
routes or replace the gateway's state. Hosts still enforce command shapes and
effective authority. Actual target execution remains necessary evidence.

## Capability lowering

`capabilities SOURCE` emits deterministic browser/service maxima and lists of
lowered and unsupported clause identities. Unknown policy prose retains an
unverified obligation; it never grants authority. Contradictory explicit
allow/deny rules for one profile operation produce K0714. Empty profiles deny all.

Browser rules support `dom within application_root`, `network only
same_origin_api`, `storage only identity_scoped_encrypted_vault`, `timers`,
`randomness`, `clock`, and `navigation only same_origin_auth`. Same-origin API
means `/api` and descendants with GET/POST/PUT/PATCH/DELETE. Navigation is confined
to same-origin authentication entry points. Vault storage grants no plaintext
durable store. Native `capability server` supports `http within
configured_listener`, `database only relay_store`, `oidc only configured_provider`,
`randomness`, `clock`, and `assets only public_static`. Named resources are fixed
by external deployment configuration, never by commands from application code.
The browser/native event profiles also enforce fixed denials of arbitrary code
execution, browser identity secrets and session-token logging.

Browser Wasm embeds its maximum in exactly one `kelft.capabilities.v1` custom
section. With `--intent`, the compiler derives that section from declarations;
`--host-policy` cannot replace it. Core-only browser builds may supply an explicit
host policy, otherwise the maximum denies all. External grants and any additional
host restriction intersect this embedded maximum. Lowering is not evidence of
runtime behavior; target-specific capability verification remains mandatory.

## Intent graph and identity

The interchange object has `schemaVersion: "0.2"`, `id`, `nodes`, `edges`,
`dependencyHashes`, and `orchestrationDependencyHashes`.
Nodes contain `id`, `kind`, `scope`, `name`, `value`, `form`, and source `span`.
Forms are `declaration`, `prose`, `string`, `expression`, and `field`.
Expression nodes carry the parsed Core expression tree. Source spans are UTF-8
byte offsets and are excluded from semantic hashes, including expression spans.
Edges contain `from`, `to`, and `kind`; the initial edge kind is `contains`.

Declaration identities are qualified names starting with the app name. Quoted
scenario names use the SHA-256 of their decoded name. Explicit clause labels
produce `scope.label`. Unlabeled clauses use `scope.kind:<semantic-content-hash>`.
Reordering independent declarations or changing whitespace/comments has no effect
on graph hashes. Exact duplicate anonymous clauses are rejected rather than given
position-dependent identities. Changing an unlabeled clause is removal/addition.
Orchestration nodes remain available to tools but are excluded from application
semantic hashes. Build context hashes are separately bound to proposals.

`must` and `ensures` create mandatory obligations. `prefer` ranks acceptable
implementations. `may` delegates only its stated choice. `unknown` retains a
question and a stage gate (`synthesis`, `acceptance`, or `production`; default
`acceptance`). A declaration-only check may succeed with unverified obligations;
it must report them. Unresolved decisions return exit 2 at their applicable gate.
An invalid program returns exit 1. No model call occurs during checking or builds.

Context paths resolve relative to the declaring source within the project root.
Missing, changed, or escaped dependencies invalidate dependent evidence. Context
selectors restrict the slice sent to an implementation provider. Reference files
are dependencies, not executable instructions or implicit permissions.

Implementation clauses bind `"./file.kelft::symbol"`; ownership is `human`, `ai`,
or `shared` (default `human` for explicit bindings). Human-owned files cannot be
changed by synthesis. Shared changes require exact-bundle review. Generated Core
is checked against the same obligations as manual Core.

## Changes and public contracts

Named change blocks are transformations against an exact accepted base. Selectors
match a named scope and descendants; `*` is a terminal scope wildcard, not an
arbitrary filesystem glob. Empty matches and contradictory overlapping policies
are errors. Models cannot authorize changes to their own preservation boundaries.

`preserve api.*` compares exact endpoint, method, name, request/response/error
schemas and relevant behavior obligations. Additions and removals are changes.
Internal refactoring is allowed. `evolve api.* compatible` permits new endpoints
and optional request fields while preserving all old requests. Response additions
require the baseline to declare an extensible schema. Changes outside that finite
compatibility rule are rejected. `change api.*` permits an exact reviewed diff;
it does not override other requirements or independently confer approval.

Structural checks and behavioral tests are separate evidence. Exact schema
comparison does not establish universal observational equivalence. Preserved
behavior obligations and trusted tests must be rerun, never silently weakened.

## Evidence, proposals, and builds

Evidence records outcome separately from method. Methods are `proven`, `tested`,
`observed`, `human-approved`, `model-evaluated`, `unverified`, or `blocked`.
Every obligation names its evidence strategy; unsupported strategies remain
unverified. Mandatory obligations block acceptance until their required evidence
is present. Parsing a scenario or generating its test is not a passed test.

Proposal review binds the exact source, Intent graph, generated Core, ownership,
assumptions, public contracts, context, compiler/runtime, host grants, trusted
verifiers, tests, target, and budget. Acceptance rechecks these inputs and records
immutable content-addressed snapshots and ledger events. Application is
transactional and recoverable; concurrent edits invalidate approval.

Billing is orchestration metadata, separate from application obligations. An
explicitly authorized local-agent run whose cost cannot be verified records
`needs-human` cost evidence and usage without asserting a dollar bound. That
record participates in exact-bundle review and acceptance history, but does not
block functional acceptance. Existing reservations and invoices are retained.
Metered API calls retain their configured budget safeguards.

`check` is deterministic validation; `synth` stages untrusted proposals; `review`
reports changes and evidence; `accept --hash` applies the exact verified proposal;
`build` consumes accepted inputs without AI. Core-only builds retain their existing
interface. v0.1 JSON remains readable without rewriting old artifacts or hashes.

Operator configuration may register `releaseTargets` with explicit identifiers,
entries, target/profile pairs, protected `.mjs` verifier runners and named checks.
Supported profiles are JavaScript/node24, Wasm/wasi-preview1, Wasm/browser-events-v1,
native/native-posix-v1 and native/native-events-v1. A `kind: target` verifier
registration binds an obligation to one target and one named check. Neither
generated tests nor model assertions may create these trusted registrations.

Review builds every registered target, runs its protected verifier against that
artifact, and requires an execution-specific response matching the canonical
request and artifact hashes. Only actually executed tested/observed checks can
pass. Missing/stale checks and invented proof methods fail. Evidence binds source,
candidate, bindings, Node runtime, compiler, verifier, policy, native dependencies,
host adapters and toolchain inputs. Target-specific runtime dependencies reported
by the runner remain in evidence and must match during acceptance's rerun.
Existing verifier source changes require explicit `approvedVerificationChanges`.
All implementation bindings must be loaded and reachable across the verified
executables; a target need not import bindings belonging to another executable.
Every loaded typed binding is guarded.

Accepted `build --release ID -o ARTIFACT` (or an unambiguous target/profile pair)
rechecks accepted inputs and recompiles without AI. It publishes output only if
its bytes match the reviewed target artifact. Target, policy or runtime-profile
flags cannot expand accepted authority. Outputs cannot overwrite accepted source,
verification fixtures or ledger state. Unregistered profiles remain unavailable
through accepted builds; Core-only compiler commands retain their existing use.

## Execution and delivery obligations

### Explicit migration

`intent migrate LEGACY.json SOURCE.kelft MAPPING.json` deterministically emits a
v0.2 migration receipt. It retains the v0.1 semantic hash and exact original byte
hash, the new source semantic hash, and an explicit mapping for every historical
constraint, assumption and verification target. Hard constraints must map to
application obligations; preferences map to preferences. Unresolved historical
assumptions map to unknowns blocking synthesis or acceptance, never production
alone, or to explicit quoted decisions in source context resolving them. The
receipt retains their historical unresolved status and the review exposes the
new decision. Mappings cannot grant capabilities or supply passing evidence.

`migrate LEGACY.json SOURCE.kelft MAPPING.json -o RECEIPT.json` is the trusted
driver convenience command. It preserves all inputs. Source synthesis may name
the receipt as `migrationFile` in operator configuration. Initial acceptance
revalidates it, requires fresh evidence, and stores an immutable receipt alongside
its ledger event. Subsequent changes retain that historical link while following
normal preservation/review rules. Existing v0.1 files and hashes are not rewritten.

Core application logic compiles directly to Wasm for browsers and through portable
C for native servers. A versioned typed event/command ABI connects asynchronous
platform operations to deterministic Core transitions. The browser bridge owns
DOM, events, transport, storage, timers, and cryptographic mechanisms, never
application validation, reconciliation, rendering decisions, or authorization.
Wasm and native retain the shared value semantics and conformance suite.

Runtime authority intersects external grants with embedded restrictions. Intent
declarations and build-agent roles cannot mint authority. Node's existing compiler
profile is unchanged. Native web adapters use libmicrohttpd, SQLite, and Iddawc;
all toolchains and dependency artifacts must be pinned before release evidence.

The Relay application profile includes OIDC code flow with PKCE; server sessions and CSRF;
workspace permissions and last-admin protection; recipient-bound, single-use
seven-day invitations; revision-based, idempotent offline operations; safe
independent-field merging; preserved conflicts; and an optional encrypted offline
vault. The vault uses random data keys, AES-256-GCM and Argon2id wrapping, with
15-minute default inactivity locking. Known revocation locks workspace data and
quarantines encrypted work; disconnected devices cannot learn revocation early.
No automatic deletion or passphrase recovery is implied.

Application conformance, security and offline integration, browser behavior,
and live authoring workflows require their own verification. Unverifiable
billing is recorded as `needs-human` without a dollar-ceiling compliance claim
or an application acceptance blocker. Backend availability alone does not
establish application behavior.

Orchestration may select `modelContextFiles` as a unique subset of protected
`contextFiles`. All protected inputs are still staged, hashed, reviewed and checked
for concurrent changes. The model receives their hashes, the complete authoritative
declarations, reviewed ownership and the selected file contents; the selection
does not alter application meaning, capability grants or verification coverage.

Synthesis requires an explicitly configured model. Without an explicit configuration
argument, the driver discovers one sibling NAME.ai.json, NAME/orchestration.json
(lowercase source basename), or project kelft.ai.json. Ambiguous discovery is an
error. Discovery never changes capabilities or bypasses configuration validation.

## Generation from declarations

`kelft synth APP.kelft --from-declarations` selects an empty-project generation
profile. Its orchestration must supply a protected `platformManifest` listing
explicit generic library/documentation files and their byte hashes. Optional
`derivedFiles` are compiler-generated domain models, rechecked against declaration
lowering. The project must have no accepted baseline, supplied implementation
bindings, pre-existing application Core, or candidate styling. Dependency closure
checks forbid importing implementations outside the registered platform and
candidate paths. The generation record retains the initial empty candidate,
declaration hash, platform classification and hashes.

Orchestration may add an explicit `allowAssets` list of CSS paths alongside Core
`allowFiles`. CSS accepts local styling only: no imported resources, URL loading,
escaped identifiers or executable legacy features. Assets are proposals, never
capability grants. Their contents participate in candidate hashes, review,
transactional acceptance/recovery and stale-input checks for accepted builds.
Missing required entries/assets and partial module sets cannot pass acceptance.
Technical repair rounds may complete partial proposals without changing authority
or registering unexecuted model tests as trusted evidence.

Compiler feedback may include deterministic source excerpts resolved from UTF-8
byte spans. A paused compiler repair may continue orchestration with a fresh
provider session, retaining the original proposal count and archived review.
Runtime-check diagnostics may also be supplied to a bounded continuation; they
report observed errors and never turn a failed check into passed evidence. A
repaired candidate must execute its target checks again. Continuation rejects
changed inputs, changed candidate bytes, an altered accepted
baseline, and exhausted round limits. It supplies technical feedback only;
material decisions still require authoritative declaration changes.

This profile supplies a fixed compiler and host SDK. Complete generation claims
must disclose that boundary and identify every deterministic, model-generated and
pre-existing input. A passing fixture or integrated proposal over prewritten
application libraries does not establish empty-project application generation.
