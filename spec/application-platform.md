# Fixed application platform for declaration-only generation

This profile supplies language/runtime mechanisms, never application policy. The
compiler emits domain models and API boundaries from the authoritative declarations.
Core decides authentication/session policy, permissions, schemas/migrations,
transactions, rendering, optimistic state, replay, retries and recovery.

## Core event entry points

Both targets export `pub fn transition(state:j::Value,event:j::Value)->j::Value`.
Their `main()->void` parses `args()[0]`, calls `transition` on `state` and `event`,
and prints exactly the canonical JSON result followed by a newline. The result is
`{schemaVersion:"0.2",state:...,commands:[...]}`. There are no callbacks or async
functions. Every local variable needs a type; every function needs explicit returns.
JSON numbers use `j::Value::Number(i32_to_string(n))`. `j::field` of a missing key is
Null. Maps and arrays have value semantics; copy a value before an inout borrow.
`selfhost/json.kelft`, `selfhost/hash.kelft` and their generic dependencies are
available. `hash::sha256(text)` returns a `sha256:`-prefixed digest. Use its first
32 hex characters with UUID version/variant bits when deriving stable UUIDs;
random UUIDs can also be formed from a native `crypto.random` result.

## Native command and completion interface

The host sends `service.start` with config `{origin,issuer,clientId,storageGeneration}`.
Each HTTP request starts with fresh Core state and receives config plus
`{type:"http.request",method,path,query,headers,body}`. `body` is a string. A generated
API gateway validates wire inputs and adds `endpoint` (`api.` plus the declared
endpoint name, for example `api.session`) and `input` (decoded request including
path values). The host also supplies `redirectUrl` for the original absolute URL.
Treat endpoint names as the declared names, never invent a second external API. Unknown routes
are errors. `/auth/callback` query parameters are decoded into its declared input.

Native Core emits exactly one command per transition. Nonterminal commands carry
an `id` (at most 128 bytes); completions are
`{type:"host.complete",id,command,ok,result? ,error?}`. Put continuation state in the
frame's state. The host executes at most 128 steps per request; each transition
has a five-second execution bound and one MiB frame bound.

| Command | Fields beyond type/id | Successful completion result |
|---|---|---|
| `db.begin` | `mode:"read"` or `"write"` | `{}` |
| `db.query` | `sql`, `parameters` | `{rows:[objects],changes:i32}` |
| `db.commit` | optional `response` | `{}` |
| `db.rollback` | none | `{}` |
| `clock.read` | none | `{day:i32,second:i32}` |
| `crypto.random` | `bytes:16..64` | `{hex:string}` |
| `oidc.begin` | optional `prompt:"login"` or `"select_account"` | `{authorizationUrl,state,nonce,handle}` |
| `oidc.complete` | `handle`, `redirectUrl` | verified claims described below |

SQL requires an open transaction, one statement per command, bounded parameters
(string, i32, Boolean or null), and at most 256 result rows. Aliases must be unique.
Core emits schema creation and migrations through SQL commands; no schema is
preinstalled. Network operations are forbidden inside a transaction. Writes,
revision checks, receipts and audit writes belong in the same write transaction.
Unexpected failure rolls back; never issue a successful response before commit.

Terminal commands omit id: `service.ready` at startup; `http.respond` with
`status,headers,body`; or `http.asset` with a flat public filename in `path`.
Allowed response headers are content-type, cache-control, set-cookie (string or
at most four strings), location, content-security-policy, x-content-type-options,
and referrer-policy. Newlines in header values are rejected. The compiler boundary
validates declared response and error bodies and handles declared static routes.
With an API gateway, HTTP `db.commit` commands must include the prospective
`http.respond` command in `response`, so validation happens before committing.
Retain that response in state and emit it after successful commit completion.

OIDC is an externally configured, vetted protocol mechanism. A complete result
contains `issuer`, `subject`, `email`, `emailVerified`, and `name`. The host validates
TLS, PKCE, state, nonce, signatures, issuer, audience and expiry. Core binds the
flow handle/state to a secure login cookie and consumes that association once.
Core generates and hashes opaque session tokens and CSRF tokens, selects cookie
attributes and expiry, and checks authorization on each request. Handles expire
after ten minutes and cannot survive restart. No provider secrets reach Core or
the browser. An explicit provider login prompt supports account switching.

The generic restore utility creates a new 64-hex-digit storage generation in
reserved `_kelft_runtime_restore` metadata. The host exposes it on `service.start`;
otherwise it is empty. Core must compare it with its own persisted generation,
invalidate its own credentials atomically when it changes, and remember it before
`service.ready`. Ordinary restart keeps the same generation. The utility never
knows application table names or deletes application credentials.

## Browser command and event interface

The platform initially dispatches `initialise` with `online,width,url`. It also
dispatches `platform.changed` with `online,visible,width`, `platform.activity`,
and `platform.vault-lock` with `reason` and either `identity` or `all:true`.
Core retains state between events and may emit multiple commands. Asynchronous
operation IDs must remain unique until completion. Timer IDs cannot be rearmed
until fired or cancelled. Validate the entire effect list before sending it.

| Command | Fields | Completion |
|---|---|---|
| `dom.render` | `tree` | none |
| `unload.guard` | `enabled:bool` | none |
| `http.request` | `id,url,method?,headers?,body?` | `http.complete` with id/status/body, or `http.failed` |
| `timer` | `id,delayMs:0..30000` | `timer.fired` with id |
| `timer.cancel` | `id` | none |
| `clock.read` | `id` | host.complete result day/second/monotonicSecond |
| `random.uuid` | `id` | host.complete result `{uuid}` |
| `navigate` | same-origin `/auth/login` URL | navigation |
| `vault.list` | `id` | host.complete array of catalog entries |
| `vault.create` | `id,identity,passphrase,payload` | host.complete `{persisted:true,unlocked:true}` |
| `vault.unlock` | `id,identity,passphrase` | host.complete `{unlocked:true,payload}` |
| `vault.store` | `id,identity,payload` | host.complete `{persisted:true}` |
| `vault.lock` | `id,identity,reason?` | host.complete `{locked:true}` |
| `vault.lock-all` | `id,reason?` | host.complete `{locked:true}` |
| `vault.quarantine` | `id,identity` | host.complete `{quarantined:true}` |
| `vault.recover` | `id,identity` | host.complete `{quarantined:false,unlocked:false}` |
| `vault.delete` | `id,identity` | host.complete `{deleted:true}` |

Browser `host.complete` uses the same flat envelope as native completion:
`{type:"host.complete",id,command,ok,result?,error?}`. `http.complete` is
`{type:"http.complete",id,status,body}` with a UTF-8 string body; `http.failed`
is `{type:"http.failed",id}`. `timer.fired` is `{type:"timer.fired",id}`.
These fields are not nested in `data`. Native terminal commands and browser
command lists use the frame shape described above; the browser may emit an empty
command list while retaining its state.

Every vault identity is exactly `{issuer,subject,workspace}`. Catalog entries are
`{identity,quarantined,version}`. Vault payloads are application-defined JSON and
must preserve both snapshots and pending operations. A successful store completion
means an encrypted IndexedDB transaction committed. Failures do not imply
persistence. Recovery only clears quarantine; Core must first verify fresh server
authorization and still request passphrase unlocking. Passphrases must not enter
durable state or HTTP requests. Locking clears host-held keys; Core must also clear
its protected plaintext. Inactivity uses monotonic seconds, not wrapping epoch ms.

DOM trees are strings or `{tag,attributes?,style?,events?,children?}`. Event maps
use click/input/change/submit/keydown and `{type,data?}` actions. They dispatch
`{type,data,value,key}` to Core. Supported tags include div/section/main/header/
footer/nav/h1/h2/h3/p/span/button/input/label/form/ul/li/select/option/textarea/dialog.
The complete attribute allowlist is id, class, title, type, value, placeholder,
disabled, name, role, for, checked, selected, required, readonly, maxlength,
minlength, inputmode, aria-label, aria-live, aria-pressed, aria-describedby,
aria-expanded, aria-controls, and autocomplete. Other attributes, including
aria-selected, aria-current, hidden, tabindex, and data-* fields, are rejected.
Values are strings, booleans or numbers. A boolean false removes an attribute;
use strings "true"/"false" for ARIA states. Text remains text, never HTML.
Stable IDs preserve focus.

The complete inline-style allowlist is display, gridTemplateColumns,
flexDirection, alignItems, justifyContent, gap, padding, margin, backgroundColor,
color, border, borderRadius, fontSize, fontWeight, width, maxWidth, minHeight,
position, top, right, bottom, and left. Styles outside that list belong in the
reviewed CSS asset. Event actions have type:string and optional data:JSON.

Browser Fetch sends same-origin cookies, rejects redirects, and bypasses caching.
Mutations should supply lowercase content-type/x-csrf-token headers. The host
accepts no arbitrary headers, code, HTML injection or external resource loading.
CSS is a reviewed local asset, not a platform-supplied application theme. The
service worker caches only the deterministic public static-asset manifest.

## Evidence and generation

Generated code and assets are proposals. Models cannot edit declarations,
capabilities, platform inputs or verifiers. Partial modules may be proposed over
multiple rounds; missing entries/assets and failed checks prevent acceptance.
Only explicit registration followed by execution makes a proposed test evidence.
Passing a health check or printing a success string does not establish application
behavior. Accepted native and Wasm builds do not invoke AI.
