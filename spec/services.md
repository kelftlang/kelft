# Native service event ABI v1

The `native-events-v1` service driver links validated, directly emitted C17 Core
with narrow libmicrohttpd, SQLite and Iddawc mechanisms. Application decisions
remain in Core. Service dependencies, transitive binary inputs, source licenses,
compiler and flags are pinned before building; builds run without network access.

The envelope matches the browser event transport:
`{schemaVersion:"0.2",state,event}` becomes
`{schemaVersion:"0.2",state,commands}`. An asynchronous command has a string `id`;
its completion event repeats that ID. Native v1 executes one command per
transition, serializes requests, and runs each Core transition in an isolated
child with fresh runtime state. Core receives no callback, pointer or calling
convention. Each frame is bounded to 1 MiB, transitions to five seconds, and each
request to 128 transitions. Failed transitions cannot commit pending storage.

The native host supplies an `http.request` event containing method, path, query,
selected headers, cookie values and bounded UTF-8 body. Core alone selects routes,
checks sessions/CSRF/permissions, and emits `http.respond` with status, headers and
body. Public static files are an explicit transport command, never an implicit
fallback for API paths. The host validates command shapes before effects and
intersects artifact restrictions with external grants; neither provider settings
nor declaration parsing supplies grants.

Mechanism commands are:

| Command | Completion and boundary |
| --- | --- |
| `db.begin` | Begin a read or immediate-write transaction on the externally configured database. |
| `db.query` | Execute one prepared statement with explicitly bound JSON scalar parameters; return rows and changed-row count. |
| `db.commit`, `db.rollback` | Finish the current transaction. Any unclosed transaction rolls back at request end. |
| `crypto.random` | Return bounded cryptographically random bytes as hex, without implementing application token policy. |
| `clock.read` | Return UTC day and second-of-day, avoiding the Core i32 Unix-seconds limit in 2038. |
| `oidc.begin` | Create a bounded opaque protocol handle and an authorization URL using code flow, S256 PKCE, state and nonce. |
| `oidc.complete` | Validate the redirect and token exchange; return validated issuer/subject and selected claims, never raw tokens or client secrets. |
| `http.respond` | Complete the request exactly once. |
| `http.asset` | Serve a named file from the configured public asset directory, without following links. |
| `service.ready` | Complete initialization after all startup transactions have finished. |

SQLite queries are bounded in SQL length, parameters, rows, result bytes and
execution time. SQL cannot attach databases, load extensions, access files or
change host configuration. Core chooses schema, queries, mutations and commit
policy. No network command may run while a database transaction is open.
Migrations and application writes use the same explicit transactional interface.
Responses cannot acknowledge an open transaction: unfinished transactions roll
back and produce a transport failure. Completion events use
`{type:"host.complete",id,command,ok,result?,error?}`.
For a declared API route, `db.commit` includes a prospective `response` command.
The trusted generated Core gateway validates it before the host can commit, then
validates the eventual terminal response again. Invalid prospective responses
trap while the transaction can still roll back. The host independently checks
the optional command shape and HTTP authority. Core-only event programs retain
the older commit shape. Unfinished OIDC flow consumption may commit a declared
redirect before the protocol exchange; subsequent failure is a declared error.

Iddawc always verifies TLS, state, nonce, signature, issuer, audience and expiry;
application commands cannot disable these checks. The provider, client secret
and redirect origin are external configuration constrained by artifact grants.
Core additionally checks its login-flow association and applies session policy.
Protocol handles are temporary and single use. Restart invalidates unfinished
login flows. Error/log output contains no tokens, codes, secrets or request bodies.

Discovery, authorization, token and JWKS URLs use verified HTTPS without following
redirects. They must share the configured issuer's origin or an explicitly
operator-granted `--oidc-origin`; application commands cannot expand that set.
The adapter checks the audience against its configured client ID and checks `azp`
when present or required by a multi-valued audience. It permits signed asymmetric
JWT algorithms advertised by the provider and rejects unsigned and symmetric ID tokens. `oidc.begin` may request the bounded `login` or `select_account` prompt; neither prompt changes validation. Discovery/JWKS
downloads and token exchanges run in bounded, isolated protocol workers; worker
handles and credentials stay outside Core state.

The native server profile is a release gate separate from standalone
`native-posix-v1` compilation. The presence of this ABI specification or pinned
dependency inputs does not establish an implemented or verified Relay server.
