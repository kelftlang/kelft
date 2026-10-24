# Kelft-SH 0.1

Status: frozen bootstrap specification. All source files use `.kelft`.

Kelft Intent is a typed contract above the executable language. An AI elaborator
is an untrusted author. Compilation of resolved source is deterministic and uses
no model. The specification and conformance fixtures, not a backend, define behavior.

## Syntax

Identifiers are ASCII `[A-Za-z_][A-Za-z_0-9]*`. Source is strictly UTF-8.
Keywords are reserved identifiers. Whitespace outside strings/comments is ASCII.
Intrinsic function names and prelude type names cannot be redeclared in their
respective namespaces. Top-level declarations cannot conflict with import aliases.
Decimal literals and tuple field indices use `0|[1-9][0-9]*` (no leading zeros).
Comments are `//` and non-nested `/* ... */`. Strings accept `\n`, `\r`, `\t`,
`\0`, `\"`, `\\`, and `\u{hex}` scalar escapes. Decimal integer literals only.
Every AST/IR node carries a file ID and half-open UTF-8 byte span.

```ebnf
module = { import | declaration } ;
qualified_name = IDENT { "::" IDENT } ;
fields = IDENT ":" type { "," IDENT ":" type } [ "," ] ;
place = IDENT { "." ( IDENT | INT ) | "[" expression "]" } ;
import = "import" STRING "as" IDENT ";" ;
declaration = [ "pub" ] ( function | structure | enumeration | alias ) ;
function = "fn" IDENT [ type_parameters ] "(" [ parameters ] ")" "->" type block ;
type_parameters = "<" IDENT { "," IDENT } ">" ;
parameters = [ "inout" ] IDENT ":" type { "," [ "inout" ] IDENT ":" type } ;
structure = "struct" IDENT [ type_parameters ] "{" [ fields ] "}" ;
enumeration = "enum" IDENT [ type_parameters ] "{" variant { "," variant } [ "," ] "}" ;
variant = IDENT [ "(" type { "," type } ")" ] ;
alias = "type" IDENT [ type_parameters ] "=" type ";" ;
type = qualified_name [ "<" type { "," type } ">" ] | "(" type { "," type } ")" ;
block = "{" { statement } "}" ;
statement = binding | assignment | expression ";" | block | conditional | loop
          | iteration | match | "return" [ expression ] ";"
          | ( "break" | "continue" ) ";" ;
binding = "let" [ "mut" ] IDENT ":" type "=" expression ";" ;
conditional = "if" expression block [ "else" ( block | conditional ) ] ;
loop = "while" expression block ;
iteration = "for" pattern "in" expression block ;
match = "match" expression "{" { pattern "=>" block [ "," ] } "}" ;
pattern = "_" | IDENT | qualified_name [ "(" pattern { "," pattern } ")" ]
        | "(" pattern { "," pattern } ")" | "true" | "false" ;
assignment = place "=" expression ";" ;
```

Calls take optional explicit `::<T, U>` arguments and mark mutable arguments
`inout place`. Structs use `Name { field: value }`, variants `Name::Variant(args)`,
arrays `[a, b]`, tuples `(a, b)`, fields `value.field`, tuple fields `value.0`.
From low to high precedence: `||`, `&&`, `|`, `^`, `&`, `== !=`,
`< <= > >=`, `<< >> >>>`, `+ -`, `* / %`, unary `! - ~`, call/field/index.
Binary operators associate left. Assignment is a statement. Blocks, `if`, and
`match` do not yield values. All bindings and return signatures are annotated.
Generic function arguments are explicit. No methods, implicit conversions, traits,
closures, exceptions, global mutable state, floats, async, FFI, or reference identity.

Imports are relative `.kelft` paths with explicit aliases; imported names use
`alias::Name` and must be `pub`. Cycles and duplicate declarations are errors.
Declarations in a module may refer forward to other declarations. Resolution uses
canonical files under an explicit project root (default current working directory).

## Types and values

Primitives: `i32`, `u8`, `bool`, immutable `string`, `void`. Built-ins: `Array<T>`,
`Map<K,V>` (keys: string/i32/u8/bool). Standard aliases: String, Vec<T>, Bytes;
standard generic enums: Option<T>, Result<T,E>. Generic declarations are resolved
and instantiated deterministically; unbounded specialization is diagnosed.

Every aggregate has structural value semantics, including parameters and returns.
Bindings are immutable unless `let mut`. Mutation rebuilds the affected value path.
An `inout` argument is an exclusive, nonescaping location for the duration of a call;
all other arguments must avoid the same root. Nested scoped forwarding is permitted.
Mutation is visible on any normal return, including an Error result.

Operand, argument, constructor, and assignment-place evaluation is left-to-right.
Boolean operators short-circuit. Collection loops snapshot the collection at entry.
Maps iterate ascending by numeric keys, false before true, or UTF-8 byte order.
There is no locale collation or string normalization. Equality is structural.

i32 addition/subtraction/multiplication/negation wrap. Division truncates toward zero;
zero division and MIN/-1 trap. MIN%-1 is zero. Bitwise operations use 32 bits.
Shift counts are masked with 31; >> is arithmetic, >>> logical then interpreted i32.
u8 accepts literals 0..255; arithmetic requires explicit widening.

String length/index/slice use UTF-8 bytes. Slices must be code-point aligned.
Invalid UTF-8 and invalid bounds trap with stable codes. Runtime failures print
`error[CODE]` to stderr and exit 1; recoverable filesystem failures return Result.
Resource exhaustion and timing are outside portable conformance.

## Bootstrap library

Collection, string/byte conversion, numeric conversion, SHA-256, JSON, filesystem,
path, arguments, streams, and exit operations are the bounded compiler substrate.
Host capabilities are externally supplied; unavailable operations cannot be
introduced by source or an Intent proposal. No dynamic source evaluation.
