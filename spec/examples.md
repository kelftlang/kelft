# Source examples

These examples illustrate the existing source contracts. They do not extend the
grammar or establish application acceptance. First-party code blocks on this
page are available under MIT-0.

## Executable Core

Save this as `hello.kelft` and check it with `kelft check hello.kelft --json`.
An explicit native build uses `kelft build hello.kelft -o hello`; building does
not execute the result. Source and output paths are relative to the invocation
directory, with imports restricted by the selected project root.

```kelft
fn greeting(name: string) -> string {
    return "Hello, " + name;
}

fn main() -> void {
    println(greeting("Kelft"));
}
```

All function parameters and return types are explicit. This example uses Core
strings; lengths and spans follow the UTF-8 contracts in the language reference.

## Intent declarations

An Intent module also uses `.kelft`, with a top-level `app` declaration. Save
this separately as `greeting.kelft`; do not concatenate it with the Core module.

```kelft
app Greeting {
    intent "Greet a person."
    behavior greet(name: Text) -> Text {
        must (name != "")
        ensures (result != "")
    }
}
```

The prose describes an outcome, while parentheses introduce formal Boolean
predicates. `result` belongs to a non-void behavior's postcondition. Checking
this file validates declarations; the unbound behavior still needs an
implementation and trusted verification evidence. Build File in the editor
accepts Core source, not application synthesis or acceptance.
