//! Informational commands do not initialize project authority or launch workers.
use crate::native_target::Target;

const USAGE: &str = "Usage: kelft COMMAND [OPTIONS]\n\
Commands:\n\
  rebuild [--source DIRECTORY] [--out DIRECTORY] [--json]\n\
  test [PATH] [--corpus] [--filter TEXT] [--shard I/N] [--list] [--json] [--project-root ROOT] [--capabilities POLICY]\n\
  build SOURCE -o OUTPUT [--target ARCH-PLATFORM] [--emit object|executable]\n\
  check|tokens|ast|ir SOURCE [--project-root ROOT] [--json]\n\
  capabilities [--json]\n\
  doctor [--json]\n\
  target list|add TARGET --from PACK.tar.gz|remove TARGET [--json]\n\
  metadata|tree|lock [--manifest-path kelft.toml] [--locked] [--offline] [--json]\n\
  native-build SOURCE --project-root ROOT -o EXECUTABLE\n\
  run SOURCE --project-root ROOT [--capabilities POLICY] [-- ARGS...]\n\
  intent verify INTENT SOURCE POLICY FIXTURES --project-root ROOT [--json]\n\
  intent accept INTENT SOURCE POLICY FIXTURES LEDGER --project-root ROOT [--json]\n\
  engine-run javascript|wasm MODULE --project-root ROOT [--policy POLICY] [-- ARGS...]\n\
  help [COMMAND]\n\
  version\n\n\
Optional engines require a separately prepared platform profile.\n\
Use kelft help COMMAND for details.\n";

pub fn information(args: &[String]) -> Result<Option<String>, &'static str> {
    let Some(command) = args.first().map(String::as_str) else {
        return Ok(None);
    };
    match command {
        "capabilities" => {
            if args.len()>2 || args.get(1).is_some_and(|v|v!="--json") {return Err("usage: kelft capabilities [--json]");}
            let host=Target::current().map_err(|_|"unsupported native host")?;
            let mut cross=vec![];
            if host==Target::WindowsX64 {
                let pinned=option_env!("KELFT_WINDOWS_LINUX_CROSS_SHA256");
                cross.push(serde_json::json!({"target":"linux-x86_64","emit":if pinned.is_some(){vec!["object","executable"]}else{vec!["object"]},"linkerProfile":if pinned.is_some(){Some("lld-elf-static/1")}else{None},"profileSHA256":pinned,"readiness":"not-evaluated","certification":"not-evaluated"}));
            }
            if host==Target::LinuxX64 {
                let pinned=option_env!("KELFT_LINUX_WINDOWS_CROSS_SHA256");
                cross.push(serde_json::json!({"target":"windows-x86_64","emit":if pinned.is_some(){vec!["object","executable"]}else{vec!["object"]},"linkerProfile":if pinned.is_some(){Some("lld-coff/1")}else{None},"profileSHA256":pinned,"readiness":"not-evaluated","certification":"not-evaluated"}));
            }
            Ok(Some(format!("{}\n",serde_json::json!({"schema":"kelft.capabilities/1","host":host.id(),"certification":"not-evaluated","commands":["build","check","tokens","ast","ir","native-build","run","intent verify","intent accept","engine-run","help","version","capabilities","doctor"],"build":{"defaultTarget":host.id(),"defaultProjectRoot":"current-directory","targetSyntax":["ARCH-PLATFORM","--target ARCH --platform PLATFORM"],"profiles":[{"target":host.id(),"emit":["object","executable"]}],"crossProfiles":cross,"downloadsDuringBuild":false},"optionalEngines":"separately-prepared"}))))
        }
        "version" | "--version" => {
            if args.len() != 1 {
                return Err("version accepts no arguments");
            }
            let package: serde_json::Value =
                serde_json::from_str(include_str!("../release.json"))
                    .map_err(|_| "invalid embedded package identity")?;
            let version = package["version"]
                .as_str()
                .ok_or("embedded version missing")?;
            let target = Target::current().map_err(|_| "unsupported native host")?;
            Ok(Some(format!(
                "kelft {version}; Kelft-SH 0.1; Intent 0.2; installed native {}\n",
                target.id()
            )))
        }
        "help" | "--help" | "-h" => {
            if args.len() > 2 || command != "help" && args.len() != 1 {
                return Err("expected help [COMMAND] or --help");
            }
            let topic = args.get(1).map(String::as_str);
            let text = match topic {
                Some("rebuild") => "Usage: kelft rebuild [--source DIRECTORY] [--out DIRECTORY] [--json]\nRebuild the Kelft compiler offline with this installation's native host and linker.\nDefaults to the current source directory and build/local below that source.\n",
                Some("test") => "Usage: kelft test [PATH] [--corpus] [--filter TEXT] [--shard I/N] [--list] [--json] [--project-root ROOT] [--capabilities POLICY]\nRun native Kelft test functions, isolated per case. Defaults to tests/kelft.\nWith --corpus, run shared conformance fixtures (default tests/conformance.json).\n",
                None => USAGE,
                Some("metadata"|"tree"|"lock") => "Usage: kelft metadata|tree|lock [--manifest-path kelft.toml] [--locked] [--offline] [--json]\nRequires a workspace-capable installation. Local path manifests only.\nmetadata/tree are read-only; lock explicitly updates the root kelft.lock.\n--locked rejects missing or stale locks. kelft-toolchain.toml enables declared source and installed toolchain pins.\nDeclare [sources] files in each package. Import closure and workspace builds remain unavailable.\n",
                Some("build") => "Usage: kelft build SOURCE -o OUTPUT [--target ARCH-PLATFORM] [--platform PLATFORM] [--emit object|executable] [--project-root ROOT] [--json]\nDefaults to the host target and current project directory.\nOptions: --capabilities POLICY, --intent DECLARATIONS, --bindings BINDINGS\nCross builds require a separately prepared offline target profile; unavailable profiles fail closed.\n",
                Some("check"|"tokens"|"ast"|"ir") => "Usage: kelft check|tokens|ast|ir SOURCE [--project-root ROOT] [--intent DECLARATIONS] [--bindings BINDINGS] [--json]\nInspect source through the measured compiler without output-directory or linker authority.\n",
                Some("capabilities") => "Usage: kelft capabilities [--json]\nDescribe this coordinator's command interfaces without claiming target certification.\n",
                Some("doctor") => "Usage: kelft doctor [--json]\nInspect installed compiler/boundary identities. Linker/SDK execution and certification require separate verification.\n",
                Some("native-build") => {
                    "Usage: kelft native-build SOURCE --project-root ROOT -o EXECUTABLE\n\
Compile and link a native executable through the measured compiler and linker.\n\
Options: --capabilities POLICY, --intent DECLARATIONS, --bindings BINDINGS, --object-output OBJECT\n"
                }
                Some("run") => {
                    "Usage: kelft run SOURCE --project-root ROOT [--capabilities POLICY] [-- ARGS...]\n\
Build and execute with separate compiler and candidate authority.\n\
Arguments after -- are passed to the program; its exit status is returned.\n"
                }
                Some("intent") => {
                    "Usage: kelft intent verify INTENT SOURCE POLICY FIXTURES --project-root ROOT [--json]\n\
       kelft intent accept INTENT SOURCE POLICY FIXTURES LEDGER --project-root ROOT [--json]\n\
Verify native behavior against trusted fixtures and policy. Acceptance writes an authenticated ledger event.\n"
                }
                Some("engine-run") => {
                    "Usage: kelft engine-run javascript|wasm MODULE --project-root ROOT [--policy POLICY] [-- ARGS...]\n\
Requires a separately prepared native platform engine profile; unavailable profiles fail closed.\n\
The policy grants filesystem reads and writes and cannot delegate execution.\n"
                }
                Some("target") => {
                    "Usage: kelft target list [--json]\n       kelft target add TARGET --from PACK.tar.gz [--json]\n       kelft target remove TARGET [--json]\n\nInstall local, release-locked offline target packs. The native profile belongs to the core.\n"
                }
                Some("version") => {
                    "Usage: kelft version\nPrint the compiler release, language versions and installed native target.\n"
                }
                Some("help") => {
                    "Usage: kelft help [COMMAND]\nAliases for general help: --help, -h\n"
                }
                Some(_) => return Err("unknown installed help command"),
            };
            Ok(Some(text.to_owned()))
        }
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|s| (*s).into()).collect()
    }
    #[test]
    fn help_describes_explicit_authority_and_optional_profiles() {
        let help = information(&args(&["help"])).unwrap().unwrap();
        assert_eq!(information(&args(&["--help"])).unwrap().unwrap(), help);
        assert_eq!(information(&args(&["-h"])).unwrap().unwrap(), help);
        assert!(help.contains("--project-root ROOT"));
        assert!(help.contains("separately prepared platform profile"));
        assert!(!help.contains("protocol"));
        assert!(
            information(&args(&["help", "engine-run"]))
                .unwrap()
                .unwrap()
                .contains("fail closed")
        );
    }
    #[test]
    fn version_identifies_embedded_release_and_actual_host() {
        let version = information(&args(&["version"])).unwrap().unwrap();
        assert_eq!(
            version,
            information(&args(&["--version"])).unwrap().unwrap()
        );
        assert!(version.starts_with("kelft "));
        assert!(version.ends_with(&format!("{}\n", Target::current().unwrap().id())));
    }
    #[test]
    fn informational_commands_do_not_swallow_execution_or_extra_arguments() {
        for command in ["native-build", "run", "intent", "engine-run", "protocol"] {
            assert!(information(&args(&[command])).unwrap().is_none());
        }
        for values in [
            &["version", "run"][..],
            &["help", "unknown"],
            &["--help", "run"],
            &["help", "run", "extra"],
        ] {
            assert!(information(&args(values)).is_err());
        }
    }
}
