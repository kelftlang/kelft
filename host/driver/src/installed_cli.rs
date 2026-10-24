//! Informational commands do not initialize project authority or launch workers.
use crate::native_target::Target;
use std::{fs,io::Read,path::Path};

fn valid_version(value:&str)->bool {
    if value.is_empty()||value.len()>128{return false;}
    fn identifiers(value:&str,pre:bool)->bool {value.split('.').all(|part|!part.is_empty()&&part.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'-')&&!(pre&&part.len()>1&&part.starts_with('0')&&part.bytes().all(|b|b.is_ascii_digit())))}
    let mut build=value.split('+');let first=build.next().unwrap();if let Some(extra)=build.next(){if !identifiers(extra,false)||build.next().is_some(){return false;}}
    let (core,pre)=first.split_once('-').map_or((first,None),|(a,b)|(a,Some(b)));if pre.is_some_and(|p|!identifiers(p,true)){return false;}
    let parts:Vec<_>=core.split('.').collect();parts.len()==3&&parts.iter().all(|part|!part.is_empty()&&part.len()<=8&&part.bytes().all(|b|b.is_ascii_digit())&&(part.len()==1||!part.starts_with('0')))
}
pub fn embedded_release()->serde_json::Value {serde_json::from_str(include_str!("../release.json")).expect("embedded release identity")}
pub fn read_release(root:&Path)->Result<Option<serde_json::Value>,&'static str> {
    let file=root.join("release.json");let stat=match fs::symlink_metadata(&file){Ok(value)=>value,Err(error)if error.kind()==std::io::ErrorKind::NotFound=>return Ok(None),Err(_)=>return Err("cannot read installed release metadata")};
    if !stat.is_file()||stat.len()>65536{return Err("invalid compiler release metadata");}
    let mut bytes=Vec::new();fs::File::open(file).map_err(|_|"cannot read compiler release metadata")?.take(65537).read_to_end(&mut bytes).map_err(|_|"cannot read compiler release metadata")?;
    if bytes.len()>65536{return Err("invalid compiler release metadata");}let value:serde_json::Value=serde_json::from_slice(&bytes).map_err(|_|"invalid compiler release metadata")?;
    if !matches!(value["schema"].as_str(),Some("kelft.compiler-release/1"|"kelft.compiler-version/1"))||!value["version"].as_str().is_some_and(valid_version){return Err("invalid compiler release metadata");}
    if value["coreVersion"]!="0.1"||value["intentVersion"]!="0.2"{return Err("unsupported compiler language versions");}Ok(Some(value))
}
pub fn installed_release()->Result<serde_json::Value,&'static str>{
    let exe=std::env::current_exe().map_err(|_|"installed executable unavailable")?;let exe=fs::canonicalize(exe).map_err(|_|"installed executable unavailable")?;
    if let Some(bin)=exe.parent(){if bin.file_name().and_then(|name|name.to_str())==Some("bin"){if let Some(root)=bin.parent(){if let Some(value)=read_release(root)?{return Ok(value);}}}}
    Ok(embedded_release())
}

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
            Ok(Some(format!("{}\n",serde_json::json!({"schema":"kelft.capabilities/1","host":host.id(),"hostFeatures":["release-metadata/1"],"certification":"not-evaluated","commands":["build","check","tokens","ast","ir","native-build","run","intent verify","intent accept","engine-run","help","version","capabilities","doctor"],"build":{"defaultTarget":host.id(),"defaultProjectRoot":"current-directory","targetSyntax":["ARCH-PLATFORM","--target ARCH --platform PLATFORM"],"profiles":[{"target":host.id(),"emit":["object","executable"]}],"crossProfiles":cross,"downloadsDuringBuild":false},"optionalEngines":"separately-prepared"}))))
        }
        "version" | "--version" => {
            if args.len() != 1 {
                return Err("version accepts no arguments");
            }
            let package = installed_release()?;
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
    #[test]
    fn metadata_is_bounded_and_confined_to_the_named_installation() {
        let root=std::env::temp_dir().join(format!("kelft version λ {}-{}",std::process::id(),std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));fs::create_dir(&root).unwrap();
        assert!(read_release(&root).unwrap().is_none());
        let value=serde_json::json!({"schema":"kelft.compiler-release/1","version":"0.1.0-alpha.2","coreVersion":"0.1","intentVersion":"0.2"});fs::write(root.join("release.json"),value.to_string()).unwrap();assert_eq!(read_release(&root).unwrap().unwrap()["version"],"0.1.0-alpha.2");
        for text in ["{", "{}", &"x".repeat(65537)]{fs::write(root.join("release.json"),text).unwrap();assert!(read_release(&root).is_err());}
        fs::remove_file(root.join("release.json")).unwrap();fs::remove_dir(root).unwrap();
    }
    #[test]
    fn version_metadata_uses_canonical_semver() {
        for version in ["0.1.0-alpha.2","1.2.3","1.2.3-rc.1+build.01"]{assert!(valid_version(version));}
        for version in ["","01.2.3","1.2","1.2.3-01","1.2.3-","1.2.3+x+y","1.2.3\n"]{assert!(!valid_version(version));}
    }
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
