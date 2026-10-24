//! Native installed entry. Compiler transactions reuse the reviewed protocol;
//! there is no Wasm engine or Node dependency in this binary.
const NATIVE_INSTALLED: bool = true;
mod protocol;
mod native;
mod orchestration;
mod installed_cli;
mod installed_request;
mod installed_targets;
mod installed_workspace;
mod installed_testing;
mod installed_rebuild;
#[cfg(target_os="linux")]
mod installed_linux_host;
use kelft_wasi::native_target;
#[path = "installed_execution.rs"]
mod execution;
include!(env!("KELFT_NATIVE_PINS"));
use std::{env, fs, path::PathBuf};
#[cfg(target_os="linux")]
#[path="installed_boundary_linux.rs"]
mod platform_boundary;
#[cfg(target_os="linux")]
pub(crate) use platform_boundary::boundary_command;
#[cfg(all(target_os="macos",feature="macos-host"))]
#[path="installed_boundary_macos.rs"]
mod platform_boundary;
#[cfg(all(target_os="macos",feature="macos-host"))]
pub(crate) use platform_boundary::boundary_command;
#[cfg(all(target_os="windows",feature="windows-host"))]
#[path="installed_boundary_windows.rs"]
mod platform_boundary;
#[cfg(all(target_os="windows",feature="windows-host"))]
pub(crate) use platform_boundary::boundary_command;
type Error = Box<dyn std::error::Error>;
pub(crate) fn installed_paths() -> Result<(PathBuf, PathBuf), Error> {
    let executable=fs::canonicalize(env::current_exe()?)?;
    let bin=executable.parent().ok_or("installed bin directory missing")?;
    if bin.file_name().and_then(|s|s.to_str())!=Some("bin") {return Err("install below bin/".into());}
    let suffix=native_target::Target::current()?.executable_suffix();
    let boundary=bin.join(format!("kelft-boundary{suffix}"));
    let compiler=bin.parent().ok_or("installed root missing")?.join(format!("rootfs/compiler{suffix}"));
    for (file,expected) in [(&boundary,BOUNDARY_SHA256),(&compiler,COMPILER_SHA256)] {
        let metadata=fs::symlink_metadata(file)?;
        if !metadata.file_type().is_file() || metadata.len()>268435456 || (file==&boundary||!installed_rebuild::enabled())&&protocol::hash(&fs::read(file)?)!=expected {return Err("installed native entry input changed".into());}
    }
    native_target::Target::current()?.validate_executable(&fs::read(&compiler)?)?;
    Ok((boundary,compiler))
}
pub(crate) fn compiler_sha256()->Result<String,Error>{
    let (_,compiler)=installed_paths()?;Ok(protocol::hash(&fs::read(compiler)?))
}
fn engine_dispatch(args:Vec<String>)->Result<i32,Error>{
    let end=args.iter().position(|a|a=="--").unwrap_or(args.len());
    if end<3||!matches!(args[1].as_str(),"javascript"|"wasm"){return Err("unknown explicit engine".into());}
    let(mut root,mut policy)=(None,None);let mut at=3;
    while at<end{
        if at+1>=end{return Err("engine option value missing".into());}
        let slot=match args[at].as_str(){"--project-root"=>&mut root,"--policy"=>&mut policy,_=>return Err("unsupported installed engine option".into())};
        if slot.is_some(){return Err("duplicate installed engine option".into());}*slot=Some(args[at+1].clone());at+=2;
    }
    let root=fs::canonicalize(root.ok_or("explicit engine project root required")?)?;
    if root.parent().is_none(){return Err("invalid engine project root".into());}
    let permissions:serde_json::Value=if let Some(file)=policy{
        let file=fs::canonicalize(file)?;if !file.starts_with(&root){return Err("engine policy escapes project".into());}
        if fs::metadata(&file)?.len()>1048576{return Err("engine policy exceeds bound".into());}serde_json::from_slice(&fs::read(file)?)?
    }else{serde_json::json!({"read":[],"write":[]})};
    let fields=permissions.as_object().ok_or("engine policy object required")?;
    if fields.keys().any(|s|!matches!(s.as_str(),"read"|"write"|"execute"))||fields.get("execute").is_some_and(|v|v!=&serde_json::json!(false)){return Err("engine policy cannot delegate execution".into());}
    let(mounts,_)=orchestration::permissions(&root,&permissions)?;
    let installed=fs::canonicalize(env::current_exe()?)?.parent().ok_or("installed bin")?.parent().ok_or("installed root")?.to_path_buf();
    let temporary=fs::canonicalize(native::private_temp_dir()?)?;
    let mut boundary=boundary_command()?;let command=&mut boundary.command;command.args(&args[..end]);
    for mount in mounts{
        if temporary.starts_with(&mount.host)||PathBuf::from("/tmp").starts_with(&mount.host)||mount.write&&(installed.starts_with(&mount.host)||mount.host.starts_with(&installed)){return Err("engine grant overlaps private or trusted state".into());}
        if mount.read { command.arg("--read").arg(&mount.host); }
        if mount.write { command.arg("--write").arg(&mount.host); }
    }
    if end<args.len(){command.arg("--").args(&args[end+1..]);}
    command.env_clear();
    #[cfg(all(unix,not(target_os="macos")))] {use std::os::unix::process::CommandExt;return Err(command.exec().into());}
    #[cfg(any(target_os="macos",target_os="windows"))] {use std::io::Write;let output=boundary.run(&protocol::Limits{timeout_ms:600000,memory_bytes:1<<30,stdout_bytes:16<<20,stderr_bytes:16<<20})?;std::io::stdout().write_all(&output.stdout)?;std::io::stderr().write_all(&output.stderr)?;if let Some(error)=output.failure{return Err(error.into());}output.exit.ok_or("native engine boundary interrupted".into())}
}
fn dispatch()->Result<i32,Error>{
    let mut args:Vec<String>=env::args().skip(1).collect();
    installed_rebuild::watch_lifetime(&mut args)?;
    if args.first().is_some_and(|v|v=="bootstrap"){return installed_rebuild::bootstrap(&args);}
    match installed_rebuild::stage_runtime(&args){
        Ok(Some(code))=>return Ok(code),Ok(None)=>{},Err(error)=>{
            if args.first().is_some_and(|v|v=="doctor"){println!("{}",serde_json::json!({"schema":"kelft.doctor/1","status":"failure","scope":"installed-entry-inputs","host":native_target::Target::current()?.id(),"error":error.to_string(),"certification":"not-evaluated"}));return Ok(1);}
            if args.iter().any(|v|v=="--json"){println!("{}",serde_json::json!({"schema":"kelft.command-result/1","command":args.first(),"status":"failure","error":{"code":"INSTALLED_INPUTS","message":error.to_string()}}));return Ok(1);}return Err(error);
        }
    }
    if args.first().is_some_and(|v|v=="rebuild"){return match installed_rebuild::dispatch(&args){Ok(code)=>Ok(code),Err(error)=>{if args.iter().any(|v|v=="--json"){println!("{}",serde_json::json!({"schema":"kelft.command-result/1","command":"rebuild","status":"failure","error":{"code":"REBUILD_INPUT","message":error.to_string()}}));}else{eprintln!("error[REBUILD_INPUT]: {error}");}Ok(1)}};}
    if args.first().is_some_and(|v|v=="test") {return installed_testing::dispatch(&args);}
    if args.first().is_some_and(|v|v=="target") {
        return match installed_targets::dispatch(&args){Ok(code)=>Ok(code),Err(e)=>{if args.iter().any(|v|v=="--json"){println!("{}",serde_json::json!({"schema":"kelft.command-result/1","command":"target","status":"failure","error":{"code":"COMPONENT_IO","message":e.to_string()}}));}else{eprintln!("error[COMPONENT_IO]: {e}");}Ok(1)}};
    }
    // Informational help/version remain independent of package payloads.
    if let Some(text)=installed_cli::information(&args)? {
        if args.first().is_some_and(|v|v=="capabilities") {
            let _lock=installed_targets::build_lock()?;let mut value:serde_json::Value=serde_json::from_str(&text)?;
            if installed_targets::enabled() {value["build"]["crossProfiles"]=installed_targets::status()?;value["targetCatalogSHA256"]=serde_json::json!(installed_targets::catalog_sha256());value["commands"].as_array_mut().ok_or("capability commands")?.push(serde_json::json!("target list/add/remove"));}
            value["workspace"]=installed_workspace::capabilities();
            if installed_testing::enabled(){value["commands"].as_array_mut().ok_or("capability commands")?.push(serde_json::json!("test"));}
            value["testing"]=serde_json::json!({"available":installed_testing::enabled(),"contract":"kelft.test-report/1","backend":"native","isolation":"per-case","certification":"not-evaluated"});
            value["rebuilding"]=serde_json::json!({"available":installed_rebuild::enabled(),"network":false,"hostToolsRequired":false});
            if installed_rebuild::enabled(){value["commands"].as_array_mut().ok_or("capability commands")?.push(serde_json::json!("rebuild"));}
            if installed_workspace::enabled(){for command in ["metadata","tree","lock"] {value["commands"].as_array_mut().ok_or("capability commands")?.push(serde_json::json!(command));}}
            println!("{value}");
        }else if args.first().is_some_and(|s|matches!(s.as_str(),"version"|"--version"))&&installed_targets::root()?.join("rebuild.json").is_file(){println!("{}; local rebuild",text.trim_end());}else{print!("{text}");}return Ok(0);
    }
    let _installation_lock=installed_targets::build_lock()?;
    if args.first().is_some_and(|v|v=="doctor") {
        if args.len()>2 || args.get(1).is_some_and(|v|v!="--json") {return Err("usage: kelft doctor [--json]".into());}
        let host=native_target::Target::current()?;
        let inspected=installed_paths();
        let result=match &inspected {
            Ok((boundary,compiler))=>serde_json::json!({"schema":"kelft.doctor/1","status":"success","host":host.id(),"scope":"installed-entry-inputs","compiler":compiler,"boundary":boundary,"certification":"not-evaluated","linkerSDK":"not-evaluated"}),
            Err(error)=>serde_json::json!({"schema":"kelft.doctor/1","status":"failure","host":host.id(),"scope":"installed-entry-inputs","error":error.to_string(),"certification":"not-evaluated"}),
        };
        let mut result=result;result["compilerSHA256"]=serde_json::json!(compiler_sha256().ok());result["origin"]=serde_json::json!(if installed_targets::root()?.join("rebuild.json").is_file(){"local-rebuild"}else{"distribution"});let mut valid=inspected.is_ok();if installed_targets::enabled(){match installed_targets::status(){Ok(components)=>{if components.as_array().is_some_and(|rows|rows.iter().any(|r|r["integrity"]=="modified"||r["integrity"]=="incomplete")){valid=false;result["status"]=serde_json::json!("failure");}result["components"]=components;},Err(e)=>{valid=false;result["componentError"]=serde_json::json!(e.to_string());result["status"]=serde_json::json!("failure");}}}
        result["release"]=installed_cli::installed_release()?;
        result["workspace"]=installed_workspace::capabilities();
        println!("{}",serde_json::to_string(&result)?);return Ok(if valid{0}else{1});
    }
    if args.first().is_some_and(|v|matches!(v.as_str(),"metadata"|"tree"|"lock")) {return installed_workspace::dispatch(&args);}
    if args.first().is_some_and(|v|installed_request::is_public(v)) {
        return public_dispatch(&args);
    }
    let (_,compiler)=installed_paths()?;
    match args.first().map(String::as_str) {
        Some("native-build"|"protocol"|"--sha256-self-test") => {
            #[cfg(all(unix,not(target_os="macos")))] { use std::os::unix::process::CommandExt;
                let mut boundary=boundary_command()?;
                return Err(boundary.command.args(args).env_clear().exec().into()); }
            #[cfg(any(target_os="macos",target_os="windows"))] {
                use std::io::Write;let mut boundary=boundary_command()?;boundary.command.args(args).env_clear();
                let limits=protocol::Limits{timeout_ms:600000,memory_bytes:1<<30,stdout_bytes:16<<20,stderr_bytes:16<<20};let output=boundary.run(&limits)?;
                std::io::stdout().write_all(&output.stdout)?;std::io::stderr().write_all(&output.stderr)?;if let Some(error)=output.failure{return Err(error.into());}return output.exit.ok_or("native boundary interrupted".into());
            }
        }
        Some("engine-run")=>return engine_dispatch(args),
        Some("run"|"intent")=>{},
        _=>return Err("expected native-build, run, intent verify/accept, or engine-run; use kelft help".into()),
    }
    if args[0]=="intent" && !args.get(1).is_some_and(|a|a=="verify"||a=="accept") {return Err("installed Intent command must be verify or accept".into());}
    let index=args.iter().position(|a|a=="--project-root").ok_or("explicit --project-root required")?;
    let root=fs::canonicalize(args.get(index+1).ok_or("project root missing")?)?;
    if root.parent().is_none() || !root.is_dir() {return Err("invalid native project root".into());}
    args.drain(index..index+2);
    execution::PROJECT_ROOT.set(root.clone()).map_err(|_|"project authority already initialized")?;
    // Candidate code can invoke the installed compiler through an explicit
    // process grant. Never hold the coordinator's installation lock across it.
    drop(_installation_lock);
    orchestration::dispatch(orchestration::Options{compiler,compiler_hash:compiler_sha256()?,root,args,javascript_runtime:None})
}
fn public_dispatch(args:&[String])->Result<i32,Error>{
    use std::io::Write;
    let host=native_target::Target::current()?;
    let json=args.iter().any(|a|a=="--json");
    let failure=|code:&str,message:String,exit:i32|->Result<i32,Error>{
        if json {println!("{}",serde_json::json!({"schema":"kelft.command-result/1","status":"failure","command":args[0],"host":host.id(),"error":{"code":code,"message":message}}));}
        else {eprintln!("error[{code}]: {message}");}Ok(exit)
    };
    let mut request=match installed_request::parse(args,host,&env::current_dir()?) {Ok(r)=>r,Err(e)=>return failure("INVALID_INVOCATION",e,64)};
    if let Err(e)=request.boundary_args(host){return failure("UNSUPPORTED_TARGET_PROFILE",e,1);}
    if let Err(e)=request.prepare_paths(&env::current_dir()?){return failure("INVALID_PATH",e,1);}
    if installed_targets::enabled()&&request.target!=host&&request.emit=="executable"&&!installed_targets::available(request.target.id())?{let (arch,platform)=installed_request::parts(request.target);return failure("MISSING_COMPONENT",format!("target pack unavailable or altered; install this release's pack with kelft target add {arch}-{platform} --from PACK.tar.gz"),1);}
    let routed=request.boundary_args(host)?;
    if let Err(e)=installed_paths(){return failure("INSTALLED_INPUTS",e.to_string(),1);}
    let mut boundary=match boundary_command(){Ok(b)=>b,Err(e)=>return failure("BOUNDARY_FAILURE",e.to_string(),1)};boundary.command.args(routed).env_clear();
    let limits=protocol::Limits{timeout_ms:600000,memory_bytes:1<<30,stdout_bytes:16<<20,stderr_bytes:16<<20};
    // Captured public results use the same bounded lifetime supervisor as Windows/macOS.
    #[cfg(all(unix,not(target_os="macos")))] let output=native::run(&mut boundary.command,&limits);
    #[cfg(any(target_os="macos",target_os="windows"))] let output=boundary.run(&limits);
    let output=match output{Ok(value)=>value,Err(e)=>return failure("BOUNDARY_FAILURE",e.to_string(),1)};
    if let Some(e)=output.failure{return failure("BOUNDARY_FAILURE",e,1);}
    let status=match output.exit{Some(status)=>status,None=>return failure("BOUNDARY_FAILURE","native compiler exit missing".into(),1)};
    if request.json {
        let data=if output.stdout.is_empty(){serde_json::Value::Null}else{serde_json::from_slice(&output.stdout).unwrap_or_else(|_|serde_json::Value::String(String::from_utf8_lossy(&output.stdout).into_owned()))};
        println!("{}",serde_json::json!({"schema":"kelft.command-result/1","status":if status==0{"success"}else{"failure"},"command":request.command,"host":host.id(),"target":request.target.id(),"emit":if request.command=="build"{Some(request.emit)}else{None},"data":data,"diagnostics":String::from_utf8_lossy(&output.stderr)}));
    } else {std::io::stdout().write_all(&output.stdout)?;std::io::stderr().write_all(&output.stderr)?;}
    Ok(if status==0{0}else{1})
}
fn main(){
    // The native coordinator owns session keys and receipts, outside every candidate namespace.
    #[cfg(unix)] unsafe { unsafe extern "C" {fn umask(mask:u32)->u32;} umask(0o077); }
    match dispatch(){Ok(code)=>std::process::exit(code),Err(error)=>{eprintln!("error[K0600]: {error}");std::process::exit(125);}}
}
