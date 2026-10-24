//! Fixed mechanisms around the embedded native Kelft workspace policy.
//! This adapter never parses manifests, resolves packages or creates lock text.
use kelft_wasi::{workspace_store::{Snapshot, fingerprint}, native_target::Target};
use serde_json::{Value, json};
use std::{fs, io::{self, Write}, path::{Path, PathBuf}};
type Error = Box<dyn std::error::Error>;
#[cfg(kelft_workspace)]
const POLICY: &[u8] = include_bytes!(env!("KELFT_WORKSPACE_POLICY"));
#[cfg(not(kelft_workspace))]
const POLICY: &[u8] = &[];
pub fn enabled() -> bool { !POLICY.is_empty() }
fn identity() -> Result<Value, Error> {
    crate::installed_paths()?;
    #[cfg(target_os="linux")]
    let executable = fs::File::open("/proc/self/exe")?;
    #[cfg(not(target_os="linux"))]
    let executable = fs::File::open(std::env::current_exe()?)?;
    Ok(json!({"host":Target::current()?.id(),"compiler-sha256":crate::compiler_sha256()?,
        "boundary-sha256":crate::BOUNDARY_SHA256,"coordinator-sha256":fingerprint(executable,268435456)?["sha256"],
        "workspace-policy-sha256":crate::protocol::hash(POLICY)}))
}
pub fn capabilities() -> Value {
    json!({"available":enabled(),"contract":"kelft.workspace-command/2","lockContract":"kelft-local-lock/1",
        "lockScope":"local-manifest-graph","sourceContentPinned":false,"workspaceBuilds":false,
        "lockContracts":["kelft-local-lock/1","kelft-local-lock/2"],"declaredInputPinsAvailable":enabled(),
        "installedToolchain":if enabled(){identity().unwrap_or_else(|e|json!({"error":e.to_string()}))}else{Value::Null},
        "network":false,"certification":"not-evaluated","policySHA256":if enabled(){Some(crate::protocol::hash(POLICY))}else{None}})
}
fn forward(path: &Path) -> Result<String, Error> {
    Ok(path.to_str().ok_or("workspace paths must be Unicode")?.replace('\\', "/"))
}
fn discover(manifest: &str, cwd: &Path) -> Result<(Vec<PathBuf>, Value, Vec<Snapshot>), Error> {
    let start = if manifest.is_empty() {fs::canonicalize(cwd)?} else {
        let path = if Path::new(manifest).is_absolute() {PathBuf::from(manifest)} else {cwd.join(manifest)};
        if path.file_name().and_then(|s|s.to_str()) != Some("kelft.toml") {return Err("--manifest-path must name kelft.toml".into());}
        fs::canonicalize(path.parent().ok_or("manifest parent missing")?)?
    };
    let mut paths = vec![];let mut rows = vec![];let mut retained = vec![];
    for parent in start.ancestors() {
        if parent.parent().is_none() { break; }
        if paths.len() >= 32 {return Err("workspace discovery exceeds 32 ancestors".into());}
        let mut snapshot = Snapshot::open(parent)?;
        rows.push(json!({"relative":forward(start.strip_prefix(parent)?)?,"manifest":snapshot.observe("kelft.toml")?}));
        paths.push(parent.to_owned());
        retained.push(snapshot);
    }
    Ok((paths, Value::Array(rows), retained))
}
fn run(args: &[String]) -> Result<i32, Error> {
    if !enabled() {return Err("workspace policy is unavailable in this installation; use a workspace-capable native distribution".into());}
    crate::installed_paths()?;
    let cwd = fs::canonicalize(std::env::current_dir()?)?;
    let mut request = json!({"schema":"kelft.workspace-command/2","arguments":args,"installedToolchain":identity()?});
    let mut roots = vec![];let mut discovery = vec![];let mut snapshot: Option<Snapshot> = None;
    for _ in 0..144 {
        let action = crate::installed_targets::evaluate(POLICY, &request)?;
        if action["schema"] != "kelft.workspace-action/2" {return Err("invalid workspace action contract".into());}
        match action["operation"].as_str().ok_or("workspace operation missing")? {
            "discover" => {
                if request.get("ancestors").is_some() {return Err("repeated workspace discovery".into());}
                let (paths, observations, retained) = discover(action["manifest"].as_str().ok_or("workspace discovery path missing")?, &cwd)?;
                roots = paths;discovery = retained;request["ancestors"] = observations;
            }
            "select-root" => {
                if snapshot.is_some() {return Err("workspace policy changed its selected root".into());}
                let index = action["root"].as_u64().ok_or("workspace root index missing")? as usize;
                let root = roots.get(index).ok_or("workspace root index outside observations")?;
                let installed = crate::installed_targets::root()?;
                if args.first().is_some_and(|a|a=="lock") && root.starts_with(&installed) {
                    return Err("workspace lock overlaps the running installation".into());
                }
                snapshot = Some(Snapshot::open(root)?);request["selectedRoot"] = json!(index);
                request["manifests"] = json!({});request["locks"] = json!({});request["toolchains"] = json!({});request["sources"] = json!({});
            }
            "read-manifests" | "read-locks" | "read-toolchains" | "read-sources" => {
                let kind = match action["operation"].as_str() {Some("read-manifests")=>"manifests",Some("read-locks")=>"locks",Some("read-toolchains")=>"toolchains",_=>"sources"};
                let leaf = match kind {"manifests"=>"kelft.toml","locks"=>"kelft.lock",_=>"kelft-toolchain.toml"};
                let paths = action["paths"].as_array().ok_or("workspace read paths missing")?;
                if paths.is_empty() || paths.len() > 128 {return Err("workspace read count".into());}
                for path in paths {
                    let path = path.as_str().ok_or("workspace read path must be text")?;
                    if (kind != "sources" && path.rsplit('/').next() != Some(leaf)) || request[kind].get(path).is_some() {return Err("invalid/repeated workspace read".into());}
                    let store = snapshot.as_mut().ok_or("workspace root missing")?;
                    request[kind][path] = if kind == "sources" {store.observe_source(path)?} else {json!(store.observe(path)?)};
                }
            }
            "acquire-lock" => {
                for store in &discovery {store.unchanged()?;}
                if args.first().map(String::as_str) != Some("lock") {return Err("read-only workspace command requested maintenance".into());}
                request["locks"]["kelft.lock"] = json!(snapshot.as_mut().ok_or("workspace root missing")?.acquire()?);
                request["exclusive"] = json!(true);
            }
            "publish-lock" => {
                for store in &discovery {store.unchanged()?;}
                if identity()? != request["installedToolchain"] {return Err("installed toolchain changed; retry the command".into());}
                if args.first().map(String::as_str) != Some("lock") || request["exclusive"] != true || request["published"] == true {return Err("workspace publication not authorized".into());}
                let text = action["contents"].as_str().ok_or("workspace lock text missing")?;
                snapshot.as_mut().ok_or("workspace root missing")?.publish(text)?;
                request["locks"]["kelft.lock"] = json!(text);request["published"] = json!(true);
            }
            "complete" => {
                for store in &discovery {store.unchanged()?;}
                if let Some(store) = &snapshot {store.unchanged()?;}
                if action["result"]["data"]["toolchainVerified"] == true && identity()? != request["installedToolchain"] {return Err("installed toolchain changed; retry the command".into());}
                let mut result = action["result"].clone();
                if result["schema"] != "kelft.command-result/1" {return Err("invalid workspace result".into());}
                result["command"] = json!(args[0]);result["host"] = json!(Target::current()?.id());
                let code = result["exit"].as_i64().ok_or("workspace exit missing")?;
                if ![0,1,64].contains(&code) {return Err("invalid workspace exit".into());}
                if args.iter().any(|v|v=="--json") {println!("{result}");}
                else if code != 0 {eprintln!("error[{}]: {}",result["error"]["code"].as_str().unwrap_or("WORKSPACE"),result["error"]["message"].as_str().unwrap_or("workspace operation failed"));}
                else {io::stdout().write_all(action["text"].as_str().ok_or("workspace text result missing")?.as_bytes())?;}
                return Ok(code as i32);
            }
            _ => return Err("unsupported workspace operation".into()),
        }
    }
    Err("workspace policy step limit".into())
}
pub fn dispatch(args: &[String]) -> Result<i32, Error> {
    match run(args) {
        Ok(code) => Ok(code),
        Err(error) => {
            if args.iter().any(|a|a=="--json") {println!("{}",json!({"schema":"kelft.command-result/1","command":args[0],"status":"failure","error":{"code":"WORKSPACE_IO","message":error.to_string()}}));}
            else {eprintln!("error[WORKSPACE_IO]: {error}");}
            Ok(1)
        }
    }
}
