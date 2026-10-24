use crate::{
    execution,
    protocol::{self, Limits, Mount, WorkerRequest},
};
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::Sha256;
use std::{
    fs,
    io::Write,
    path::{Component, Path, PathBuf},
    process::Command,
};
type Error = Box<dyn std::error::Error>;
fn installed_target() -> &'static str {
    crate::native_target::Target::current().expect("validated native host").artifact()
}
fn installed_profile() -> &'static str {
    crate::native_target::Target::current().expect("validated native host").runtime()
}

pub struct Options {
    pub compiler: PathBuf,
    pub compiler_hash: String,
    pub root: PathBuf,
    pub args: Vec<String>,
    pub javascript_runtime: Option<PathBuf>,
}
pub fn canonical(path: &Path) -> Result<PathBuf, Error> {
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut clean = PathBuf::new();
    for part in absolute.components() {
        match part {
            Component::ParentDir => {
                clean.pop();
            }
            Component::CurDir => {}
            other => clean.push(other.as_os_str()),
        }
    }
    let mut existing = clean.clone();
    let mut tail = vec![];
    loop {
        match fs::symlink_metadata(&existing) {
            Ok(_) => break,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                tail.push(
                    existing
                        .file_name()
                        .ok_or("invalid filesystem path")?
                        .to_owned(),
                );
                existing.pop();
            }
            Err(error) => return Err(error.into()),
        }
    }
    let mut result = fs::canonicalize(existing)?;
    for component in tail.iter().rev() {
        result.push(component);
    }
    Ok(result)
}
fn guest(root: &Path, path: &str) -> Result<String, Error> {
    let path = canonical(&root.join(path))?;
    Ok(crate::native_target::guest_path(root, &path)?)
}
fn configuration(read: &[String], write: &[String]) -> String {
    let mut out = "1c8:/project".to_owned();
    for (kind, roots) in [('r', read), ('w', write)] {
        for root in roots {
            out.push(kind);
            out.push_str(&root.len().to_string());
            out.push(':');
            out.push_str(root);
        }
    }
    out
}
fn compiler_request(
    options: &Options,
    args: Vec<String>,
    output: &Path,
    control: Option<&Path>,
    fixtures: Option<&Path>,
    ledger: Option<&Path>,
) -> Result<WorkerRequest, Error> {
    let mut mounts = vec![
        Mount {
            host: options.root.clone(),
            guest: "/project".into(),
            read: true,
            write: false,
        },
        Mount {
            host: canonical(output)?,
            guest: "/output".into(),
            read: true,
            write: true,
        },
    ];
    let mut read = vec!["/project".to_owned(), "/output".to_owned()];
    let mut write = vec!["/output".to_owned()];
    if let Some(path) = control {
        mounts.push(Mount {
            host: canonical(path)?,
            guest: "/control".into(),
            read: true,
            write: false,
        });
        read.push("/control".into());
    }
    if let Some(path) = fixtures {
        mounts.push(Mount {
            host: canonical(path)?,
            guest: "/fixtures".into(),
            read: true,
            write: false,
        });
        read.push("/fixtures".into());
    }
    if let Some(path) = ledger {
        mounts.push(Mount {
            host: canonical(path)?,
            guest: "/ledger".into(),
            read: true,
            write: true,
        });
        read.push("/ledger".into());
        write.push("/ledger".into());
    }
    let bytes = fs::read(&options.compiler)?;
    if protocol::hash(&bytes) != options.compiler_hash {
        return Err("trusted compiler changed during the operation".into());
    }
    Ok(WorkerRequest {
        schema_version: "0.1".into(),
        module: canonical(&options.compiler)?,
        artifact_hash: protocol::hash(&bytes),
        args,
        mounts,
        configuration: configuration(&read, &write),
        limits: Limits {
            timeout_ms: 300_000,
            memory_bytes: 1 << 30,
            stdout_bytes: 64 << 20,
            stderr_bytes: 64 << 20,
        },
    })
}
pub(crate) fn invoke(
    options: &Options,
    args: Vec<String>,
    output: &Path,
    control: Option<&Path>,
    fixtures: Option<&Path>,
    ledger: Option<&Path>,
) -> Result<(i32, Vec<u8>, Vec<u8>), Error> {
    let result = execution::execute(&compiler_request(
        options, args, output, control, fixtures, ledger,
    )?)?;
    if result.status != "exited" {
        return Err(result.error.unwrap_or(result.status).into());
    }
    Ok((
        result.exit.ok_or("compiler exit missing")?,
        protocol::unhex(&result.stdout_hex)?,
        protocol::unhex(&result.stderr_hex)?,
    ))
}
fn phase(
    options: &Options,
    phase: &str,
    output: &Path,
    control: &Path,
    fixtures: &Path,
    ledger: Option<&Path>,
) -> Result<Value, Error> {
    let (code, stdout, stderr) = invoke(
        options,
        vec![
            "protocol".into(),
            phase.into(),
            "/control/request.json".into(),
        ],
        output,
        Some(control),
        Some(fixtures),
        ledger,
    )?;
    if ![0, 1, 2].contains(&code) || !stderr.is_empty() {
        return Err(format!(
            "compiler protocol failed: {}",
            String::from_utf8_lossy(&stderr)
        )
        .into());
    }
    if stdout.is_empty() {
        return Err("compiler returned empty protocol response".into());
    }
    Ok(serde_json::from_slice(&stdout)?)
}
fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str, Error> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing string field {key}").into())
}
fn random() -> Result<String, Error> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| "session entropy unavailable")?;
    Ok(protocol::hex(&bytes))
}
fn write_json(path: &Path, value: &Value) -> Result<(), Error> {
    fs::write(path, serde_json::to_vec(value)?)?;
    Ok(())
}
fn registry_snapshot(from: &Path, to: Option<&Path>) -> Result<Value, Error> {
    fn copy(
        from: &Path,
        to: Option<&Path>,
        prefix: &str,
        entries: &mut serde_json::Map<String, Value>,
        total: &mut u64,
    ) -> Result<(), Error> {
        if let Some(to) = to {
            fs::create_dir_all(to)?;
        }
        let mut files: Vec<_> = fs::read_dir(from)?.collect::<Result<_, _>>()?;
        files.sort_by_key(|e| e.file_name());
        for entry in files {
            let metadata = fs::symlink_metadata(entry.path())?;
            if metadata.file_type().is_symlink() {
                return Err("fixture registry symlinks are not permitted".into());
            }
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| "fixture name is not UTF-8")?;
            let key = format!("{prefix}{name}");
            let destination = to.map(|to| to.join(&name));
            if metadata.is_dir() {
                copy(
                    &entry.path(),
                    destination.as_deref(),
                    &(key + "/"),
                    entries,
                    total,
                )?;
            } else {
                *total += metadata.len();
                if metadata.len() > 1 << 20 || *total > 64 << 20 || entries.len() >= 4096 {
                    return Err("fixture registry exceeds limits".into());
                }
                let bytes = fs::read(entry.path())?;
                entries.insert(key, Value::String(protocol::hash(&bytes)));
                if let Some(destination) = destination {
                    fs::write(destination, bytes)?;
                }
            }
        }
        Ok(())
    }
    let mut entries = serde_json::Map::new();
    let mut total = 0;
    copy(from, to, "", &mut entries, &mut total)?;
    Ok(Value::Object(entries))
}
/// Private artifact handoff paths are already absolute paths inside the engine
/// namespace. They must not be translated through the host /project mapping.
#[cfg(feature = "wasi")]
pub(crate) fn artifact_permissions(value: &Value) -> Result<(Vec<Mount>, String), Error> {
    permissions_with_paths(Path::new("/"), value, true)
}
pub(crate) fn permissions(root: &Path, value: &Value) -> Result<(Vec<Mount>, String), Error> {
    permissions_with_paths(root, value, false)
}
fn permissions_with_paths(root: &Path, value: &Value, delegated: bool) -> Result<(Vec<Mount>, String), Error> {
    let mut by_guest = std::collections::BTreeMap::<String, Mount>::new();
    let mut reads = vec![];
    let mut writes = vec![];
    for (operation, write) in [("read", false), ("write", true)] {
        for input in value
            .get(operation)
            .and_then(Value::as_array)
            .ok_or("invalid external capability policy")?
        {
            let input = input.as_str().ok_or("invalid capability root")?;
            let path = if delegated {
                let path = Path::new(input);
                if !path.is_absolute() || path.components().any(|part| matches!(part, Component::ParentDir | Component::CurDir)) {
                    return Err("delegated capability root must be normalized and absolute".into());
                }
                let normalized = canonical(path)?;
                if normalized.to_str() != Some(input) { return Err("delegated capability root changed during resolution".into()); }
                input.to_owned()
            } else { guest(root, input)? };
            let host = canonical(&root.join(input))?;
            if write {
                fs::create_dir_all(&host)?;
            }
            if !host.is_dir() {
                return Err("WASI capability roots must be existing directories".into());
            }
            if write {
                writes.push(path.clone());
            } else {
                reads.push(path.clone());
            }
            by_guest
                .entry(path.clone())
                .and_modify(|m| { m.write |= write; m.read |= !write; })
                .or_insert(Mount {
                    host,
                    guest: path,
                    read: !write,
                    write,
                });
        }
    }
    Ok((
        by_guest.into_values().collect(),
        configuration(&reads, &writes),
    ))
}
fn file_snapshot(mounts: &[Mount]) -> Result<Value, Error> {
    fn visit(
        host: &Path,
        guest: &str,
        values: &mut serde_json::Map<String, Value>,
        total: &mut u64,
    ) -> Result<(), Error> {
        for entry in fs::read_dir(host)? {
            let entry = entry?;
            let metadata = fs::symlink_metadata(entry.path())?;
            let path = format!("{guest}/{}", entry.file_name().to_string_lossy());
            if metadata.file_type().is_symlink() {
                values.insert(
                    path,
                    json!({"symlink":fs::read_link(entry.path())?.to_string_lossy()}),
                );
            } else if metadata.is_dir() {
                values.insert(path.clone(), json!({"directory":true}));
                visit(&entry.path(), &path, values, total)?;
            } else {
                *total += metadata.len();
                if *total > 64 << 20 {
                    return Err("file-effect capture exceeds limit".into());
                }
                let bytes = fs::read(entry.path())?;
                values.insert(
                    path,
                    json!({"hash":protocol::hash(&bytes),"bytesHex":protocol::hex(&bytes)}),
                );
            }
        }
        Ok(())
    }
    let mut values = serde_json::Map::new();
    let mut total = 0;
    for mount in mounts.iter().filter(|m| m.write) {
        visit(&mount.host, &mount.guest, &mut values, &mut total)?;
    }
    Ok(Value::Object(values))
}
fn transact(options: &Options) -> Result<i32, Error> {
    let args = &options.args;
    let is_intent = args[0] == "intent";
    let action = if is_intent {
        args.get(1).ok_or("missing Intent command")?.as_str()
    } else {
        "run"
    };
    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce).map_err(|_| "session entropy unavailable")?;
    let session = crate::native::private_temp_dir()?.join(format!("kelft-session-{}", protocol::hex(&nonce)));
    fs::create_dir(&session)?;
    let run = (|| {
        let control = session.join("control");
        let output = session.join("output");
        let fixtures = session.join("fixtures");
        fs::create_dir(&control)?;
        fs::create_dir(&output)?;
        fs::create_dir(&fixtures)?;
        let mut key = [0u8; 32];
        getrandom::fill(&mut key).map_err(|_| "receipt entropy unavailable")?;
        fs::write(control.join("session.key"), key)?;
        let mut target = if crate::NATIVE_INSTALLED { installed_target() } else { "wasm" }.to_owned();
        let mut runtime_profile = if crate::NATIVE_INSTALLED { installed_profile() } else { "wasi-preview1" }.to_owned();
        let mut program_args = vec![];
        let mut policy_path = String::new();
        let mut proposal = String::new();
        let mut base = String::new();
        let mut approved = vec![];
        for (i, arg) in args.iter().enumerate() {
            if arg == "--target" {
                target = args.get(i + 1).ok_or("target value missing")?.clone();
            }
            if arg == "--runtime-profile" {
                runtime_profile = args.get(i + 1).ok_or("runtime profile missing")?.clone();
            }
            if arg == "--capabilities" {
                policy_path = args.get(i + 1).ok_or("capabilities value missing")?.clone();
            }
            if arg == "--proposal" {
                proposal = guest(&options.root, args.get(i + 1).ok_or("proposal missing")?)?;
            }
            if arg == "--base" {
                base = guest(&options.root, args.get(i + 1).ok_or("base missing")?)?;
            }
            if arg == "--allow-change" {
                approved.push(args.get(i + 1).ok_or("change ID missing")?.clone());
            }
            if arg == "--" {
                program_args = args[i + 1..].to_vec();
                break;
            }
        }
        let mut positional = vec![];
        let mut i = 0;
        while i < args.len() && args[i] != "--" {
            if [
                "--target",
                "--runtime-profile",
                "--capabilities",
                "--proposal",
                "--base",
                "--allow-change",
            ]
            .contains(&args[i].as_str())
            {
                if i + 1 >= args.len() {
                    return Err("option value missing".into());
                }
                i += 2;
                continue;
            }
            if args[i] == "--json" {
                i += 1;
                continue;
            }
            if args[i].starts_with('-') {
                return Err(format!("unsupported driver option {}", args[i]).into());
            }
            positional.push(args[i].clone());
            i += 1;
        }
        if target == "javascript"
            && !args
                .iter()
                .take_while(|s| s.as_str() != "--")
                .any(|s| s == "--runtime-profile")
        {
            runtime_profile = "node24".into();
        }
        if !(crate::NATIVE_INSTALLED && target == installed_target() && runtime_profile == installed_profile()
            || !crate::NATIVE_INSTALLED && target == "wasm" && runtime_profile == "wasi-preview1"
            || !crate::NATIVE_INSTALLED && target == "javascript"
                && runtime_profile == "node24"
                && options.javascript_runtime.is_some())
        {
            return Err("unsupported runtime; JavaScript requires explicit --javascript-runtime Node 24 executable".into());
        }
        if target == "javascript" && std::env::var_os("KELFT_NO_NODE").is_some() {
            return Err("JavaScript execution is disabled in this Node-free environment".into());
        }
        let entry = guest(
            &options.root,
            positional
                .get(if is_intent { 3 } else { 1 })
                .ok_or("candidate missing")?,
        )?;
        let mut registry = json!({});
        let mut registry_root = None;
        let mut policy_revision = None;
        let mut intent_path = String::new();
        let mut external_policy = json!({"read":[],"write":[]});
        let mut candidate_permissions = external_policy.clone();
        let mut ledger = None;
        let mut parent = String::new();
        if is_intent {
            intent_path = guest(&options.root, positional.get(2).ok_or("Intent missing")?)?;
            policy_path = positional.get(4).ok_or("external policy missing")?.clone();
            let intent: Value =
                serde_json::from_slice(&fs::read(options.root.join(&positional[2]))?)?;
            candidate_permissions = intent
                .get("permissions")
                .ok_or("Intent permissions missing")?
                .clone();
            let fixture_root = canonical(
                &options
                    .root
                    .join(positional.get(5).ok_or("trusted fixture root missing")?),
            )?;
            registry = registry_snapshot(&fixture_root, Some(&fixtures))?;
            registry_root = Some(fixture_root);
            if action == "accept" {
                let path = options.root.join(
                    positional
                        .get(6)
                        .map(String::as_str)
                        .unwrap_or("build/intent-ledger"),
                );
                fs::create_dir_all(&path)?;
                ledger = Some(canonical(&path)?);
                parent = positional.get(7).cloned().unwrap_or_default();
            }
        }
        if !policy_path.is_empty() {
            let file = options.root.join(&policy_path);
            let bytes = fs::read(&file)?;
            external_policy = serde_json::from_slice(&bytes)?;
            policy_revision = Some((file, protocol::hash(&bytes)));
            if !is_intent {
                candidate_permissions = external_policy.clone();
            }
        }
        // Authority originates in the external policy, never in an Intent or plan.
        let _ = permissions(&options.root, &external_policy)?;
        fs::write(
            control.join("policy.json"),
            serde_json::to_vec(&external_policy)?,
        )?;
        let compiler_hash = options.compiler_hash.clone();
        let registry_hash = protocol::hash(&serde_json::to_vec(&registry)?);
        let artifact_name = if crate::NATIVE_INSTALLED { "candidate" } else if target == "wasm" {
            "candidate.wasm"
        } else {
            "candidate.mjs"
        };
        let driver_hash = protocol::hash(&fs::read(std::env::current_exe()?)?);
        let program_host = if crate::NATIVE_INSTALLED {
            json!({"name":format!("installed-native-{}-boundary",std::env::consts::OS),"architecture":if cfg!(target_arch="aarch64"){"arm64"}else{"x86_64"}})
        } else if target == "wasm" {
            json!({"name":"wasmtime","version":"49.0.3"})
        } else {
            json!({"name":"node","version":node_version(options)?})
        };
        #[cfg(all(target_os="macos",feature="macos-host"))]
        let program_host=if crate::NATIVE_INSTALLED{let mut host=program_host;host.as_object_mut().ok_or("native host identity required")?.insert("resourceContract".into(),serde_json::to_value(kelft_wasi::native_resources::Contract::for_role(kelft_wasi::native_target::Target::current()?,"candidate")?)?);host}else{program_host};
        let mut request = json!({"schemaVersion":"0.1","sessionId":random()?,"action":action,"entry":entry,"target":target,"runtimeProfile":runtime_profile,"artifactPath":format!("/output/{artifact_name}"),"args":program_args,"permissions":candidate_permissions,"intentPath":intent_path,"policyPath":"/control/policy.json","proposalPath":proposal,"basePath":base,"approved":approved,"ledger":"/ledger","parent":parent,"compilerHash":compiler_hash,"registryHash":registry_hash,"driverHash":driver_hash,"runtimeIdentity":{"compilerHost":{"name":"wasmtime","version":"49.0.3"},"programHost":program_host},"limits":Limits::fixture()});
        if crate::NATIVE_INSTALLED {
            request["artifactPath"]=json!(format!("/out/{artifact_name}"));
            request["ledger"]=json!("/out/ledger");
            request["nativeToolchain"]=json!("/control/toolchain.json");
            request["runtimeIdentity"]=json!({"compilerHost":{"name":"installed-native-kelft","compilerHash":compiler_hash},"programHost":program_host,"driverHash":driver_hash});
        }
        write_json(&control.join("request.json"), &request)?;
        let plan = phase(
            options,
            "prepare",
            &output,
            &control,
            &fixtures,
            ledger.as_deref(),
        )?;
        if plan.get("schemaVersion") != Some(&json!("0.1"))
            || string(&plan, "sessionId")? != string(&request, "sessionId")?
            || string(&plan, "registryHash")? != registry_hash
            || plan["target"] != request["target"]
            || plan["runtimeProfile"] != request["runtimeProfile"]
            || plan["limits"] != request["limits"]
            || plan["artifactPath"] != request["artifactPath"]
            || string(&plan, "requestHash")? != protocol::hash(&serde_json::to_vec(&request)?)
        {
            return Err("compiler returned invalid execution plan".into());
        }
        let report = plan.get("report").ok_or("plan report missing")?;
        if string(report, "state")? != "passed" {
            println!("{}", serde_json::to_string(report)?);
            return Ok(if string(report, "state")? == "needs-human" {
                2
            } else {
                1
            });
        }
        let expected_plan_hash = protocol::hash(&serde_json::to_vec(&{
            let mut p = plan.clone();
            p.as_object_mut()
                .ok_or("plan object required")?
                .remove("planHash");
            p
        })?);
        if string(&plan, "planHash")? != expected_plan_hash {
            return Err("plan hash mismatch".into());
        }
        write_json(&control.join("plan.json"), &plan)?;
        let artifact = output.join(artifact_name);
        if protocol::hash(&fs::read(&artifact)?) != string(report, "artifactHash")? {
            return Err("prepared artifact mismatch".into());
        }
        let mut results = vec![];
        let mut ids = std::collections::BTreeSet::new();
        for item in report
            .get("executionRequests")
            .and_then(Value::as_array)
            .ok_or("execution requests missing")?
        {
            let id = string(item, "id")?;
            if !ids.insert(id) {
                return Err("duplicate execution ID".into());
            }
            let verifier = string(item, "verifier")?;
            if string(item, "target")? != target
                || string(item, "artifactHash")? != string(report, "artifactHash")?
            {
                return Err("unregistered target or substituted artifact".into());
            }
            if verifier == "fixture" {
                let fixture = string(item, "fixture")?;
                if registry.get(fixture).and_then(Value::as_str)
                    != Some(string(item, "fixtureHash")?)
                {
                    return Err("fixture identity does not match trusted registry".into());
                }
            } else if verifier != "run" || action != "run" || id != "run" {
                return Err("unregistered verifier".into());
            }
            let requested = item
                .get("permissions")
                .ok_or("execution permissions missing")?;
            for operation in ["read", "write"] {
                for root in requested
                    .get(operation)
                    .and_then(Value::as_array)
                    .ok_or("invalid requested permission")?
                {
                    let path = canonical(
                        &options
                            .root
                            .join(root.as_str().ok_or("invalid requested root")?),
                    )?;
                    let mut allowed = false;
                    for authority in external_policy
                        .get(operation)
                        .and_then(Value::as_array)
                        .ok_or("invalid external authority")?
                    {
                        let root = canonical(
                            &options
                                .root
                                .join(authority.as_str().ok_or("invalid authority root")?),
                        )?;
                        if path.starts_with(root) {
                            allowed = true;
                        }
                    }
                    if !allowed {
                        return Err("execution plan exceeds external authority".into());
                    }
                }
            }
            let (mounts, configuration) = permissions(&options.root, requested)?;
            #[cfg(feature = "installed-native")]
            let mut configuration = configuration;
            if let Some(process)=requested.get("process") {
                #[cfg(not(feature = "installed-native"))]
                return Err("process execution requires the native broker".into());
                #[cfg(feature = "installed-native")]
                {
                if !crate::NATIVE_INSTALLED||Some(process)!=external_policy.get("process"){return Err("process execution exceeds external authority or requires the native broker".into());}
                let policy=json!({"read":mounts.iter().filter(|m|m.read).map(|m|m.guest.clone()).collect::<Vec<_>>(),"write":mounts.iter().filter(|m|m.write).map(|m|m.guest.clone()).collect::<Vec<_>>(),"execute":false,"process":process});
                let parsed:kelft_wasi::host_channel::Policy=serde_json::from_value(policy.clone())?;if !parsed.validate(){return Err("invalid process capability policy".into());}configuration=serde_json::to_string(&policy)?;
                }
            }
            for mount in &mounts {
                if session.starts_with(&mount.host) || mount.host.starts_with(&session) {
                    return Err("candidate grant overlaps private transaction state".into());
                }
                if mount.write
                    && ledger.as_ref().is_some_and(|path| {
                        path.starts_with(&mount.host) || mount.host.starts_with(path)
                    })
                {
                    return Err("candidate write grant overlaps the acceptance ledger".into());
                }
                if mount.write
                    && (canonical(&options.compiler)?.starts_with(&mount.host)
                        || canonical(&std::env::current_exe()?)?.starts_with(&mount.host)
                        || canonical(&options.root.join("bootstrap/seed"))?
                            .starts_with(&mount.host))
                {
                    return Err("candidate write grant overlaps trusted compiler assets".into());
                }
            }
            let before = file_snapshot(&mounts)?;
            let args = item
                .get("args")
                .and_then(Value::as_array)
                .ok_or("execution arguments missing")?
                .iter()
                .map(|v| {
                    v.as_str()
                        .map(String::from)
                        .ok_or("invalid execution argument")
                })
                .collect::<Result<_, _>>()?;
            let result = if crate::NATIVE_INSTALLED || target == "wasm" {
                execution::execute(&WorkerRequest {
                    schema_version: "0.1".into(),
                    module: artifact.clone(),
                    artifact_hash: string(report, "artifactHash")?.into(),
                    args,
                    mounts: mounts.clone(),
                    configuration,
                    limits: Limits::fixture(),
                })?
            } else {
                javascript(options, &artifact, &args, requested)?
            };
            let mut row = serde_json::to_value(result)?;
            let object = row
                .as_object_mut()
                .ok_or("execution result object required")?;
            object.insert("id".into(), json!(id));
            object.insert("verifier".into(), json!(verifier));
            object.insert("fixtureHash".into(), item["fixtureHash"].clone());
            object.insert(
                "fileEffects".into(),
                json!({"before":before,"after":file_snapshot(&mounts)?}),
            );
            results.push(row);
        }
        if let Some((file, hash)) = policy_revision {
            if protocol::hash(&fs::read(file)?) != hash {
                return Err("external authority changed during verification".into());
            }
        }
        if let Some(root) = registry_root {
            if registry_snapshot(&root, None)? != registry {
                return Err("trusted fixture registry changed during verification".into());
            }
        }
        let mut evidence = json!({"schemaVersion":"0.1","sessionId":request["sessionId"],"planHash":plan["planHash"],"compilerHash":compiler_hash,"registryHash":registry_hash,"driverHash":driver_hash,"runtimeIdentity":request["runtimeIdentity"],"results":results});
        let mut mac = Hmac::<Sha256>::new_from_slice(&key).map_err(|_| "invalid receipt key")?;
        mac.update(&serde_json::to_vec(&evidence)?);
        let receipt = format!(
            "hmac-sha256:{}",
            protocol::hex(&mac.finalize().into_bytes())
        );
        evidence
            .as_object_mut()
            .ok_or("evidence object required")?
            .insert("receipt".into(), json!(receipt));
        write_json(&control.join("evidence.json"), &evidence)?;
        let decision = phase(
            options,
            "finalize",
            &output,
            &control,
            &fixtures,
            ledger.as_deref(),
        )?;
        if action == "run" {
            if string(&decision, "state")? != "passed" {
                return Err("run evidence rejected".into());
            }
            let row = &evidence["results"][0];
            std::io::stdout().write_all(&protocol::unhex(string(row, "stdoutHex")?)?)?;
            std::io::stderr().write_all(&protocol::unhex(string(row, "stderrHex")?)?)?;
            return Ok(row["exit"].as_i64().ok_or("exit status missing")? as i32);
        }
        println!("{}", serde_json::to_string(&decision)?);
        Ok(if string(&decision, "state")? == "passed" {
            0
        } else if string(&decision, "state")? == "needs-human" {
            2
        } else {
            1
        })
    })();
    // The session was created exclusively above and is never preopened to candidates.
    if canonical(&session)?.parent() != Some(canonical(&crate::native::private_temp_dir()?)?.as_path()) {
        return Err("invalid session cleanup target".into());
    }
    let cleanup = fs::remove_dir_all(&session);
    if run.is_ok() {
        cleanup?;
    }
    run
}

fn node_version(options: &Options) -> Result<String, Error> {
    let runtime = options
        .javascript_runtime
        .as_ref()
        .ok_or("explicit JavaScript runtime required")?;
    let version = crate::native::run(Command::new(runtime).arg("--version"), &Limits::fixture())?;
    if version.exit != Some(0)
        || version.failure.is_some()
        || !String::from_utf8_lossy(&version.stdout).starts_with("v24.")
    {
        return Err("JavaScript profile requires Node 24".into());
    }
    Ok(String::from_utf8(version.stdout)?.trim().to_owned())
}
fn javascript(
    options: &Options,
    artifact: &Path,
    args: &[String],
    permissions: &Value,
) -> Result<crate::protocol::ExecutionResult, Error> {
    let runtime = options
        .javascript_runtime
        .as_ref()
        .ok_or("explicit JavaScript runtime required")?;
    node_version(options)?;
    let mut policy = permissions.clone();
    policy
        .as_object_mut()
        .ok_or("policy object required")?
        .insert("execute".into(), json!(false));
    let mut command = Command::new(runtime);
    command
        .arg(artifact)
        .args(args)
        .current_dir(&options.root)
        .env_clear()
        .env("KELFT_CAPABILITIES", serde_json::to_string(&policy)?)
        .env("NODE_OPTIONS", "")
        .env("NODE_PATH", "");
    for name in [
        "PATH",
        "Path",
        "SystemRoot",
        "SYSTEMROOT",
        "WINDIR",
        "TEMP",
        "TMP",
        "LANG",
        "LC_ALL",
    ] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    let result = crate::native::run(&mut command, &Limits::fixture())?;
    Ok(crate::protocol::ExecutionResult {
        status: if result.failure.is_some() {
            "resource-error".into()
        } else {
            "exited".into()
        },
        artifact_hash: protocol::hash(&fs::read(artifact)?),
        exit: result.exit,
        stdout_hex: protocol::hex(&result.stdout),
        stderr_hex: protocol::hex(&result.stderr),
        trap: None,
        error: result.failure,
    })
}

pub fn dispatch(options: Options) -> Result<i32, Error> {
    let command = options.args.first().ok_or("missing command")?.as_str();
    #[cfg(feature = "wasi")]
    if command == "bootstrap" {
        crate::verification::bootstrap(&options)?;
        return Ok(0);
    }
    #[cfg(feature = "wasi")]
    if command == "conformance" {
        crate::verification::conformance(&options, &options.root.join("build/wasm-conformance"))?;
        return Ok(0);
    }
    if command == "run"
        || command == "intent"
            && options
                .args
                .get(1)
                .is_some_and(|s| s == "verify" || s == "accept")
    {
        return transact(&options);
    }
    let mut args = options.args.clone();
    let mut output = options.root.join("build/wasi-driver-output");
    fs::create_dir_all(&output)?;
    if command == "intent" {
        let intent_command = args.get(1).ok_or("missing Intent command")?.clone();
        let end = if intent_command == "proposal" {
            5
        } else if ["diff", "assumptions"].contains(&intent_command.as_str()) {
            4
        } else {
            3
        };
        for i in 2..end.min(args.len()) {
            if !args[i].starts_with('-') {
                args[i] = guest(&options.root, &args[i])?;
            }
        }
    } else {
        if !["build", "check", "ir", "tokens", "ast"].contains(&command) {
            return Err("unsupported compiler command".into());
        }
        args[1] = guest(&options.root, args.get(1).ok_or("entry missing")?)?;
        if let Some(index) = args.iter().position(|v| v == "-o") {
            let path = canonical(
                &options
                    .root
                    .join(args.get(index + 1).ok_or("output path missing")?),
            )?;
            output = path.parent().ok_or("output parent missing")?.to_owned();
            fs::create_dir_all(&output)?;
            args[index + 1] = format!(
                "/output/{}",
                path.file_name()
                    .ok_or("output filename missing")?
                    .to_string_lossy()
            );
        }
        if !args.iter().any(|v| v == "--target") {
            args.extend(["--target".into(), "wasm".into()]);
        }
        if let Some(index) = args.iter().position(|v| v == "--project-root") {
            args[index + 1] = "/project".into();
        } else {
            args.extend(["--project-root".into(), "/project".into()]);
        }
        if let Some(index) = args.iter().position(|v| v == "--capabilities") {
            args[index + 1] = guest(
                &options.root,
                args.get(index + 1).ok_or("capabilities path missing")?,
            )?;
        }
    }
    let (code, stdout, stderr) = invoke(&options, args, &output, None, None, None)?;
    std::io::stdout().write_all(&stdout)?;
    std::io::stderr().write_all(&stderr)?;
    Ok(code)
}

#[cfg(all(test, feature = "wasi"))]
mod delegated_permission_tests {
    use super::*;
    #[test]
    fn preserves_absolute_guest_paths_and_independent_read_write_grants() {
        let root = std::env::temp_dir().join(format!("kelft-delegated-policy-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let path = fs::canonicalize(&root).unwrap().to_string_lossy().into_owned();
        let policy = json!({"read":[path],"write":[path]});
        let (mounts, config) = artifact_permissions(&policy).unwrap();
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].guest, path);
        assert!(mounts[0].read && mounts[0].write);
        assert!(config.contains(&format!("r{}:{}", path.len(), path)));
        assert!(config.contains(&format!("w{}:{}", path.len(), path)));
        let (write_only, _) = artifact_permissions(&json!({"read":[],"write":[path]})).unwrap();
        assert!(!write_only[0].read && write_only[0].write);
        assert!(artifact_permissions(&json!({"read":["relative"],"write":[]})).is_err());
        assert!(artifact_permissions(&json!({"read":[format!("{path}/../{}",root.file_name().unwrap().to_string_lossy())],"write":[]})).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
