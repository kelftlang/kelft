use crate::{
    execution,
    orchestration::{self, Options},
    protocol::{self, Limits, WorkerRequest},
};
use hmac::{Hmac, Mac};
use serde_json::{Value, json};
use sha2::Sha256;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::Instant,
};
type Error = Box<dyn std::error::Error>;
pub static BOOTSTRAP_STARTED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
fn failure(message: &str) -> Error {
    message.to_owned().into()
}
fn executable(name: &str) -> PathBuf {
    if let Some(path) = std::env::var_os(if name == "wasm-tools" {
        "KELFT_WASM_TOOLS"
    } else {
        "KELFT_WASMTIME"
    }) {
        return path.into();
    }
    let os = if std::env::consts::OS == "macos" {
        "macos"
    } else {
        std::env::consts::OS
    };
    let arch = std::env::consts::ARCH;
    let version = if name == "wasmtime" {
        "v49.0.3"
    } else {
        "1.262.0"
    };
    if let Ok(root) = std::env::current_dir() {
        let cached = root
            .join(".cache/wasm-tools")
            .join(format!("{name}-{version}-{arch}-{os}"))
            .join(format!("{name}{}", std::env::consts::EXE_SUFFIX));
        if cached.is_file() {
            return cached;
        }
    }
    name.into()
}
fn validate(file: &Path) -> Result<(), Error> {
    let result = crate::native::run(
        Command::new(executable("wasm-tools"))
            .arg("validate")
            .arg(file),
        &Limits::fixture(),
    )?;
    if result.exit != Some(0) || result.failure.is_some() {
        return Err(format!(
            "independent module validation failed: {}",
            String::from_utf8_lossy(&result.stderr)
        )
        .into());
    }
    Ok(())
}
fn compile(options: &Options, entry: &str, file: &Path) -> Result<(), Error> {
    if file.exists() {
        fs::remove_file(file)?;
    }
    let result = orchestration::invoke(
        options,
        vec![
            "build".into(),
            format!("/project/{entry}"),
            "--project-root".into(),
            "/project".into(),
            "--target".into(),
            "wasm".into(),
            "-o".into(),
            format!(
                "/output/{}",
                file.file_name()
                    .ok_or("artifact filename missing")?
                    .to_string_lossy()
            ),
        ],
        file.parent().ok_or("artifact parent missing")?,
        None,
        None,
        None,
    )?;
    if result.0 != 0 || !result.2.is_empty() {
        return Err(format!(
            "Wasm compilation failed for {entry}: {}",
            String::from_utf8_lossy(&result.2)
        )
        .into());
    }
    if fs::metadata(file)?.len() == 0 {
        return Err(failure("empty compiler artifact"));
    }
    validate(file)
}
fn tools() -> Result<(), Error> {
    for (tool, version) in [("wasmtime", "49.0.3"), ("wasm-tools", "1.262.0")] {
        let result = crate::native::run(
            Command::new(executable(tool)).arg("--version"),
            &Limits::fixture(),
        )?;
        if result.exit != Some(0)
            || result.failure.is_some()
            || !String::from_utf8_lossy(&result.stdout).starts_with(&format!("{tool} {version}"))
        {
            return Err(failure("pinned Wasm tool unavailable or version mismatch"));
        }
    }
    Ok(())
}
pub fn conformance(options: &Options, output: &Path) -> Result<usize, Error> {
    fs::create_dir_all(output)?;
    tools()?;
    let corpus: Value =
        serde_json::from_slice(&fs::read(options.root.join("tests/conformance.json"))?)?;
    if corpus["schemaVersion"] != "0.1" {
        return Err(failure("unsupported conformance schema"));
    }
    let mut count = 0;
    for group in ["positive", "runtime"] {
        for case in corpus[group]
            .as_array()
            .ok_or("conformance group missing")?
        {
            let entry = case["entry"].as_str().ok_or("conformance entry missing")?;
            let file = output.join("fixture.wasm");
            compile(options, entry, &file)?;
            let result = execution::execute(&WorkerRequest {
                schema_version: "0.1".into(),
                module: file.clone(),
                artifact_hash: protocol::hash(&fs::read(&file)?),
                args: vec![],
                mounts: vec![],
                configuration: "1".into(),
                limits: Limits::fixture(),
            })?;
            if result.status != "exited"
                || result.exit.map(i64::from) != case["exit"].as_i64()
                || protocol::unhex(&result.stdout_hex)?
                    != case["stdout"]
                        .as_str()
                        .ok_or("stdout expectation missing")?
                        .as_bytes()
                || protocol::unhex(&result.stderr_hex)?
                    != case["stderr"]
                        .as_str()
                        .ok_or("stderr expectation missing")?
                        .as_bytes()
            {
                return Err(format!("Wasm conformance mismatch: {entry}").into());
            }
            count += 1;
        }
    }
    for group in ["negative", "negativeModules"] {
        for case in corpus[group].as_array().ok_or("negative group missing")? {
            let entry = case["entry"].as_str().ok_or("negative entry missing")?;
            let (code, _, stderr) = orchestration::invoke(
                options,
                vec![
                    "check".into(),
                    format!("/project/{entry}"),
                    "--project-root".into(),
                    "/project".into(),
                ],
                output,
                None,
                None,
                None,
            )?;
            let expected = format!(
                "error[{}]",
                case["code"]
                    .as_str()
                    .ok_or("diagnostic expectation missing")?
            );
            if code == 0 || !String::from_utf8_lossy(&stderr).contains(&expected) {
                return Err(format!("negative conformance mismatch: {entry}").into());
            }
            count += 1;
        }
    }
    fs::write(output.join("invalid-utf8.kelft"), [255u8])?;
    let (code, _, stderr) = orchestration::invoke(
        options,
        vec![
            "check".into(),
            "/output/invalid-utf8.kelft".into(),
            "--project-root".into(),
            "/output".into(),
        ],
        output,
        None,
        None,
        None,
    )?;
    if code == 0 || !String::from_utf8_lossy(&stderr).contains("error[K0005]") {
        return Err(failure("malformed UTF-8 conformance mismatch"));
    }
    count += 1;
    count += probes(options, output)?;
    println!("Wasm conformance passed: {count} checks");
    Ok(count)
}
fn probes(options: &Options, output: &Path) -> Result<usize, Error> {
    let mut count = 0;
    let source = output.join("probe.kelft");
    let file = output.join("probe.wasm");
    let entry = source
        .strip_prefix(&options.root)?
        .to_str()
        .ok_or("invalid probe path")?
        .replace('\\', "/");
    for (code, expected) in [
        ("fn main()->i32{return 7;}", 7),
        ("fn main()->i32{return 256;}", 1),
    ] {
        fs::write(&source, code)?;
        compile(options, &entry, &file)?;
        let result = execution::execute(&WorkerRequest {
            schema_version: "0.1".into(),
            module: file.clone(),
            artifact_hash: protocol::hash(&fs::read(&file)?),
            args: vec![],
            mounts: vec![],
            configuration: "1".into(),
            limits: Limits::fixture(),
        })?;
        if result.status != "exited"
            || result.exit != Some(expected)
            || expected == 1 && result.trap.as_deref() != Some("KRT_EXIT")
        {
            return Err(failure("main exit semantics mismatch"));
        }
        count += 1;
    }
    fs::write(&source, "fn main()->void{print(\"abcdef\");}")?;
    compile(options, &entry, &file)?;
    let result = execution::execute(&WorkerRequest {
        schema_version: "0.1".into(),
        module: file.clone(),
        artifact_hash: protocol::hash(&fs::read(&file)?),
        args: vec![],
        mounts: vec![],
        configuration: "1".into(),
        limits: Limits {
            stdout_bytes: 5,
            ..Limits::fixture()
        },
    })?;
    if result.status != "resource-error" {
        return Err(failure(
            "output exhaustion was accepted as normal execution",
        ));
    }
    count += 1;
    fs::write(&source, "fn main()->void{while true {}}")?;
    compile(options, &entry, &file)?;
    if execution::execute(&WorkerRequest {
        schema_version: "0.1".into(),
        module: file.clone(),
        artifact_hash: protocol::hash(&fs::read(&file)?),
        args: vec![],
        mounts: vec![],
        configuration: "1".into(),
        limits: Limits {
            timeout_ms: 150,
            ..Limits::fixture()
        },
    })
    .is_ok()
    {
        return Err(failure("execution timeout was accepted"));
    }
    count += 1;
    fs::write(&source, "fn main()->void{read_text(\"outside.txt\");}")?;
    compile(options, &entry, &file)?;
    let result = execution::execute(&WorkerRequest {
        schema_version: "0.1".into(),
        module: file.clone(),
        artifact_hash: protocol::hash(&fs::read(&file)?),
        args: vec![],
        mounts: vec![],
        configuration: "1".into(),
        limits: Limits::fixture(),
    })?;
    if result.trap.as_deref() != Some("KRT_CAPABILITY") {
        return Err(failure("filesystem default denial failed"));
    }
    count += 1;
    let filesystem = output.join("filesystem with spaces");
    let allowed = filesystem.join("allowed");
    let outside = filesystem.join("outside");
    fs::create_dir_all(&allowed)?;
    fs::create_dir_all(&outside)?;
    fs::write(allowed.join("notes-é.txt"), b"inside")?;
    fs::write(outside.join("secret.txt"), b"outside")?;
    let link = allowed.join("escape");
    #[cfg(unix)]
    {
        if fs::symlink_metadata(&link).is_ok() {
            fs::remove_file(&link)?;
        }
        std::os::unix::fs::symlink(&outside, &link)?;
    }
    #[cfg(windows)]
    {
        if fs::symlink_metadata(&link).is_ok() {
            fs::remove_dir(&link)?;
        }
        let script = filesystem.join("junction.ps1");
        fs::write(
            &script,
            "param([string]$Link,[string]$Target)\n$ErrorActionPreference='Stop'\nNew-Item -ItemType Junction -Path $Link -Target $Target | Out-Null\n",
        )?;
        let powershell =
            PathBuf::from(std::env::var_os("SystemRoot").ok_or("SystemRoot unavailable")?)
                .join("System32/WindowsPowerShell/v1.0/powershell.exe");
        let setup = crate::native::run(
            Command::new(powershell)
                .args([
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                ])
                .arg(script)
                .arg(&link)
                .arg(&outside),
            &Limits::fixture(),
        )?;
        if setup.exit != Some(0) || setup.failure.is_some() {
            return Err(format!(
                "junction fixture setup failed: {}",
                String::from_utf8_lossy(&setup.stderr)
            )
            .into());
        }
    }
    fs::write(
        &source,
        "fn main()->void{let argv:Array<string>=args();match read_text(argv[0]){Result::Ok(value)=>{println(value);},Result::Error(message)=>{println(message);}}}",
    )?;
    compile(options, &entry, &file)?;
    for (path, trap) in [
        ("/data/notes-é.txt", false),
        ("/data/../outside/secret.txt", true),
        ("/data/escape/secret.txt", true),
    ] {
        let result = execution::execute(&WorkerRequest {
            schema_version: "0.1".into(),
            module: file.clone(),
            artifact_hash: protocol::hash(&fs::read(&file)?),
            args: vec![path.into()],
            mounts: vec![crate::protocol::Mount {
                host: fs::canonicalize(&allowed)?,
                guest: "/data".into(),
                read: true,
                write: false,
            }],
            configuration: "1r5:/datac1:/".into(),
            limits: Limits::fixture(),
        })?;
        if trap {
            if result.trap.as_deref() != Some("KRT_CAPABILITY") {
                return Err(format!(
                    "filesystem escape was not denied: {path}; {}",
                    String::from_utf8_lossy(&protocol::unhex(&result.stdout_hex)?)
                )
                .into());
            }
        } else if result.exit != Some(0) || protocol::unhex(&result.stdout_hex)? != b"inside\n" {
            return Err(failure("Unicode/path-with-spaces filesystem access failed"));
        }
        count += 1;
    }
    fs::write(
        &source,
        "fn main()->void{match write_text(\"/data/read-only.txt\",\"no\"){Result::Ok(value)=>{println(\"written\");},Result::Error(message)=>{println(message);}}}",
    )?;
    compile(options, &entry, &file)?;
    let result = execution::execute(&WorkerRequest {
        schema_version: "0.1".into(),
        module: file.clone(),
        artifact_hash: protocol::hash(&fs::read(&file)?),
        args: vec![],
        mounts: vec![crate::protocol::Mount {
            host: fs::canonicalize(&allowed)?,
            guest: "/data".into(),
            read: true,
            write: false,
        }],
        configuration: "1r5:/dataw5:/datac1:/".into(),
        limits: Limits::fixture(),
    })?;
    if result.exit != Some(0)
        || protocol::unhex(&result.stdout_hex)? != b"EACCES\n"
        || allowed.join("read-only.txt").exists()
    {
        return Err(failure("stock WASI read-only preopen was not enforced"));
    }
    count += 1;
    fs::write(
        &source,
        "fn main()->void{match write_once(\"/data/value.txt\",\"ok\"){Result::Ok(value)=>{},Result::Error(message)=>{exit(1);}}match write_once(\"/data/value.txt\",\"ok\"){Result::Ok(value)=>{},Result::Error(message)=>{exit(2);}}match write_once(\"/data/value.txt\",\"changed\"){Result::Ok(value)=>{exit(3);},Result::Error(message)=>{println(message);}}}",
    )?;
    compile(options, &entry, &file)?;
    if allowed.join("value.txt").exists() {
        fs::remove_file(allowed.join("value.txt"))?;
    }
    let result = execution::execute(&WorkerRequest {
        schema_version: "0.1".into(),
        module: file.clone(),
        artifact_hash: protocol::hash(&fs::read(&file)?),
        args: vec![],
        mounts: vec![crate::protocol::Mount {
            host: fs::canonicalize(&allowed)?,
            guest: "/data".into(),
            read: true,
            write: true,
        }],
        configuration: "1r5:/dataw5:/datac1:/".into(),
        limits: Limits::fixture(),
    })?;
    if result.exit != Some(0)
        || protocol::unhex(&result.stdout_hex)? != b"EEXIST\n"
        || fs::read(allowed.join("value.txt"))? != b"ok"
    {
        return Err(failure("exclusive immutable writes failed"));
    }
    count += 1;
    // Valid modules with proprietary imports or wrong WASI signatures must fail
    // before execution, independently of the compiler's own Core verifier.
    for (module, field) in [
        ("proprietary", "execute"),
        ("wasi_snapshot_preview1", "fd_write"),
    ] {
        let mut bytes = vec![0, 97, 115, 109, 1, 0, 0, 0, 1, 4, 1, 96, 0, 0];
        let mut imports = vec![1, module.len() as u8];
        imports.extend_from_slice(module.as_bytes());
        imports.push(field.len() as u8);
        imports.extend_from_slice(field.as_bytes());
        imports.extend([0, 0]);
        bytes.extend([2, imports.len() as u8]);
        bytes.extend(imports);
        bytes.extend([7, 10, 1, 6]);
        bytes.extend_from_slice(b"_start");
        bytes.extend([0, 0]);
        fs::write(&file, bytes)?;
        validate(&file)?;
        if execution::execute(&WorkerRequest {
            schema_version: "0.1".into(),
            module: file.clone(),
            artifact_hash: protocol::hash(&fs::read(&file)?),
            args: vec![],
            mounts: vec![],
            configuration: "1".into(),
            limits: Limits::fixture(),
        })
        .is_ok()
        {
            return Err(failure(
                "unregistered import or invalid WASI signature was accepted",
            ));
        }
        count += 1;
    }
    // Early returns must release loop and match snapshots rather than retaining
    // thousands of distinct collection trees until the process exits.
    fs::write(
        &source,
        "fn first(values:Array<i32>)->i32{for value in values {let found:Option<i32>=Option::<i32>::Some(value);match found {Option::Some(v)=>{return v;},Option::None=>{}}}return 0;}fn main()->void{let mut i:i32=0;while i<1200 {let mut values:Array<i32>=[];let mut k:i32=0;while k<1025 {array_push::<i32>(inout values,k);k=k+1;}if first(values)!=0 {exit(1);}i=i+1;}println(\"ok\");}",
    )?;
    compile(options, &entry, &file)?;
    let result = execution::execute(&WorkerRequest {
        schema_version: "0.1".into(),
        module: file.clone(),
        artifact_hash: protocol::hash(&fs::read(&file)?),
        args: vec![],
        mounts: vec![],
        configuration: "1".into(),
        limits: Limits {
            memory_bytes: 16 << 20,
            ..Limits::fixture()
        },
    })?;
    if result.status != "exited"
        || result.exit != Some(0)
        || protocol::unhex(&result.stdout_hex)? != b"ok\n"
    {
        return Err(failure("snapshot ownership exceeded the bounded heap"));
    }
    count += 1;
    // The private control mount is present only for compiler phases. The valid
    // receipt baseline is generated by the Rust collector and checked in Kelft.
    let control = output.join("protocol control");
    fs::create_dir_all(&control)?;
    let fixtures = output.join("protocol fixtures");
    copy_tree(&options.root.join("pilot/fixtures"), &fixtures)?;
    let key = [11u8; 32];
    fs::write(control.join("session.key"), key)?;
    let intent: Value = serde_json::from_slice(&fs::read(options.root.join("pilot/intent.json"))?)?;
    let intent_file = output.join("intent.json");
    fs::write(&intent_file, serde_json::to_vec(&intent)?)?;
    fs::copy(
        options.root.join("pilot/policy.json"),
        control.join("policy.json"),
    )?;
    let mut registry = serde_json::Map::new();
    for e in fs::read_dir(&fixtures)? {
        let e = e?;
        if e.path().is_file() {
            registry.insert(
                e.file_name()
                    .into_string()
                    .map_err(|_| "invalid fixture path")?,
                json!(protocol::hash(&fs::read(e.path())?)),
            );
        }
    }
    let registry_hash = protocol::hash(&serde_json::to_vec(&registry)?);
    let compiler_hash = protocol::hash(&fs::read(&options.compiler)?);
    let driver_hash = protocol::hash(&fs::read(std::env::current_exe()?)?);
    let request = json!({"schemaVersion":"0.1","sessionId":"probe-session","action":"verify","entry":"/project/pilot/task-filter.kelft","target":"wasm","runtimeProfile":"wasi-preview1","artifactPath":"/output/candidate.wasm","args":[],"permissions":intent["permissions"],"intentPath":"/output/intent.json","policyPath":"/control/policy.json","proposalPath":"","basePath":"","approved":[],"ledger":"/ledger","parent":"","compilerHash":compiler_hash,"registryHash":registry_hash,"driverHash":driver_hash,"runtimeIdentity":{"compilerHost":{"name":"wasmtime","version":"49.0.3"},"programHost":{"name":"wasmtime","version":"49.0.3"}},"limits":Limits::fixture()});
    fs::write(control.join("request.json"), serde_json::to_vec(&request)?)?;
    let phase = |mode: &str| {
        orchestration::invoke(
            options,
            vec![
                "protocol".into(),
                mode.into(),
                "/control/request.json".into(),
            ],
            output,
            Some(&control),
            Some(&fixtures),
            None,
        )
    };
    let (code, stdout, stderr) = phase("prepare")?;
    if code != 0 || !stderr.is_empty() {
        return Err(format!(
            "protocol probe prepare failed: {}",
            String::from_utf8_lossy(&stderr)
        )
        .into());
    }
    let plan: Value = serde_json::from_slice(&stdout)?;
    fs::write(control.join("plan.json"), serde_json::to_vec(&plan)?)?;
    let artifact = output.join("candidate.wasm");
    let mut rows = vec![];
    for item in plan["report"]["executionRequests"]
        .as_array()
        .ok_or("probe requests missing")?
    {
        let (mounts, configuration) =
            orchestration::permissions(&options.root, &item["permissions"])?;
        let args = item["args"]
            .as_array()
            .ok_or("probe args missing")?
            .iter()
            .map(|v| {
                v.as_str()
                    .ok_or("invalid probe argument")
                    .map(str::to_owned)
            })
            .collect::<Result<_, _>>()?;
        let result = execution::execute(&WorkerRequest {
            schema_version: "0.1".into(),
            module: artifact.clone(),
            artifact_hash: protocol::hash(&fs::read(&artifact)?),
            args,
            mounts,
            configuration,
            limits: Limits::fixture(),
        })?;
        let mut row = serde_json::to_value(result)?;
        row["id"] = item["id"].clone();
        row["verifier"] = item["verifier"].clone();
        row["fixtureHash"] = item["fixtureHash"].clone();
        row["fileEffects"] = json!({"before":{},"after":{}});
        rows.push(row);
    }
    let unsigned = json!({"schemaVersion":"0.1","sessionId":request["sessionId"],"planHash":plan["planHash"],"compilerHash":compiler_hash,"registryHash":registry_hash,"driverHash":driver_hash,"runtimeIdentity":request["runtimeIdentity"],"results":rows});
    let sign = |value: &Value| -> Result<Value, Error> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&key).map_err(|_| "bad probe key")?;
        mac.update(&serde_json::to_vec(value)?);
        let mut signed = value.clone();
        signed["receipt"] = json!(format!(
            "hmac-sha256:{}",
            protocol::hex(&mac.finalize().into_bytes())
        ));
        Ok(signed)
    };
    fs::write(
        control.join("evidence.json"),
        serde_json::to_vec(&sign(&unsigned)?)?,
    )?;
    let (code, stdout, stderr) = phase("finalize")?;
    if code != 0
        || !stderr.is_empty()
        || serde_json::from_slice::<Value>(&stdout)?["state"] != "passed"
    {
        return Err(failure("valid execution evidence was rejected"));
    }
    count += 1;
    for mutation in 0..12 {
        let mut value = unsigned.clone();
        match mutation {
            0 => value["sessionId"] = json!("stale-session"),
            1 => value["results"][0]["artifactHash"] = json!(protocol::hash(b"substitution")),
            2 => value["results"]
                .as_array_mut()
                .ok_or("results array required")?
                .clear(),
            3 => {
                let row = value["results"][0].clone();
                value["results"]
                    .as_array_mut()
                    .ok_or("results array required")?
                    .push(row);
            }
            4 => value["results"][0]["verifier"] = json!("arbitrary-command"),
            5 => value["results"][0]["stdoutHex"] = json!("zz"),
            6 => value["results"][0]["stdoutHex"] = json!(protocol::hex(b"wrong output\n")),
            7 => {
                value["results"][0]["fileEffects"] =
                    json!({"before":{},"after":{"/project/unrequested":{ "directory":true}}})
            }
            9 => {
                value["results"][0]
                    .as_object_mut()
                    .ok_or("result object required")?
                    .remove("stderrHex");
            }
            10 => {
                value["results"][0]["status"] = json!("execution-error");
                value["results"][0]["exit"] = Value::Null;
                value["results"][0]["error"] = json!("timed out");
            }
            11 => {
                value["results"][0]["trap"] = json!(false);
            }
            _ => {}
        }
        let mut signed = sign(&value)?;
        if mutation == 8 {
            signed["receipt"] = json!(format!("hmac-sha256:{}", "0".repeat(64)));
        }
        fs::write(control.join("evidence.json"), serde_json::to_vec(&signed)?)?;
        let (code, stdout, stderr) = phase("finalize")?;
        if [6, 7, 10].contains(&mutation) {
            if code != 1
                || !stderr.is_empty()
                || serde_json::from_slice::<Value>(&stdout)?["state"] != "failed"
            {
                return Err(format!(
                    "incorrect candidate result was not rejected by the contract: {mutation}"
                )
                .into());
            }
        } else if code != 1 || !String::from_utf8_lossy(&stderr).contains("error[K0601]") {
            return Err(format!(
                "invalid evidence did not produce a protocol diagnostic: {mutation}"
            )
            .into());
        }
        count += 1;
    }
    fs::write(
        control.join("evidence.json"),
        serde_json::to_vec(&sign(&unsigned)?)?,
    )?;
    let mut changed = intent.clone();
    changed["intent"]["summary"] = json!("changed after preparation");
    fs::write(&intent_file, serde_json::to_vec(&changed)?)?;
    if phase("finalize")?.0 == 0 {
        return Err(failure("changed Intent revision accepted"));
    }
    count += 1;
    changed = intent.clone();
    changed["permissions"]["read"] = json!(["."]);
    fs::write(&intent_file, serde_json::to_vec(&changed)?)?;
    if phase("prepare")?.0 == 0 {
        return Err(failure("permission expansion reached execution"));
    }
    count += 1;
    fs::write(&intent_file, serde_json::to_vec(&intent)?)?;
    let fixture_file = fixtures.join("order.json");
    let original = fs::read(&fixture_file)?;
    let mut changed_fixture: Value = serde_json::from_slice(&original)?;
    changed_fixture["stdout"] = json!("substituted fixture");
    fs::write(&fixture_file, serde_json::to_vec(&changed_fixture)?)?;
    let (code, _, stderr) = phase("finalize")?;
    fs::write(&fixture_file, original)?;
    if code != 1 || !String::from_utf8_lossy(&stderr).contains("error[K0601]") {
        return Err(failure("changed fixture revision was not rejected"));
    }
    count += 1;
    let proposal_file = output.join("proposal.json");
    let proposal_guest = format!(
        "/output/{}",
        proposal_file
            .file_name()
            .ok_or("proposal filename missing")?
            .to_string_lossy()
    );
    let mut proposal = json!({"schemaVersion":"0.1","baseHash":protocol::hash(&serde_json::to_vec(&intent)?),"candidateHash":plan["report"]["candidateHash"],"preserve":intent["constraints"].as_array().ok_or("constraints missing")?.iter().map(|v|v["id"].clone()).collect::<Vec<_>>(),"requestedAuthority":intent["permissions"],"next":intent});
    fs::write(&proposal_file, serde_json::to_vec(&proposal)?)?;
    let mut accept_request = request.clone();
    accept_request["action"] = json!("accept");
    accept_request["proposalPath"] = json!(proposal_guest);
    accept_request["basePath"] = request["intentPath"].clone();
    fs::write(
        control.join("request.json"),
        serde_json::to_vec(&accept_request)?,
    )?;
    let ledger = output.join("proposal ledger");
    fs::create_dir_all(&ledger)?;
    let accept_phase = |mode: &str| {
        orchestration::invoke(
            options,
            vec![
                "protocol".into(),
                mode.into(),
                "/control/request.json".into(),
            ],
            output,
            Some(&control),
            Some(&fixtures),
            Some(&ledger),
        )
    };
    let (code, stdout, stderr) = accept_phase("prepare")?;
    if code != 0 || !stderr.is_empty() {
        return Err(format!(
            "proposal preparation failed: {}",
            String::from_utf8_lossy(&stderr)
        )
        .into());
    }
    let accept_plan: Value = serde_json::from_slice(&stdout)?;
    fs::write(control.join("plan.json"), serde_json::to_vec(&accept_plan)?)?;
    let mut accept_evidence = unsigned.clone();
    accept_evidence["planHash"] = accept_plan["planHash"].clone();
    fs::write(
        control.join("evidence.json"),
        serde_json::to_vec(&sign(&accept_evidence)?)?,
    )?;
    let (code, stdout, stderr) = accept_phase("finalize")?;
    if code != 0
        || !stderr.is_empty()
        || serde_json::from_slice::<Value>(&stdout)?["state"] != "passed"
    {
        return Err(format!(
            "valid proposal acceptance failed: {}",
            String::from_utf8_lossy(&stderr)
        )
        .into());
    }
    count += 1;
    let accepted = fs::read_dir(&ledger)?.count();
    proposal["preserve"]
        .as_array_mut()
        .ok_or("preservation list missing")?
        .reverse();
    fs::write(&proposal_file, serde_json::to_vec(&proposal)?)?;
    let (code, _, stderr) = accept_phase("finalize")?;
    if code != 1
        || !String::from_utf8_lossy(&stderr).contains("error[K0601]")
        || fs::read_dir(&ledger)?.count() != accepted
    {
        return Err(failure(
            "stale proposal revision changed the acceptance ledger",
        ));
    }
    count += 1;
    Ok(count)
}
fn copy_tree(from: &Path, to: &Path) -> Result<(), Error> {
    fs::create_dir_all(to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink() {
            continue;
        }
        if metadata.is_dir() {
            copy_tree(&entry.path(), &to.join(entry.file_name()))?;
        } else {
            let extension = entry
                .path()
                .extension()
                .and_then(|s| s.to_str())
                .map(str::to_owned);
            if extension
                .as_deref()
                .is_some_and(|s| ["kelft", "json", "tsv"].contains(&s))
            {
                fs::copy(entry.path(), to.join(entry.file_name()))?;
            }
        }
    }
    Ok(())
}
pub fn input_hash(root: &Path) -> Result<String, Error> {
    fn entries(root: &Path, path: &Path, out: &mut Vec<(String, String)>) -> Result<(), Error> {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let metadata = fs::symlink_metadata(entry.path())?;
            if metadata.file_type().is_symlink() {
                return Err(failure("compiler inputs must not be symlinks"));
            }
            if metadata.is_dir() {
                entries(root, &entry.path(), out)?;
            } else {
                out.push((
                    entry
                        .path()
                        .strip_prefix(root)?
                        .to_string_lossy()
                        .replace('\\', "/"),
                    protocol::hash(&fs::read(entry.path())?),
                ));
            }
        }
        Ok(())
    }
    let mut out = vec![];
    for dir in ["selfhost", "stdlib", "spec"] {
        entries(root, &root.join(dir), &mut out)?;
    }
    out.sort();
    Ok(protocol::hash(&serde_json::to_vec(&out)?))
}
pub fn bootstrap(options: &Options) -> Result<(), Error> {
    let output = options.root.join("build/bootstrap-wasm");
    fs::create_dir_all(&output)?;
    let report_file = options.root.join("build/bootstrap-wasm-report.json");
    let start = Instant::now();
    let mut report = json!({"schemaVersion":"0.1","lane":"wasm-seed","result":"failed","sourceHash":input_hash(&options.root)?,"seedHash":protocol::hash(&fs::read(&options.compiler)?),"driverHash":protocol::hash(&fs::read(std::env::current_exe()?)?),"lockHash":protocol::hash(&fs::read(options.root.join("pnpm-lock.yaml"))?),"cargoLockHash":protocol::hash(&fs::read(options.root.join("driver/Cargo.lock"))?),"toolsLockHash":protocol::hash(&fs::read(options.root.join("bootstrap/wasm-tools.lock.json"))?),"runtime":{"wasmtime":"49.0.3","wasmTools":"1.262.0","rustc":env!("KELFT_RUSTC_VERSION")},"platforms":{"build":format!("{}-{}",std::env::consts::OS,std::env::consts::ARCH),"host":"wasm32-wasi-preview1","target":"wasm32-wasi-preview1"},"stages":[],"conformance":{"passed":0,"failed":0},"determinism":false,"reproducibility":false,"independence":false,"intent":false});
    fs::write(&report_file, serde_json::to_vec_pretty(&report)?)?;
    BOOTSTRAP_STARTED.store(true, std::sync::atomic::Ordering::Relaxed);
    let run = (|| {
        tools()?;
        let mut previous = options.compiler.clone();
        let mut stages = vec![];
        let mut count = 0;
        for stage in 1..=3 {
            let compiler = output.join(format!("stage{stage}.wasm"));
            let current = Options {
                compiler: previous.clone(),
                compiler_hash: protocol::hash(&fs::read(&previous)?),
                root: options.root.clone(),
                args: vec![],
                javascript_runtime: None,
            };
            compile(&current, "selfhost/main.kelft", &compiler)?;
            let stage_options = Options {
                compiler: compiler.clone(),
                compiler_hash: protocol::hash(&fs::read(&compiler)?),
                root: options.root.clone(),
                args: vec![],
                javascript_runtime: None,
            };
            count += conformance(&stage_options, &output)?;
            stages.push(json!({"stage":stage,"compilerHash":protocol::hash(&fs::read(&compiler)?),"artifactPath":compiler.strip_prefix(&options.root)?.to_string_lossy().replace('\\',"/"),"result":"passed"}));
            previous = compiler;
            report["stages"] = json!(stages);
            report["conformance"]["passed"] = json!(count);
            fs::write(&report_file, serde_json::to_vec_pretty(&report)?)?;
        }
        if fs::read(output.join("stage2.wasm"))? != fs::read(output.join("stage3.wasm"))? {
            return Err(failure("W2/W3 compiler artifacts differ"));
        }
        report["determinism"] = json!(true);
        let isolated = output.join("isolated checkout with spaces");
        if isolated.exists() {
            let parent = fs::canonicalize(&output)?;
            if fs::canonicalize(&isolated)?.parent() != Some(parent.as_path()) {
                return Err(failure("invalid isolation cleanup target"));
            }
            fs::remove_dir_all(&isolated)?;
        }
        fs::create_dir(&isolated)?;
        for dir in ["selfhost", "stdlib", "examples", "tests/fixtures", "pilot"] {
            copy_tree(&options.root.join(dir), &isolated.join(dir))?;
        }
        fs::copy(
            options.root.join("tests/conformance.json"),
            isolated.join("tests/conformance.json"),
        )?;
        let isolated_compiler = isolated.join("compiler.wasm");
        fs::copy(output.join("stage2.wasm"), &isolated_compiler)?;
        let isolated_build = isolated.join("build");
        fs::create_dir(&isolated_build)?;
        let isolated_options = Options {
            compiler_hash: protocol::hash(&fs::read(&isolated_compiler)?),
            compiler: isolated_compiler,
            root: fs::canonicalize(&isolated)?,
            args: vec![],
            javascript_runtime: None,
        };
        let rebuilt = isolated_build.join("rebuilt.wasm");
        compile(&isolated_options, "selfhost/main.kelft", &rebuilt)?;
        if fs::read(&rebuilt)? != fs::read(output.join("stage2.wasm"))? {
            return Err(failure("relocated compiler is not reproducible"));
        }
        report["reproducibility"] = json!(true);
        report["independence"] = json!(
            !isolated.join("src").exists()
                && !isolated.join("node_modules").exists()
                && !isolated.join("bootstrap/seed/compiler.mjs").exists()
        );
        if report["independence"] != true {
            return Err(failure("isolated checkout contains bootstrap dependencies"));
        }
        count += conformance(&isolated_options, &isolated_build)?;
        report["conformance"]["passed"] = json!(count);
        // A separate stock CLI invocation proves the module needs no driver imports.
        let cli = crate::native::run(
            Command::new(executable("wasmtime"))
                .args(["run", "-C", "cache=n", "--dir"])
                .arg(format!("{}::/project", options.root.display()))
                .arg("--dir")
                .arg(format!("{}::/output", output.display()))
                .args([
                    "--env",
                    "KELFT_WASI_CAPABILITIES=1r8:/projectw7:/outputc8:/project",
                ])
                .arg(output.join("stage2.wasm"))
                .args([
                    "build",
                    "/project/selfhost/main.kelft",
                    "--project-root",
                    "/project",
                    "--target",
                    "wasm",
                    "-o",
                    "/output/stock-cli-rebuilt.wasm",
                ]),
            &Limits {
                timeout_ms: 300_000,
                memory_bytes: 1 << 30,
                stdout_bytes: 64 << 20,
                stderr_bytes: 64 << 20,
            },
        )?;
        if cli.exit != Some(0)
            || cli.failure.is_some()
            || !cli.stderr.is_empty()
            || fs::read(output.join("stock-cli-rebuilt.wasm"))?
                != fs::read(output.join("stage2.wasm"))?
        {
            return Err(failure("stock Wasmtime compiler rebuild failed"));
        }
        report["standardWasmtime"] = json!(true);
        let intent_options = Options {
            compiler: output.join("stage2.wasm"),
            compiler_hash: protocol::hash(&fs::read(output.join("stage2.wasm"))?),
            root: options.root.clone(),
            args: vec![
                "intent".into(),
                "verify".into(),
                "pilot/intent.json".into(),
                "pilot/task-filter.kelft".into(),
                "pilot/policy.json".into(),
                "pilot/fixtures".into(),
            ],
            javascript_runtime: None,
        };
        if orchestration::dispatch(intent_options)? != 0 {
            return Err(failure("Wasm Intent verification failed"));
        }
        report["intent"] = json!(true);
        let ledger = output.join("acceptance-ledger");
        fs::create_dir_all(&ledger)?;
        let accept = |candidate: &str| -> Result<i32, Error> {
            orchestration::dispatch(Options {
                compiler: output.join("stage2.wasm"),
                compiler_hash: protocol::hash(&fs::read(output.join("stage2.wasm"))?),
                root: options.root.clone(),
                args: vec![
                    "intent".into(),
                    "accept".into(),
                    "pilot/intent.json".into(),
                    candidate.into(),
                    "pilot/policy.json".into(),
                    "pilot/fixtures".into(),
                    ledger.to_str().ok_or("invalid ledger path")?.into(),
                ],
                javascript_runtime: None,
            })
        };
        if accept("pilot/task-filter.kelft")? != 0 {
            return Err(failure("Wasm Intent acceptance failed"));
        }
        let accepted: Vec<_> = fs::read_dir(&ledger)?.collect::<Result<_, _>>()?;
        if accepted.len() < 3 {
            return Err(failure("accepted ledger is incomplete"));
        }
        let mut event_found = false;
        for entry in &accepted {
            let value: Value = serde_json::from_slice(&fs::read(entry.path())?)?;
            if value["action"] == "accept" {
                let hash = protocol::hash(&serde_json::to_vec(&value)?);
                if entry.file_name().to_string_lossy() != format!("{}.json", &hash[7..]) {
                    return Err(failure("accepted ledger hash mismatch"));
                }
                event_found = true;
            }
        }
        if !event_found
            || accept("pilot/revisions/0.kelft")? != 1
            || fs::read_dir(&ledger)?.count() != accepted.len()
        {
            return Err(failure(
                "failed mandatory evidence changed the acceptance ledger",
            ));
        }
        report["intentAcceptance"] = json!(true);
        if input_hash(&options.root)?
            != report["sourceHash"].as_str().ok_or("source hash missing")?
        {
            return Err(failure("compiler inputs changed during bootstrap"));
        }
        Ok::<(), Error>(())
    })();
    if let Err(error) = &run {
        report["failure"] = json!(error.to_string());
        report["conformance"]["failed"] = json!(1);
    } else {
        report["result"] = json!("passed");
    }
    report["elapsedMs"] = json!(start.elapsed().as_millis() as u64);
    fs::write(&report_file, serde_json::to_vec_pretty(&report)?)?;
    let mut provenance = report.clone();
    provenance["signed"] = json!(false);
    fs::write(
        options.root.join("build/bootstrap-wasm-provenance.json"),
        serde_json::to_vec_pretty(&provenance)?,
    )?;
    run?;
    println!("Wasm bootstrap passed: W2/W3 identical, isolated Node-free rebuild identical");
    Ok(())
}
