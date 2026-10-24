const NATIVE_INSTALLED: bool = false;
mod execution;
mod native;
mod orchestration;
mod native_target;
mod protocol;
mod stdio;
mod verification;

use protocol::{Limits, WorkerRequest};
use std::{env, fs, path::PathBuf};

fn main() {
    match dispatch() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            if env::args()
                .skip(1)
                .take_while(|s| s != "--")
                .any(|s| s == "bootstrap")
            {
                let failed = serde_json::json!({"schemaVersion":"0.1","lane":"wasm-seed","result":"failed","failure":error.to_string(),"conformance":{"passed":0,"failed":1},"determinism":false,"reproducibility":false,"independence":false});
                let report = PathBuf::from("build/bootstrap-wasm-report.json");
                // Preserve a detailed report written by the bootstrap runner;
                // replace stale success if failure occurred before it started.

                if !verification::BOOTSTRAP_STARTED.load(std::sync::atomic::Ordering::Relaxed) {
                    let _ = fs::create_dir_all("build");
                    if let Ok(bytes) = serde_json::to_vec_pretty(&failed) {
                        let _ = fs::write(report, bytes);
                    }
                }
            }
            eprintln!("error[K0600]: {error}");
            std::process::exit(1);
        }
    }
}

fn dispatch() -> Result<i32, Box<dyn std::error::Error>> {
    let mut args: Vec<String> = env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("--worker") {
        if args.len() != 3 {
            return Err("worker requires request and response paths".into());
        }
        let request: WorkerRequest = serde_json::from_slice(&fs::read(&args[1])?)?;
        let result = execution::worker(&request)?;
        fs::write(&args[2], serde_json::to_vec(&result)?)?;
        return Ok(0);
    }
    if args.first().map(String::as_str) == Some("version") {
        println!("kelft-wasi 0.1.0; protocol 0.1; wasmtime 49.0.3");
        return Ok(0);
    }
    #[cfg(target_os = "linux")]
    if args.first().map(String::as_str) == Some("artifact-exec") {
        // Private entry: the direct native parent owns the process group,
        // deadline, captured pipes and sealed descriptor lifetime. Never
        // recurse through current_exe(), which is a sealed memfd here.
        if args.len() < 4 || args[3] != "--" {
            return Err("artifact-exec requires sealed module/policy descriptors and --".into());
        }
        let descriptor = |value: &str| -> Result<PathBuf, Box<dyn std::error::Error>> {
            let number = value.strip_prefix("/proc/self/fd/").ok_or("descriptor path required")?;
            let fd: u32 = number.parse()?;
            if fd < 3 || fd > 1_048_576 || fd.to_string() != number {
                return Err("invalid artifact descriptor".into());
            }
            Ok(PathBuf::from(value))
        };
        let module = descriptor(&args[1])?;
        let policy_file = descriptor(&args[2])?;
        let bytes = fs::read(&module)?;
        let policy: serde_json::Value = serde_json::from_slice(&fs::read(policy_file)?)?;
        if policy.get("execute") != Some(&serde_json::Value::Bool(false)) {
            return Err("artifact execution authority cannot be delegated".into());
        }
        let (mounts, configuration) = orchestration::artifact_permissions(&policy)?;
        let request = WorkerRequest {
            schema_version: "0.1".into(), module,
            artifact_hash: protocol::hash(&bytes), args: args[4..].to_vec(),
            mounts, configuration, limits: Limits::fixture(),
        };
        let result = execution::worker(&request)?;
        use std::io::Write;
        std::io::stdout().write_all(&protocol::unhex(&result.stdout_hex)?)?;
        std::io::stderr().write_all(&protocol::unhex(&result.stderr_hex)?)?;
        if result.status != "exited" {
            return Err(result.error.unwrap_or(result.status).into());
        }
        return Ok(result.exit.ok_or("missing exit status")?);
    }
    if args.first().map(String::as_str) == Some("exec") {
        let file = args.get(1).ok_or("exec requires a .wasm module")?;
        let bytes = fs::read(file)?;
        let mut root = fs::canonicalize(env::current_dir()?)?;
        if let Some(index) = option_index(&args, "--project-root") {
            root = fs::canonicalize(args.get(index + 1).ok_or("project root missing")?)?;
        }
        let policy = if let Some(index) = option_index(&args, "--capabilities") {
            serde_json::from_slice(&fs::read(args.get(index + 1).ok_or("policy missing")?)?)?
        } else {
            serde_json::json!({"read":[],"write":[]})
        };
        let (mounts, configuration) = orchestration::permissions(&root, &policy)?;
        let program_args = args
            .iter()
            .skip(2)
            .skip_while(|x| x.as_str() != "--")
            .skip(1)
            .cloned()
            .collect();
        let request = WorkerRequest {
            schema_version: "0.1".into(),
            module: fs::canonicalize(file)?,
            artifact_hash: protocol::hash(&bytes),
            args: program_args,
            mounts,
            configuration,
            limits: Limits::fixture(),
        };
        let result = execution::execute(&request)?;
        use std::io::Write;
        std::io::stdout().write_all(&protocol::unhex(&result.stdout_hex)?)?;
        std::io::stderr().write_all(&protocol::unhex(&result.stderr_hex)?)?;
        if result.status != "exited" {
            return Err(result.error.unwrap_or(result.status).into());
        }
        return Ok(result.exit.ok_or("missing exit status")?);
    }
    let mut javascript_runtime = None;
    if let Some(index) = option_index(&args, "--javascript-runtime") {
        javascript_runtime = Some(fs::canonicalize(
            args.get(index + 1).ok_or("JavaScript runtime missing")?,
        )?);
        args.drain(index..index + 2);
    }
    let mut compiler = PathBuf::from("bootstrap/seed/compiler.wasm");
    if let Some(index) = option_index(&args, "--compiler") {
        compiler = PathBuf::from(args.get(index + 1).ok_or("compiler path missing")?);
        args.drain(index..index + 2);
    } else {
        let manifest: serde_json::Value =
            serde_json::from_slice(&fs::read("bootstrap/seed/wasm-manifest.json")?)?;
        if manifest["schemaVersion"] != "0.1"
            || manifest["compilerHash"].as_str() != Some(&protocol::hash(&fs::read(&compiler)?))
        {
            return Err("Wasm seed integrity mismatch".into());
        }
    }
    let mut root = fs::canonicalize(env::current_dir()?)?;
    if let Some(index) = option_index(&args, "--project-root") {
        root = fs::canonicalize(args.get(index + 1).ok_or("project root missing")?)?;
        args.drain(index..index + 2);
    }
    let compiler_hash = protocol::hash(&fs::read(&compiler)?);
    orchestration::dispatch(orchestration::Options {
        compiler,
        compiler_hash,
        root,
        args,
        javascript_runtime,
    })
}
fn option_index(args: &[String], flag: &str) -> Option<usize> {
    args.iter()
        .take_while(|s| s.as_str() != "--")
        .position(|s| s == flag)
}
