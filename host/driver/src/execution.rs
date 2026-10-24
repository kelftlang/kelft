use crate::protocol::{self, ExecutionResult, WorkerRequest};
use crate::stdio::Capture;
use std::{
    fs,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use wasmtime::{Engine, Linker, Module, Store, StoreLimits, StoreLimitsBuilder};
use wasmtime_wasi::{
    FsPerms, WasiCtxBuilder,
    p1::{self, WasiP1Ctx},
};

type Error = Box<dyn std::error::Error>;
struct State {
    wasi: WasiP1Ctx,
    limits: StoreLimits,
}

pub fn worker(request: &WorkerRequest) -> Result<ExecutionResult, Error> {
    if request.schema_version != "0.1" {
        return Err("unsupported worker protocol".into());
    }
    request.limits.validate()?;
    let bytes = fs::read(&request.module)?;
    if bytes.is_empty()
        || bytes.len() > 256 << 20
        || protocol::hash(&bytes) != request.artifact_hash
    {
        return Err("artifact integrity mismatch".into());
    }
    let engine = Engine::default();
    let module = Module::new(&engine, &bytes)?;
    const ALLOWED: &[&str] = &[
        "args_get",
        "args_sizes_get",
        "environ_get",
        "environ_sizes_get",
        "fd_write",
        "fd_read",
        "fd_close",
        "fd_seek",
        "fd_fdstat_get",
        "fd_filestat_get",
        "fd_prestat_get",
        "fd_prestat_dir_name",
        "path_open",
        "path_readlink",
        "path_filestat_get",
        "path_create_directory",
        "proc_exit",
    ];
    for import in module.imports() {
        if import.module() != "wasi_snapshot_preview1"
            || !ALLOWED.contains(&import.name())
            || !matches!(import.ty(), wasmtime::ExternType::Func(_))
        {
            return Err(format!(
                "unsupported module import {}::{}",
                import.module(),
                import.name()
            )
            .into());
        }
    }
    let stdout = Capture::new(request.limits.stdout_bytes);
    let stderr = Capture::new(request.limits.stderr_bytes);
    let mut wasi = WasiCtxBuilder::new();
    wasi.arg("program.wasm")
        .args(&request.args)
        .stdout(stdout.clone())
        .stderr(stderr.clone())
        .env("KELFT_WASI_CAPABILITIES", &request.configuration);
    let mut guests = std::collections::BTreeSet::new();
    for mount in &request.mounts {
        if !mount.guest.starts_with('/')
            || !guests.insert(&mount.guest)
            || !mount.host.is_absolute()
        {
            return Err("invalid or duplicate preopen".into());
        }
        wasi.preopened_dir(
            fs::canonicalize(&mount.host)?,
            &mount.guest,
            if mount.write {
                FsPerms::ReadWrite
            } else {
                FsPerms::ReadOnly
            },
        )?;
    }
    let state = State {
        wasi: wasi.build_p1(),
        limits: StoreLimitsBuilder::new()
            .memory_size(request.limits.memory_bytes)
            .instances(1)
            .build(),
    };
    let mut store = Store::new(&engine, state);
    store.limiter(|state| &mut state.limits);
    let mut linker = Linker::new(&engine);
    p1::add_to_linker_sync(&mut linker, |state: &mut State| &mut state.wasi)?;
    // Kelft defines exit codes 0..=255. The upstream WASI adapter reserves
    // 126..=255; bind the language contract explicitly at this host boundary.
    linker.allow_shadowing(true);
    linker.func_wrap("wasi_snapshot_preview1", "proc_exit", |status: i32| -> Result<(), wasmtime::Error> {
        if !(0..=255).contains(&status) {
            return Err(wasmtime::Error::msg("exit outside Kelft range 0..=255"));
        }
        Err(wasmtime_wasi::I32Exit(status).into())
    })?;
    linker.allow_shadowing(false);
    let instance = linker.instantiate(&mut store, &module)?;
    let entry = instance.get_typed_func::<(), ()>(&mut store, "_start")?;
    let invocation = entry.call(&mut store, ());
    let mut result = ExecutionResult {
        status: "exited".into(),
        artifact_hash: request.artifact_hash.clone(),
        exit: Some(0),
        stdout_hex: protocol::hex(&stdout.contents()),
        stderr_hex: protocol::hex(&stderr.contents()),
        trap: None,
        error: None,
    };
    if let Err(error) = invocation {
        if let Some(exit) = error.downcast_ref::<wasmtime_wasi::I32Exit>() {
            result.exit = Some(exit.0);
        } else {
            result.status = "execution-error".into();
            result.exit = None;
            result.error = Some(error.to_string());
        }
    }
    let error_bytes = stderr.contents();
    if result.status == "exited" && result.exit == Some(1) {
        if let Ok(text) = std::str::from_utf8(&error_bytes) {
            if let Some(code) = text
                .strip_prefix("error[")
                .and_then(|s| s.strip_suffix("]\n"))
            {
                if code.starts_with("KRT_") {
                    result.trap = Some(code.to_owned());
                }
            }
        }
    }
    if stdout.overflowed() || stderr.overflowed() || result.trap.as_deref() == Some("KRT_MEMORY") {
        result.status = "resource-error".into();
        result.exit = None;
        result.error = Some("execution resource limit exceeded".into());
    }
    Ok(result)
}

pub fn execute(request: &WorkerRequest) -> Result<ExecutionResult, Error> {
    request.limits.validate()?;
    let mut nonce = [0u8; 24];
    getrandom::fill(&mut nonce).map_err(|_| "cannot generate session identity")?;
    let dir = std::env::temp_dir().join(format!("kelft-wasi-{}", protocol::hex(&nonce)));
    fs::create_dir(&dir)?;
    let run = (|| {
        let input = dir.join("request.json");
        let output = dir.join("result.json");
        fs::write(&input, serde_json::to_vec(request)?)?;
        let mut child = Command::new(std::env::current_exe()?)
            .arg("--worker")
            .arg(&input)
            .arg(&output)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let start = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if start.elapsed() > Duration::from_millis(request.limits.timeout_ms) {
                child.kill()?;
                child.wait()?;
                return Err("execution timed out".into());
            }
            thread::sleep(Duration::from_millis(5));
        };
        if !status.success() {
            return Err("worker execution failed; no evidence accepted".into());
        }
        let data = fs::read(output)?;
        if data.is_empty()
            || data.len() > 2 * (request.limits.stdout_bytes + request.limits.stderr_bytes) + 65536
        {
            return Err("missing or oversized execution evidence".into());
        }
        let result: ExecutionResult = serde_json::from_slice(&data)?;
        if result.artifact_hash != request.artifact_hash {
            return Err("execution evidence artifact mismatch".into());
        }
        Ok(result)
    })();
    if fs::canonicalize(&dir)?.parent() != Some(fs::canonicalize(std::env::temp_dir())?.as_path()) {
        return Err("invalid execution cleanup target".into());
    }
    let cleanup = fs::remove_dir_all(&dir);
    if run.is_ok() {
        cleanup?;
    }
    run
}

#[cfg(test)]
mod artifact_exit_tests {
    use super::*;
    fn module(status: i32) -> Vec<u8> {
        fn size(mut n: usize, out: &mut Vec<u8>) {loop {let b=(n&127) as u8;n>>=7;out.push(b|if n>0 {128} else {0});if n==0 {break;}}}
        fn section(id:u8, bytes:Vec<u8>, out:&mut Vec<u8>){out.push(id);size(bytes.len(),out);out.extend(bytes);}
        fn name(s:&str,out:&mut Vec<u8>){size(s.len(),out);out.extend(s.bytes());}
        let mut out=b"\0asm\x01\0\0\0".to_vec();
        section(1,vec![2,0x60,1,0x7f,0,0x60,0,0],&mut out);
        let mut imports=vec![1];name("wasi_snapshot_preview1",&mut imports);name("proc_exit",&mut imports);imports.extend([0,0]);section(2,imports,&mut out);
        section(3,vec![1,1],&mut out);let mut exports=vec![1];name("_start",&mut exports);exports.extend([0,1]);section(7,exports,&mut out);
        let mut body=vec![0,0x41];let mut value=status;loop {let b=(value&127) as u8;value>>=7;let done=(value==0&&b&64==0)||(value == -1&&b&64!=0);body.push(b|if done {0}else{128});if done {break;}}body.extend([0x10,0,0x0b]);let mut code=vec![1];size(body.len(),&mut code);code.extend(body);section(10,code,&mut out);out
    }
    fn run(status:i32) -> ExecutionResult {
        let bytes=module(status);let path=std::env::temp_dir().join(format!("kelft-artifact-exit-{}-{}.wasm",std::process::id(),status));fs::write(&path,&bytes).unwrap();
        let request=WorkerRequest {schema_version:"0.1".into(),module:path.clone(),artifact_hash:protocol::hash(&bytes),args:vec![],mounts:vec![],configuration:String::new(),limits:protocol::Limits::fixture()};
        let result=worker(&request);fs::remove_file(path).unwrap();result.unwrap()
    }
    #[test] fn wasm_host_preserves_all_kelft_exit_boundaries() {for status in [0,1,42,125,126,127,255] {let result=run(status);assert_eq!(result.status,"exited");assert_eq!(result.exit,Some(status));assert_eq!(result.stdout_hex,"");assert_eq!(result.stderr_hex,"");}}
    #[test] fn wasm_host_rejects_out_of_range_exit_imports() {for status in [-1,256,i32::MAX,i32::MIN] {let result=run(status);assert_eq!(result.status,"execution-error");assert_eq!(result.exit,None);}}
}
