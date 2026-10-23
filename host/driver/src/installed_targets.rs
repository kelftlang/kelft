//! Fixed installation mechanism around the embedded Kelft component policy.
//! Policy results can name only catalog-owned files; neither projects nor
//! component archives can provide executable installer hooks or new authority.
use kelft_wasi::{
    component_store::{self, Store},
    distribution_archive,
};
use serde_json::{Value, json};
use std::{
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
};
type Error = Box<dyn std::error::Error>;
#[cfg(kelft_target_components)]
const CATALOG: &str = include_str!(env!("KELFT_TARGET_CATALOG"));
#[cfg(kelft_target_components)]
const POLICY: &[u8] = include_bytes!(env!("KELFT_COMPONENT_POLICY"));
#[cfg(not(kelft_target_components))]
const CATALOG: &str = "";
#[cfg(not(kelft_target_components))]
const POLICY: &[u8] = &[];
pub fn enabled() -> bool {
    !CATALOG.is_empty()
}
pub fn catalog_sha256() -> String {
    crate::protocol::hash(CATALOG.as_bytes())
}
pub fn root() -> Result<PathBuf, Error> {
    let exe = fs::canonicalize(std::env::current_exe()?)?;
    let bin = exe.parent().ok_or("installed bin missing")?;
    if bin.file_name().and_then(|v| v.to_str()) != Some("bin") {
        return Err("install below bin/".into());
    }
    Ok(bin.parent().ok_or("installed root missing")?.to_path_buf())
}
pub fn build_lock() -> Result<Option<component_store::Lock>, Error> {
    if !enabled() {
        return Ok(None);
    }
    Ok(Some(component_store::lock(&root()?, false)?))
}
fn catalog() -> Result<Value, Error> {
    if !enabled() {
        return Err("this core predates installable target packs; install a component-capable native distribution".into());
    }
    Ok(serde_json::from_str(CATALOG)?)
}
fn nonce() -> Result<String, Error> {
    let mut b = [0; 16];
    getrandom::fill(&mut b).map_err(|_| "component entropy unavailable")?;
    Ok(distribution_archive::hex(&b))
}
struct Temporary {
    path: PathBuf,
}
impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
fn temporary() -> Result<Temporary, Error> {
    let path = crate::native::private_temp_dir()?.join(format!("kelft-component-{}", nonce()?));
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(0o700).create(&path)?;
    }
    #[cfg(windows)]
    fs::create_dir(&path)?;
    Ok(Temporary { path })
}
fn observed(store: &Store, catalog: &Value) -> Result<Vec<Value>, Error> {
    let mut result = vec![];
    for component in catalog["components"]
        .as_array()
        .ok_or("component catalog array")?
    {
        let mut files = vec![];
        for record in component["files"]
            .as_array()
            .ok_or("component files array")?
        {
            files.push(store.observation(
                record["path"].as_str().ok_or("file path")?,
                record["mode"].as_u64().ok_or("file mode")? as u32,
            ));
        }
        let receipt = receipt_name(component)?;
        let (receipt, receipt_present) = match store.read(&receipt) {
            Ok(f) => {
                let mut bytes = vec![];
                f.take(129).read_to_end(&mut bytes)?;
                (distribution_archive::hex(&bytes), true)
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => (String::new(), false),
            Err(_) => ("invalid".into(), true),
        };
        result.push(json!({"files":files,"receipt":receipt,"receiptPresent":receipt_present}));
    }
    Ok(result)
}
fn receipt_name(component: &Value) -> Result<String, Error> {
    let target = component["target"].as_str().ok_or("catalog target")?;
    if !matches!(target, "linux-x86_64" | "windows-x86_64") {
        return Err("invalid component receipt identity".into());
    }
    Ok(format!(".kelft-targets/{target}.receipt"))
}
fn request(args: &[String], catalog: &Value, store: &Store) -> Result<Value, Error> {
    Ok(
        json!({"phase":"select","arguments":args,"catalog":catalog,"host":kelft_wasi::native_target::Target::current()?.id(),"compilerSHA256":crate::compiler_sha256()?,"observed":observed(store,catalog)?}),
    )
}
fn policy(request: &Value, temporary: &Temporary) -> Result<Value, Error> {
    policy_image(request, temporary, POLICY)
}
pub(crate) fn evaluate(image: &[u8], request: &Value) -> Result<Value, Error> {
    let temporary = temporary()?;
    policy_image(request, &temporary, image)
}
fn policy_image(request: &Value, temporary: &Temporary, image_bytes: &[u8]) -> Result<Value, Error> {
    let control = temporary.path.join("control");
    fs::create_dir_all(&control)?;
    let file = control.join("request.json");
    let bytes = serde_json::to_vec(request)?;
    if bytes.len() > 16 << 20 {
        return Err("component policy request limit".into());
    }
    fs::write(&file, &bytes)?;
    #[cfg(any(target_os = "linux", all(target_os = "macos", feature = "macos-host")))]
    let output = {
        use std::os::unix::fs::PermissionsExt;
        let image = temporary.path.join("policy");
        if !image.exists() {
            fs::write(&image, image_bytes)?;
            fs::set_permissions(&image, fs::Permissions::from_mode(0o700))?;
        }
        let result = temporary.path.join(format!("result-{}", nonce()?));
        let mut boundary = crate::boundary_command()?;
        boundary
            .command
            .arg("candidate-run")
            .arg(&image)
            .arg("--project-root")
            .arg(&control)
            .arg("--artifact-hash")
            .arg(crate::protocol::hash(image_bytes))
            .arg("--result")
            .arg(&result)
            .args([
                "--timeout-ms",
                "60000",
                "--memory-bytes",
                "1073741824",
                "--stdout-bytes",
                "4194304",
                "--stderr-bytes",
                "1048576",
                "--policy",
                "{\"execute\":false,\"read\":[\"/project\"],\"write\":[]}",
                "--read",
            ])
            .arg(&control)
            .args(["--", "/project/request.json"])
            .env_clear();
        let output = crate::native::run(
            &mut boundary.command,
            &crate::protocol::Limits {
                timeout_ms: 60000,
                memory_bytes: 1 << 30,
                stdout_bytes: 4 << 20,
                stderr_bytes: 1 << 20,
            },
        )?;
        if output.failure.is_some() {
            return Err("component policy supervision failed".into());
        }
        if output.stdout.is_empty() {return Err(format!("Kelft policy failed: {}",String::from_utf8_lossy(&output.stderr)).into());}
        output.stdout
    };
    #[cfg(all(target_os = "windows", feature = "windows-host"))]
    let output = {
        use kelft_wasi::{
            windows_artifact,
            windows_filesystem_session::{Grant, MappedGrant},
            windows_supervisor::Limits,
        };
        let mut windows = [0u16; 32768];
        let n = unsafe {
            windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW(
                windows.as_mut_ptr(),
                windows.len() as u32,
            )
        } as usize;
        if n == 0 || n >= windows.len() {
            return Err("system directory missing".into());
        }
        let system = String::from_utf16(&windows[..n])?;
        let limits = Limits {
            wall_ms: 60000,
            memory_bytes: 1 << 30,
            output_bytes: 4 << 20,
        };
        let grants = [MappedGrant {
            guest: "/project".into(),
            grant: Grant {
                path: control,
                read: true,
                write: false,
            },
        }];
        let result = windows_artifact::run_compiler_mapped(
            image_bytes,
            &crate::protocol::hash(image_bytes),
            &system,
            &["/project/request.json".into()],
            limits,
            limits,
            &grants,
            &[],
            "/project",
            None,
        )?;
        if result.failure.is_some() {
            return Err("component policy supervision failed".into());
        }
        if result.stdout.is_empty() {return Err(format!("Kelft policy failed: {}",String::from_utf8_lossy(&result.stderr)).into());}
        result.stdout
    };
    #[cfg(not(any(
        target_os = "linux",
        all(target_os = "windows", feature = "windows-host"),
        all(target_os = "macos", feature = "macos-host")
    )))]
    let output: Vec<u8> = {
        return Err("installable components are unsupported on this host".into());
    };
    let result: Value = serde_json::from_slice(&output).map_err(|_| {
        format!(
            "invalid Kelft component policy response: {}",
            String::from_utf8_lossy(&output)
        )
    })?;
    Ok(result)
}
fn open_archive(path: &Path) -> Result<fs::File, Error> {
    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)?
    };
    #[cfg(windows)]
    let file = {
        use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
        let file = fs::OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(0x00200000)
            .open(path)?;
        if file.metadata()?.file_attributes() & 0x400 != 0 {
            return Err("target pack cannot be a reparse point".into());
        }
        file
    };
    Ok(file)
}
fn component<'a>(catalog: &'a Value, plan: &Value) -> Result<&'a Value, Error> {
    let index = plan["component"].as_u64().ok_or("component plan index")? as usize;
    catalog["components"]
        .as_array()
        .and_then(|v| v.get(index))
        .ok_or_else(|| "policy component outside catalog".into())
}
fn cleanup(store: &Store, component: &Value) -> Result<(), Error> {
    store.remove(&receipt_name(component)?)?;
    for file in component["files"].as_array().ok_or("catalog file list")? {
        store.remove(file["path"].as_str().ok_or("catalog file name")?)?;
    }
    Ok(())
}
fn present(mut result: Value, args: &[String]) -> Result<i32, Error> {
    let exit = result
        .get("exit")
        .and_then(Value::as_i64)
        .unwrap_or(if result["status"] == "success" { 0 } else { 1 }) as i32;
    let json = args.iter().any(|v| v == "--json");
    for key in ["operation", "component", "archive", "json", "exit"] {
        result
            .as_object_mut()
            .ok_or("policy result object")?
            .remove(key);
    }
    if json {
        println!("{}", result);
    } else if exit != 0 {
        eprintln!(
            "error[{}]: {}",
            result["error"]["code"]
                .as_str()
                .unwrap_or("TARGET_COMPONENT"),
            result["error"]["message"]
                .as_str()
                .unwrap_or("component failure")
        );
    } else {
        println!("{}", serde_json::to_string_pretty(&result["data"])?);
    }
    Ok(exit)
}
pub fn dispatch(args: &[String]) -> Result<i32, Error> {
    let catalog = catalog()?;
    let root = root()?;
    let _lock = component_store::lock(&root, true)?;
    let store = Store::open(&root)?;
    let temporary = temporary()?;
    let mut req = request(args, &catalog, &store)?;
    let mut plan = policy(&req, &temporary)?;
    if plan["status"] != "success" {
        return present(plan, args);
    }
    let mut payloads = None;
    if plan.get("component").is_some() {
        payloads = Some(store.payloads()?);
        let selected = component(&catalog, &plan)?;
        store.recover(&receipt_name(selected)?)?;
        for file in selected["files"].as_array().ok_or("catalog files")? {
            store.recover(file["path"].as_str().ok_or("catalog file")?)?;
        }
    }
    if plan["operation"] == "inspect" {
        let path = PathBuf::from(plan["archive"].as_str().ok_or("policy archive path")?);
        let staged = payloads
            .as_ref()
            .ok_or("component staging missing")?
            .path
            .clone();
        let inspection = distribution_archive::inspect(open_archive(&path)?, &staged)?;
        req["phase"] = json!("archive");
        req["inspection"] = inspection;
        plan = policy(&req, &temporary)?;
        if plan["status"] != "success" {
            return present(plan, args);
        }
        if plan["operation"] != "add" {
            return Err("Kelft did not authorize component publication".into());
        }
        let selected = component(&catalog, &plan)?;
        // Deactivate first. A crash leaves an unavailable component, never a partly
        // activated one. All recovery operations are bounded to this catalog entry.
        store.remove(&receipt_name(selected)?)?;
        for (index, file) in selected["files"]
            .as_array()
            .ok_or("catalog file list")?
            .iter()
            .enumerate()
        {
            let mut source = fs::File::open(staged.join((index + 1).to_string()))?;
            store.put(
                file["path"].as_str().ok_or("catalog file name")?,
                &mut source,
                file["mode"].as_u64().ok_or("catalog file mode")? as u32,
            )?;
        }
        req["observed"] = json!(observed(&store, &catalog)?);
        req["phase"] = json!("published");
        let activation = policy(&req, &temporary)?;
        if activation["status"] != "success" {
            return present(activation, args);
        }
        if activation["operation"] != "activate" || activation["component"] != plan["component"] {
            return Err("Kelft did not authorize component activation".into());
        }
        let receipt = format!(
            "{}\n",
            selected["archive"]["sha256"]
                .as_str()
                .ok_or("archive digest")?
        );
        store.put(&receipt_name(selected)?, &mut receipt.as_bytes(), 0o644)?;
    } else if plan["operation"] == "remove" {
        cleanup(&store, component(&catalog, &plan)?)?;
    }
    present(policy(&request(args, &catalog, &store)?, &temporary)?, args)
}
pub fn status() -> Result<Value, Error> {
    let catalog = catalog()?;
    let store = Store::open(&root()?)?;
    let temporary = temporary()?;
    let plan = policy(
        &request(&["target".into(), "list".into()], &catalog, &store)?,
        &temporary,
    )?;
    if plan["status"] != "success" {
        return Err(format!("component policy failed: {plan}").into());
    }
    Ok(plan["data"].clone())
}
pub fn available(target: &str) -> Result<bool, Error> {
    let rows = status()?;
    Ok(rows
        .as_array()
        .ok_or("target state list")?
        .iter()
        .any(|r| r["target"] == target && r["installed"] == true))
}
