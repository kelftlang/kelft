//! Filesystem and process mechanisms for native compiler rebuilding.
//! Kelft owns rebuild options, target selection and source inventory decisions.
use crate::{native, native_target::Target, protocol};
use serde_json::{Value, json};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::Command,
};
type Error = Box<dyn std::error::Error>;
#[cfg(kelft_rebuild)]
const POLICY: &[u8] = include_bytes!(env!("KELFT_REBUILD_POLICY"));
#[cfg(not(kelft_rebuild))]
const POLICY: &[u8] = &[];
pub fn enabled() -> bool {
    !POLICY.is_empty()
}
pub(crate) fn load_policy(name: &str, fallback: &[u8]) -> Result<Vec<u8>, Error> {
    if !matches!(name, "testing" | "rebuild") {
        return Err("unknown compiler policy".into());
    }
    if enabled() {
        let file = crate::installed_targets::root()?.join(format!(
            "rootfs/policies/{name}{}",
            Target::current()?.executable_suffix()
        ));
        if file.exists() {
            let bytes = read(&file, 64 << 20)?;
            Target::current()?.validate_executable(&bytes)?;
            return Ok(bytes);
        }
    }
    if fallback.is_empty() {
        return Err("compiler policy is unavailable".into());
    }
    Ok(fallback.to_vec())
}
pub(crate) fn has_policy(name: &str) -> bool {
    enabled()
        && crate::installed_targets::root().is_ok_and(|root| {
            root.join(format!(
                "rootfs/policies/{name}{}",
                Target::current()
                    .map(|t| t.executable_suffix())
                    .unwrap_or("")
            ))
            .is_file()
        })
}
fn nonce() -> Result<String, Error> {
    let mut bytes = [0; 16];
    getrandom::fill(&mut bytes).map_err(|_| "rebuild entropy unavailable")?;
    Ok(protocol::hex(&bytes))
}
fn plain(path: &Path) -> Result<fs::Metadata, Error> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err("rebuild paths cannot follow symbolic links".into());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err("rebuild paths cannot follow reparse points".into());
        }
    }
    Ok(metadata)
}
fn parents(path: &Path) -> Result<(), Error> {
    for parent in path.ancestors() {
        if parent.exists() {
            plain(parent)?;
        }
    }
    Ok(())
}
fn relative(name: &str) -> Result<(), Error> {
    if name.is_empty()
        || name.len() > 240
        || name.contains(['\\', ':', '\0'])
        || name
            .split('/')
            .any(|p| p.is_empty() || p == "." || p == "..")
        || Path::new(name).is_absolute()
    {
        return Err("invalid seed payload path".into());
    }
    Ok(())
}
fn read(path: &Path, limit: u64) -> Result<Vec<u8>, Error> {
    parents(path)?;
    let metadata = plain(path)?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err("rebuild input must be a bounded regular file".into());
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(1).custom_flags(0x00200000);
    }
    let mut file = options.open(path)?;
    let mut bytes = vec![];
    Read::by_ref(&mut file)
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 != metadata.len() || file.metadata()?.len() != metadata.len() {
        return Err("rebuild input changed while reading".into());
    }
    Ok(bytes)
}
fn walk(
    root: &Path,
    dir: &Path,
    rows: &mut Vec<Value>,
    depth: usize,
    source_only: bool,
) -> Result<(), Error> {
    let file_limit = if source_only {
        4096
    } else if cfg!(target_os = "macos") {
        131072
    } else {
        8192
    };
    if depth > 64 || rows.len() > file_limit {
        return Err("rebuild traversal bound".into());
    }
    parents(dir)?;
    if !plain(dir)?.is_dir() {
        return Err("rebuild directory required".into());
    }
    let mut children = fs::read_dir(dir)?
        .map(|e| e.map(|e| e.path()))
        .collect::<Result<Vec<_>, _>>()?;
    children.sort();
    if children.len() > file_limit {
        return Err("rebuild directory bound".into());
    }
    for file in children {
        let metadata = plain(&file)?;
        if metadata.is_dir() {
            walk(root, &file, rows, depth + 1, source_only)?;
        } else if metadata.is_file() {
            if source_only && file.extension().and_then(|s| s.to_str()) != Some("kelft") {
                continue;
            }
            let name = file
                .strip_prefix(root)?
                .to_str()
                .ok_or("Unicode rebuild paths required")?
                .replace('\\', "/");
            let bytes = read(&file, if source_only { 8 << 20 } else { 256 << 20 })?;
            #[cfg(unix)]
            let mode = {
                use std::os::unix::fs::PermissionsExt;
                metadata.permissions().mode() & 0o777
            };
            #[cfg(windows)]
            let mode = if name.starts_with("bin/") || name.ends_with(".exe") {
                0o755
            } else {
                0o644
            };
            rows.push(json!({"path":name,"bytes":bytes.len(),"sha256":protocol::hash(&bytes),"mode":mode}));
            if rows.len() > file_limit {
                return Err("rebuild file bound".into());
            }
        } else {
            return Err("unsupported rebuild filesystem entry".into());
        }
    }
    Ok(())
}
fn runtime_files(root: &Path) -> Result<Vec<Value>, Error> {
    let mut rows = vec![];
    for dir in ["bin", "rootfs"] {
        walk(root, &root.join(dir), &mut rows, 0, false)?;
    }
    if root.join("notices").exists() {
        walk(root, &root.join("notices"), &mut rows, 0, false)?;
    }
    let parts = root.join("seed-parts.json");
    if parts.exists() {
        let manifest: Value = serde_json::from_slice(&read(&parts, 2 << 20)?)?;
        if manifest["schema"] != "kelft.seed-parts/1" {
            return Err("unsupported split seed manifest".into());
        }
        for item in manifest["files"]
            .as_array()
            .ok_or("split seed files missing")?
        {
            let name = item["path"].as_str().ok_or("split seed path missing")?;
            relative(name)?;
            if !name.starts_with("rootfs/") || rows.iter().any(|r| r["path"] == name) {
                return Err("invalid or duplicate split seed destination".into());
            }
            let bytes = payload(root, name)?;
            if !matches!(item["mode"].as_u64(), Some(0o644 | 0o755)) {
                return Err("invalid split seed mode".into());
            }
            rows.push(json!({"path":name,"bytes":bytes.len(),"sha256":protocol::hash(&bytes),"mode":item["mode"]}));
        }
    }
    for name in [
        "manifest.json",
        "supervisor.json",
        "rebuild.json",
        "seed.json",
        "runtime-modes.json",
    ] {
        let file = root.join(name);
        if file.exists() {
            let bytes = read(&file, 16 << 20)?;
            #[cfg(unix)]
            let mode = {
                use std::os::unix::fs::PermissionsExt;
                fs::metadata(&file)?.permissions().mode() & 0o777
            };
            #[cfg(windows)]
            let mode = 0o644;
            rows.push(json!({"path":name,"bytes":bytes.len(),"sha256":protocol::hash(&bytes),"mode":mode}));
        }
    }
    let seed = root.join("seed.json");
    if seed.exists() {
        let metadata: Value = serde_json::from_slice(&read(&seed, 16 << 20)?)?;
        if metadata["schema"] == "kelft.native-seed/1" {
            let mut modes = std::collections::BTreeMap::new();
            for item in metadata["files"]
                .as_array()
                .ok_or("seed inventory missing")?
            {
                let name = item["path"].as_str().ok_or("seed mode path missing")?;
                relative(name)?;
                let mode = item["mode"].as_u64().ok_or("seed mode missing")?;
                if mode != 0o644 && mode != 0o755 || modes.insert(name, mode).is_some() {
                    return Err("invalid or duplicate seed mode".into());
                }
            }
            for row in &mut rows {
                if let Some(mode) = modes.get(row["path"].as_str().ok_or("runtime path missing")?) {
                    row["mode"] = json!(mode);
                }
            }
        }
    }
    let mode_file = root.join("runtime-modes.json");
    if mode_file.exists() {
        let metadata: Value = serde_json::from_slice(&read(&mode_file, 16 << 20)?)?;
        if metadata["schema"] != "kelft.runtime-modes/1" {
            return Err("unsupported runtime mode inventory".into());
        }
        let files = metadata["files"]
            .as_array()
            .ok_or("runtime modes missing")?;
        if files.len() > 131072 {
            return Err("runtime mode inventory bound".into());
        }
        let mut modes = std::collections::BTreeMap::new();
        for file in files {
            let name = file["path"].as_str().ok_or("runtime mode path missing")?;
            relative(name)?;
            let mode = file["mode"].as_u64().ok_or("runtime mode missing")?;
            if !matches!(mode, 0o444 | 0o555 | 0o600 | 0o644 | 0o700 | 0o755)
                || modes.insert(name, mode).is_some()
            {
                return Err("invalid or duplicate runtime mode".into());
            }
        }
        for row in &mut rows {
            if let Some(mode) = modes.get(row["path"].as_str().ok_or("runtime mode path")?) {
                row["mode"] = json!(mode);
            }
        }
    }
    rows.sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));
    let total: u64 = rows
        .iter()
        .map(|r| r["bytes"].as_u64().unwrap_or(u64::MAX))
        .sum();
    let total_limit = if cfg!(target_os = "macos") {
        16u64 << 30
    } else {
        512u64 << 20
    };
    if total > total_limit {
        return Err("runtime exceeds prepared package bound".into());
    }
    Ok(rows)
}
fn payload(root: &Path, name: &str) -> Result<Vec<u8>, Error> {
    relative(name)?;
    let file = root.join(name);
    if file.exists() {
        return read(&file, 256 << 20);
    }
    let manifest: Value = serde_json::from_slice(&read(&root.join("seed-parts.json"), 2 << 20)?)?;
    if manifest["schema"] != "kelft.seed-parts/1" {
        return Err("unsupported split seed manifest".into());
    }
    let item = manifest["files"]
        .as_array()
        .ok_or("split seed files missing")?
        .iter()
        .find(|r| r["path"] == name)
        .ok_or("missing seed payload")?;
    let size = item["bytes"].as_u64().ok_or("split seed size missing")?;
    if size > 256 << 20 {
        return Err("split seed exceeds file bound".into());
    }
    let parts = item["parts"].as_array().ok_or("split seed parts missing")?;
    if parts.is_empty() || parts.len() > 8 {
        return Err("split seed part bound".into());
    }
    let mut bytes = vec![];
    for part in parts {
        let path = part["path"]
            .as_str()
            .ok_or("split seed part path missing")?;
        relative(path)?;
        if !path.starts_with("parts/") {
            return Err("split seed part escapes parts directory".into());
        }
        let chunk = read(&root.join(path), 48 << 20)?;
        if chunk.len() as u64
            != part["bytes"]
                .as_u64()
                .ok_or("split seed part size missing")?
            || protocol::hash(&chunk)
                != part["sha256"]
                    .as_str()
                    .ok_or("split seed part digest missing")?
        {
            return Err("split seed part changed".into());
        }
        bytes.extend_from_slice(&chunk);
        if bytes.len() as u64 > size {
            return Err("split seed payload grew".into());
        }
    }
    if bytes.len() as u64 != size
        || protocol::hash(&bytes) != item["sha256"].as_str().ok_or("split seed digest missing")?
    {
        return Err("split seed payload changed".into());
    }
    Ok(bytes)
}
fn copy_files(source: &Path, destination: &Path, rows: &[Value]) -> Result<(), Error> {
    for row in rows {
        let name = row["path"].as_str().ok_or("runtime path missing")?;
        let bytes = payload(source, name)?;
        if protocol::hash(&bytes) != row["sha256"].as_str().ok_or("runtime digest missing")? {
            return Err("runtime changed while copying".into());
        }
        let to = destination.join(name);
        fs::create_dir_all(to.parent().ok_or("runtime parent missing")?)?;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&to)?;
        use std::io::Write;
        file.write_all(&bytes)?;
        file.sync_all()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                &to,
                fs::Permissions::from_mode(
                    row["mode"].as_u64().ok_or("runtime mode missing")? as u32
                ),
            )?;
        }
    }
    Ok(())
}
#[cfg(all(unix, any(target_os = "macos", test)))]
fn seal_runtime_tools(destination: &Path, rows: &[Value]) -> Result<(), Error> {
    for name in ["rootfs/toolchain/sdk", "rootfs/toolchain/usr"] {
        let base = destination.join(name);
        if base.exists() {
            use std::os::unix::fs::PermissionsExt;
            let mut directories = std::collections::BTreeSet::new();
            directories.insert(base.clone());
            for row in rows {
                let file = destination.join(row["path"].as_str().ok_or("runtime path missing")?);
                if file.starts_with(&base) {
                    for parent in file.parent().ok_or("runtime parent missing")?.ancestors() {
                        if !parent.starts_with(&base) {
                            break;
                        }
                        directories.insert(parent.to_owned());
                    }
                }
            }
            for directory in directories.iter().rev() {
                parents(directory)?;
                fs::set_permissions(directory, fs::Permissions::from_mode(0o555))?;
            }
        }
    }
    Ok(())
}
fn cache() -> Result<PathBuf, Error> {
    #[cfg(windows)]
    let base = kelft_wasi::windows_snapshot::temporary_directory()?
        .parent()
        .ok_or("local application data missing")?
        .to_owned();
    #[cfg(unix)]
    let home = || -> Result<PathBuf, Error> {
        let mut record = std::mem::MaybeUninit::<libc::passwd>::uninit();
        let mut buffer = vec![0u8; 65536];
        let mut result = std::ptr::null_mut();
        let status = unsafe {
            libc::getpwuid_r(
                libc::getuid(),
                record.as_mut_ptr(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                &mut result,
            )
        };
        if status != 0 || result.is_null() {
            return Err("user profile directory unavailable".into());
        }
        let record = unsafe { record.assume_init() };
        let directory = unsafe { std::ffi::CStr::from_ptr(record.pw_dir) }.to_str()?;
        Ok(PathBuf::from(directory))
    };
    #[cfg(target_os = "macos")]
    let base = home()?.join("Library/Caches");
    #[cfg(all(unix, not(target_os = "macos")))]
    let base = if let Some(dir) = std::env::var_os("XDG_CACHE_HOME") {
        PathBuf::from(dir)
    } else {
        home()?.join(".cache")
    };
    if !base.is_absolute() {
        return Err("native runtime cache must be absolute".into());
    }
    let root = base.join("kelft/native-runtime");
    parents(&root)?;
    fs::create_dir_all(&root)?;
    parents(&root)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    }
    Ok(fs::canonicalize(root)?)
}
fn output(result: native::Output) -> Result<i32, Error> {
    use std::io::Write;
    std::io::stdout().write_all(&result.stdout)?;
    std::io::stderr().write_all(&result.stderr)?;
    if let Some(error) = result.failure {
        return Err(error.into());
    }
    result.exit.ok_or("native process interrupted".into())
}
struct Coordinator {
    command: Command,
    _lifeline: fs::File,
}
fn coordinator(root: &Path, args: &[String]) -> Result<Coordinator, Error> {
    #[cfg(windows)]
    let (input, lifeline) = kelft_wasi::windows_lifeline::pair()?;
    #[cfg(unix)]
    let (input, lifeline) = {
        let (input, lifeline) = std::os::unix::net::UnixStream::pair()?;
        (
            fs::File::from(std::os::fd::OwnedFd::from(input)),
            fs::File::from(std::os::fd::OwnedFd::from(lifeline)),
        )
    };
    let mut command = Command::new(root.join(format!(
        "bin/kelft{}",
        Target::current()?.executable_suffix()
    )));
    command
        .arg("--runtime-lifeline")
        .args(args)
        .stdin(std::process::Stdio::from(input));
    Ok(Coordinator {
        command,
        _lifeline: lifeline,
    })
}
/// Keep relocated coordinators and their boundary services tied to the caller.
pub fn watch_lifetime(args: &mut Vec<String>) -> Result<(), Error> {
    if !enabled() || args.first().is_none_or(|s| s != "--runtime-lifeline") {
        return Ok(());
    }
    args.remove(0);
    #[cfg(windows)]
    kelft_wasi::windows_lifeline::watch_stdin()?;
    #[cfg(unix)]
    {
        use std::os::fd::FromRawFd;
        let descriptor = unsafe { libc::fcntl(0, libc::F_DUPFD_CLOEXEC, 3) };
        if descriptor < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let mut input = unsafe { fs::File::from_raw_fd(descriptor) };
        std::thread::Builder::new()
            .name("kelft-runtime-lifetime".into())
            .spawn(move || {
                let mut byte = [0u8; 1];
                loop {
                    match input.read(&mut byte) {
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                        _ => break,
                    }
                }
                unsafe {
                    libc::_exit(125);
                }
            })?;
    }
    Ok(())
}
/// Snapshot runtime files outside project grants before entering any boundary.
pub fn stage_runtime(args: &[String]) -> Result<Option<i32>, Error> {
    if !enabled()
        || args.first().is_some_and(|s| {
            matches!(
                s.as_str(),
                "help" | "--help" | "-h" | "version" | "--version"
            )
        })
    {
        return Ok(None);
    }
    stage_from(&crate::installed_targets::root()?, args, None)
}
fn stage_from(
    root: &Path,
    args: &[String],
    authenticated: Option<&[Value]>,
) -> Result<Option<i32>, Error> {
    let rows = runtime_files(root)?;
    if authenticated.is_some_and(|expected| expected != rows.as_slice()) {
        return Err("authenticated seed changed before snapshot".into());
    }
    let identity = protocol::hash(&serde_json::to_vec(&rows)?);
    let store = cache()?;
    let destination = store.join(&identity[7..]);
    if root == destination {
        ensure_protocol(&destination)?;
        return Ok(None);
    }
    let cwd = fs::canonicalize(std::env::current_dir()?)?;
    if store.starts_with(&cwd) {
        return Err(
            "project includes the runtime cache; choose a narrower project directory".into(),
        );
    }
    if !destination.exists() {
        let temporary = store.join(format!(".staging-{}", nonce()?));
        fs::create_dir(&temporary)?;
        let cleanup = Scratch {
            parent: store.clone(),
            path: temporary.clone(),
        };
        copy_files(root, &temporary, &rows)?;
        #[cfg(target_os = "macos")]
        seal_runtime_tools(&temporary, &rows)?;
        if runtime_files(root)? != rows || runtime_files(&temporary)? != rows {
            return Err("runtime changed during snapshot".into());
        }
        match fs::rename(&temporary, &destination) {
            Ok(()) => {}
            Err(error) if destination.exists() => {
                let _ = error;
            }
            Err(error) => return Err(error.into()),
        }
        drop(cleanup);
    }
    if runtime_files(&destination)? != rows {
        return Err("cached native runtime changed".into());
    }
    let mut child = coordinator(&destination, args)?;
    child.command.current_dir(&cwd);
    Ok(Some(output(native::run_with_stdin(
        &mut child.command,
        &protocol::Limits {
            timeout_ms: 900000,
            memory_bytes: 1 << 30,
            stdout_bytes: 16 << 20,
            stderr_bytes: 16 << 20,
        },
    )?)?))
}
fn authenticate_seed(root: &Path) -> Result<Vec<Value>, Error> {
    let snapshot = runtime_files(root)?;
    let metadata: Value = serde_json::from_slice(&read(&root.join("seed.json"), 16 << 20)?)?;
    if metadata["schema"] != "kelft.native-seed/1"
        || metadata["target"].as_str() != Some(Target::current()?.id())
        || metadata["trust"] != "initial-binary-trust"
    {
        return Err("seed host or integrity contract differs".into());
    }
    let files = metadata["files"]
        .as_array()
        .ok_or("seed inventory missing")?;
    if files.is_empty() || files.len() > 8192 {
        return Err("seed inventory bound".into());
    }
    let mut expected = std::collections::BTreeMap::new();
    let mut names = std::collections::BTreeSet::new();
    let mut total = 0u64;
    let maximum = if cfg!(target_os = "macos") {
        16u64 << 30
    } else {
        512u64 << 20
    };
    for item in files {
        let name = item["path"].as_str().ok_or("seed payload path missing")?;
        relative(name)?;
        if !names.insert(name.to_ascii_lowercase()) {
            return Err("duplicate seed payload path".into());
        }
        let size = item["bytes"].as_u64().ok_or("seed payload size missing")?;
        total = total
            .checked_add(size)
            .ok_or("seed payload size overflow")?;
        if size > 256 << 20 || total > maximum {
            return Err("seed payload exceeds prepared package bound".into());
        }
        let bytes = payload(root, name)?;
        if item["bytes"].as_u64() != Some(bytes.len() as u64)
            || item["sha256"] != protocol::hash(&bytes)
        {
            return Err(format!("seed payload differs: {name}").into());
        }
        expected.insert(name, item);
    }
    let suffix = Target::current()?.executable_suffix();
    for name in [
        format!("bin/kelft{suffix}"),
        format!("bin/kelft-boundary{suffix}"),
        format!("rootfs/compiler{suffix}"),
        "rootfs/control/toolchain.json".into(),
    ] {
        if !expected.contains_key(name.as_str()) {
            return Err("seed missing required native input".into());
        }
    }
    for row in &snapshot {
        let name = row["path"].as_str().ok_or("runtime path missing")?;
        if name == "seed.json" {
            continue;
        }
        let declared = expected
            .get(name)
            .ok_or("runtime file absent from seed inventory")?;
        if declared["bytes"] != row["bytes"] || declared["sha256"] != row["sha256"] {
            return Err("seed runtime observation differs".into());
        }
    }
    if runtime_files(root)? != snapshot {
        return Err("seed changed during authentication".into());
    }
    Ok(snapshot)
}
pub fn bootstrap(args: &[String]) -> Result<i32, Error> {
    if !enabled() || args.len() < 5 || args[1] != "--package" || args[3] != "--" {
        return Err("usage: bootstrap --package DIRECTORY -- COMMAND".into());
    }
    let package = fs::canonicalize(&args[2])?;
    parents(&package)?;
    let authenticated = authenticate_seed(&package)?;
    let expected = payload(
        &package,
        &format!("bin/kelft{}", Target::current()?.executable_suffix()),
    )?;
    if protocol::hash(&expected) != protocol::hash(&read(&std::env::current_exe()?, 64 << 20)?) {
        return Err("bootstrap launcher differs from seed package".into());
    }
    stage_from(&package, &args[4..], Some(&authenticated))?
        .ok_or_else(|| "bootstrap seed must be separate from runtime cache".into())
}
struct Scratch {
    parent: PathBuf,
    path: PathBuf,
}
impl Drop for Scratch {
    fn drop(&mut self) {
        if self.path.parent() == Some(self.parent.as_path())
            && self
                .path
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.starts_with(".kelft-rebuild-") || s.starts_with(".staging-"))
            && fs::canonicalize(&self.path).is_ok_and(|p| p == self.path)
        {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}
fn boundary(args: Vec<String>) -> Result<native::Output, Error> {
    let mut boundary = crate::boundary_command()?;
    boundary.command.args(args).env_clear();
    #[cfg(target_os = "linux")]
    let result = native::run(
        &mut boundary.command,
        &protocol::Limits {
            timeout_ms: 600000,
            memory_bytes: 1 << 30,
            stdout_bytes: 16 << 20,
            stderr_bytes: 16 << 20,
        },
    );
    #[cfg(any(target_os = "windows", target_os = "macos"))]
    let result = boundary.run(&protocol::Limits {
        timeout_ms: 600000,
        memory_bytes: 1 << 30,
        stdout_bytes: 16 << 20,
        stderr_bytes: 16 << 20,
    });
    result
}
fn ensure_protocol(root: &Path) -> Result<(), Error> {
    let identity = crate::compiler_sha256()?;
    let marker = root.join(".protocol-checked.json");
    if marker.exists() {
        let value: Value = serde_json::from_slice(&read(&marker, 4096)?)?;
        if value["compilerSHA256"] == identity && value["protocol"] == "0.1" {
            return Ok(());
        }
    }
    let parent = cache()?;
    let probe = parent.join(format!(".kelft-rebuild-probe-{}", nonce()?));
    fs::create_dir(&probe)?;
    let _cleanup = Scratch {
        parent,
        path: probe.clone(),
    };
    let source = probe.join("probe.kelft");
    fs::write(&source, b"fn main()->void {}\n")?;
    let result = boundary(vec![
        "tokens".into(),
        source.to_str().ok_or("probe path")?.into(),
        "--project-root".into(),
        probe.to_str().ok_or("probe root")?.into(),
    ])?;
    if result.exit != Some(0) || result.failure.is_some() {
        return Err(format!(
            "installed compiler protocol probe failed: {}",
            String::from_utf8_lossy(&result.stderr)
        )
        .into());
    }
    let value: Value = serde_json::from_slice(&result.stdout)?;
    if !value
        .as_array()
        .is_some_and(|a| !a.is_empty() && a[0]["span"]["start"] == 0)
    {
        return Err("installed compiler protocol differs".into());
    }
    fs::write(
        marker,
        serde_json::to_vec(&json!({"compilerSHA256":identity,"protocol":"0.1"}))?,
    )?;
    Ok(())
}
fn sources(root: &Path) -> Result<Vec<Value>, Error> {
    let mut rows = vec![];
    for name in ["selfhost", "stdlib"] {
        walk(root, &root.join(name), &mut rows, 0, true)?;
    }
    rows.sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));
    Ok(rows)
}
fn full_output(raw: &str, source: &Path) -> Result<PathBuf, Error> {
    let path = Path::new(raw);
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        source.join(path)
    };
    let mut normalized = PathBuf::new();
    for part in absolute.components() {
        match part {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                if !normalized.pop() {
                    return Err("invalid rebuild output".into());
                }
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    parents(&normalized)?;
    let mut ancestor = normalized.clone();
    let mut missing = vec![];
    while !ancestor.exists() {
        missing.push(
            ancestor
                .file_name()
                .ok_or("output ancestor missing")?
                .to_owned(),
        );
        if !ancestor.pop() {
            return Err("output ancestor missing".into());
        }
    }
    let mut resolved = fs::canonicalize(ancestor)?;
    for component in missing.iter().rev() {
        resolved.push(component);
    }
    normalized = resolved;
    if normalized == source
        || source.starts_with(&normalized)
        || normalized == crate::installed_targets::root()?
        || normalized.starts_with(cache()?)
    {
        return Err("rebuild output overlaps source or runtime cache".into());
    }
    Ok(normalized)
}
fn policy(request: &Value) -> Result<Value, Error> {
    let image = load_policy("rebuild", POLICY)?;
    let result = crate::installed_targets::evaluate(&image, request)?;
    if result["schema"] != "kelft.rebuild-action/1" {
        return Err("invalid rebuild policy response".into());
    }
    Ok(result)
}
fn present_failure(action: &Value, args: &[String]) -> Result<i32, Error> {
    let code = action["exit"].as_i64().unwrap_or(1) as i32;
    if args.iter().any(|s| s == "--json") {
        println!(
            "{}",
            json!({"schema":"kelft.command-result/1","command":"rebuild","status":"failure","error":action["error"]})
        );
        return Ok(code);
    }
    eprintln!(
        "error[{}]: {}",
        action["error"]["code"].as_str().unwrap_or("REBUILD_INPUT"),
        action["error"]["message"]
            .as_str()
            .unwrap_or("rebuild failed")
    );
    Ok(code)
}
pub fn dispatch(args: &[String]) -> Result<i32, Error> {
    if !enabled() {
        return Err("this installation does not include native rebuilding".into());
    }
    let mut request =
        json!({"schema":"kelft.rebuild-request/1","arguments":args,"host":Target::current()?.id()});
    let action = policy(&request)?;
    if action["operation"] == "complete" {
        return present_failure(&action, args);
    }
    let cwd = std::env::current_dir()?;
    let raw = Path::new(action["source"].as_str().ok_or("source missing")?);
    let source = fs::canonicalize(if raw.is_absolute() {
        raw.to_owned()
    } else {
        cwd.join(raw)
    })?;
    parents(&source)?;
    if !source.is_dir() || source.parent().is_none() {
        return Err("invalid rebuild source root".into());
    }
    let rows = sources(&source)?;
    request["sources"] = json!(rows);
    let action = policy(&request)?;
    if action["operation"] == "complete" {
        return present_failure(&action, args);
    }
    let destination = full_output(action["out"].as_str().ok_or("output missing")?, &source)?;
    if destination.exists() {
        let old: Value =
            serde_json::from_slice(&read(&destination.join("rebuild.json"), 16 << 20)?)?;
        if old["schema"] != "kelft.native-rebuild/1" {
            return Err("output exists and is not a local compiler rebuild".into());
        }
    }
    let work = source.join(format!(".kelft-rebuild-{}", nonce()?));
    fs::create_dir(&work)?;
    let _cleanup = Scratch {
        parent: source.clone(),
        path: work.clone(),
    };
    let package = work.join("package");
    fs::create_dir(&package)?;
    let installed = crate::installed_targets::root()?;
    let inputs = runtime_files(&installed)?;
    copy_files(&installed, &package, &inputs)?;
    let seed_metadata = package.join("seed.json");
    if seed_metadata.exists() {
        fs::remove_file(seed_metadata)?;
    }
    let mut modes: Vec<Value> = inputs
        .iter()
        .filter(|row| row["path"] != "runtime-modes.json" && row["path"] != "seed.json")
        .map(|row| json!({"path":row["path"],"mode":row["mode"]}))
        .collect();
    let suffix = Target::current()?.executable_suffix();
    let compiler_name = format!("rootfs/compiler{suffix}");
    for item in &mut modes {
        if item["path"] == compiler_name {
            item["mode"] = json!(0o755);
        }
    }
    fs::write(
        package.join("runtime-modes.json"),
        serde_json::to_vec(&json!({"schema":"kelft.runtime-modes/1","files":modes}))?,
    )?;
    // The host and linker inputs are retained; the compiler itself is rebuilt.
    let compiler = package.join(format!("rootfs/compiler{suffix}"));
    fs::remove_file(&compiler)?;
    let maximum = work.join("maximum.json");
    #[cfg(target_os = "linux")]
    let maximum_bytes = read(&installed.join("rootfs/control/maximum.json"), 1 << 20)?;
    #[cfg(not(target_os = "linux"))]
    let maximum_bytes = b"{\"read\":[\"/project\",\"/control\",\"/fixtures\",\"/out\"],\"write\":[\"/out\"],\"execute\":false}".to_vec();
    // Linux's compiler measures linker/runtime files inside its fixed namespace.
    // Retain the authenticated seed maximum needed for those reads and service
    // calls; the boundary keeps its fixed linker, mounts and capability policy.
    fs::write(&maximum, &maximum_bytes)?;
    let object = compiler.with_extension(if suffix.is_empty() { "o" } else { "obj" });
    let text = |p: &Path| -> Result<String, Error> {
        Ok(p.to_str().ok_or("Unicode rebuild paths required")?.into())
    };
    let result = boundary(vec![
        "native-build".into(),
        text(&source.join(action["entry"].as_str().ok_or("entry missing")?))?,
        "--project-root".into(),
        text(&source)?,
        "--capabilities".into(),
        text(&maximum)?,
        "--object-output".into(),
        text(&object)?,
        "-o".into(),
        text(&compiler)?,
    ])?;
    fs::write(
        work.join("compiler.log"),
        [result.stdout.clone(), result.stderr.clone()].concat(),
    )?;
    if result.exit != Some(0) || result.failure.is_some() {
        use std::io::Write;
        std::io::stderr().write_all(&result.stderr)?;
        return Err("compiler rebuild failed".into());
    }
    let bytes = read(&compiler, 64 << 20)?;
    Target::current()?.validate_executable(&bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&compiler, fs::Permissions::from_mode(0o755))?;
    }
    let compiler_hash = protocol::hash(&bytes);
    let receipt: Value = serde_json::from_slice(&result.stdout)?;
    if receipt["executableHash"] != compiler_hash {
        return Err("compiler rebuild receipt differs".into());
    }
    if sources(&source)? != rows || runtime_files(&installed)? != inputs {
        return Err("rebuild inputs changed".into());
    }
    let object_bytes = read(&object, 256 << 20)?;
    let saved_object = work.join(object.file_name().ok_or("object filename")?);
    fs::rename(&object, &saved_object)?;
    let object = saved_object;
    fs::write(
        work.join("generation.json"),
        serde_json::to_vec(&json!({
            "schema":"kelft.native-generation/1","host":Target::current()?.id(),
            "sourceInventorySHA256":protocol::hash(&serde_json::to_vec(&rows)?),"sources":rows,
            "compiler":{"sha256":compiler_hash,"bytes":bytes.len()},
            "object":{"sha256":protocol::hash(&object_bytes),"bytes":object_bytes.len()},
            "boundarySHA256":protocol::hash(&read(&installed.join(format!("bin/kelft-boundary{suffix}")),64<<20)?),
            "seedCompilerSHA256":crate::compiler_sha256()?,"maximumSHA256":protocol::hash(&maximum_bytes),
            "releaseEligible":false
        }))?,
    )?;
    let policies = package.join("rootfs/policies");
    fs::create_dir_all(&policies)?;
    let mut policy_records = serde_json::Map::new();
    for item in action["policies"]
        .as_array()
        .ok_or("rebuild policy list missing")?
    {
        let name = item["name"].as_str().ok_or("rebuild policy name missing")?;
        let entry = item["entry"]
            .as_str()
            .ok_or("rebuild policy entry missing")?;
        if !matches!(
            (name, entry),
            ("testing", "selfhost/toolchain/testing.kelft")
                | ("rebuild", "selfhost/toolchain/rebuild.kelft")
        ) {
            return Err("unsupported rebuild policy image".into());
        }
        let image = policies.join(format!("{name}{suffix}"));
        // Retained policy snapshots may be read-only. Replace only the copy in
        // this unpublished work directory before invoking the confined writer.
        if image.exists() {
            plain(&image)?;
            fs::remove_file(&image)?;
        }
        let arguments = [
            "native-build",
            &text(&source.join(entry))?,
            "--project-root",
            &text(&source)?,
            "--capabilities",
            &text(&maximum)?,
            "-o",
            &text(&image)?,
        ]
        .map(String::from);
        let mut child = coordinator(&package, &arguments)?;
        let result = native::run_with_stdin(
            &mut child.command,
            &protocol::Limits {
                timeout_ms: 600000,
                memory_bytes: 1 << 30,
                stdout_bytes: 4 << 20,
                stderr_bytes: 1 << 20,
            },
        )?;
        if result.exit != Some(0) || result.failure.is_some() {
            return Err(format!(
                "{name} policy rebuild failed: {}",
                String::from_utf8_lossy(&result.stderr)
            )
            .into());
        }
        let bytes = read(&image, 64 << 20)?;
        Target::current()?.validate_executable(&bytes)?;
        if name == "rebuild" {
            let checked = crate::installed_targets::evaluate(
                &bytes,
                &json!({"schema":"kelft.rebuild-request/1","arguments":["rebuild"],"host":Target::current()?.id()}),
            )?;
            if checked["schema"] != "kelft.rebuild-action/1"
                || checked["operation"] != "rebuild"
                || checked["protocol"] != "0.1"
            {
                return Err("rebuilt policy protocol differs".into());
            }
        }
        policy_records.insert(
            name.into(),
            json!({"sha256":protocol::hash(&bytes),"bytes":bytes.len()}),
        );
    }
    if policy_records.len() != 2 || sources(&source)? != rows {
        return Err("rebuild policy inputs changed or are incomplete".into());
    }
    let report = json!({"schema":"kelft.native-rebuild/1","status":"built","host":Target::current()?.id(),"protocol":"0.1","origin":"local-rebuild","sourceRoot":source,"sources":rows,"sourceInventorySHA256":protocol::hash(&serde_json::to_vec(&rows)?),"seedCompilerSHA256":crate::compiler_sha256()?,"compiler":{"sha256":compiler_hash,"bytes":bytes.len()},"object":{"sha256":protocol::hash(&object_bytes),"bytes":object_bytes.len()},"policies":policy_records,"hostsRebuilt":false,"releaseEligible":false});
    fs::write(
        package.join("rebuild.json"),
        serde_json::to_vec_pretty(&report)?,
    )?;
    fs::copy(
        &object,
        package.join(object.file_name().ok_or("object filename")?),
    )?;
    // An actual compiler command checks the new core's protocol before publication.
    let probe = work.join("probe.kelft");
    fs::write(&probe, b"fn main()->void {}\n")?;
    let arguments = [
        "tokens",
        probe.to_str().ok_or("probe path")?,
        "--project-root",
        source.to_str().ok_or("source path")?,
        "--json",
    ]
    .map(String::from);
    let mut child = coordinator(&package, &arguments)?;
    let checked = native::run_with_stdin(
        &mut child.command,
        &protocol::Limits {
            timeout_ms: 600000,
            memory_bytes: 1 << 30,
            stdout_bytes: 4 << 20,
            stderr_bytes: 1 << 20,
        },
    )?;
    if checked.exit != Some(0) || checked.failure.is_some() {
        return Err(format!(
            "rebuilt compiler probe failed: {}",
            String::from_utf8_lossy(&checked.stderr)
        )
        .into());
    }
    let response: Value = serde_json::from_slice(&checked.stdout)?;
    if response["status"] != "success" || !response["data"].is_array() {
        return Err("rebuilt compiler protocol differs".into());
    }
    fs::create_dir_all(destination.parent().ok_or("output parent")?)?;
    parents(&destination)?;
    let publish = destination
        .parent()
        .unwrap()
        .join(format!(".kelft-rebuild-{}", nonce()?));
    fs::create_dir(&publish)?;
    let _publish_cleanup = Scratch {
        parent: destination.parent().unwrap().to_owned(),
        path: publish.clone(),
    };
    copy_files(&package, &publish, &runtime_files(&package)?)?;
    fs::copy(
        package.join(object.file_name().unwrap()),
        publish.join(object.file_name().unwrap()),
    )?;
    let backup = destination
        .parent()
        .unwrap()
        .join(format!(".kelft-rebuild-{}", nonce()?));
    let had_previous = destination.exists();
    if had_previous {
        fs::rename(&destination, &backup)?;
    }
    if let Err(error) = fs::rename(&publish, &destination) {
        if had_previous {
            let _ = fs::rename(&backup, &destination);
        }
        return Err(error.into());
    }
    if had_previous {
        drop(Scratch {
            parent: destination.parent().unwrap().to_owned(),
            path: backup,
        });
    }
    if action["json"] == true {
        println!(
            "{}",
            json!({"schema":"kelft.command-result/1","command":"rebuild","status":"success","output":destination,"data":report})
        );
    } else {
        println!(
            "Built {}",
            destination.join(format!("bin/kelft{suffix}")).display()
        );
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn test_parent() -> PathBuf {
        let parent = std::env::temp_dir();
        if cfg!(unix) {
            fs::canonicalize(parent).unwrap()
        } else {
            parent
        }
    }
    #[test]
    fn seed_authentication_binds_payloads_and_snapshot_without_pinning_local_rebuilds() {
        let parent = test_parent();
        let root = parent.join(format!(".kelft-rebuild-{}", nonce().unwrap()));
        fs::create_dir_all(root.join("rootfs/control")).unwrap();
        fs::create_dir(root.join("bin")).unwrap();
        let _cleanup = Scratch {
            parent,
            path: root.clone(),
        };
        let suffix = Target::current().unwrap().executable_suffix();
        let core = format!("rootfs/compiler{suffix}");
        for name in [
            format!("bin/kelft{suffix}"),
            format!("bin/kelft-boundary{suffix}"),
            core.clone(),
        ] {
            fs::write(root.join(name), b"native fixture").unwrap();
        }
        fs::write(root.join("rootfs/control/toolchain.json"), b"{}").unwrap();
        let files = runtime_files(&root).unwrap();
        let metadata = json!({"schema":"kelft.native-seed/1","target":Target::current().unwrap().id(),"trust":"initial-binary-trust","files":files});
        let manifest = root.join("seed.json");
        fs::write(&manifest, serde_json::to_vec(&metadata).unwrap()).unwrap();
        let authenticated = authenticate_seed(&root).unwrap();
        fs::write(root.join(&core), b"edited fixture").unwrap();
        assert!(
            authenticate_seed(&root)
                .unwrap_err()
                .to_string()
                .contains("seed payload differs")
        );
        assert!(runtime_files(&root).is_ok());
        assert!(
            stage_from(&root, &["doctor".into()], Some(&authenticated))
                .unwrap_err()
                .to_string()
                .contains("authenticated seed changed")
        );
        fs::write(root.join(&core), b"native fixture").unwrap();
        fs::write(root.join("rootfs/unlisted"), b"unexpected input").unwrap();
        assert!(authenticate_seed(&root).is_err());
        fs::remove_file(root.join("rootfs/unlisted")).unwrap();
        let mut missing = metadata.clone();
        missing["files"]
            .as_array_mut()
            .unwrap()
            .retain(|row| row["path"] != core);
        fs::write(&manifest, serde_json::to_vec(&missing).unwrap()).unwrap();
        assert!(authenticate_seed(&root).is_err());
        let mut duplicate = metadata.clone();
        let mut alias = duplicate["files"][0].clone();
        alias["path"] = json!(alias["path"].as_str().unwrap().to_ascii_uppercase());
        duplicate["files"].as_array_mut().unwrap().push(alias);
        fs::write(&manifest, serde_json::to_vec(&duplicate).unwrap()).unwrap();
        assert!(authenticate_seed(&root).is_err());
        let mut oversized = metadata.clone();
        oversized["files"][0]["bytes"] = json!((256u64 << 20) + 1);
        fs::write(&manifest, serde_json::to_vec(&oversized).unwrap()).unwrap();
        assert!(
            authenticate_seed(&root)
                .unwrap_err()
                .to_string()
                .contains("prepared package bound")
        );
        fs::write(&manifest, serde_json::to_vec(&metadata).unwrap()).unwrap();
        assert!(authenticate_seed(&root).is_ok());
    }
    #[cfg(unix)]
    #[test]
    fn project_copies_remain_removable_and_execution_tools_are_sealed() {
        use std::os::unix::fs::PermissionsExt;
        let parent = test_parent();
        let root = parent.join(format!(".kelft-rebuild-{}", nonce().unwrap()));
        fs::create_dir(&root).unwrap();
        let _cleanup = Scratch {
            parent,
            path: root.clone(),
        };
        let source = root.join("source");
        fs::create_dir_all(source.join("rootfs/toolchain/sdk/usr/lib")).unwrap();
        fs::create_dir(source.join("bin")).unwrap();
        fs::write(source.join("bin/kelft"), b"fixture").unwrap();
        let name = "rootfs/toolchain/sdk/usr/lib/libSystem.tbd";
        fs::write(source.join(name), b"import declarations").unwrap();
        fs::set_permissions(source.join(name), fs::Permissions::from_mode(0o444)).unwrap();
        let rows = runtime_files(&source).unwrap();
        let project = root.join("project");
        fs::create_dir(&project).unwrap();
        copy_files(&source, &project, &rows).unwrap();
        assert_ne!(
            fs::metadata(project.join("rootfs/toolchain/sdk"))
                .unwrap()
                .permissions()
                .mode()
                & 0o200,
            0
        );
        fs::remove_dir_all(&project).unwrap();
        let execution = root.join("execution");
        fs::create_dir(&execution).unwrap();
        copy_files(&source, &execution, &rows).unwrap();
        seal_runtime_tools(&execution, &rows).unwrap();
        assert_eq!(
            fs::metadata(execution.join("rootfs/toolchain/sdk"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o555
        );
        assert_eq!(runtime_files(&execution).unwrap(), rows);
        // Restore only these private fixture directories before test cleanup.
        for name in [
            "rootfs/toolchain/sdk",
            "rootfs/toolchain/sdk/usr",
            "rootfs/toolchain/sdk/usr/lib",
        ] {
            fs::set_permissions(execution.join(name), fs::Permissions::from_mode(0o755)).unwrap();
        }
    }
    #[cfg(unix)]
    #[test]
    fn runtime_snapshots_preserve_pinned_manifest_modes() {
        use std::os::unix::fs::PermissionsExt;
        let parent = test_parent();
        let root = parent.join(format!(".kelft-rebuild-{}", nonce().unwrap()));
        fs::create_dir(&root).unwrap();
        let _cleanup = Scratch {
            parent,
            path: root.clone(),
        };
        let source = root.join("source");
        let destination = root.join("destination");
        for dir in [&source, &destination] {
            fs::create_dir(dir).unwrap();
            for name in ["bin", "rootfs"] {
                fs::create_dir(dir.join(name)).unwrap();
            }
        }
        fs::write(source.join("manifest.json"), b"{}").unwrap();
        fs::set_permissions(
            source.join("manifest.json"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let rows = runtime_files(&source).unwrap();
        assert_eq!(rows[0]["mode"], 0o600);
        copy_files(&source, &destination, &rows).unwrap();
        assert_eq!(runtime_files(&destination).unwrap(), rows);
        fs::set_permissions(
            source.join("manifest.json"),
            fs::Permissions::from_mode(0o777),
        )
        .unwrap();
        fs::write(
            source.join("runtime-modes.json"),
            br#"{"schema":"kelft.runtime-modes/1","files":[{"path":"manifest.json","mode":384}]}"#,
        )
        .unwrap();
        let observed = runtime_files(&source).unwrap();
        assert_eq!(
            observed
                .iter()
                .find(|r| r["path"] == "manifest.json")
                .unwrap()["mode"],
            0o600
        );
        fs::write(
            source.join("runtime-modes.json"),
            br#"{"schema":"kelft.runtime-modes/1","files":[{"path":"../outside","mode":384}]}"#,
        )
        .unwrap();
        assert!(runtime_files(&source).is_err());
    }
    #[test]
    fn split_payloads_authenticate_parts_and_reject_escape() {
        let parent = test_parent();
        let root = parent.join(format!(".kelft-rebuild-{}", nonce().unwrap()));
        fs::create_dir(&root).unwrap();
        let _cleanup = Scratch {
            parent,
            path: root.clone(),
        };
        fs::create_dir(root.join("parts")).unwrap();
        fs::write(root.join("parts/0"), b"abc").unwrap();
        let manifest = json!({"schema":"kelft.seed-parts/1","files":[{"path":"rootfs/tool","bytes":3,"mode":493,"sha256":protocol::hash(b"abc"),"parts":[{"path":"parts/0","bytes":3,"sha256":protocol::hash(b"abc")}]}]});
        fs::write(
            root.join("seed-parts.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        assert_eq!(payload(&root, "rootfs/tool").unwrap(), b"abc");
        fs::write(root.join("parts/0"), b"bad").unwrap();
        assert!(payload(&root, "rootfs/tool").is_err());
        assert!(payload(&root, "../escape").is_err());
    }
    #[test]
    fn source_observation_rejects_directory_aliases() {
        let parent = test_parent();
        let root = parent.join(format!(".kelft-rebuild-{}", nonce().unwrap()));
        fs::create_dir(&root).unwrap();
        let _cleanup = Scratch {
            parent,
            path: root.clone(),
        };
        let target = root.join("target");
        fs::create_dir(&target).unwrap();
        let link = root.join("link");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&target, &link).unwrap();
        #[cfg(windows)]
        {
            if std::os::windows::fs::symlink_dir(&target, &link).is_err() {
                return;
            }
        }
        assert!(walk(&root, &link, &mut vec![], 0, true).is_err());
    }
}
