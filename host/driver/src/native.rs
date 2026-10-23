use crate::protocol::{self, Limits};
use std::{
    fs,
    io::Read,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
type Error = Box<dyn std::error::Error>;
pub struct Output {
    pub exit: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub failure: Option<String>,
}
pub fn private_temp_dir() -> Result<std::path::PathBuf, Error> {
    #[cfg(all(target_os="windows",feature="windows-host"))]
    { Ok(kelft_wasi::windows_snapshot::temporary_directory()?) }
    #[cfg(not(all(target_os="windows",feature="windows-host")))]
    { Ok(fs::canonicalize(std::env::temp_dir())?) }
}
pub fn run(command: &mut Command, limits: &Limits) -> Result<Output, Error> {
    command.stdin(Stdio::null());
    run_with_stdin(command,limits)
}
pub fn run_with_stdin(command: &mut Command, limits: &Limits) -> Result<Output, Error> {
    run_with_cancel(command,limits,None)
}
pub fn run_with_cancel(command: &mut Command, limits: &Limits,cancel:Option<&std::sync::atomic::AtomicBool>) -> Result<Output, Error> {
    limits.validate()?;
    let mut nonce = [0u8; 24];
    getrandom::fill(&mut nonce).map_err(|_| "process entropy unavailable")?;
    let directory = private_temp_dir()?.join(format!("kelft-process-{}", protocol::hex(&nonce)));
    fs::create_dir(&directory)?;
    let run = (|| {
        let stdout = directory.join("stdout");
        let stderr = directory.join("stderr");
        command
            .stdout(Stdio::from(fs::File::create(&stdout)?))
            .stderr(Stdio::from(fs::File::create(&stderr)?));
        let mut child = command.spawn()?;
        let start = Instant::now();
        let mut failure = None;
        let status = loop {
            if cancel.is_some_and(|v|v.load(std::sync::atomic::Ordering::Acquire)) {
                failure=Some("process session cancelled".into());child.kill()?;break child.wait()?;
            }
            if fs::metadata(&stdout)?.len() > limits.stdout_bytes as u64
                || fs::metadata(&stderr)?.len() > limits.stderr_bytes as u64
            {
                failure = Some("process output limit exceeded".into());
                child.kill()?;
                break child.wait()?;
            }
            if start.elapsed() > Duration::from_millis(limits.timeout_ms) {
                failure = Some("process timed out".into());
                child.kill()?;
                break child.wait()?;
            }
            if let Some(status) = child.try_wait()? {
                break status;
            }
            thread::sleep(Duration::from_millis(5));
        };
        if fs::metadata(&stdout)?.len() > limits.stdout_bytes as u64
            || fs::metadata(&stderr)?.len() > limits.stderr_bytes as u64
        {
            failure = Some("process output limit exceeded".into());
        }
        let mut out = vec![];
        let mut err = vec![];
        fs::File::open(stdout)?
            .take(limits.stdout_bytes as u64)
            .read_to_end(&mut out)?;
        fs::File::open(stderr)?
            .take(limits.stderr_bytes as u64)
            .read_to_end(&mut err)?;
        Ok(Output {
            exit: status.code(),
            stdout: out,
            stderr: err,
            failure,
        })
    })();
    if fs::canonicalize(&directory)?.parent()
        != Some(fs::canonicalize(private_temp_dir()?)?.as_path())
    {
        return Err("invalid process cleanup target".into());
    }
    let cleanup = fs::remove_dir_all(directory);
    if run.is_ok() {
        cleanup?;
    }
    run
}
