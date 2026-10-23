//! Development controls for authenticated task lifetime. These controls do not
//! certify the artifact service, compiler driver, installed package or target.
#[cfg(target_os = "macos")]
mod platform {
    use kelft_wasi::{macos_task::{Endpoint, export_self},
        macos_seatbelt::{Prepared, Role, Limits}};
    use std::{io::{self, BufRead, Read, Write}, os::unix::process::CommandExt, process::Command,
        time::{Duration, Instant}};
    use kelft_wasi::macos_process::{self, Child};
    type Error = Box<dyn std::error::Error>;
    struct OwnedChild(Child);
    impl Drop for OwnedChild { fn drop(&mut self) { let _ = self.0.kill(); let _ = self.0.wait(); } }
    fn spawn(arguments: &[&str]) -> io::Result<OwnedChild> {
        Ok(OwnedChild(macos_process::spawn(&std::env::current_exe()?, &arguments.iter().map(|s|s.to_string()).collect::<Vec<_>>(), &[], &[])?))
    }
    fn line(output: &mut impl BufRead) -> io::Result<String> {
        let mut text = String::new();
        let n = output.take(4097).read_line(&mut text)?;
        if n == 0 || n > 4096 || !text.ends_with('\n') { return Err(io::Error::other(format!("bounded helper readiness missing: bytes={n} text={text:?}"))); }
        Ok(text.trim_end_matches('\n').to_owned())
    }
    fn ready(text: &str) -> io::Result<()> { println!("{text}"); io::stdout().flush() }
    fn child_line(child:&mut Child,output:&mut impl BufRead)->Result<String,Error>{
        match line(output){Ok(text)=>Ok(text),Err(error)=>{
            let start=Instant::now();let status=loop{let status=child.try_wait()?;if status.is_some()||start.elapsed()>=Duration::from_secs(1){break status;}std::thread::sleep(Duration::from_millis(5));};let mut diagnostic=String::new();
            if status.is_some(){if let Some(stderr)=child.stderr.take(){stderr.take(65536).read_to_string(&mut diagnostic)?;}}
            Err(format!("{error}: child={} status={status:?} reason={:?}: {diagnostic}",child.id(),child.exit_reason()).into())
        }}
    }
    fn worker(endpoint: &str, image: &str, candidate_mode: &str) -> Result<(), Error> {
        export_self(endpoint)?;
        let image = std::path::Path::new(image);
        if !image.is_absolute() || !image.is_file() { return Err("absolute prepared candidate image required".into()); }
        Prepared::new(Role::Candidate, image, None, Limits::native(15)?)?.enter()?;
        // The separate image inherits no endpoint argument or ambient environment.
        // It deliberately survives stdin EOF, so only trusted task termination
        // can satisfy a death control. The authenticated lifetime must remain effective across
        // the real exec, not just while the trusted Rust helper is running.
        Err(Command::new(image).arg(candidate_mode).env_clear().exec().into())
    }
    fn guardian(sender: u32, task_pid: u32) -> Result<(), Error> {
        let endpoint = Endpoint::new()?;
        ready(endpoint.name())?;
        let task = endpoint.receive(sender, task_pid)?;
        ready("guardian-ready")?;
        let mut byte = [0];
        // Only the supervisor owns the write end. EOF or I/O failure both
        // terminate the authenticated task through RAII cleanup.
        let _ = io::stdin().read(&mut byte);
        task.terminate()?;
        task.wait_dead(Duration::from_secs(2))?;
        Ok(())
    }
    fn supervisor(outer: &str, image: &str, candidate_mode: &str) -> Result<(), Error> {
        let endpoint = Endpoint::new()?;
        let mut child = spawn(&["--worker", endpoint.name(), image, candidate_mode])?;
        let task = endpoint.receive(child.0.id(), child.0.id())?;
        let mut output = io::BufReader::new(child.0.stdout.take().ok_or("worker stdout missing")?);
        if child_line(&mut child.0,&mut output)? != "isolated-worker-ready" { return Err("candidate isolation readiness differs".into()); }
        let sender = std::process::id().to_string(); let pid = child.0.id().to_string();
        let mut guard = spawn(&["--guardian", &sender, &pid])?;
        let mut guard_output = io::BufReader::new(guard.0.stdout.take().ok_or("guardian stdout missing")?);
        task.export(&child_line(&mut guard.0,&mut guard_output)?)?;
        if child_line(&mut guard.0,&mut guard_output)? != "guardian-ready" { return Err("guardian readiness differs".into()); }
        ready(&pid)?;
        task.export(outer)?;
        ready("supervisor-ready")?;
        // Monitor the guardian while retaining ownership of the worker. The
        // guardian monitors this process through its private pipe in turn.
        if unsafe { libc::fcntl(0, libc::F_SETFL, libc::O_NONBLOCK) } < 0 { return Err(io::Error::last_os_error().into()); }
        let start = Instant::now();
        loop {
            let mut byte = [0];
            match io::stdin().read(&mut byte) {
                Ok(1) if byte[0] == b'G' => { guard.0.kill()?; guard.0.wait()?; }
                Ok(0) => return Err("outer supervisor disappeared".into()),
                Err(error) if error.kind() != io::ErrorKind::WouldBlock && error.kind() != io::ErrorKind::Interrupted => return Err(error.into()),
                _ => (),
            }
            if guard.0.try_wait()?.is_some() {
                task.terminate()?; task.wait_dead(Duration::from_secs(2))?;
                child.0.wait()?; return Ok(());
            }
            if child.0.try_wait()?.is_some() { return Err("isolated worker exited before death control".into()); }
            if start.elapsed() > Duration::from_secs(10) { return Err("lifetime control deadline exceeded".into()); }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    fn wait(child: &mut Child) -> Result<(), Error> {
        let start = Instant::now();
        loop {
            if let Some(status) = child.try_wait()? {
                if status.success() { return Ok(()); }
                let mut diagnostic = String::new();
                if let Some(stderr) = child.stderr.take() { stderr.take(65536).read_to_string(&mut diagnostic)?; }
                return Err(format!("trusted helper failed: {status}: {diagnostic}").into());
            }
            if start.elapsed() > Duration::from_secs(5) { return Err("trusted helper exit deadline exceeded".into()); }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    fn collect(image: &str) -> Result<(), Error> {
        use sha2::{Digest,Sha256};let source=std::fs::canonicalize(image)?;let mut input=std::fs::File::open(&source)?;
        if input.metadata()?.len()>64<<20{return Err("candidate image exceeds bound".into());}let mut bytes=vec![];Read::by_ref(&mut input).take((64<<20)+1).read_to_end(&mut bytes)?;
        let expected=format!("sha256:{:x}",Sha256::digest(&bytes));let snapshot=kelft_wasi::macos_snapshot::Image::new(&bytes,&expected,&std::fs::canonicalize(std::env::temp_dir())?)?;
        let image=snapshot.path().to_str().ok_or("Unicode snapshot required")?;
        let mut observations = Vec::new();
        for candidate_mode in ["--wait","--churn"] {
        for kill_supervisor in [true, false] {
            let endpoint = Endpoint::new()?;
            let mut supervisor = spawn(&["--supervisor", endpoint.name(), image, candidate_mode])?;
            let mut output = io::BufReader::new(supervisor.0.stdout.take().ok_or("supervisor stdout missing")?);
            let pid: u32 = child_line(&mut supervisor.0,&mut output)?.parse()?;
            let task = endpoint.receive(supervisor.0.id(), pid)?;
            if child_line(&mut supervisor.0,&mut output)? != "supervisor-ready" || task.dead()? { return Err("live isolated worker positive control failed".into()); }
            let generation=task.current_generation()?;std::thread::sleep(Duration::from_millis(50));
            let generation_changed=task.current_generation()?!=generation;
            if candidate_mode=="--churn"&&!generation_changed{return Err("exec churn positive control did not change the kernel generation".into());}
            if kill_supervisor { supervisor.0.kill()?; supervisor.0.wait()?; }
            else { supervisor.0.stdin.as_mut().ok_or("supervisor control missing")?.write_all(b"G")?; }
            task.wait_dead(Duration::from_secs(3)).map_err(|error| io::Error::other(format!("{} control for worker {pid}: {error}", if kill_supervisor {"supervisor-death"} else {"guardian-death"})))?;
            if !kill_supervisor { wait(&mut supervisor.0)?; }
            observations.push(serde_json::json!({"mechanism": if kill_supervisor {"supervisor-death"} else {"guardian-death"},
                "candidateMode":candidate_mode,"execGenerationChangeVerified":generation_changed,"liveIsolatedWorkerPositive": true, "authenticatedProcessTerminationVerified": true}));
        }
        }
        // A trusted helper can supply its lifetime token but cannot choose the PID
        // expected by the receiver or forge the kernel sender audit trailer.
        for wrong_sender in [true, false] {
            let endpoint = Endpoint::new()?;
            let child = spawn(&["--worker", endpoint.name(), image, "--wait"])?;
            let pid = child.0.id();
            let result = endpoint.receive(if wrong_sender {std::process::id()} else {pid},
                if wrong_sender {pid} else {i32::MAX as u32});
            let error=result.err().ok_or("mismatched lifetime handoff accepted")?;
            if error.kind()!=io::ErrorKind::InvalidData{return Err(format!("authentication probe did not reach a valid handoff rejection: {error}").into());}
            observations.push(serde_json::json!({"mechanism":if wrong_sender {"sender-authentication"} else {"task-authentication"},
                "rejected":true,"rejectionKind":"invalid-data","error":error.to_string()}));
        }
        snapshot.verify()?;
        println!("{}", serde_json::json!({"schema":"kelft-macos-task-lifetime-development/2", "state":"passed",
            "observations":observations,"supervisorDeathVerified":true,"guardianDeathVerified":true,
            "separateCandidateExecVerified":true,"authenticatedSnapshotVerified":true,"artifactServiceIntegrated":false,"certified":false,"releaseEligible":false}));
        Ok(())
    }
    pub fn main() -> Result<(), Error> {
        let arguments = std::env::args().skip(1).collect::<Vec<_>>();
        match arguments.as_slice() {
            [mode, image] if mode == "--collect" => collect(image),
            [mode, endpoint, image, candidate_mode] if mode == "--worker" => worker(endpoint, image, candidate_mode),
            [mode, endpoint, image, candidate_mode] if mode == "--supervisor" => supervisor(endpoint, image, candidate_mode),
            [mode, sender, task] if mode == "--guardian" => guardian(sender.parse()?, task.parse()?),
            _ => Err("expected --collect on a native macOS host".into()),
        }
    }
}
#[cfg(target_os = "macos")]
fn main() { if let Err(error) = platform::main() { eprintln!("error[K0600]: {error}"); std::process::exit(125); } }
#[cfg(not(target_os = "macos"))]
fn main() { eprintln!("native macOS execution required"); std::process::exit(125); }
