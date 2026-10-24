//! Native component controls, not a compiler/package certificate.
#[cfg(target_os = "macos")]
mod platform {
    use kelft_wasi::{
        filesystem_channel::{self as rpc, Operation, Request},
        macos_seatbelt::{Limits, LinkerPaths, Prepared, Role, resource_contract},
        unix_filesystem::Broker,
    };
    use std::{
        fs,
        io::{self, Read},
        os::unix::{
            fs::DirBuilderExt,
            io::{AsRawFd, FromRawFd},
        },
        path::PathBuf,
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    type Error = Box<dyn std::error::Error>;
    fn denied(operation: &str, error: io::Error) -> Result<(), Error> {
        if !matches!(error.raw_os_error(), Some(libc::EPERM) | Some(libc::EACCES)) {
            return Err(format!("{operation}: expected authorization denial, got {error}").into());
        }
        Ok(())
    }
    fn request(operation: Operation, handle: u64, path: &str) -> Request {
        Request {
            sequence: 1,
            operation,
            handle,
            path: path.into(),
            amount: 0,
            data: vec![],
        }
    }
    fn capture(
        mut input: impl Read + Send + 'static,
        overflow: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> std::thread::JoinHandle<io::Result<Vec<u8>>> {
        std::thread::spawn(move || {
            let mut bytes = vec![];
            input.by_ref().take(65537).read_to_end(&mut bytes)?;
            if bytes.len() > 65536 {
                overflow.store(true, std::sync::atomic::Ordering::Release);
                bytes.truncate(65536);
            }
            Ok(bytes)
        })
    }
    fn native() -> Result<(), Error> {
        let name = std::ffi::CString::new("sysctl.proc_translated")?;
        let mut translated = 0i32;
        let mut size = std::mem::size_of_val(&translated);
        let result = unsafe {
            libc::sysctlbyname(
                name.as_ptr(),
                (&mut translated as *mut i32).cast(),
                &mut size,
                std::ptr::null_mut(),
                0,
            )
        };
        if result == 0 && translated != 0 {
            return Err("emulated macOS execution cannot satisfy native controls".into());
        }
        if result != 0 && io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT) {
            return Err(io::Error::last_os_error().into());
        }
        Ok(())
    }
    // This dedicated worker is single-threaded. After fork the child performs
    // only _exit, so inherited allocator/runtime locks are never touched.
    fn fork_control(expect_denial: bool) -> Result<(), Error> {
        let child = unsafe { libc::fork() };
        if child == 0 { unsafe { libc::_exit(0) }; }
        if child < 0 {
            let error = io::Error::last_os_error();
            if expect_denial { return denied("direct fork", error); }
            return Err(format!("fork positive control: {error}").into());
        }
        let mut status = 0;
        loop {
            let waited = unsafe { libc::waitpid(child, &mut status, 0) };
            if waited == child { break; }
            if waited < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) { continue; }
            return Err("fork positive-control cleanup failed".into());
        }
        if expect_denial { return Err("direct fork unexpectedly available".into()); }
        if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
            return Err("fork positive control failed".into());
        }
        Ok(())
    }
    fn worker(args: &[String]) -> Result<(), Error> {
        if args.len() != 4 {
            return Err("fixed worker arguments required".into());
        }
        native()?;
        let role = match args[1].as_str() {
            "compiler" => Role::Compiler,
            "candidate" => Role::Candidate,
            "linker" => Role::Linker,
            _ => return Err("unknown component role".into()),
        };
        let root = fs::canonicalize(&args[2])?;
        let endpoint: u16 = args[3].parse()?;
        let image = fs::canonicalize(std::env::current_exe()?)?;
        let (input, output, sdk, tools, object) = (
            root.join("input"),
            root.join("output"),
            root.join("sdk"),
            root.join("tools"),
            root.join("object"),
        );
        if fs::read(&input)? != b"broker-positive-control" {
            return Err("filesystem read positive control differs".into());
        }
        let root_descriptor=fs::File::open("/")?;
        let relative_input=std::ffi::CString::new(input.strip_prefix("/")?.to_str().ok_or("Unicode control input required")?)?;
        let before=unsafe{libc::openat(root_descriptor.as_raw_fd(),relative_input.as_ptr(),libc::O_RDONLY|libc::O_CLOEXEC)};
        if before<0{return Err(io::Error::last_os_error().into());}drop(unsafe{fs::File::from_raw_fd(before)});
        fs::write(root.join("before"), b"write-positive-control")?;
        fs::remove_file(root.join("before"))?;
        std::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, endpoint))?;
        if !Command::new(&image)
            .arg("--spawn-control")
            .env_clear()
            .status()?
            .success()
        {
            return Err("subprocess positive control failed".into());
        }
        fork_control(false)?;
        let params = if role == Role::Linker {
            Some(LinkerPaths {
                sdk: &sdk,
                tools: &tools,
                object: &object,
                output: &output,
            })
        } else {
            None
        };
        let contract = resource_contract(role)?;
        let ceiling = contract.memory.ceiling_bytes as usize;
        let prepared = Prepared::new(
            role,
            &image,
            params,
            Limits::native(10)?,
        )?;
        let descriptor: i32 = std::env::var("KELFT_FS_DESCRIPTOR")?.parse()?;
        if descriptor < 3 {
            return Err("private broker descriptor required".into());
        }
        let mut transport = unsafe { fs::File::from_raw_fd(descriptor) };
        prepared.enter()?;
        drop(fs::File::open("/")?);
        let traversed=unsafe{libc::openat(root_descriptor.as_raw_fd(),relative_input.as_ptr(),libc::O_RDONLY|libc::O_CLOEXEC)};
        if traversed>=0{drop(unsafe{fs::File::from_raw_fd(traversed)});return Err("literal loader root grant exposed a descendant".into());}
        denied("retained root descriptor traversal",io::Error::last_os_error())?;
        let mut bounds = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        for (resource, expected) in [
            (libc::RLIMIT_AS, ceiling as u64),
            (libc::RLIMIT_STACK, 16u64 << 20),
        ] {
            if unsafe { libc::getrlimit(resource, &mut bounds) } != 0
                || bounds.rlim_cur != expected
                || bounds.rlim_max != expected
            {
                return Err("native resource limits differ".into());
            }
        }
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        if mapping == libc::MAP_FAILED {
            return Err("anonymous mapping positive control failed".into());
        }
        unsafe { mapping.cast::<u8>().write_volatile(42); }
        if unsafe { libc::munmap(mapping, 4096) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                ceiling,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        if mapping != libc::MAP_FAILED {
            unsafe { libc::munmap(mapping, ceiling) };
            return Err("address-space bound did not reject an oversized mapping".into());
        }
        if io::Error::last_os_error().raw_os_error() != Some(libc::ENOMEM) {
            return Err("oversized mapping failed for an unverified reason".into());
        }
        // The installed hard limit must also reject cumulative reservations and
        // attempts by an isolated worker to raise its own ceiling.
        let chunk = ceiling / 16;
        let mut mappings = Vec::with_capacity(17);
        let mut exhausted = false;
        for _ in 0..17 {
            let mapping = unsafe { libc::mmap(std::ptr::null_mut(), chunk,
                libc::PROT_NONE, libc::MAP_PRIVATE | libc::MAP_ANON, -1, 0) };
            if mapping == libc::MAP_FAILED {
                exhausted = io::Error::last_os_error().raw_os_error() == Some(libc::ENOMEM);
                break;
            }
            mappings.push(mapping);
        }
        let successful_reservations = mappings.len();
        for mapping in mappings {
            if unsafe { libc::munmap(mapping, chunk) } != 0 { return Err(io::Error::last_os_error().into()); }
        }
        if !exhausted || successful_reservations == 0 { return Err("repeated reservation control failed".into()); }
        let raised = libc::rlimit { rlim_cur: ceiling as u64 + 4096, rlim_max: ceiling as u64 + 4096 };
        if unsafe { libc::setrlimit(libc::RLIMIT_AS, &raised) } == 0
            || io::Error::last_os_error().raw_os_error() != Some(libc::EPERM) {
            return Err("worker could raise its hard resource ceiling".into());
        }
        let mut denial_errors = vec![];
        if let Err(error) = denied(
            "project read",
            fs::read(&input)
                .err()
                .ok_or("native unauthorized read succeeded")?,
        ) { denial_errors.push(error.to_string()); }
        if let Err(error) = denied(
            "project write",
            fs::write(root.join("denied"), b"must-not-exist")
                .err()
                .ok_or("native unauthorized write succeeded")?,
        ) { denial_errors.push(error.to_string()); }
        if let Err(error) = denied(
            "loopback connection",
            std::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, endpoint))
                .err()
                .ok_or("network unexpectedly available")?,
        ) { denial_errors.push(error.to_string()); }
        if let Err(error) = denied(
            // Use the very image whose read/map/exec path is granted for the
            // initial role launch. A hidden unrelated executable's ENOENT
            // cannot stand in for process creation denial.
            "subprocess spawn of readable role image",
            Command::new(&image)
                .arg("--spawn-control")
                .env_clear()
                .spawn()
                .err()
                .ok_or("subprocess unexpectedly available")?,
        ) { denial_errors.push(error.to_string()); }
        if let Err(error) = fork_control(true) { denial_errors.push(error.to_string()); }
        let mut open = request(Operation::OpenRead, 1, ".");
        rpc::write_request(&mut transport, &open)?;
        let file = rpc::read_response(&mut transport, 1)?;
        if file.status != 0 {
            return Err("broker read open positive control failed".into());
        }
        open = Request {
            sequence: 2,
            operation: Operation::Read,
            handle: file.value,
            path: String::new(),
            amount: 64,
            data: vec![],
        };
        rpc::write_request(&mut transport, &open)?;
        let read = rpc::read_response(&mut transport, 2)?;
        if read.status != 0 || read.data != b"broker-positive-control" {
            return Err("broker read positive control failed".into());
        }
        open = Request {
            sequence: 3,
            operation: Operation::CreateNew,
            handle: 2,
            path: "broker-output".into(),
            amount: 0,
            data: vec![],
        };
        rpc::write_request(&mut transport, &open)?;
        let file = rpc::read_response(&mut transport, 3)?;
        if file.status != 0 {
            return Err("broker create positive control failed".into());
        }
        open = Request {
            sequence: 4,
            operation: Operation::Write,
            handle: file.value,
            path: String::new(),
            amount: 3,
            data: vec![0, 255, 128],
        };
        rpc::write_request(&mut transport, &open)?;
        if rpc::read_response(&mut transport, 4)?.status != 0 {
            return Err("broker write positive control failed".into());
        }
        if role == Role::Linker {
            if fs::read(sdk.join("fixture"))? != b"sdk-positive-control" {
                return Err("linker SDK positive control differs".into());
            }
            fs::write(output.join("linker-output"), b"linker-positive-control")?;
        } else {
            if let Err(error) = denied(
                "linker SDK read from candidate/compiler",
                fs::read(sdk.join("fixture"))
                    .err()
                    .ok_or("candidate received linker authority")?,
            ) { denial_errors.push(error.to_string()); }
            if let Err(error) = denied(
                "linker output write from candidate/compiler",
                fs::write(output.join("linker-output"), b"denied")
                    .err()
                    .ok_or("candidate received linker output authority")?,
            ) { denial_errors.push(error.to_string()); }
        }
        println!("{}", serde_json::json!({"state":if denial_errors.is_empty() {"passed"} else {"failed"}, "role":args[1],
            "positiveControls":if role == Role::Linker {12} else {10},
            "denialControls":(if role == Role::Linker {9} else {11}) - denial_errors.len(),
            "loaderRootDirectoryPositive":true,"rootDescriptorTraversalDenied":true,
            "resourceContract":contract, "limitReadbackVerified":true,
            "smallMappingPositive":true, "oversizedReservationDenied":true,
            "repeatedReservationDenied":true, "ceilingRaiseDenied":true,
            "repeatedReservationCount":successful_reservations,
            "denialErrors":denial_errors}));
        if !denial_errors.is_empty() { return Err(denial_errors.join("; ").into()); }
        Ok(())
    }
    fn resource_baseline() -> Result<(), Error> {
        native()?;
        let mut limits = serde_json::Map::new();
        for (name, resource) in [("addressSpace", libc::RLIMIT_AS), ("stack", libc::RLIMIT_STACK)] {
            let mut value = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
            if unsafe { libc::getrlimit(resource, &mut value) } != 0 {
                return Err(io::Error::last_os_error().into());
            }
            limits.insert(name.into(), serde_json::json!({
                "softBytes": value.rlim_cur.to_string(), "hardBytes": value.rlim_max.to_string()
            }));
        }
        let output = Command::new("/bin/ps").env_clear()
            .args(["-o", "vsz=,rss=", "-p", &std::process::id().to_string()]).output()?;
        if !output.status.success() || !output.stderr.is_empty() {
            return Err("native process memory baseline observation failed".into());
        }
        let values = std::str::from_utf8(&output.stdout)?.split_whitespace()
            .map(str::parse::<u64>).collect::<Result<Vec<_>, _>>()?;
        if values.len() != 2 || values[0] == 0 || values[1] == 0 {
            return Err("native process memory baseline is incomplete".into());
        }
        println!("{}", serde_json::json!({
            "schema": "kelft-macos-resource-baseline/1", "limits": limits,
            "virtualBytes": values[0].checked_mul(1024).ok_or("baseline size overflow")?.to_string(),
            "residentBytes": values[1].checked_mul(1024).ok_or("baseline size overflow")?.to_string(),
            "isolated": false, "resourceBoundVerified": false
        }));
        Ok(())
    }
    fn resource_candidate() -> Result<(), Error> {
        native()?;
        // Independent unsandboxed diagnostic. This cannot substitute for the
        // production role's own positive controls and limit enforcement checks.
        let ceiling = if cfg!(target_arch = "aarch64") { 512u64 << 30 } else { 64u64 << 30 };
        let mut result = serde_json::json!({
            "schema": "kelft-macos-resource-candidate/1", "isolated": false,
            "configuredPolicyChanged": false, "certified": false,
            "candidateAddressSpaceBytes": ceiling.to_string(),
            "stackBytes": (16u64 << 20).to_string()
        });
        for (name, resource, value) in [("addressSpace", libc::RLIMIT_AS, ceiling), ("stack", libc::RLIMIT_STACK, 16u64 << 20)] {
            let bound = libc::rlimit { rlim_cur: value, rlim_max: value };
            if unsafe { libc::setrlimit(resource, &bound) } != 0 {
                result["state"] = "setup-rejected".into();
                result["failedResource"] = name.into();
                result["errno"] = io::Error::last_os_error().raw_os_error().into();
                println!("{result}");return Ok(());
            }
            let mut observed = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
            if unsafe { libc::getrlimit(resource, &mut observed) } != 0 || observed.rlim_cur != value || observed.rlim_max != value {
                return Err("candidate resource readback differs".into());
            }
        }
        let positive = unsafe { libc::mmap(std::ptr::null_mut(), 4096, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_PRIVATE | libc::MAP_ANON, -1, 0) };
        if positive == libc::MAP_FAILED {return Err("candidate mapping positive control failed".into());}
        unsafe { positive.cast::<u8>().write_volatile(42); }
        if unsafe { libc::munmap(positive,4096) } != 0 {return Err(io::Error::last_os_error().into());}
        let oversized = unsafe { libc::mmap(std::ptr::null_mut(), ceiling as usize, libc::PROT_NONE, libc::MAP_PRIVATE | libc::MAP_ANON, -1, 0) };
        let oversized_errno = if oversized == libc::MAP_FAILED {io::Error::last_os_error().raw_os_error()} else {None};
        if oversized != libc::MAP_FAILED && unsafe { libc::munmap(oversized,ceiling as usize) } != 0 {return Err(io::Error::last_os_error().into());}
        let chunk = (ceiling/16) as usize;let mut mappings = vec![];let mut repeated_errno = None;
        for _ in 0..17 {
            let mapping = unsafe { libc::mmap(std::ptr::null_mut(), chunk, libc::PROT_NONE, libc::MAP_PRIVATE | libc::MAP_ANON, -1, 0) };
            if mapping == libc::MAP_FAILED {repeated_errno=io::Error::last_os_error().raw_os_error();break;}
            mappings.push(mapping);
        }
        let successful = mappings.len();for mapping in mappings {if unsafe {libc::munmap(mapping,chunk)} != 0 {return Err(io::Error::last_os_error().into());}}
        result["smallMappingPositive"] = true.into();
        result["oversizedReservationErrno"] = oversized_errno.into();
        result["repeatedReservationErrno"] = repeated_errno.into();
        result["repeatedReservationCount"] = successful.into();
        result["repeatedReservationChunkBytes"] = chunk.to_string().into();
        result["candidateReservationControlsPassed"] = (oversized_errno==Some(libc::ENOMEM)&&repeated_errno==Some(libc::ENOMEM)).into();
        result["state"] = "observed".into();
        println!("{result}");Ok(())
    }
    fn parent(root: PathBuf) -> Result<(), Error> {
        native()?;
        fs::DirBuilder::new().mode(0o700).create(&root)?;
        let image = std::env::current_exe()?;
        for role in ["compiler", "candidate", "linker"] {
            let directory = root.join(role);
            fs::DirBuilder::new().mode(0o700).create(&directory)?;
            for name in ["sdk", "tools", "output", "writable"] {
                fs::create_dir(directory.join(name))?;
            }
            fs::write(directory.join("input"), b"broker-positive-control")?;
            fs::write(directory.join("object"), b"private-object")?;
            fs::write(directory.join("sdk/fixture"), b"sdk-positive-control")?;
            let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
            let endpoint = listener.local_addr()?.port();
            let (mut host, child) = std::os::unix::net::UnixStream::pair()?;
            let mut broker = Broker::default();
            broker.add_root(&directory.join("input"), true, false)?;
            broker.add_root(&directory.join("writable"), false, true)?;
            let service = std::thread::spawn(move || {
                let mut output = host.try_clone()?;
                broker.serve(&mut host, &mut output)
            });
            let descriptor = child.as_raw_fd();
            if unsafe { libc::fcntl(descriptor, libc::F_SETFD, 0) } < 0 {
                return Err(io::Error::last_os_error().into());
            }
            let mut child_process = Command::new(&image)
                .args(["--worker", role])
                .arg(&directory)
                .arg(endpoint.to_string())
                .env_clear()
                .env("KELFT_FS_DESCRIPTOR", descriptor.to_string())
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?;
            drop(child);
            let overflow = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let stdout = capture(
                child_process.stdout.take().ok_or("capture missing")?,
                overflow.clone(),
            );
            let stderr = capture(
                child_process.stderr.take().ok_or("capture missing")?,
                overflow.clone(),
            );
            let start = Instant::now();
            let status = loop {
                if start.elapsed() > Duration::from_secs(15)
                    || overflow.load(std::sync::atomic::Ordering::Acquire)
                {
                    child_process.kill()?;
                    child_process.wait()?;
                    return Err("native component supervisor bound exceeded".into());
                }
                if let Some(status) = child_process.try_wait()? {
                    break status;
                }
                std::thread::sleep(Duration::from_millis(5));
            };
            service.join().map_err(|_| "component broker panicked")??;
            let stdout = String::from_utf8(stdout.join().map_err(|_| "capture panicked")??)?;
            let stderr = String::from_utf8(stderr.join().map_err(|_| "capture panicked")??)?;
            if overflow.load(std::sync::atomic::Ordering::Acquire) {
                return Err("native component output exceeded its bound".into());
            }
            fs::write(directory.join("stdout"), &stdout)?;
            fs::write(directory.join("stderr"), &stderr)?;
            if !status.success() {
                return Err(format!("{role} control failed: {status}: {stdout}{stderr}").into());
            }
            if fs::read(directory.join("writable/broker-output"))? != [0, 255, 128]
                || directory.join("denied").exists()
            {
                return Err("broker output or denial differs".into());
            }
            print!("{stdout}");
        }
        Ok(())
    }
    fn guest(image: &str, root: PathBuf) -> Result<(), Error> {
        native()?;
        let source = fs::canonicalize(image)?;
        let mut file=fs::File::open(&source)?;if file.metadata()?.len()>64<<20{return Err("guest image exceeds bound".into());}
        let mut bytes=vec![];Read::by_ref(&mut file).take((64<<20)+1).read_to_end(&mut bytes)?;
        use sha2::{Digest,Sha256};let expected=format!("sha256:{:x}",Sha256::digest(&bytes));
        let snapshot=kelft_wasi::macos_snapshot::Image::new(&bytes,&expected,&fs::canonicalize(std::env::temp_dir())?)?;
        fs::DirBuilder::new().mode(0o700).create(&root)?;
        for name in ["project", "out"] { fs::create_dir(root.join(name))?; }
        fs::write(root.join("project/input"), "broker-positive-control hé 😀")?;
        use kelft_wasi::{macos_supervisor::{Host,Limits as SupervisionLimits},macos_filesystem_session::{self,Grant}};
        let helper_bytes=fs::read(std::env::current_exe()?)?;let helper_hash=format!("sha256:{:x}",Sha256::digest(&helper_bytes));
        let host=Host::new(&helper_bytes,&helper_hash,&fs::canonicalize(std::env::temp_dir())?)?;
        let grants=[Grant{guest:"/project".into(),path:root.join("project"),read:true,write:false},Grant{guest:"/out".into(),path:root.join("out"),read:false,write:true}];
        let output=macos_filesystem_session::run(&host,&snapshot,Role::Candidate,&[],SupervisionLimits{wall_ms:15000,output_bytes:65536},&grants,"/project",&[],&[],None,&[],std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)))?;
        let stdout=output.stdout;let stderr=output.stderr;fs::write(root.join("stdout"),&stdout)?;fs::write(root.join("stderr"),&stderr)?;
        if output.exit!=Some(0)||output.failure.is_some()||!stderr.is_empty(){return Err(format!("supervised guest failed: {:?}: {}{}",output.failure,String::from_utf8_lossy(&stdout),String::from_utf8_lossy(&stderr)).into());}
        if stdout != b"darwin-guest-broker-ok\n" || fs::read(root.join("out/new/deep/result"))? != "hé 😀".as_bytes()
            || fs::read(root.join("project/input"))? != "broker-positive-control hé 😀".as_bytes() {
            return Err("native guest broker result differs".into());
        }
        snapshot.verify()?;
        println!("{}", serde_json::json!({"schema":"kelft-macos-guest-filesystem-development/1","state":"passed",
            "candidateExecVerified":true,"nativeSupervisorIntegrated":true,"descriptorBrokerVerified":true,"guestPathsVerified":true,"authenticatedSnapshotVerified":true,
            "directFilesystemFallback":false,"artifactServiceIntegrated":false,"certified":false,"releaseEligible":false}));
        Ok(())
    }
    pub fn main() -> Result<(), Error> {
        let args = std::env::args().skip(1).collect::<Vec<_>>();
        if kelft_wasi::macos_supervisor::helper(&args)?.is_some(){return Ok(());}
        if args == ["--spawn-control"] {
            native()
        } else if args.len() == 3 && args[0] == "--guest" {
            guest(&args[1], std::path::absolute(&args[2])?)
        } else if args.first().map(String::as_str) == Some("--worker") {
            worker(&args)
        } else if args == ["--resource-baseline"] {
            resource_baseline()
        } else if args == ["--resource-candidate"] {
            resource_candidate()
        } else if args.len() == 2 && args[0] == "--collect" {
            parent(std::path::absolute(&args[1])?)
        } else {
            Err("expected --collect fresh-output-directory".into())
        }
    }
}
#[cfg(target_os = "macos")]
fn main() {
    if let Err(error) = platform::main() {
        eprintln!("error[K0600]: {error}");
        std::process::exit(125);
    }
}
#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("native macOS execution required");
    std::process::exit(125);
}
