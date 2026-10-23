//! Fixed native role boundaries. Enter only from a dedicated single-threaded
//! execution helper, before exec; never invoke sandbox setup from pre_exec.
#[cfg(target_os = "macos")]
use std::ffi::{CStr, c_char, c_int};
use std::{
    ffi::CString,
    io,
    path::{Component, Path},
};
use crate::{native_resources::Contract, native_target::Target};

fn target() -> io::Result<Target> {
    match std::env::consts::ARCH {
        "x86_64" => Ok(Target::MacosX64),
        "aarch64" => Ok(Target::MacosArm64),
        _ => Err(invalid("unsupported macOS resource architecture")),
    }
}
pub fn resource_contract(role: Role) -> io::Result<Contract> {
    Contract::for_role(target()?, match role {
        Role::Compiler => "compiler", Role::Candidate => "candidate", Role::Linker => "linker",
        Role::JavaScript | Role::Wasm => return Err(invalid("optional engine resource contract is unreviewed")),
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Compiler,
    Candidate,
    Linker,
    JavaScript,
    Wasm,
}
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub address_space: u64,
    pub stack: u64,
    pub cpu_seconds: u64,
}
impl Limits {
    pub fn native(cpu_seconds: u64) -> io::Result<Self> {
        let contract = resource_contract(Role::Compiler)?;
        let limits = Self { address_space: contract.memory.ceiling_bytes,
            stack: contract.initial_stack_bytes, cpu_seconds };
        limits.validate()?;
        Ok(limits)
    }
    pub fn validate(self) -> io::Result<()> {
        let contract = resource_contract(Role::Compiler)?;
        if self.address_space != contract.memory.ceiling_bytes
            || self.stack != contract.initial_stack_bytes
            || self.cpu_seconds == 0
            || self.cpu_seconds > contract.compiler.wall_ms / 1000
        {
            return Err(invalid("native role resource bounds differ"));
        }
        Ok(())
    }
}
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn parameter(path: &Path) -> io::Result<CString> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir | Component::CurDir))
    {
        return Err(invalid("absolute normalized role parameter required"));
    }
    let text = path
        .to_str()
        .ok_or_else(|| invalid("Unicode role path required"))?;
    if text.starts_with('/')
        && text[1..]
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
    {
        return Err(invalid("normalized role path required"));
    }
    if text == "/" {
        return Err(invalid("root filesystem role grant is forbidden"));
    }
    CString::new(text).map_err(|_| invalid("role parameter contains NUL"))
}
const BASE: &str = r#"(version 1)
(deny default)
(allow signal (target self))
; The dynamic loader opens the root directory itself at exec startup. This
; exact directory rule grants neither descendants nor any write operation.
(allow file-read-data file-read-metadata (literal "/"))
(allow process-exec (literal (param "EXECUTABLE")))
(allow file-read* file-map-executable
 (literal (param "EXECUTABLE"))
 (subpath "/usr/lib")
 (subpath "/System/Library")
 (subpath "/System/Cryptexes/OS")
 (subpath "/System/Cryptexes/App")
 (subpath "/System/Volumes/Preboot/Cryptexes/OS/System")
 (subpath "/System/Volumes/Preboot/Cryptexes/App/System"))
(allow file-read-data (literal "/dev/null") (literal "/dev/random") (literal "/dev/urandom"))
(allow file-write-data (literal "/dev/null"))
"#;
const LINKER: &str = r#"
(allow sysctl-read (sysctl-name "hw.pagesize") (sysctl-name "hw.pagesize_compat"))
(allow file-read* file-map-executable (subpath (param "SDK")) (subpath (param "TOOLS")))
(allow file-read* (literal (param "OBJECT")))
(allow file-read* file-write* (subpath (param "OUTPUT")))
"#;
pub struct LinkerPaths<'a> {
    pub sdk: &'a Path,
    pub tools: &'a Path,
    pub object: &'a Path,
    pub output: &'a Path,
}
pub struct Prepared {
    profile: CString,
    parameters: Vec<CString>,
    limits: Limits,
}
impl Prepared {
    /// Engine inputs are immutable snapshot files, never project or SDK roots.
    pub fn engine(role:Role,image:&Path,inputs:&[std::path::PathBuf],limits:Limits)->io::Result<Self>{
        let engine=match role{Role::JavaScript=>"javascript",Role::Wasm=>"wasm",_=>return Err(invalid("explicit optional engine role required"))};
        let contract=crate::native_resources::EngineContract::for_engine(target()?,engine)?;
        limits.validate()?;if inputs.is_empty()||inputs.len()>2||limits.address_space!=contract.memory.ceiling_bytes||limits.stack!=contract.stack_ceiling_bytes{return Err(invalid("optional engine parameters differ"));}
        let directory=image.parent().ok_or_else(||invalid("private engine directory required"))?;
        let mut parameters=vec![CString::new("EXECUTABLE").unwrap(),parameter(image)?,CString::new("ENGINE_DIRECTORY").unwrap(),parameter(directory)?];let mut profile=BASE.to_owned();
        profile.push_str("\n(allow file-read-data (literal (param \"ENGINE_DIRECTORY\")))\n");
        profile.push_str("\n(allow sysctl-read (sysctl-name \"hw.pagesize\") (sysctl-name \"hw.pagesize_compat\"))\n");
        if role==Role::JavaScript{profile.push_str("(allow sysctl-read (sysctl-name \"kern.ostype\") (sysctl-name \"kern.hostname\") (sysctl-name \"kern.osrelease\") (sysctl-name \"kern.version\") (sysctl-name \"hw.machine\"))\n");}
        for(index,input)in inputs.iter().enumerate(){if input.parent()!=Some(directory)||!matches!(input.file_name().and_then(|v|v.to_str()),Some("control.mjs"|"program.mjs"|"program.wasm")){return Err(invalid("engine input is outside its immutable snapshot"));}let key=format!("ENGINE_INPUT_{index}");parameters.extend([CString::new(key.as_str()).unwrap(),parameter(input)?]);profile.push_str(&format!("(allow file-read* (literal (param \"{key}\")))\n"));}
        for(index,parent)in directory.ancestors().take_while(|parent|parent.parent().is_some()).enumerate(){if index>=64{return Err(invalid("engine ancestor metadata budget"));}let key=format!("ENGINE_PARENT_{index}");parameters.extend([CString::new(key.as_str()).unwrap(),parameter(parent)?]);profile.push_str(&format!("(allow file-read-metadata (literal (param \"{key}\")))\n"));}
        Ok(Self{profile:CString::new(profile).unwrap(),parameters,limits})
    }
    /// Only the trusted linker gets toolchain reads and a private output directory.
    /// Other roles receive project access exclusively through their broker pipes.
    pub fn new(
        role: Role,
        image: &Path,
        linker: Option<LinkerPaths<'_>>,
        limits: Limits,
    ) -> io::Result<Self> {
        resource_contract(role)?;
        limits.validate()?;
        let mut parameters = vec![CString::new("EXECUTABLE").unwrap(), parameter(image)?];
        if (role == Role::Linker) != linker.is_some() {
            return Err(invalid("linker parameters do not match the role"));
        }
        let mut profile = BASE.to_owned();
        if let Some(paths) = linker {
            for (name, path) in [
                ("SDK", paths.sdk),
                ("TOOLS", paths.tools),
                ("OBJECT", paths.object),
                ("OUTPUT", paths.output),
            ] {
                parameters.push(CString::new(name).unwrap());
                parameters.push(parameter(path)?);
            }
            profile.push_str(LINKER);
        }
        Ok(Self {
            profile: CString::new(profile).unwrap(),
            parameters,
            limits,
        })
    }
    pub fn bounded_candidate(image:&Path,cwd:&Path,memory:u64,cpu_seconds:u64)->io::Result<Self>{
        let mut prepared=Self::new(Role::Candidate,image,None,Limits::native(cpu_seconds)?)?;
        if !(16<<20..=resource_contract(Role::Candidate)?.memory.ceiling_bytes).contains(&memory){return Err(invalid("unsupported process virtual-address ceiling"));}
        prepared.limits.address_space=memory;
        let mut profile=prepared.profile.to_str().map_err(|_|invalid("invalid profile"))?.to_owned();
        // libc/Rust startup needs the hardware page size before mapping stack guards.
        profile.push_str("\n(allow sysctl-read (sysctl-name \"hw.pagesize\") (sysctl-name \"hw.pagesize_compat\"))\n");
        for (index,parent) in cwd.ancestors().enumerate(){if parent.parent().is_none(){if index==0{return Err(invalid("root working directory is forbidden"));}break;}if index>=64{return Err(invalid("working directory ancestor budget"));}let key=format!("CWD_{index}");prepared.parameters.extend([CString::new(key.as_str()).unwrap(),parameter(parent)?]);profile.push_str(&format!("\n(allow file-read-metadata (literal (param \"{key}\")))\n"));}
        prepared.profile=CString::new(profile).unwrap();Ok(prepared)
    }
    /// Fail closed if any limit, sandbox setup or installed-state check fails.
    /// The caller must terminate this dedicated helper on error, without exec.
    #[cfg(target_os = "macos")]
    pub fn enter(&self) -> io::Result<()> {
        #[repr(C)]
        struct Rlimit {
            current: u64,
            maximum: u64,
        }
        #[link(name = "sandbox")]
        unsafe extern "C" {
            fn sandbox_init_with_parameters(
                profile: *const c_char,
                flags: u64,
                parameters: *const *const c_char,
                error: *mut *mut c_char,
            ) -> c_int;
            fn sandbox_free_error(error: *mut c_char);
            fn sandbox_check(pid: c_int, operation: *const c_char, kind: c_int, ...) -> c_int;
        }
        unsafe extern "C" {
            fn setrlimit(resource: c_int, limit: *const Rlimit) -> c_int;
            fn getrlimit(resource: c_int, limit: *mut Rlimit) -> c_int;
            fn getpid() -> c_int;
            fn setpgid(pid: c_int, group: c_int) -> c_int;
        }
        // Darwin RLIMIT_AS, STACK, CORE and CPU. Both soft and hard limits are fixed.
        for (resource, value) in [
            (5, self.limits.address_space),
            (3, self.limits.stack),
            (4, 0),
            (0, self.limits.cpu_seconds),
        ] {
            if unsafe {
                setrlimit(
                    resource,
                    &Rlimit {
                        current: value,
                        maximum: value,
                    },
                )
            } != 0
            {
                return Err(io::Error::other(format!(
                    "native resource {resource} limit {value} failed: {}",
                    io::Error::last_os_error()
                )));
            }
            let mut observed = Rlimit { current: 0, maximum: 0 };
            if unsafe { getrlimit(resource, &mut observed) } != 0
                || observed.current != value || observed.maximum != value {
                return Err(io::Error::other("native resource limit readback differs"));
            }
        }
        if unsafe { setpgid(0, 0) } != 0 {
            return Err(io::Error::other(format!(
                "native worker process group failed: {}",
                io::Error::last_os_error()
            )));
        }
        let mut parameters = self
            .parameters
            .iter()
            .map(|value| value.as_ptr())
            .collect::<Vec<_>>();
        parameters.push(std::ptr::null());
        let mut error = std::ptr::null_mut();
        let result = unsafe {
            sandbox_init_with_parameters(self.profile.as_ptr(), 0, parameters.as_ptr(), &mut error)
        };
        let detail = if error.is_null() {
            String::new()
        } else {
            let detail = unsafe { CStr::from_ptr(error) }
                .to_string_lossy()
                .into_owned();
            unsafe { sandbox_free_error(error) };
            detail
        };
        if result != 0 {
            return Err(io::Error::other(format!(
                "native Seatbelt setup failed: {detail}"
            )));
        }
        if unsafe { sandbox_check(getpid(), std::ptr::null(), 0) } != 1 {
            return Err(io::Error::other(
                "native Seatbelt state could not be verified",
            ));
        }
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    pub fn enter(&self) -> io::Result<()> {
        self.limits.validate()?;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "native macOS Seatbelt is required",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn limits() -> Limits { Limits::native(600).unwrap() }
    #[test]
    fn bounded_process_cwd_keeps_root_out_of_role_parameters() {
        let prepared=Prepared::bounded_candidate(Path::new("/private/image"),Path::new("/private/workspace/work"),limits().address_space,30).unwrap();
        let directories=prepared.parameters.chunks_exact(2).filter(|pair|pair[0].to_str().unwrap().starts_with("CWD_")).map(|pair|pair[1].to_str().unwrap()).collect::<Vec<_>>();
        assert_eq!(directories,["/private/workspace/work","/private/workspace","/private"]);
        let profile=prepared.profile.to_str().unwrap();
        assert!(profile.contains("(allow file-read-metadata (literal (param \"CWD_0\")))"));
        assert!(!profile.contains("(subpath (param \"CWD_"));
        assert!(profile.contains("(allow sysctl-read (sysctl-name \"hw.pagesize\") (sysctl-name \"hw.pagesize_compat\"))"));
        assert!(!profile.contains("(allow sysctl-read)"));
        assert!(!profile.contains("(allow sysctl-write"));
        for cwd in ["/","relative","/private/../escape"] {
            assert!(Prepared::bounded_candidate(Path::new("/private/image"),Path::new(cwd),limits().address_space,30).is_err());
        }
    }
    #[test]
    fn candidate_and_compiler_have_only_fixed_runtime_reads() {
        for role in [
            Role::Candidate,
            Role::Compiler,
        ] {
            let prepared = Prepared::new(
                role,
                &std::env::current_dir().unwrap().join("image"),
                None,
                limits(),
            )
            .unwrap();
            assert_eq!(prepared.parameters.len(), 2);
            let profile = prepared.profile.to_str().unwrap();
            for name in [
                "SDK",
                "TOOLS",
                "OBJECT",
                "OUTPUT",
                "process-fork",
                "network-outbound",
                "/project",
                "/control",
            ] {
                assert!(!profile.contains(name));
            }
        }
    }
    #[test]
    fn role_parameters_cannot_supply_a_profile_or_broad_root_grant() {
        for path in ["/", "relative", "/private/../escape", "/private\0image"] {
            assert!(Prepared::new(Role::Candidate, Path::new(path), None, limits()).is_err());
        }
        assert!(Prepared::new(Role::Linker, Path::new("/private/linker"), None, limits()).is_err());
        assert!(
            Prepared::new(
                Role::Candidate,
                Path::new("/private/image"),
                Some(LinkerPaths {
                    sdk: Path::new("/sdk"),
                    tools: Path::new("/tools"),
                    object: Path::new("/object"),
                    output: Path::new("/output")
                }),
                limits()
            )
            .is_err()
        );
    }
    #[test]
    fn bounds_cannot_be_relaxed() {
        for limits in [
            Limits {
                address_space: limits().address_space + 1,
                ..limits()
            },
            Limits {
                stack: 32 << 20,
                ..limits()
            },
            Limits {
                cpu_seconds: 601,
                ..limits()
            },
        ] {
            assert!(
                Prepared::new(Role::Candidate, Path::new("/private/image"), None, limits).is_err()
            );
        }
        for role in [Role::JavaScript, Role::Wasm] {
            assert!(Prepared::new(role, Path::new("/private/engine"), None, limits()).is_err());
        }
        assert!(Limits { address_space: 1 << 30, ..limits() }.validate().is_err());
    }
    #[test]
    fn optional_engine_inputs_cannot_be_replaced_with_project_or_toolchain_roots(){
        let directory=std::env::current_dir().unwrap().join("runtime");let image=directory.join("image");let inputs=[directory.join("control.mjs"),directory.join("program.mjs")];
        let prepared=Prepared::engine(Role::JavaScript,&image,&inputs,limits()).unwrap();let profile=prepared.profile.to_str().unwrap();assert!(profile.contains("ENGINE_INPUT_0"));assert!(profile.contains("ENGINE_PARENT_0"));assert!(!profile.contains("param \"SDK\""));assert!(!profile.contains("param \"OUTPUT\""));
        for path in [directory.parent().unwrap().join("project/program.mjs"),directory.join("../project/program.mjs"),directory.join("toolchain")]{assert!(Prepared::engine(Role::JavaScript,&image,&[path],limits()).is_err());}
        assert!(Prepared::engine(Role::Compiler,&image,&inputs,limits()).is_err());assert!(Prepared::engine(Role::Wasm,&image,&[],limits()).is_err());
    }
    #[cfg(not(target_os = "macos"))]
    #[test]
    fn a_non_native_host_never_claims_a_sandbox() {
        assert_eq!(
            Prepared::new(
                Role::Candidate,
                &std::env::current_dir().unwrap().join("image"),
                None,
                limits()
            )
            .unwrap()
            .enter()
            .unwrap_err()
            .kind(),
            io::ErrorKind::Unsupported
        );
    }
}
