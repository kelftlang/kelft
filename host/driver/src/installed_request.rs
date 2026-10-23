//! Public CLI validation and host/guest routing. Compiler semantics stay in Kelft.
use crate::native_target::Target;
use std::{collections::BTreeMap, path::Path};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub command: String,
    pub worker_command: &'static str,
    pub source: String,
    pub target: Target,
    pub emit: &'static str,
    pub json: bool,
    pub options: BTreeMap<String, String>,
}

pub fn is_public(command: &str) -> bool {
    matches!(command, "build" | "check" | "tokens" | "ast" | "ir")
}

pub fn parse(args: &[String], host: Target, cwd: &Path) -> Result<Request, String> {
    let command = args.first().ok_or("command required")?;
    if !is_public(command) { return Err("unsupported public command".into()); }
    let source = args.get(1).filter(|s| !s.is_empty() && !s.starts_with('-'))
        .ok_or("source path required")?.clone();
    let mut options = BTreeMap::new();
    let mut json = false;
    let mut at = 2;
    while at < args.len() {
        let flag = &args[at];
        if flag == "--json" {
            if json { return Err("duplicate --json".into()); }
            json = true; at += 1; continue;
        }
        if !matches!(flag.as_str(), "-o" | "--project-root" | "--target" | "--platform" |
            "--emit" | "--capabilities" | "--intent" | "--bindings") {
            return Err(format!("unknown option: {flag}"));
        }
        let value = args.get(at + 1).filter(|s| !s.is_empty() && !s.starts_with('-'))
            .ok_or_else(|| format!("missing option value: {flag}"))?;
        if options.insert(flag.clone(), value.clone()).is_some() {
            return Err(format!("duplicate option: {flag}"));
        }
        at += 2;
    }
    if options.contains_key("--bindings") && !options.contains_key("--intent") {
        return Err("implementation bindings require --intent".into());
    }
    let target = target(host, options.get("--target").map(String::as_str),
        options.get("--platform").map(String::as_str))?;
    let emit = match options.get("--emit").map(String::as_str).unwrap_or("executable") {
        "object" => "object", "executable" => "executable", _ => return Err("unsupported emission kind".into()),
    };
    if command == "build" {
        if !options.contains_key("-o") { return Err("build requires -o".into()); }
    } else if ["-o", "--emit", "--target", "--platform"].iter().any(|k| options.contains_key(*k)) {
        return Err("target, emission and output options require build".into());
    }
    if !options.contains_key("--project-root") {
        options.insert("--project-root".into(), cwd.to_str().ok_or("project root must be Unicode")?.into());
    }
    let worker_command = match command.as_str() {
        "build" if emit == "object" => "native-object",
        "build" => "native-build", "check" => "check", "tokens" => "tokens", "ast" => "ast", "ir" => "ir",
        _ => unreachable!(),
    };
    Ok(Request { command: command.clone(), worker_command, source, target, emit, json, options })
}

pub fn target(host: Target, requested: Option<&str>, platform: Option<&str>) -> Result<Target, String> {
    let (host_arch, host_platform) = parts(host);
    let (arch, combined_platform) = match requested {
        None => (host_arch, None),
        Some("x86_64") => ("x86_64", None), Some("arm64") => ("arm64", None),
        Some(name) => {
            let value = Target::ALL.into_iter().find(|t| {
                let (a, p) = parts(*t); name == format!("{a}-{p}")
            }).ok_or_else(|| format!("unsupported target: {name}"))?;
            let (a, p) = parts(value); (a, Some(p))
        }
    };
    if platform.is_some() && combined_platform.is_some() && platform != combined_platform {
        return Err("conflicting target and platform".into());
    }
    let selected = platform.or(combined_platform).unwrap_or(host_platform);
    Target::ALL.into_iter().find(|t| parts(*t) == (arch, selected))
        .ok_or_else(|| format!("unsupported platform: {selected}"))
}

pub fn parts(target: Target) -> (&'static str, &'static str) {
    match target {
        Target::LinuxX64 => ("x86_64", "linux"), Target::LinuxArm64 => ("arm64", "linux"),
        Target::WindowsX64 => ("x86_64", "windows"), Target::WindowsArm64 => ("arm64", "windows"),
        Target::MacosX64 => ("x86_64", "macos"), Target::MacosArm64 => ("arm64", "macos"),
    }
}

impl Request {
    pub fn prepare_paths(&mut self, cwd: &Path) -> Result<(), String> {
        let resolve = |value: &str| {
            let file=Path::new(value);
            std::fs::canonicalize(if file.is_absolute(){file.to_owned()}else{cwd.join(file)})
                .map_err(|e|format!("invalid input path {value}: {e}"))
        };
        let root=resolve(&self.options["--project-root"])?;
        if !root.is_dir() || root.parent().is_none() {return Err("invalid project root".into());}
        let source=resolve(&self.source)?;
        if !source.is_file() || !source.starts_with(&root) {return Err("source escapes project root".into());}
        self.source=source.to_str().ok_or("Unicode source path required")?.into();
        self.options.insert("--project-root".into(),root.to_str().ok_or("Unicode project path required")?.into());
        let mut inputs=vec![source];
        for key in ["--capabilities","--intent","--bindings"] {
            if let Some(value)=self.options.get(key).cloned() {
                let file=resolve(&value)?;
                if !file.is_file() || !file.starts_with(&root) {return Err(format!("{key} escapes project root"));}
                self.options.insert(key.into(),file.to_str().ok_or("Unicode input path required")?.into());inputs.push(file);
            }
        }
        if let Some(value)=self.options.get("-o").cloned() {
            let absolute=if Path::new(&value).is_absolute(){std::path::PathBuf::from(value)}else{cwd.join(value)};
            let parent=std::fs::canonicalize(absolute.parent().ok_or("output parent required")?).map_err(|e|format!("output directory must exist: {e}"))?;
            let output=parent.join(absolute.file_name().ok_or("output filename required")?);
            if output.extension().and_then(|v|v.to_str()).is_some_and(|v|v.eq_ignore_ascii_case("kelft")) {return Err("output must not overwrite a Kelft source path".into());}
            if output.exists() {
                let actual=std::fs::canonicalize(&output).map_err(|e|e.to_string())?;
                if inputs.contains(&actual) {return Err("output overlaps compiler input".into());}
            }
            self.options.insert("-o".into(),output.to_str().ok_or("Unicode output path required")?.into());
        }
        Ok(())
    }
    /// The boundary repeats path validation before granting any authority.
    pub fn boundary_args(&self, host: Target) -> Result<Vec<String>, String> {
        let cross = (host == Target::WindowsX64 && self.target == Target::LinuxX64 &&
            (self.emit == "object" || option_env!("KELFT_WINDOWS_LINUX_CROSS_SHA256").is_some())) ||
            (host == Target::LinuxX64 && self.target == Target::WindowsX64 &&
            (self.emit == "object" || option_env!("KELFT_LINUX_WINDOWS_CROSS_SHA256").is_some()));
        if self.target != host {
          if !cross {
            return Err(format!("UNSUPPORTED_TARGET_PROFILE: {} -> {}; an offline cross profile is required",
                host.id(), self.target.id()));
          }
        }
        let command = if cross {if self.emit == "object" {"cross-object"}else{"cross-build"}} else {self.worker_command};
        let mut args = vec![command.into(), self.source.clone()];
        if cross {args.extend(["--artifact-target".into(),self.target.id().into()]);}
        for (flag, value) in &self.options {
            if !matches!(flag.as_str(), "--target" | "--platform" | "--emit") {
                args.extend([flag.clone(), value.clone()]);
            }
        }
        Ok(args)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn parse_on(host: Target, args: &[&str]) -> Result<Request, String> {
        parse(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>(), host, Path::new("/project"))
    }
    #[test]
    fn requested_build_forms_select_artifact_target_independently_of_host() {
        let cases = [(Target::LinuxX64, None, Target::LinuxX64),
            (Target::LinuxX64, Some("x86_64-windows"), Target::WindowsX64),
            (Target::WindowsX64, Some("x86_64-linux"), Target::LinuxX64)];
        for (host, selection, expected) in cases {
            let mut args = vec!["build", "examples/hello.kelft", "-o", "hello"];
            if let Some(value) = selection { args.extend(["--target", value]); }
            let request = parse_on(host, &args).unwrap();
            assert_eq!(request.target, expected);
            assert_eq!(request.options["--project-root"], "/project");
            assert_eq!(request.worker_command, "native-build");
        }
    }
    #[test]
    fn target_names_and_split_forms_agree_for_all_six_targets() {
        for t in Target::ALL {
            let (a, p) = parts(t);
            assert_eq!(target(Target::LinuxX64, Some(&format!("{a}-{p}")), None).unwrap(), t);
            assert_eq!(target(Target::LinuxX64, Some(a), Some(p)).unwrap(), t);
            assert_eq!(target(t, None, None).unwrap(), t);
        }
        assert!(target(Target::LinuxX64, Some("x86_64-windows"), Some("linux")).is_err());
        assert!(target(Target::LinuxX64, Some("native"), None).is_err());
    }
    #[test]
    fn invalid_requests_fail_before_boundary_invocation() {
        for args in [vec!["build", "a"], vec!["build", "a", "-o"],
            vec!["build", "a", "-o", "b", "--target", "bad"],
            vec!["build", "a", "-o", "b", "-o", "c"],
            vec!["check", "a", "-o", "b"], vec!["ir", "a", "--emit", "object"],
            vec!["check", "a", "--bindings", "b"], vec!["check", "a", "--json", "--json"],
            vec!["check", "a", "--toolchain", "untrusted"], vec!["check", "--json"]] {
            assert!(parse_on(Target::LinuxX64, &args).is_err(), "{args:?}");
        }
    }
    #[test]
    fn routing_preserves_scoped_options_and_does_not_fallback_across_targets() {
        let r = parse_on(Target::LinuxX64, &["build", "a", "-o", "b", "--emit", "object", "--json"]).unwrap();
        assert_eq!(r.boundary_args(Target::LinuxX64).unwrap(), vec!["native-object", "a", "--project-root", "/project", "-o", "b"]);
        let r = parse_on(Target::LinuxX64, &["build", "a", "-o", "b", "--target", "x86_64-windows"]).unwrap();
        if option_env!("KELFT_LINUX_WINDOWS_CROSS_SHA256").is_none() {assert!(r.boundary_args(Target::LinuxX64).unwrap_err().contains("UNSUPPORTED_TARGET_PROFILE"));}
        let r = parse_on(Target::LinuxX64, &["build", "a", "-o", "b", "--emit", "object", "--target", "x86_64-windows"]).unwrap();
        assert_eq!(&r.boundary_args(Target::LinuxX64).unwrap()[..4], &["cross-object", "a", "--artifact-target", "windows-x86_64"]);
        let r = parse_on(Target::WindowsX64, &["build", "a", "-o", "b", "--emit", "object", "--target", "x86_64-linux"]).unwrap();
        let args = r.boundary_args(Target::WindowsX64).unwrap();
        assert_eq!(&args[..4], &["cross-object", "a", "--artifact-target", "linux-x86_64"]);
        assert!(!args.iter().any(|v| v == "native-build"));
    }
    #[test]
    fn path_preflight_rejects_escapes_and_input_overwrites() {
        let mut nonce=[0;16];getrandom::fill(&mut nonce).unwrap();
        let name=nonce.iter().map(|b|format!("{b:02x}")).collect::<String>();
        let scratch=std::env::temp_dir().join(format!("kelft-public-paths-{name}"));
        std::fs::create_dir(&scratch).unwrap();
        let project=scratch.join("project");std::fs::create_dir(&project).unwrap();
        std::fs::write(project.join("main.kelft"),"fn main()->void {}").unwrap();
        std::fs::write(project.join("policy.json"),"{}").unwrap();
        std::fs::write(scratch.join("outside.kelft"),"fn main()->void {}").unwrap();
        let request=|values:&[&str]|parse(&values.iter().map(|s|s.to_string()).collect::<Vec<_>>(),Target::LinuxX64,&project).unwrap();
        let mut valid=request(&["build","main.kelft","-o","hello"]);valid.prepare_paths(&project).unwrap();
        assert!(Path::new(&valid.source).is_absolute());
        for values in [vec!["build","main.kelft","-o","main.kelft"],
            vec!["build","main.kelft","-o","policy.json","--capabilities","policy.json"],
            vec!["check","../outside.kelft"],
            vec!["check","main.kelft","--intent","../outside.kelft"]] {
            assert!(request(&values).prepare_paths(&project).is_err(),"{values:?}");
        }
        assert_eq!(std::fs::read_to_string(project.join("main.kelft")).unwrap(),"fn main()->void {}");
        assert_eq!(scratch.parent(),Some(std::env::temp_dir().as_path()));
        std::fs::remove_dir_all(scratch).unwrap();
    }
}
