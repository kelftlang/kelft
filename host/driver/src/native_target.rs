//! Target identities shared by installed orchestration and native host adapters.
//! Selection never implies that a target has passed its certification gates.
use std::{io, path::{Component, Path, PathBuf}};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target { LinuxX64, WindowsX64, MacosX64, LinuxArm64, MacosArm64, WindowsArm64 }
impl Target {
    pub const ALL: [Self; 6] = [Self::LinuxX64, Self::WindowsX64, Self::MacosX64, Self::LinuxArm64, Self::MacosArm64, Self::WindowsArm64];
    pub fn current() -> io::Result<Self> {
        match (std::env::consts::OS, std::env::consts::ARCH) {
            ("linux", "x86_64") => Ok(Self::LinuxX64), ("linux", "aarch64") => Ok(Self::LinuxArm64),
            ("windows", "x86_64") => Ok(Self::WindowsX64), ("windows", "aarch64") => Ok(Self::WindowsArm64),
            ("macos", "x86_64") => Ok(Self::MacosX64), ("macos", "aarch64") => Ok(Self::MacosArm64),
            _ => Err(invalid("unsupported native host")),
        }
    }
    pub fn id(self) -> &'static str { match self {
        Self::LinuxX64=>"linux-x86_64", Self::LinuxArm64=>"linux-arm64", Self::WindowsX64=>"windows-x86_64",
        Self::WindowsArm64=>"windows-arm64", Self::MacosX64=>"macos-x86_64", Self::MacosArm64=>"macos-arm64",
    }}
    pub fn artifact(self) -> &'static str { match self {
        Self::LinuxX64=>"native-linux-x86_64-v1", Self::LinuxArm64=>"native-linux-arm64-v1",
        Self::WindowsX64=>"native-windows-x86_64-v1", Self::WindowsArm64=>"native-windows-arm64-v1",
        Self::MacosX64=>"native-macos-x86_64-v1", Self::MacosArm64=>"native-macos-arm64-v1",
    }}
    pub fn runtime(self) -> &'static str { match self {
        Self::LinuxX64=>"linux-x86_64-development-v1", Self::LinuxArm64=>"linux-arm64-development-v1",
        Self::WindowsX64=>"windows-x86_64-development-v1", Self::WindowsArm64=>"windows-arm64-development-v1",
        Self::MacosX64=>"macos-x86_64-development-v1", Self::MacosArm64=>"macos-arm64-development-v1",
    }}
    pub fn executable_suffix(self) -> &'static str { if matches!(self, Self::WindowsX64|Self::WindowsArm64) {".exe"} else {""} }
    /// Check format, CPU and executable kind before any OS loader receives bytes.
    pub fn validate_executable(self, bytes: &[u8]) -> io::Result<()> {
        let bad=||invalid("native executable format or architecture differs");
        match self {
            Self::LinuxX64|Self::LinuxArm64 => {
                if bytes.len()<64 || bytes[..7]!=[127,69,76,70,2,1,1] || u16::from_le_bytes(bytes[16..18].try_into().unwrap())!=2 ||
                    u16::from_le_bytes(bytes[18..20].try_into().unwrap())!=if self==Self::LinuxX64 {62} else {183} {return Err(bad());}
            }
            Self::WindowsX64|Self::WindowsArm64 => {
                if bytes.len()<64 || &bytes[..2]!=b"MZ" {return Err(bad());}
                let at=u32::from_le_bytes(bytes[60..64].try_into().unwrap()) as usize;
                if at<64 || at>bytes.len().saturating_sub(264) || &bytes[at..at+4]!=b"PE\0\0" ||
                    u16::from_le_bytes(bytes[at+4..at+6].try_into().unwrap())!=if self==Self::WindowsX64 {0x8664} else {0xaa64} ||
                    u16::from_le_bytes(bytes[at+20..at+22].try_into().unwrap())<240 ||
                    u16::from_le_bytes(bytes[at+24..at+26].try_into().unwrap())!=0x20b {return Err(bad());}
                let flags=u16::from_le_bytes(bytes[at+22..at+24].try_into().unwrap());
                if flags&2==0 || flags&0x2000!=0 {return Err(bad());}
            }
            Self::MacosX64|Self::MacosArm64 => {
                if bytes.len()<32 || u32::from_le_bytes(bytes[..4].try_into().unwrap())!=0xfeedfacf ||
                    u32::from_le_bytes(bytes[4..8].try_into().unwrap())!=if self==Self::MacosX64 {0x01000007} else {0x0100000c} ||
                    u32::from_le_bytes(bytes[8..12].try_into().unwrap())&0x00ffffff!=if self==Self::MacosX64 {3} else {0} ||
                    u32::from_le_bytes(bytes[12..16].try_into().unwrap())!=2 {return Err(bad());}
                let count=u32::from_le_bytes(bytes[16..20].try_into().unwrap()) as usize;
                let size=u32::from_le_bytes(bytes[20..24].try_into().unwrap()) as usize;
                if count==0 || count>4096 || size>bytes.len()-32 {return Err(bad());}
                let mut at=32; for _ in 0..count {
                    if at>32+size || 32+size-at<8 {return Err(bad());}
                    let command=u32::from_le_bytes(bytes[at+4..at+8].try_into().unwrap()) as usize;
                    if command<8 || command%8!=0 || command>32+size-at {return Err(bad());}at+=command;
                }
                if at!=32+size {return Err(bad());}
            }
        } Ok(())
    }
}
fn invalid(message: &'static str) -> io::Error {io::Error::new(io::ErrorKind::InvalidInput,message)}

/// Guest paths are portable names; host paths remain native PathBuf values.
/// Never replace backslashes in a Unix filename or parse a drive path as a guest.
pub fn guest_path(root: &Path, host: &Path) -> io::Result<String> {
    let relative=host.strip_prefix(root).map_err(|_|invalid("host path escapes mapped root"))?;
    let mut guest=String::from("/project");
    for part in relative.components() {
        let Component::Normal(name)=part else {return Err(invalid("non-normal host path component"));};
        let name=name.to_str().ok_or_else(||invalid("host path is not Unicode"))?;
        if name.contains(['\\','\0']) {return Err(invalid("host filename cannot be represented in guest namespace"));}
        guest.push('/');guest.push_str(name);
    } Ok(guest)
}
pub fn host_path(root: &Path, guest: &str) -> io::Result<PathBuf> {
    if !root.is_absolute() || guest.contains(['\\','\0']) {return Err(invalid("invalid mapped path"));}
    if guest=="/project" {return Ok(root.to_owned());}
    let relative=guest.strip_prefix("/project/").ok_or_else(||invalid("unmapped guest root"))?;
    let mut result=root.to_owned();
    for part in relative.split('/') {
        if part.is_empty() || matches!(part,"."|"..") || part.contains(':') {return Err(invalid("invalid guest component"));}
        result.push(part);
    } Ok(result)
}
#[cfg(test)] mod tests {
    use super::*;
    #[test] fn all_targets_have_distinct_protocol_identities() {
        let names:std::collections::HashSet<_>=Target::ALL.map(Target::artifact).into_iter().collect();assert_eq!(names.len(),6);
        for target in Target::ALL {assert_eq!(target.artifact(),format!("native-{}-v1",target.id()));assert_eq!(target.runtime(),format!("{}-development-v1",target.id()));}
        assert!(Target::current().is_ok());
    }
    #[test] fn guest_mapping_does_not_accept_drive_paths_or_traversal() {
        let root=std::env::current_dir().unwrap();let file=root.join("hé 😀").join("file");
        assert_eq!(host_path(&root,&guest_path(&root,&file).unwrap()).unwrap(),file);
        for path in ["C:\\project", "/project/../secret","/project//file","/project/C:secret","/project/a\\b","/project/.","/project/"] {assert!(host_path(&root,path).is_err(),"{path}");}
    }
    #[test] fn truncated_images_never_reach_an_os_loader() {
        for target in Target::ALL {for n in 0..320 {assert!(target.validate_executable(&vec![0;n]).is_err());}}
        let mut elf=vec![0;64];elf[..7].copy_from_slice(&[127,69,76,70,2,1,1]);elf[16..18].copy_from_slice(&2u16.to_le_bytes());elf[18..20].copy_from_slice(&62u16.to_le_bytes());
        Target::LinuxX64.validate_executable(&elf).unwrap();assert!(Target::LinuxArm64.validate_executable(&elf).is_err());
        elf[16]=3;assert!(Target::LinuxX64.validate_executable(&elf).is_err());
    }
}
