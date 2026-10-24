//! Installation-root-relative file mechanisms. No component selection or
//! compatibility decisions are made here. All writes use retained ancestors.
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
};
pub fn invalid(s: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, s)
}
fn parts(name: &str) -> io::Result<Vec<&str>> {
    if name.is_empty()
        || name.len() > 220
        || name.starts_with('/')
        || name.contains(['\\', ':', '\0'])
    {
        return Err(invalid("component relative path"));
    }
    let p: Vec<_> = name.split('/').collect();
    for part in &p {
        if part.is_empty()
            || matches!(*part, "." | "..")
            || part.ends_with(['.', ' '])
            || !part
                .bytes()
                .all(|c| c.is_ascii_graphic() && !b"<>\"|?*".contains(&c))
        {
            return Err(invalid("component path alias"));
        }
    }
    Ok(p)
}
pub struct Store {
    pub path: PathBuf,
    #[cfg_attr(windows, allow(dead_code))]
    root: fs::File,
    #[cfg(windows)]
    _roots: crate::windows_filesystem::Broker,
}
pub struct Parent {
    pub file: fs::File,
    pub leaf: String,
    #[cfg(windows)]
    pub path: PathBuf,
    #[cfg(windows)]
    _ancestors: crate::windows_filesystem::Broker,
}
/// Only ordinal members live here. The retained directory prevents path
/// substitution; interrupted decompression is cleaned by the next maintenance.
pub struct Payloads {
    parent: Parent,
    pub path: PathBuf,
}
impl Payloads {
    fn clean(&mut self) -> io::Result<()> {
        let mut count = 0;
        for entry in fs::read_dir(&self.path)? {
            count += 1;
            if count > 8192 {
                return Err(invalid("private archive staging bound"));
            }
            let name = entry?
                .file_name()
                .into_string()
                .map_err(|_| invalid("private staging name"))?;
            let number: usize = name
                .parse()
                .map_err(|_| invalid("private staging ordinal"))?;
            if number >= 8192 || number.to_string() != name {
                return Err(invalid("private staging alias"));
            }
            self.parent.leaf = name;
            self.parent.remove()?;
        }
        Ok(())
    }
}
impl Drop for Payloads {
    fn drop(&mut self) {
        let _ = self.clean();
    }
}
impl Store {
    pub fn payloads(&self) -> io::Result<Payloads> {
        let parent = self.parent(".kelft-targets/archive/0", true)?;
        #[cfg(unix)]
        let path = {
            use std::os::fd::AsRawFd;
            PathBuf::from(format!("/proc/self/fd/{}", parent.file.as_raw_fd()))
        };
        #[cfg(windows)]
        let path = parent.path.clone();
        let mut result = Payloads { parent, path };
        result.clean()?;
        Ok(result)
    }
    pub fn open(path: &Path) -> io::Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let root = fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(path)?;
            Ok(Self {
                path: path.to_path_buf(),
                root,
            })
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            let mut roots = crate::windows_filesystem::Broker::default();
            roots.add_root(path, true, false)?;
            let root = fs::OpenOptions::new()
                .read(true)
                .share_mode(3)
                .custom_flags(0x02200000)
                .open(path)?;
            Ok(Self {
                path: path.to_path_buf(),
                root,
                _roots: roots,
            })
        }
    }
    pub fn parent(&self, name: &str, create: bool) -> io::Result<Parent> {
        let names = parts(name)?;
        self.descend(&names, create)
    }
    /// Workspace observations support Unicode components. Component archives
    /// continue to use the original ASCII-only `parent` path contract.
    pub(crate) fn workspace_parent(&self, name: &str) -> io::Result<Parent> {
        if name.is_empty() || name.len() > 1024 || name.starts_with('/') || name.contains(['\\', ':', '\0']) {
            return Err(invalid("workspace relative path"));
        }
        let names: Vec<_> = name.split('/').collect();
        for part in &names {
            if part.is_empty() || matches!(*part, "." | "..") || part.len() > 255 || part.ends_with(['.', ' ']) ||
                part.chars().any(|c| c.is_control() || "<>\"|?*".contains(c)) {
                return Err(invalid("workspace path alias"));
            }
        }
        self.descend(&names, false)
    }
    fn descend(&self, names: &[&str], create: bool) -> io::Result<Parent> {
        #[cfg(unix)]
        {
            use std::{
                ffi::CString,
                os::fd::{AsRawFd, FromRawFd},
            };
            let mut parent = self.root.try_clone()?;
            for part in &names[..names.len() - 1] {
                let name = CString::new(*part).unwrap();
                let mut fd = unsafe {
                    libc::openat(
                        parent.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if fd < 0 && create && io::Error::last_os_error().kind() == io::ErrorKind::NotFound
                {
                    if unsafe {
                        libc::mkdirat(
                            parent.as_raw_fd(),
                            name.as_ptr(),
                            if names.first() == Some(&".kelft-targets") {
                                0o700
                            } else {
                                0o755
                            },
                        )
                    } < 0
                        && io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists
                    {
                        return Err(io::Error::last_os_error());
                    }
                    fd = unsafe {
                        libc::openat(
                            parent.as_raw_fd(),
                            name.as_ptr(),
                            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                        )
                    };
                }
                if fd < 0 {
                    return Err(io::Error::last_os_error());
                }
                parent = unsafe { fs::File::from_raw_fd(fd) };
            }
            Ok(Parent {
                file: parent,
                leaf: names.last().unwrap().to_string(),
            })
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            let mut ancestors = crate::windows_filesystem::Broker::default();
            let mut path = self.path.clone();
            ancestors.add_root(&path, true, false)?;
            for name in &names[..names.len() - 1] {
                path.push(name);
                if create && !path.exists() {
                    fs::create_dir(&path)?;
                }
                ancestors.add_root(&path, true, false)?;
            }
            let file = fs::OpenOptions::new()
                .read(true)
                .share_mode(3)
                .custom_flags(0x02200000)
                .open(&path)?;
            Ok(Parent {
                file,
                leaf: names.last().unwrap().to_string(),
                path,
                _ancestors: ancestors,
            })
        }
    }
    pub fn read(&self, name: &str) -> io::Result<fs::File> {
        self.parent(name, false)?.open(false)
    }
    pub fn observation(&self, name: &str, mode: u32) -> serde_json::Value {
        let result = (|| -> io::Result<serde_json::Value> {
            let mut f = self.read(name)?;
            let m = f.metadata()?;
            if m.len() > 256 << 20 {
                return Err(invalid("component file bound"));
            }
            let mut sha = Sha256::new();
            let mut b = [0; 65536];
            let mut count = 0u64;
            loop {
                let n = f.read(&mut b)?;
                if n == 0 {
                    break;
                }
                count += n as u64;
                if count > 256 << 20 {
                    return Err(invalid("component file grew"));
                }
                sha.update(&b[..n]);
            }
            let after = f.metadata()?;
            if count != m.len() || after.len() != m.len() || after.modified()? != m.modified()? {
                return Err(invalid("component changed"));
            }
            #[cfg(unix)]
            let valid = {
                use std::os::unix::fs::PermissionsExt;
                m.permissions().mode() & 0o777 == mode
            };
            #[cfg(windows)]
            let valid = {
                let _ = mode;
                true
            };
            Ok(
                serde_json::json!({"present":true,"size":count,"sha256":format!("sha256:{:x}",sha.finalize()),"modeValid":valid}),
            )
        })();
        match result {
            Ok(v) => v,
            Err(e) if e.kind() == io::ErrorKind::NotFound => serde_json::json!({"present":false}),
            Err(_) => serde_json::json!({"present":true,"modeValid":false}),
        }
    }
    pub fn put(&self, name: &str, input: &mut impl Read, mode: u32) -> io::Result<()> {
        let stage = self.parent(&stage_name(name), true)?;
        stage.remove()?;
        self.parent(name, true)?.put(input, mode, &stage)
    }
    pub fn recover(&self, name: &str) -> io::Result<()> {
        self.remove(&stage_name(name))
    }
    pub fn remove(&self, name: &str) -> io::Result<()> {
        match self.parent(name, false) {
            Ok(parent) => parent.remove(),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
}
impl Parent {
    pub fn open(&self, write: bool) -> io::Result<fs::File> {
        #[cfg(unix)]
        {
            use std::{
                ffi::CString,
                os::fd::{AsRawFd, FromRawFd},
            };
            let name = CString::new(self.leaf.as_str()).unwrap();
            let fd = unsafe {
                libc::openat(
                    self.file.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_CLOEXEC
                        | libc::O_NOFOLLOW
                        | libc::O_NONBLOCK
                        | if write {
                            libc::O_RDWR | libc::O_CREAT
                        } else {
                            libc::O_RDONLY
                        },
                    0o644,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let f = unsafe { fs::File::from_raw_fd(fd) };
            if !f.metadata()?.is_file() {
                return Err(invalid("component regular file required"));
            }
            Ok(f)
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
            let f = fs::OpenOptions::new()
                .read(true)
                .write(write)
                .create(write)
                .share_mode(3)
                .custom_flags(0x00200000)
                .open(self.path.join(&self.leaf))?;
            let m = f.metadata()?;
            if !m.is_file() || m.file_attributes() & 0x400 != 0 {
                return Err(invalid("component reparse point or kind"));
            }
            Ok(f)
        }
    }
    pub fn remove(&self) -> io::Result<()> {
        #[cfg(unix)]
        {
            use std::{ffi::CString, os::fd::AsRawFd};
            match self.open(false) {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
                Err(e) => return Err(e),
            };
            let leaf = CString::new(self.leaf.as_str()).unwrap();
            if unsafe { libc::unlinkat(self.file.as_raw_fd(), leaf.as_ptr(), 0) } < 0 {
                return Err(io::Error::last_os_error());
            }
            self.file.sync_all()
        }
        #[cfg(windows)]
        {
            use std::os::windows::{
                fs::{MetadataExt, OpenOptionsExt},
                io::AsRawHandle,
            };
            use windows_sys::Win32::Storage::FileSystem::*;
            let f = match fs::OpenOptions::new()
                .read(true)
                .access_mode(0x00010000 | FILE_READ_ATTRIBUTES)
                .share_mode(3)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                .open(self.path.join(&self.leaf))
            {
                Ok(f) => f,
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
                Err(e) => return Err(e),
            };
            let m = f.metadata()?;
            if !m.is_file() || m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                return Err(invalid("component deletion kind"));
            }
            let info = FILE_DISPOSITION_INFO { DeleteFile: true };
            if unsafe {
                SetFileInformationByHandle(
                    f.as_raw_handle(),
                    FileDispositionInfo,
                    (&info as *const FILE_DISPOSITION_INFO).cast(),
                    std::mem::size_of_val(&info) as u32,
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
    }
    pub(crate) fn put(&self, input: &mut impl Read, mode: u32, stage: &Parent) -> io::Result<()> {
        #[cfg(unix)]
        {
            use std::{
                ffi::CString,
                os::{
                    fd::{AsRawFd, FromRawFd},
                    unix::fs::PermissionsExt,
                },
            };
            let temp = CString::new(stage.leaf.as_str()).unwrap();
            let leaf = CString::new(self.leaf.as_str()).unwrap();
            let fd = unsafe {
                libc::openat(
                    stage.file.as_raw_fd(),
                    temp.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let mut file = unsafe { fs::File::from_raw_fd(fd) };
            let result = (|| {
                bounded_copy(input, &mut file)?;
                file.set_permissions(fs::Permissions::from_mode(mode))?;
                file.sync_all()?;
                if unsafe {
                    libc::renameat(
                        stage.file.as_raw_fd(),
                        temp.as_ptr(),
                        self.file.as_raw_fd(),
                        leaf.as_ptr(),
                    )
                } < 0
                {
                    return Err(io::Error::last_os_error());
                }
                stage.file.sync_all()?;
                self.file.sync_all()
            })();
            if result.is_err() {
                unsafe { libc::unlinkat(stage.file.as_raw_fd(), temp.as_ptr(), 0) };
            }
            result
        }
        #[cfg(windows)]
        {
            use std::os::windows::{ffi::OsStrExt, fs::OpenOptionsExt, io::AsRawHandle};
            use windows_sys::Win32::Storage::FileSystem::*;
            let _ = mode;
            let temp = stage.path.join(&stage.leaf);
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .access_mode(FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | 0x00010000)
                .share_mode(3)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                .open(&temp)?;
            let result = (|| {
                bounded_copy(input, &mut f)?;
                f.sync_all()?;
                let name: Vec<u16> = self
                    .path
                    .join(&self.leaf)
                    .as_os_str()
                    .encode_wide()
                    .chain([0])
                    .collect();
                let bytes = 20 + name.len() * 2;
                let mut data = vec![0u64; bytes.div_ceil(8)];
                let p = data.as_mut_ptr().cast::<u8>();
                unsafe {
                    *p = 1;
                    std::ptr::write_unaligned(p.add(16).cast(), ((name.len() - 1) * 2) as u32);
                    std::ptr::copy_nonoverlapping(
                        name.as_ptr().cast::<u8>(),
                        p.add(20),
                        name.len() * 2,
                    );
                    if SetFileInformationByHandle(
                        f.as_raw_handle(),
                        FileRenameInfo,
                        p.cast(),
                        bytes as u32,
                    ) == 0
                    {
                        return Err(io::Error::last_os_error());
                    }
                }
                Ok(())
            })();
            drop(f);
            if result.is_err() {
                let _ = fs::remove_file(temp);
            }
            result
        }
    }
}
fn stage_name(name: &str) -> String {
    format!(".kelft-targets/stage/{:x}", Sha256::digest(name.as_bytes()))
}
fn bounded_copy(input: &mut impl Read, output: &mut impl Write) -> io::Result<()> {
    let mut total = 0usize;
    let mut b = [0; 65536];
    loop {
        let n = input.read(&mut b)?;
        if n == 0 {
            break;
        }
        total += n;
        if total > 256 << 20 {
            return Err(invalid("component copy bound"));
        }
        output.write_all(&b[..n])?;
    }
    Ok(())
}
pub struct Lock {
    _file: fs::File,
}
pub fn lock(root: &Path, exclusive: bool) -> io::Result<Lock> {
    let store = Store::open(root)?;
    let file = store
        .parent(".kelft-targets/lock", false)?
        .open(exclusive)?;
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        if unsafe {
            libc::flock(
                file.as_raw_fd(),
                if exclusive {
                    libc::LOCK_EX
                } else {
                    libc::LOCK_SH
                },
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::{
            Storage::FileSystem::{LOCKFILE_EXCLUSIVE_LOCK, LockFileEx},
            System::IO::OVERLAPPED,
        };
        let mut overlap: OVERLAPPED = unsafe { std::mem::zeroed() };
        if unsafe {
            LockFileEx(
                file.as_raw_handle(),
                if exclusive {
                    LOCKFILE_EXCLUSIVE_LOCK
                } else {
                    0
                },
                0,
                1,
                0,
                &mut overlap,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(Lock { _file: file })
}

/// A component-capable boundary retains its own shared lock and independently
/// requires the exact release activation marker before snapshotting inputs.
pub fn activation(root: &Path, target: &str) -> io::Result<Option<Lock>> {
    #[cfg(kelft_target_components)]
    {
        let lock = lock(root, false)?;
        let catalog: serde_json::Value =
            serde_json::from_str(include_str!(env!("KELFT_TARGET_CATALOG")))
                .map_err(|_| invalid("embedded target catalog"))?;
        let component = catalog["components"]
            .as_array()
            .and_then(|rows| rows.iter().find(|r| r["target"] == target))
            .ok_or_else(|| invalid("target not in release catalog"))?;
        let expected = component["archive"]["sha256"]
            .as_str()
            .ok_or_else(|| invalid("component digest"))?;
        let store = Store::open(root)?;
        let mut receipt = String::new();
        store
            .read(&format!(".kelft-targets/{target}.receipt"))?
            .take(129)
            .read_to_string(&mut receipt)?;
        if receipt != format!("{expected}\n") {
            return Err(invalid(
                "target pack is inactive; use kelft target add TARGET --from PACK.tar.gz",
            ));
        }
        Ok(Some(lock))
    }
    #[cfg(not(kelft_target_components))]
    {
        let _ = (root, target);
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn directory() -> PathBuf {
        let mut nonce = [0; 8];
        getrandom::fill(&mut nonce).unwrap();
        let root = std::env::temp_dir().join(format!(
            "kelft-store-{}",
            crate::distribution_archive::hex(&nonce)
        ));
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join(".kelft-targets")).unwrap();
        fs::write(root.join(".kelft-targets/lock"), []).unwrap();
        root
    }
    #[test]
    fn atomic_publication_replacement_deactivation_and_recovery() {
        let root = directory();
        {
            let _lock = lock(&root, true).unwrap();
            let store = Store::open(&root).unwrap();
            store
                .put("cross/fixture", &mut &b"first"[..], 0o644)
                .unwrap();
            store
                .put("cross/fixture", &mut &b"second"[..], 0o644)
                .unwrap();
            assert_eq!(fs::read(root.join("cross/fixture")).unwrap(), b"second");
            assert_eq!(store.observation("cross/fixture", 0o644)["modeValid"], true);
            for n in 1..16 {
                let name = format!("cross/{}", "x".repeat(n));
                store.put(&name, &mut &b"name bound"[..], 0o644).unwrap();
                assert_eq!(fs::read(root.join(&name)).unwrap(), b"name bound");
                store.remove(&name).unwrap();
            }
            let stage = stage_name("cross/fixture");
            fs::write(root.join(&stage), b"interrupted").unwrap();
            store.recover("cross/fixture").unwrap();
            assert!(!root.join(stage).exists());
            store.remove("cross/fixture").unwrap();
            store.remove("cross/fixture").unwrap();
        }
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    #[cfg(any(target_os = "linux", windows))]
    fn interrupted_streams_are_recovered_only_from_private_ordinal_staging() {
        let root = directory();
        {
            let store = Store::open(&root).unwrap();
            {
                let payloads = store.payloads().unwrap();
                fs::write(payloads.path.join("0"), b"partial stream").unwrap();
            }
            let stage = root.join(".kelft-targets/archive");
            assert!(!stage.join("0").exists());
            fs::write(stage.join("8191"), b"interrupted").unwrap();
            {
                let payloads = store.payloads().unwrap();
                assert_eq!(fs::read_dir(&payloads.path).unwrap().count(), 0);
            }
            fs::write(stage.join("unrelated"), b"retain").unwrap();
            assert!(store.payloads().is_err());
            assert_eq!(fs::read(stage.join("unrelated")).unwrap(), b"retain");
        }
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn traversal_and_special_files_never_become_writable_destinations() {
        let root = directory();
        {
            let store = Store::open(&root).unwrap();
            for name in [
                "../outside",
                "/absolute",
                "cross/../core",
                "cross/a:alias",
                "cross/a.",
            ] {
                assert!(store.put(name, &mut &b"bad"[..], 0o644).is_err());
            }
            fs::create_dir(root.join("directory")).unwrap();
            assert!(store.read("directory").is_err());
            assert!(store.remove("directory").is_err());
            #[cfg(unix)]
            {
                std::os::unix::fs::symlink("directory", root.join("alias")).unwrap();
                assert!(store.read("alias").is_err());
                assert!(store.put("alias/file", &mut &b"bad"[..], 0o644).is_err());
            }
        }
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn exclusive_maintenance_waits_for_shared_builds() {
        let root = directory();
        let first = lock(&root, false).unwrap();
        let second = lock(&root, false).unwrap();
        let child = root.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let _exclusive = lock(&child, true).unwrap();
            tx.send(()).unwrap();
        });
        assert!(
            rx.recv_timeout(std::time::Duration::from_millis(100))
                .is_err()
        );
        drop(first);
        assert!(
            rx.recv_timeout(std::time::Duration::from_millis(100))
                .is_err()
        );
        drop(second);
        rx.recv_timeout(std::time::Duration::from_secs(5)).unwrap();
        worker.join().unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}
