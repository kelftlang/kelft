//! Descriptor-rooted KFS1 broker. No worker receives a native path or descriptor.
#[path = "unix_host_filesystem.rs"]
mod host;
use crate::filesystem_channel::{self, HANDLE_LIMIT, Operation, Request};
use std::{
    collections::BTreeMap,
    ffi::CString,
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    os::unix::{
        fs::{MetadataExt, OpenOptionsExt},
        io::{AsRawFd, FromRawFd},
    },
    path::{Component, Path},
};
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn denied() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "filesystem grant denied")
}
fn identity(file: &File) -> io::Result<(u64, u64)> {
    let metadata = file.metadata()?;
    Ok((metadata.dev(), metadata.ino()))
}
fn open(parent: &File, name: &str, flags: i32) -> io::Result<File> {
    if name.is_empty() || name.contains(['/', '\0']) || matches!(name, "." | "..") {
        return Err(invalid("normal broker component required"));
    }
    let name = CString::new(name).map_err(|_| invalid("broker path contains NUL"))?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            0o600,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn directory(parent: &File, name: &str, device: Option<u64>) -> io::Result<File> {
    let file = open(parent, name, libc::O_RDONLY | libc::O_DIRECTORY).map_err(|error| {
        // Linux reports ENOTDIR for O_DIRECTORY|O_NOFOLLOW on a symlink.
        // Preserve ENOTDIR for regular files, and report rejected links as denial.
        if error.kind()==io::ErrorKind::NotADirectory {
            if let Ok(name)=CString::new(name) {let mut metadata=unsafe{std::mem::zeroed::<libc::stat>()};
                if unsafe{libc::fstatat(parent.as_raw_fd(),name.as_ptr(),&mut metadata,libc::AT_SYMLINK_NOFOLLOW)}==0&&metadata.st_mode&libc::S_IFMT==libc::S_IFLNK{return denied();}
            }
        }error
    })?;
    if !file.metadata()?.is_dir()
        || device.is_some_and(|value| {
            file.metadata()
                .map_or(true, |metadata| metadata.dev() != value)
        })
    {
        return Err(denied());
    }
    Ok(file)
}
struct Root {
    directory: File,
    leaf: Option<String>,
    pin: Option<File>,
    read: bool,
    write: bool,
    device: u64,
}
struct Opened {
    file: File,
    read: bool,
    write: bool,
    transferred: u64,
}
pub struct Broker {
    roots: BTreeMap<u64, Root>,
    files: BTreeMap<u64, Opened>,
    next: u64,
}
impl Default for Broker {
    fn default() -> Self {
        Self {
            roots: BTreeMap::new(),
            files: BTreeMap::new(),
            next: 1 << 32,
        }
    }
}
impl Broker {
    /// Only the parent linker service can mark its already-authorized output
    /// executable. KFS1 exposes no permission-changing operation.
    pub fn executable(&mut self, token: u64) -> io::Result<()> {
        let opened=self.files.get(&token).ok_or_else(denied)?;
        let metadata=opened.file.metadata()?;
        if !opened.write||!metadata.is_file()||metadata.nlink()!=1||metadata.uid()!=unsafe{libc::geteuid()}{return Err(denied());}
        if unsafe{libc::fchmod(opened.file.as_raw_fd(),0o700)}<0{return Err(io::Error::last_os_error());}Ok(())
    }
    pub fn add_root(&mut self, path: &Path, read: bool, write: bool) -> io::Result<u64> {
        if !path.is_absolute() || !read && !write || self.roots.len() >= HANDLE_LIMIT {
            return Err(invalid("invalid descriptor root grant"));
        }
        let mut parts = vec![];
        for part in path.components() {
            match part {
                Component::RootDir => {}
                Component::Normal(name) => parts.push(
                    name.to_str()
                        .ok_or_else(|| invalid("Unicode grant required"))?
                        .to_string(),
                ),
                _ => return Err(invalid("normalized absolute grant required")),
            }
        }
        if parts.is_empty() {
            return Err(denied());
        }
        let mut parent = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open("/")?;
        for name in &parts[..parts.len() - 1] {
            parent = directory(&parent, name, None)?;
        }
        let name = parts.last().unwrap();
        let mut leaf = Some(name.clone());
        let pin = match open(&parent, name, libc::O_RDONLY) {
            Ok(file) => {
                let metadata = file.metadata()?;
                if metadata.is_dir() {
                    parent = directory(&parent, name, None)?;
                    leaf = None;
                    None
                } else if metadata.is_file() {
                    Some(file)
                } else {
                    return Err(denied());
                }
            }
            Err(error) if write && error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        let device = parent.metadata()?.dev();
        if pin.as_ref().is_some_and(|file| {
            file.metadata()
                .map_or(true, |metadata| metadata.dev() != device)
        }) {
            return Err(denied());
        }
        let token = self.roots.len() as u64 + 1;
        self.roots.insert(
            token,
            Root {
                directory: parent,
                leaf,
                pin,
                read,
                write,
                device,
            },
        );
        Ok(token)
    }
    fn target(root: &Root, path: &str) -> io::Result<(File, String)> {
        let relative = match &root.leaf {
            Some(leaf) => {
                if path != "." {
                    return Err(denied());
                }
                leaf.as_str()
            }
            None => path,
        };
        if relative == "." {
            return Err(io::Error::from(io::ErrorKind::IsADirectory));
        }
        filesystem_channel::validate_relative(relative)?;
        let mut parts = relative.split('/').collect::<Vec<_>>();
        let leaf = parts
            .pop()
            .ok_or_else(|| invalid("missing broker leaf"))?
            .to_owned();
        let mut parent = root.directory.try_clone()?;
        for name in parts {
            parent = directory(&parent, name, Some(root.device))?;
        }
        Ok((parent, leaf))
    }
    fn open_request(&mut self, request: &Request) -> io::Result<u64> {
        if self.files.len() >= HANDLE_LIMIT {
            return Err(invalid("broker handle budget exhausted"));
        }
        let root = self.roots.get_mut(&request.handle).ok_or_else(denied)?;
        let reading = request.operation == Operation::OpenRead;
        if reading && !root.read || !reading && !root.write {
            return Err(denied());
        }
        if request.operation == Operation::CreateDirectory
            && request.path == "."
            && root.leaf.is_none()
        {
            return Ok(0);
        }
        let (parent, leaf) = Self::target(root, &request.path)?;
        if request.operation == Operation::CreateDirectory {
            let name =
                CString::new(leaf.as_str()).map_err(|_| invalid("directory name contains NUL"))?;
            if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
                return Err(io::Error::last_os_error());
            }
            let created = directory(&parent, &leaf, Some(root.device))?;
            if root.leaf.is_some() {
                root.directory = created;
                root.leaf = None;
                root.pin = None;
            }
            return Ok(0);
        }
        let flags = if reading {
            libc::O_RDONLY
        } else {
            libc::O_WRONLY
                | libc::O_CREAT
                | if request.operation == Operation::CreateNew {
                    libc::O_EXCL
                } else {
                    0
                }
        };
        // Truncate only after type, device and exact-file identity checks succeed.
        let file = open(&parent, &leaf, flags)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(io::Error::from(if metadata.is_dir() {
                io::ErrorKind::IsADirectory
            } else {
                io::ErrorKind::PermissionDenied
            }));
        }
        if metadata.dev() != root.device || !reading && metadata.nlink() != 1 {
            return Err(denied());
        }
        if let Some(pin) = &root.pin {
            if identity(pin)? != identity(&file)? {
                return Err(denied());
            }
        }
        if reading && metadata.len() > 64 << 20 {
            return Err(invalid("broker file exceeds bound"));
        }
        if !reading {
            file.set_len(0)?;
        }
        if root.leaf.is_some() && root.pin.is_none() {
            root.pin = Some(file.try_clone()?);
        }
        let token = self.next;
        self.next = self
            .next
            .checked_add(1)
            .ok_or_else(|| invalid("broker token exhausted"))?;
        self.files.insert(
            token,
            Opened {
                file,
                read: reading,
                write: !reading,
                transferred: 0,
            },
        );
        Ok(token)
    }
    fn metadata(&self, request: &Request) -> io::Result<u64> {
        let root = self.roots.get(&request.handle).ok_or_else(denied)?;
        if request.path == "." && root.leaf.is_none() {
            return Ok(2);
        }
        let (parent, leaf) = Self::target(root, &request.path)?;
        let file = open(&parent, &leaf, libc::O_RDONLY)?;
        let metadata = file.metadata()?;
        if metadata.dev() != root.device {
            return Err(denied());
        }
        if let Some(pin) = &root.pin {
            if identity(pin)? != identity(&file)? {
                return Err(denied());
            }
        }
        if metadata.is_dir() {
            Ok(2)
        } else if metadata.is_file() {
            Ok(1)
        } else {
            Err(denied())
        }
    }
    pub fn execute(&mut self, request: &Request) -> io::Result<(u64, Vec<u8>)> {
        request.validate()?;
        match request.operation {
            Operation::HostRequest | Operation::HostContinue => Err(invalid("host service is unavailable")),
            Operation::OpenRead => {
                let token = self.open_request(request)?;
                let size = self
                    .files
                    .get(&token)
                    .ok_or_else(denied)?
                    .file
                    .metadata()?
                    .len();
                Ok((token, size.to_le_bytes().to_vec()))
            }
            Operation::OpenWrite | Operation::CreateNew | Operation::CreateDirectory => {
                Ok((self.open_request(request)?, vec![]))
            }
            Operation::Metadata => Ok((self.metadata(request)?, vec![])),
            Operation::Close => {
                self.files.remove(&request.handle).ok_or_else(denied)?;
                Ok((0, vec![]))
            }
            Operation::Read | Operation::Write => {
                let file = self.files.get_mut(&request.handle).ok_or_else(denied)?;
                let reading = request.operation == Operation::Read;
                if reading && !file.read || !reading && !file.write {
                    return Err(denied());
                }
                if file.transferred + request.amount as u64 > 64 << 20 {
                    return Err(invalid("broker transfer exceeds bound"));
                }
                if reading {
                    let mut data = vec![0; request.amount as usize];
                    let count = file.file.read(&mut data)?;
                    data.truncate(count);
                    file.transferred += count as u64;
                    Ok((count as u64, data))
                } else {
                    file.file.write_all(&request.data)?;
                    file.transferred += request.data.len() as u64;
                    Ok((request.data.len() as u64, vec![]))
                }
            }
        }
    }
    pub fn serve(&mut self, input: &mut impl Read, output: &mut impl Write) -> io::Result<()> {
        filesystem_channel::serve(input, output, |request| self.execute(request))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    fn temporary() -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!(
            "kelft-unix-broker-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        std::fs::canonicalize(root).unwrap()
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
    #[test]
    fn executable_publication_requires_a_retained_write_handle_without_hardlink_aliases() {
        let root=temporary();let path=root.join("image");std::fs::write(&path,b"image").unwrap();
        let mut broker=Broker::default();let read=broker.add_root(&path,true,false).unwrap();
        let (reader,_)=broker.execute(&request(Operation::OpenRead,read,".")).unwrap();assert!(broker.executable(reader).is_err());
        let write=broker.add_root(&path,false,true).unwrap();let (writer,_)=broker.execute(&request(Operation::OpenWrite,write,".")).unwrap();
        broker.executable(writer).unwrap();assert_eq!(std::fs::metadata(&path).unwrap().mode()&0o7777,0o700);
        std::fs::hard_link(&path,root.join("alias")).unwrap();assert!(broker.executable(writer).is_err());
        broker.execute(&request(Operation::Close,reader,"")).unwrap();broker.execute(&request(Operation::Close,writer,"")).unwrap();std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn a_missing_directory_grant_remains_write_only_after_creation() {
        let root = temporary();
        let future = root.join("future hé 😀");
        let mut broker = Broker::default();
        let token = broker.add_root(&future, false, true).unwrap();
        assert!(broker.execute(&request(Operation::Metadata, token, ".")).is_err());
        broker.execute(&request(Operation::CreateDirectory, token, ".")).unwrap();
        assert_eq!(broker.execute(&request(Operation::Metadata, token, ".")).unwrap().0, 2);
        let (file, _) = broker.execute(&request(Operation::CreateNew, token, "child")).unwrap();
        broker.execute(&request(Operation::Close, file, "")).unwrap();
        assert!(broker.execute(&request(Operation::OpenRead, token, "child")).is_err());
        assert!(future.join("child").is_file());
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn real_reads_writes_and_operation_grants() {
        let root = temporary();
        std::fs::write(root.join("input"), [0, 255, 128]).unwrap();
        let mut broker = Broker::default();
        let read = broker.add_root(&root, true, false).unwrap();
        let write = broker.add_root(&root, false, true).unwrap();
        assert!(
            broker
                .execute(&request(Operation::OpenWrite, read, "input"))
                .is_err()
        );
        assert!(
            broker
                .execute(&request(Operation::OpenRead, write, "input"))
                .is_err()
        );
        let (token, size) = broker
            .execute(&request(Operation::OpenRead, read, "input"))
            .unwrap();
        assert_eq!(size, 3u64.to_le_bytes());
        let mut data = request(Operation::Read, token, "");
        data.amount = 3;
        assert_eq!(broker.execute(&data).unwrap().1, [0, 255, 128]);
        broker
            .execute(&request(Operation::Close, token, ""))
            .unwrap();
        assert!(broker.execute(&data).is_err());
        let (token, _) = broker
            .execute(&request(Operation::CreateNew, write, "hé 😀"))
            .unwrap();
        let data = Request {
            operation: Operation::Write,
            handle: token,
            path: String::new(),
            amount: 3,
            data: vec![128, 0, 255],
            sequence: 1,
        };
        broker.execute(&data).unwrap();
        assert_eq!(std::fs::read(root.join("hé 😀")).unwrap(), data.data);
        assert!(
            broker
                .execute(&request(Operation::CreateNew, write, "hé 😀"))
                .is_err()
        );
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn symlinks_traversal_and_exact_file_replacement_are_denied() {
        let root = temporary();
        let outside = temporary();
        std::fs::write(outside.join("sentinel"), b"preserved").unwrap();
        symlink(&outside, root.join("escape")).unwrap();
        let mut broker = Broker::default();
        let token = broker.add_root(&root, true, true).unwrap();
        for path in [
            "escape/sentinel",
            "../sentinel",
            "/absolute",
            "a//b",
            "C:/drive",
        ] {
            assert!(
                broker
                    .execute(&request(Operation::OpenWrite, token, path))
                    .is_err(),
                "{path}"
            );
        }
        assert_eq!(
            std::fs::read(outside.join("sentinel")).unwrap(),
            b"preserved"
        );
        let file = root.join("pinned");
        std::fs::write(&file, b"original").unwrap();
        let exact = broker.add_root(&file, true, true).unwrap();
        std::fs::rename(&file, root.join("old")).unwrap();
        std::fs::write(&file, b"replacement").unwrap();
        assert!(
            broker
                .execute(&request(Operation::OpenRead, exact, "."))
                .is_err()
        );
        assert!(
            broker
                .execute(&request(Operation::OpenWrite, exact, "."))
                .is_err()
        );
        assert_eq!(std::fs::read(&file).unwrap(), b"replacement");
        std::fs::remove_dir_all(root).unwrap();
        std::fs::remove_dir_all(outside).unwrap();
    }
    #[test]
    fn hardlinks_do_not_widen_write_authority() {
        let root = temporary();
        let outside = temporary();
        let source = outside.join("sentinel");
        std::fs::write(&source, b"preserved").unwrap();
        std::fs::hard_link(&source, root.join("link")).unwrap();
        let mut broker = Broker::default();
        let token = broker.add_root(&root, false, true).unwrap();
        assert!(
            broker
                .execute(&request(Operation::OpenWrite, token, "link"))
                .is_err()
        );
        assert_eq!(std::fs::read(source).unwrap(), b"preserved");
        std::fs::remove_dir_all(root).unwrap();
        std::fs::remove_dir_all(outside).unwrap();
    }
    #[test]
    fn retained_directory_does_not_follow_a_replacement_name() {
        let root = temporary();
        let original = root.join("directory");
        std::fs::create_dir(&original).unwrap();
        std::fs::write(original.join("input"), b"original").unwrap();
        let mut broker = Broker::default();
        let token = broker.add_root(&original, true, false).unwrap();
        std::fs::rename(&original, root.join("moved")).unwrap();
        std::fs::create_dir(&original).unwrap();
        std::fs::write(original.join("input"), b"replacement").unwrap();
        let (file, _) = broker
            .execute(&request(Operation::OpenRead, token, "input"))
            .unwrap();
        let mut data = request(Operation::Read, file, "");
        data.amount = 64;
        assert_eq!(broker.execute(&data).unwrap().1, b"original");
        std::fs::remove_dir_all(root).unwrap();
    }
}
