//! Linux-specific sealed supervisor handoff. The coordinator owns protocol
//! authentication; this adapter owns Linux descriptors and exec preparation.
use std::{fs,io::{Read,Write},process::Command};
use std::os::fd::{AsRawFd,FromRawFd};
use std::os::unix::{fs::OpenOptionsExt,process::CommandExt};
type Error=Box<dyn std::error::Error>;
fn open_image(path:&std::path::Path)->std::io::Result<fs::File>{
 fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW|libc::O_NONBLOCK).open(path)
}
fn open_root(path:&std::path::Path)->std::io::Result<fs::File>{
 fs::OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY|libc::O_NOFOLLOW).open(path)
}
pub(crate) struct BoundaryCommand {pub command:Command,_image:fs::File,_root:fs::File}
pub(crate) fn boundary_command()->Result<BoundaryCommand,Error>{
 let(path,_)=crate::installed_paths()?;
 let mut input=open_image(&path)?;
 let metadata=input.metadata()?;if !metadata.is_file()||metadata.len()>67_108_864{return Err("invalid installed boundary image".into());}
 let mut bytes=Vec::new();Read::by_ref(&mut input).take(67_108_865).read_to_end(&mut bytes)?;
 if crate::protocol::hash(&bytes)!=crate::BOUNDARY_SHA256{return Err("installed boundary image changed".into());}
 crate::native_target::Target::current()?.validate_executable(&bytes)?;
 unsafe extern "C"{fn syscall(number:i64,...)->i64;fn fcntl(fd:i32,command:i32,...)->i32;}
 #[cfg(target_arch="x86_64")]const MEMFD_CREATE:i64=319;
 #[cfg(target_arch="aarch64")]const MEMFD_CREATE:i64=279;
 let descriptor=unsafe{syscall(MEMFD_CREATE,c"kelft-native-boundary".as_ptr(),3u32)};
 if descriptor<0{return Err(std::io::Error::last_os_error().into());}
 let mut image=unsafe{fs::File::from_raw_fd(descriptor as i32)};image.write_all(&bytes)?;
 if unsafe{fcntl(image.as_raw_fd(),1033,15)}<0{return Err(std::io::Error::last_os_error().into());}
 let root=open_root(path.parent().and_then(std::path::Path::parent).ok_or("installed root missing")?)?;
 let root_fd=root.as_raw_fd();let mut command=Command::new(format!("/proc/self/fd/{}",image.as_raw_fd()));
 command.arg("--installed-root-fd").arg(root_fd.to_string());
 unsafe{command.pre_exec(move||{if fcntl(root_fd,2,0)<0{return Err(std::io::Error::last_os_error());}Ok(())});}
 Ok(BoundaryCommand{command,_image:image,_root:root})
}

#[cfg(test)]
mod tests {
 use super::*;
 use std::os::unix::{fs::{DirBuilderExt,symlink},io::AsRawFd};
 #[test]
 fn platform_opens_retain_directories_and_reject_final_symlinks_and_wrong_kinds(){
  let mut nonce=[0;16];getrandom::fill(&mut nonce).unwrap();
  let directory=std::env::temp_dir().join(format!("kelft-boundary-open-{:x}",u128::from_le_bytes(nonce)));
  fs::DirBuilder::new().mode(0o700).create(&directory).unwrap();
  let file=directory.join("image");fs::write(&file,b"authenticated-input").unwrap();
  let mut image=open_image(&file).unwrap();let mut bytes=vec![];image.read_to_end(&mut bytes).unwrap();assert_eq!(bytes,b"authenticated-input");
  let root=open_root(&directory).unwrap();assert!(root.metadata().unwrap().is_dir());
  assert_ne!(unsafe{libc::fcntl(root.as_raw_fd(),libc::F_GETFD)}&libc::FD_CLOEXEC,0);
  symlink(&file,directory.join("image-link")).unwrap();symlink(&directory,directory.join("root-link")).unwrap();
  assert!(open_image(&directory.join("image-link")).is_err());assert!(open_root(&directory.join("root-link")).is_err());assert!(open_root(&file).is_err());
  drop((image,root));fs::remove_dir_all(directory).unwrap();
 }
}
