//! Parent-owned Mach-O snapshots. Seatbelt supplies candidate write exclusion;
//! retained directory/file identities detect changed inputs before execution.
use crate::native_target::Target;
use sha2::{Digest,Sha256};
use std::{ffi::CString,fs::{self,File,OpenOptions},io::{self,Write},os::{fd::{AsRawFd,FromRawFd},unix::fs::{MetadataExt,OpenOptionsExt,FileExt}},path::{Path,PathBuf}};
fn invalid(message:&'static str)->io::Error{io::Error::new(io::ErrorKind::InvalidInput,message)}
fn digest(bytes:&[u8])->String{format!("sha256:{:x}",Sha256::digest(bytes))}
pub fn validate(bytes:&[u8])->io::Result<()>{
 validate_bounded(bytes,64<<20)
}
pub(crate) fn validate_bounded(bytes:&[u8],maximum:usize)->io::Result<()>{
 if bytes.is_empty()||bytes.len()>maximum{return Err(invalid("native Mach-O size exceeds bound"));}
 let target=Target::current()?;if !matches!(target,Target::MacosX64|Target::MacosArm64){return Err(invalid("native macOS snapshot required"));}target.validate_executable(bytes)?;
 let count=u32::from_le_bytes(bytes[16..20].try_into().unwrap());let mut offset=32;
 for _ in 0..count{
  let command=u32::from_le_bytes(bytes[offset..offset+4].try_into().unwrap());let size=u32::from_le_bytes(bytes[offset+4..offset+8].try_into().unwrap()) as usize;
  if command==0x80000028{if size!=24{return Err(invalid("invalid native entry command"));}let stack=u64::from_le_bytes(bytes[offset+16..offset+24].try_into().unwrap());if stack>16<<20{return Err(invalid("Mach-O initial stack exceeds bound"));}}
  offset+=size;
 }
 Ok(())
}
pub struct Image{parent:File,root:File,file:Option<File>,name:CString,path:PathBuf,expected:String,length:u64,root_identity:(u64,u64),trusted_tool:bool,runtime:bool,inputs:Vec<(String,File,String)>}
impl Image{
 pub fn new(bytes:&[u8],expected:&str,base:&Path)->io::Result<Self>{
  Self::prepare(bytes,expected,base,false,false)
 }
 pub(crate) fn tool(bytes:&[u8],expected:&str,base:&Path)->io::Result<Self>{Self::prepare(bytes,expected,base,true,false)}
 pub(crate) fn linker_tool(bytes:&[u8],expected:&str,base:&Path)->io::Result<Self>{Self::prepare_bounded(bytes,expected,base,true,false,128<<20)}
 pub fn runtime(bytes:&[u8],expected:&str,base:&Path)->io::Result<Self>{Self::prepare(bytes,expected,base,false,true)}
 fn prepare(bytes:&[u8],expected:&str,base:&Path,trusted_tool:bool,runtime:bool)->io::Result<Self>{
  Self::prepare_bounded(bytes,expected,base,trusted_tool,runtime,64<<20)
 }
 fn prepare_bounded(bytes:&[u8],expected:&str,base:&Path,trusted_tool:bool,runtime:bool,tool_maximum:usize)->io::Result<Self>{
  if trusted_tool{crate::macos_format::validate_tool_bounded(bytes,Target::current()?,tool_maximum)?;}else{validate_bounded(bytes,if runtime{256<<20}else{64<<20})?;}if digest(bytes)!=expected{return Err(invalid("native snapshot digest differs"));}
  if !base.is_absolute()||base.parent().is_none()||fs::canonicalize(base)?!=base{return Err(invalid("canonical private snapshot base required"));}
  let parent=OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_CLOEXEC).open(base)?;
  let mut entropy=[0;24];getrandom::fill(&mut entropy).map_err(|error|io::Error::other(error.to_string()))?;let name=CString::new(format!("kelft-image-{}",entropy.iter().map(|b|format!("{b:02x}")).collect::<String>())).unwrap();
  if unsafe{libc::mkdirat(parent.as_raw_fd(),name.as_ptr(),0o700)}<0{return Err(io::Error::last_os_error());}
  let fd=unsafe{libc::openat(parent.as_raw_fd(),name.as_ptr(),libc::O_RDONLY|libc::O_DIRECTORY|libc::O_NOFOLLOW|libc::O_CLOEXEC)};
  if fd<0{let error=io::Error::last_os_error();unsafe{libc::unlinkat(parent.as_raw_fd(),name.as_ptr(),libc::AT_REMOVEDIR);}return Err(error);}
  let root=unsafe{File::from_raw_fd(fd)};let metadata=root.metadata()?;let root_identity=(metadata.dev(),metadata.ino());
  let path=base.join(name.to_str().unwrap()).join("image");let mut image=Self{parent,root,file:None,name,path,expected:expected.into(),length:bytes.len() as u64,root_identity,trusted_tool,runtime,inputs:vec![]};
  let fd=unsafe{libc::openat(image.root.as_raw_fd(),c"image".as_ptr(),libc::O_WRONLY|libc::O_CREAT|libc::O_EXCL|libc::O_NOFOLLOW|libc::O_CLOEXEC,0o600)};
  if fd<0{return Err(io::Error::last_os_error());}
  {let mut file=unsafe{File::from_raw_fd(fd)};file.write_all(bytes)?;file.sync_all()?;if unsafe{libc::fchmod(file.as_raw_fd(),0o500)}<0{return Err(io::Error::last_os_error());}}
  let fd=unsafe{libc::openat(image.root.as_raw_fd(),c"image".as_ptr(),libc::O_RDONLY|libc::O_NOFOLLOW|libc::O_CLOEXEC)};
  if fd<0{return Err(io::Error::last_os_error());}image.file=Some(unsafe{File::from_raw_fd(fd)});image.verify()?;Ok(image)
 }
 pub fn path(&self)->&Path{&self.path}
 pub fn directory(&self)->&Path{self.path.parent().unwrap()}
 pub fn sha256(&self)->&str{&self.expected}
 pub(crate) fn is_tool(&self)->bool{self.trusted_tool}
 pub(crate) fn is_runtime(&self)->bool{self.runtime}
 pub(crate) fn runtime_inputs(&self)->Vec<(PathBuf,String)>{self.inputs.iter().map(|(name,_,hash)|(self.directory().join(name),hash.clone())).collect()}
 pub fn runtime_input(&mut self,name:&str,bytes:&[u8],expected:&str)->io::Result<PathBuf>{
  if !self.runtime||self.inputs.len()>=2||!matches!(name,"program.mjs"|"control.mjs"|"program.wasm")||self.inputs.iter().any(|(old,_,_)|old==name)||bytes.len()>64<<20||digest(bytes)!=expected{return Err(invalid("invalid engine snapshot input"));}
  let encoded=CString::new(name).unwrap();let fd=unsafe{libc::openat(self.root.as_raw_fd(),encoded.as_ptr(),libc::O_WRONLY|libc::O_CREAT|libc::O_EXCL|libc::O_NOFOLLOW|libc::O_CLOEXEC,0o600)};if fd<0{return Err(io::Error::last_os_error());}
  let mut file=unsafe{File::from_raw_fd(fd)};file.write_all(bytes)?;file.sync_all()?;if unsafe{libc::fchmod(file.as_raw_fd(),0o400)}<0{return Err(io::Error::last_os_error());}drop(file);
  let file=OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW|libc::O_CLOEXEC).open(self.directory().join(name))?;self.inputs.push((name.into(),file,expected.into()));self.verify()?;Ok(self.directory().join(name))
 }
 pub fn verify(&self)->io::Result<()>{
  let root=self.root.metadata()?;let named_root=fs::symlink_metadata(self.directory())?;
  if !named_root.is_dir()||(named_root.dev(),named_root.ino())!=self.root_identity||(root.dev(),root.ino())!=self.root_identity||root.mode()&0o7777!=0o700||root.uid()!=unsafe{libc::geteuid()}{return Err(invalid("native snapshot directory changed"));}
  let file=self.file.as_ref().ok_or_else(||invalid("native snapshot file missing"))?;let metadata=file.metadata()?;let named=fs::symlink_metadata(&self.path)?;
  if !metadata.is_file()||!named.is_file()||metadata.nlink()!=1||metadata.len()!=self.length||metadata.mode()&0o7777!=0o500||metadata.uid()!=unsafe{libc::geteuid()}||(metadata.dev(),metadata.ino())!=(named.dev(),named.ino()){return Err(invalid("native snapshot image identity changed"));}
  let mut bytes=vec![0;self.length as usize];file.read_exact_at(&mut bytes,0)?;if digest(&bytes)!=self.expected{return Err(invalid("native snapshot bytes changed"));}
  for(name,file,expected)in &self.inputs{let m=file.metadata()?;let named=fs::symlink_metadata(self.directory().join(name))?;if !m.is_file()||!named.is_file()||m.nlink()!=1||m.len()>64<<20||m.mode()&0o7777!=0o400||m.uid()!=unsafe{libc::geteuid()}||(m.dev(),m.ino())!=(named.dev(),named.ino()){return Err(invalid("engine snapshot input changed"));}let mut bytes=vec![0;m.len() as usize];file.read_exact_at(&mut bytes,0)?;if digest(&bytes)!=*expected{return Err(invalid("engine snapshot input bytes changed"));}}
  Ok(())
 }
}
impl Drop for Image{fn drop(&mut self){drop(self.file.take());unsafe{for name in [c"control.mjs",c"program.mjs",c"program.wasm"]{libc::unlinkat(self.root.as_raw_fd(),name.as_ptr(),0);}libc::unlinkat(self.root.as_raw_fd(),c"image".as_ptr(),0);let mut named:libc::stat=std::mem::zeroed();if libc::fstatat(self.parent.as_raw_fd(),self.name.as_ptr(),&mut named,libc::AT_SYMLINK_NOFOLLOW)==0&&(named.st_dev as u64,named.st_ino)==self.root_identity{libc::unlinkat(self.parent.as_raw_fd(),self.name.as_ptr(),libc::AT_REMOVEDIR);}}}}
#[cfg(test)]mod tests{
 use super::*;use std::os::unix::fs::{symlink,PermissionsExt};
 #[test]fn snapshots_authenticate_bytes_and_reject_replacement_and_mode_changes(){
  let base=fs::canonicalize(std::env::temp_dir()).unwrap();let bytes=fs::read(std::env::current_exe().unwrap()).unwrap();let hash=digest(&bytes);let image=Image::new(&bytes,&hash,&base).unwrap();image.verify().unwrap();let file=image.path().to_owned();let directory=image.directory().to_owned();
  fs::set_permissions(&file,fs::Permissions::from_mode(0o700)).unwrap();assert!(image.verify().is_err());fs::set_permissions(&file,fs::Permissions::from_mode(0o500)).unwrap();image.verify().unwrap();
  fs::remove_file(&file).unwrap();symlink(std::env::current_exe().unwrap(),&file).unwrap();assert!(image.verify().is_err());drop(image);assert!(!file.exists());assert!(!directory.exists());
 }
 #[test]fn malformed_or_changed_native_images_fail_before_snapshot_creation(){
  let base=fs::canonicalize(std::env::temp_dir()).unwrap();for n in 0..320{let bytes=vec![0;n];assert!(Image::new(&bytes,&digest(&bytes),&base).is_err());}
  let bytes=fs::read(std::env::current_exe().unwrap()).unwrap();assert!(Image::new(&bytes,&digest(b"changed"),&base).is_err());let mut other=bytes;other[4..8].copy_from_slice(&(if cfg!(target_arch="aarch64"){0x01000007u32}else{0x0100000c}).to_le_bytes());assert!(validate(&other).is_err());
 }
}
