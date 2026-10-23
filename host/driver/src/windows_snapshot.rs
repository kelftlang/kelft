//! Private executable snapshots with session-specific read/execute ACLs. Parent
//! image handles deny writes/deletion until the worker has terminated.
use crate::{native_target::Target,windows_process::AppContainerSid};
use sha2::{Digest,Sha256};
use std::{fs::{self,File},io::{self,Read,Write},os::windows::{ffi::OsStrExt,fs::{MetadataExt,OpenOptionsExt},io::FromRawHandle},path::{Path,PathBuf},ptr};
use windows_sys::Win32::{Foundation::{INVALID_HANDLE_VALUE,LocalFree},Security::{self,SECURITY_ATTRIBUTES},Storage::FileSystem::*};
fn invalid(message:&'static str)->io::Error{io::Error::new(io::ErrorKind::InvalidInput,message)}
pub(crate) fn validate(bytes:&[u8])->io::Result<()>{
 validate_bounded(bytes,64<<20)
}
fn validate_bounded(bytes:&[u8],maximum:usize)->io::Result<()>{
 if bytes.len()>maximum{return Err(invalid("native image exceeds size bound"));}Target::current()?.validate_executable(bytes)?;
 let optional=u32::from_le_bytes(bytes[60..64].try_into().unwrap()) as usize+24;
 let reserve=u64::from_le_bytes(bytes[optional+72..optional+80].try_into().unwrap());let commit=u64::from_le_bytes(bytes[optional+80..optional+88].try_into().unwrap());
 if reserve==0||reserve>16<<20||commit==0||commit>reserve{return Err(invalid("native image exceeds 16 MiB stack bound"));}Ok(())
}
struct Descriptor(Security::PSECURITY_DESCRIPTOR);
impl Drop for Descriptor{fn drop(&mut self){unsafe{LocalFree(self.0);}}}
fn wide(value:&std::ffi::OsStr)->io::Result<Vec<u16>>{let mut out:Vec<_>=value.encode_wide().collect();if out.contains(&0)||out.len()>32766{return Err(invalid("invalid native snapshot path"));}out.push(0);Ok(out)}
fn security(identity:&AppContainerSid,writable:bool)->io::Result<Descriptor>{
 let ace=if writable{"OICI"}else{""};let access=if writable{"FA"}else{"FRFX"};
 let text=format!("D:P(A;{ace};FA;;;SY)(A;{ace};FA;;;OW)(A;{ace};{access};;;{})",identity.sddl()?);let text=wide(std::ffi::OsStr::new(&text))?;let mut raw=ptr::null_mut();
 if unsafe{Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW(text.as_ptr(),1,&mut raw,ptr::null_mut())}==0{return Err(io::Error::last_os_error());}Ok(Descriptor(raw))
}
/// Resolve the operator's storage through Windows, independently of ambient
/// TEMP/USERPROFILE. Installed supervisors intentionally start with no env.
fn known_folder(id:&windows_sys::core::GUID)->io::Result<PathBuf>{
 let mut raw=ptr::null_mut();let result=unsafe{windows_sys::Win32::UI::Shell::SHGetKnownFolderPath(id,0,ptr::null_mut(),&mut raw)};
 if result!=0||raw.is_null(){return Err(io::Error::other(format!("local application data unavailable: HRESULT {result:#010x}")));}
 let path=(||{let mut length=0;while length<32768&&unsafe{*raw.add(length)}!=0{length+=1;}if length==32768{return Err(invalid("local application data exceeds bound"));}String::from_utf16(unsafe{std::slice::from_raw_parts(raw,length)}).map(PathBuf::from).map_err(|_|invalid("local application data is not Unicode"))})();
 unsafe{windows_sys::Win32::System::Com::CoTaskMemFree(raw.cast());}path
}
pub fn temporary_directory()->io::Result<PathBuf>{let path=known_folder(&windows_sys::Win32::UI::Shell::FOLDERID_LocalAppData)?.join("Temp");if !path.is_dir(){return Err(invalid("local temporary storage is unavailable"));}Ok(path)}
pub fn cross_linker_storage()->io::Result<PathBuf>{
 // Shell/Userenv helpers expand this registry value using process environment
 // variables, which the installed boundary deliberately lacks. Read the OS
 // setting without expansion and resolve SystemDrive from Windows itself.
 #[link(name="advapi32")]unsafe extern "system"{fn RegGetValueW(key:*mut std::ffi::c_void,subkey:*const u16,value:*const u16,flags:u32,kind:*mut u32,data:*mut std::ffi::c_void,size:*mut u32)->i32;}
 let key=wide(std::ffi::OsStr::new("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList"))?;let name=wide(std::ffi::OsStr::new("ProgramData"))?;
 let mut buffer=[0u16;32768];let mut size=std::mem::size_of_val(&buffer) as u32;let mut kind=0;
 let result=unsafe{RegGetValueW(0x80000002u32 as i32 as isize as *mut _,key.as_ptr(),name.as_ptr(),0x10000006,&mut kind,buffer.as_mut_ptr().cast(),&mut size)};
 if result!=0{return Err(io::Error::from_raw_os_error(result));}
 if size<2||size as usize>std::mem::size_of_val(&buffer)||size%2!=0||buffer[size as usize/2-1]!=0{return Err(invalid("invalid configured application-data path"));}
 let mut value=String::from_utf16(&buffer[..size as usize/2-1]).map_err(|_|invalid("application-data path must be Unicode"))?;
 let mut windows=[0u16;32768];let count=unsafe{windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW(windows.as_mut_ptr(),windows.len() as u32)} as usize;
 if count<3||count>=windows.len(){return Err(invalid("system drive unavailable"));}let system=String::from_utf16(&windows[..count]).map_err(|_|invalid("Unicode Windows directory required"))?;
 let system=crate::windows_filesystem_session::normalized(Path::new(&system))?;
 while let Some(at)=value.to_ascii_lowercase().find("%systemdrive%"){value.replace_range(at..at+13,&system[..2]);}
 if value.contains('%'){return Err(invalid("unsupported application-data path variable"));}
 Ok(PathBuf::from(crate::windows_filesystem_session::normalized(Path::new(&value))?))
}
/// Untrusted grants must not cover the shared storage root or any private
/// snapshot beneath it, including another concurrent compilation's snapshot.
pub fn cross_linker_storage_overlap(path:&Path)->io::Result<bool>{
 use crate::windows_filesystem_session::{normalized,within};
 let storage=fs::canonicalize(cross_linker_storage()?)?;
 if within(&storage,path)?{return Ok(true);}
 if !within(path,&storage)?{return Ok(false);}
 let storage=normalized(&storage)?;let path=normalized(path)?;
 let tail=Path::new(&path).components().nth(Path::new(&storage).components().count());
 Ok(tail.is_some_and(|c|c.as_os_str().to_string_lossy().to_ascii_lowercase().starts_with("kelft-image-")))
}
pub struct Image {path:PathBuf,directory:PathBuf,file:Option<File>,root:Option<File>,inputs:Vec<(PathBuf,File)>,work:Option<(PathBuf,File)>,scratch:Vec<(PathBuf,File)>,runtime:bool,_identity:AppContainerSid,_parents:crate::windows_filesystem::Broker}
impl Image {
 pub fn new(bytes:&[u8],expected:&str,identity:&AppContainerSid)->io::Result<Self>{
  validate(bytes)?;Self::snapshot(bytes,expected,identity,64<<20)
 }
 /// Parent-selected optional runtime inputs have their own 256 MiB image cap.
 /// Compiler/candidate artifact requests continue to use `new` and its 64 MiB cap.
 pub fn runtime(bytes:&[u8],expected:&str,identity:&AppContainerSid)->io::Result<Self>{Self::snapshot(bytes,expected,identity,256<<20)}
 /// LLVM expands its own long pathname before processing arguments. Use the
 /// shared application-data directory so that this needs no access to private user
 /// ancestor directories. Snapshot ACLs and retained handles are unchanged.
 pub(crate) fn cross_linker(bytes:&[u8],expected:&str,identity:&AppContainerSid)->io::Result<Self>{
  Self::snapshot_in(bytes,expected,identity,256<<20,cross_linker_storage()?)
 }
 fn snapshot(bytes:&[u8],expected:&str,identity:&AppContainerSid,maximum:usize)->io::Result<Self>{
  Self::snapshot_in(bytes,expected,identity,maximum,temporary_directory()?)
 }
 fn snapshot_in(bytes:&[u8],expected:&str,identity:&AppContainerSid,maximum:usize,temporary:PathBuf)->io::Result<Self>{
  if bytes.len()>maximum||format!("sha256:{:x}",Sha256::digest(bytes))!=expected{return Err(invalid("native snapshot hash or size differs"));}
  validate_bounded(bytes,maximum)?;
  let descriptor=security(identity,false)?;
  let attributes=SECURITY_ATTRIBUTES{nLength:std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,lpSecurityDescriptor:descriptor.0,bInheritHandle:0};
  let mut random=[0u8;24];getrandom::fill(&mut random).map_err(|error|io::Error::other(format!("snapshot entropy: {error}")))?;
  let mut parents=crate::windows_filesystem::Broker::default();parents.add_root(&temporary,true,false)?;
  let name=random.iter().map(|b|format!("{b:02x}")).collect::<String>();let directory=temporary.join(format!("kelft-image-{name}"));let path=directory.join("image.exe");
  let wide_directory=wide(directory.as_os_str())?;
  if unsafe{CreateDirectoryW(wide_directory.as_ptr(),&attributes)}==0{return Err(io::Error::last_os_error());}
  let mut image=Self{path,directory,file:None,root:None,inputs:vec![],work:None,scratch:vec![],runtime:maximum==256<<20,_identity:identity.clone(),_parents:parents};
  image.root=Some(fs::OpenOptions::new().access_mode(FILE_READ_ATTRIBUTES).share_mode(FILE_SHARE_READ|FILE_SHARE_WRITE).custom_flags(FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT).open(&image.directory)?);
  let wide_path=wide(image.path.as_os_str())?;
  let handle=unsafe{CreateFileW(wide_path.as_ptr(),0xc0000000,FILE_SHARE_READ,&attributes,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,ptr::null_mut())};
  if handle.is_null()||handle==INVALID_HANDLE_VALUE{return Err(io::Error::last_os_error());}
  {let mut file=unsafe{File::from_raw_handle(handle)};file.write_all(bytes)?;file.sync_all()?;}
  let mut file=fs::OpenOptions::new().read(true).share_mode(FILE_SHARE_READ).custom_flags(FILE_FLAG_OPEN_REPARSE_POINT).open(&image.path)?;
  if file.metadata()?.file_attributes()&FILE_ATTRIBUTE_REPARSE_POINT!=0{return Err(invalid("snapshot image became a reparse point"));}
  let mut snapshot=vec![];Read::by_ref(&mut file).take((maximum+1) as u64).read_to_end(&mut snapshot)?;
  if snapshot!=bytes{return Err(invalid("snapshot image changed"));}image.file=Some(file);Ok(image)
 }
 pub fn path(&self)->&Path{&self.path}
 pub fn directory(&self)->&Path{&self.directory}
 pub(crate) fn is_runtime(&self)->bool{self.runtime}
 pub fn runtime_input(&mut self,name:&str,bytes:&[u8],expected:&str)->io::Result<PathBuf>{if !self.runtime{return Err(invalid("runtime support requires an explicit runtime snapshot"));}self.support(name,bytes,expected)}
 pub(crate) fn scratch_directory(&self)->&Path{self.work.as_ref().map_or(&self.directory,|(path,_)|path)}
 /// GetTempPath in an AppContainer redirects under LOCALAPPDATA using its
 /// moniker. Prepare exactly that bounded path inside the linker workspace.
 pub(crate) fn linker_scratch(&mut self)->io::Result<()>{
  if !self.scratch.is_empty(){return Ok(());}let mut path=self.work_directory()?;
  for name in ["Packages".to_string(),self._identity.moniker()?,"AC".into(),"Temp".into()]{
   path.push(name);let descriptor=security(&self._identity,true)?;let attributes=SECURITY_ATTRIBUTES{nLength:std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,lpSecurityDescriptor:descriptor.0,bInheritHandle:0};let encoded=wide(path.as_os_str())?;
   if unsafe{CreateDirectoryW(encoded.as_ptr(),&attributes)}==0{return Err(io::Error::last_os_error());}
   let pin=fs::OpenOptions::new().access_mode(FILE_READ_ATTRIBUTES).share_mode(FILE_SHARE_READ|FILE_SHARE_WRITE).custom_flags(FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT).open(&path)?;self.scratch.push((path.clone(),pin));
  }Ok(())
 }
 /// Parent-only immutable linker inputs. Workers cannot add or replace them.
 pub(crate) fn support(&mut self,name:&str,bytes:&[u8],expected:&str)->io::Result<PathBuf>{
  let device=name.split('.').next().unwrap_or("").to_ascii_uppercase();if matches!(device.as_str(),"CON"|"PRN"|"AUX"|"NUL")||(device.starts_with("COM")||device.starts_with("LPT"))&&device.len()==4&&matches!(device.as_bytes()[3],b'1'..=b'9'){return Err(invalid("device names cannot be linker inputs"));}
  if name.is_empty()||name.len()>96||!name.bytes().all(|c|c.is_ascii_alphanumeric()||matches!(c,b'.'|b'_'|b'-'))||name.starts_with('.')||name.ends_with('.')||name.eq_ignore_ascii_case("image.exe")||name.eq_ignore_ascii_case("work")||self.inputs.iter().any(|(p,_)|p.file_name().unwrap().to_string_lossy().eq_ignore_ascii_case(name))||self.inputs.len()>=128||bytes.len()>64<<20||format!("sha256:{:x}",Sha256::digest(bytes))!=expected{return Err(invalid("invalid private linker input"));}
  let path=self.directory.join(name);let descriptor=security(&self._identity,false)?;let attributes=SECURITY_ATTRIBUTES{nLength:std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,lpSecurityDescriptor:descriptor.0,bInheritHandle:0};let wide_path=wide(path.as_os_str())?;
  let raw=unsafe{CreateFileW(wide_path.as_ptr(),0xc0000000,FILE_SHARE_READ,&attributes,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,ptr::null_mut())};if raw.is_null()||raw==INVALID_HANDLE_VALUE{return Err(io::Error::last_os_error());}
  {let mut file=unsafe{File::from_raw_handle(raw)};file.write_all(bytes)?;file.sync_all()?;}
  let mut file=fs::OpenOptions::new().read(true).share_mode(FILE_SHARE_READ).custom_flags(FILE_FLAG_OPEN_REPARSE_POINT).open(&path)?;let mut observed=vec![];Read::by_ref(&mut file).take((64<<20)+1).read_to_end(&mut observed)?;if observed!=bytes{return Err(invalid("private linker input changed"));}self.inputs.push((path.clone(),file));Ok(path)
 }
 /// Only a dedicated linker role receives a writable private output directory.
 pub(crate) fn work_directory(&mut self)->io::Result<PathBuf>{
  if let Some((path,_))=&self.work{return Ok(path.clone());}
  let path=self.directory.join("work");let descriptor=security(&self._identity,true)?;let attributes=SECURITY_ATTRIBUTES{nLength:std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,lpSecurityDescriptor:descriptor.0,bInheritHandle:0};let name=wide(path.as_os_str())?;
  if unsafe{CreateDirectoryW(name.as_ptr(),&attributes)}==0{return Err(io::Error::last_os_error());}
  let pin=fs::OpenOptions::new().access_mode(FILE_READ_DATA|FILE_READ_ATTRIBUTES).share_mode(FILE_SHARE_READ|FILE_SHARE_WRITE).custom_flags(FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT).open(&path)?;self.work=Some((path.clone(),pin));Ok(path)
 }
}
impl Drop for Image {fn drop(&mut self){
 for(path,pin)in self.scratch.drain(..).rev(){drop(pin);if let Ok(entries)=fs::read_dir(&path){for entry in entries.take(512).flatten(){let _=fs::remove_file(entry.path());}}let _=fs::remove_dir(path);}
 if let Some((path,pin))=self.work.take(){drop(pin);if let Ok(entries)=fs::read_dir(&path){for entry in entries.take(512).flatten(){let p=entry.path();if let Ok(metadata)=fs::symlink_metadata(&p){if metadata.is_dir(){let _=fs::remove_dir(p);}else{let _=fs::remove_file(p);}}}}let _=fs::remove_dir(path);}
 for(path,file)in self.inputs.drain(..){drop(file);let _=fs::remove_file(path);}drop(self.file.take());drop(self.root.take());let _=fs::remove_file(&self.path);let _=fs::remove_dir(&self.directory);
}}
#[cfg(test)]mod tests {
 use super::*;
 #[test]fn optional_runtime_size_does_not_relax_compiler_or_program_image_validation(){
  let mut bytes=fs::read(std::env::current_exe().unwrap()).unwrap();bytes.resize((64<<20)+1,0);assert!(validate(&bytes).is_err());validate_bounded(&bytes,256<<20).unwrap();assert!(validate_bounded(&bytes,64<<20).is_err());let at=u32::from_le_bytes(bytes[60..64].try_into().unwrap())as usize;bytes[at+4..at+6].copy_from_slice(&(if cfg!(target_arch="aarch64"){0x8664u16}else{0xaa64}).to_le_bytes());assert!(validate_bounded(&bytes,256<<20).is_err());
 }
 #[test]fn private_clear_environment_snapshot_worker(){
  if std::env::var("KELFT_CLEAR_ENV_SNAPSHOT_PROBE").as_deref()!=Ok("1"){return;}
  for name in ["TEMP","TMP","USERPROFILE","LOCALAPPDATA","SystemRoot"]{assert!(std::env::var_os(name).is_none());}
  assert!(cross_linker_storage().unwrap().is_dir());
  let mut buffer=[0u16;32768];let n=unsafe{windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW(buffer.as_mut_ptr(),buffer.len() as u32)} as usize;assert!(n>0&&n<buffer.len());let system=String::from_utf16(&buffer[..n]).unwrap();let bytes=fs::read(Path::new(&system).join("System32/cmd.exe")).unwrap();let digest=format!("sha256:{:x}",Sha256::digest(&bytes));let identity=AppContainerSid::fresh().unwrap();let image=Image::new(&bytes,&digest,&identity).unwrap();assert_eq!(image.directory().parent(),Some(temporary_directory().unwrap().as_path()));
  let args=["/d","/q","/c","exit /b 42"].map(String::from);let result=crate::windows_supervisor::run(&image,&identity,&system,&args,crate::windows_supervisor::Limits{wall_ms:10000,memory_bytes:268435456,output_bytes:65536},&[],vec![]).unwrap();assert_eq!(result.exit,Some(42),"{:?}",result.failure);assert!(result.failure.is_none());println!("clear-environment-native-snapshot-ok");
 }
 #[test]fn native_private_snapshots_work_without_an_ambient_profile_or_temp_environment(){
  let output=std::process::Command::new(std::env::current_exe().unwrap()).args(["--exact","windows_snapshot::tests::private_clear_environment_snapshot_worker","--nocapture"]).env_clear().env("KELFT_CLEAR_ENV_SNAPSHOT_PROBE","1").output().unwrap();assert!(output.status.success(),"{}{}",String::from_utf8_lossy(&output.stdout),String::from_utf8_lossy(&output.stderr));assert!(String::from_utf8_lossy(&output.stdout).contains("clear-environment-native-snapshot-ok"));
 }
 #[test]fn private_linker_workspace_worker(){
  if std::env::var("KELFT_LINKER_WORKSPACE_PROBE").as_deref()!=Ok("1"){return;}
  assert_eq!(fs::read("input.dat").unwrap(),b"pinned-linker-input");fs::write("work/copy.bin",b"pinned-linker-input").unwrap();assert!(fs::write("input.dat",b"changed").is_err());println!("private-linker-workspace-ok");
 }
 #[test]fn private_linker_role_worker(){
  if std::env::var("KELFT_LINKER_ROLE_PROBE").as_deref()!=Ok("1"){return;}
  #[link(name="advapi32")]unsafe extern "system"{fn RegOpenKeyExW(key:*mut std::ffi::c_void,name:*const u16,options:u32,access:u32,result:*mut *mut std::ffi::c_void)->i32;fn RegCloseKey(key:*mut std::ffi::c_void)->i32;}
  #[link(name="kernel32")]unsafe extern "system"{fn GetTempPathW(length:u32,buffer:*mut u16)->u32;}
  let name:Vec<u16>="SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\SideBySide".encode_utf16().chain([0]).collect();
  let registry=|access|{let mut key=ptr::null_mut();let result=unsafe{RegOpenKeyExW(0x80000002u32 as i32 as isize as *mut _,name.as_ptr(),0,access,&mut key)};if !key.is_null(){unsafe{RegCloseKey(key)};}result};
  let expected=std::env::var("KELFT_LINKER_ROLE_EXPECT").unwrap();assert_eq!(registry(0x20019)==0,expected=="registryRead");assert_ne!(registry(2),0,"registry writes must remain denied");
  assert!(fs::read(std::env::var("KELFT_LINKER_ROLE_OUTSIDE").unwrap()).is_err());
  assert!(std::process::Command::new(PathBuf::from(std::env::var("SystemRoot").unwrap()).join("System32/cmd.exe")).args(["/d","/q","/c","exit /b 0"]).spawn().is_err(),"linker job must forbid subprocesses");
  if expected=="registryRead"{let mut buffer=vec![0u16;32768];let length=unsafe{GetTempPathW(buffer.len() as u32,buffer.as_mut_ptr())} as usize;assert!(length>0&&length<buffer.len());let temporary=PathBuf::from(String::from_utf16(&buffer[..length]).unwrap());assert!(temporary.starts_with(std::env::var("LOCALAPPDATA").unwrap()));let file=temporary.join("bounded-probe.tmp");fs::write(&file,b"linker-temp").unwrap();assert_eq!(fs::read(&file).unwrap(),b"linker-temp");fs::remove_file(file).unwrap();}
  println!("linker-role-authority-ok {expected}");
 }
 #[test]fn native_linker_registry_and_temp_authority_stays_separate_from_workers(){
  let system=std::env::var("SystemRoot").unwrap();let bytes=fs::read(std::env::current_exe().unwrap()).unwrap();let digest=format!("sha256:{:x}",Sha256::digest(&bytes));
  let outside=std::env::temp_dir().join(format!("kelft-linker-role-outside-{}",std::process::id()));fs::write(&outside,b"must-not-reach-worker").unwrap();
  for linker in [false,true]{let identity=if linker{AppContainerSid::fresh_linker()}else{AppContainerSid::fresh()}.unwrap();let directory;
   {let mut image=Image::new(&bytes,&digest,&identity).unwrap();directory=image.directory().to_path_buf();if linker{image.linker_scratch().unwrap();}
    let args=["--exact","windows_snapshot::tests::private_linker_role_worker","--nocapture"].map(String::from);let env=[("KELFT_LINKER_ROLE_PROBE".into(),"1".into()),("KELFT_LINKER_ROLE_EXPECT".into(),if linker{"registryRead"}else{"none"}.into()),("KELFT_LINKER_ROLE_OUTSIDE".into(),outside.to_str().unwrap().into())];
    let result=crate::windows_supervisor::run(&image,&identity,&system,&args,crate::windows_supervisor::Limits{wall_ms:10000,memory_bytes:268435456,output_bytes:65536},&env,vec![]).unwrap();assert_eq!(result.exit,Some(0),"{:?}: {}{}",result.failure,String::from_utf8_lossy(&result.stdout),String::from_utf8_lossy(&result.stderr));assert!(String::from_utf8_lossy(&result.stdout).contains("linker-role-authority-ok"));
   }assert!(!directory.exists(),"linker scratch hierarchy must be cleaned up");
  }fs::remove_file(outside).unwrap();
 }
 #[test]fn native_linker_workspace_reads_pinned_inputs_and_writes_only_private_outputs(){
  let identity=AppContainerSid::fresh().unwrap();let system=std::env::var("SystemRoot").unwrap();let bytes=fs::read(std::env::current_exe().unwrap()).unwrap();let digest=format!("sha256:{:x}",Sha256::digest(&bytes));let directory;
  {let mut image=Image::new(&bytes,&digest,&identity).unwrap();directory=image.directory().to_path_buf();let input=b"pinned-linker-input";let input_hash=format!("sha256:{:x}",Sha256::digest(input));let source=image.support("input.dat",input,&input_hash).unwrap();assert!(image.support("NUL.dll",input,&input_hash).is_err());let work=image.work_directory().unwrap();
   let args=["--exact","windows_snapshot::tests::private_linker_workspace_worker","--nocapture"].map(String::from);let env=[("KELFT_LINKER_WORKSPACE_PROBE".into(),"1".into())];
   let result=crate::windows_supervisor::run(&image,&identity,&system,&args,crate::windows_supervisor::Limits{wall_ms:10000,memory_bytes:268435456,output_bytes:65536},&env,vec![]).unwrap();assert_eq!(result.exit,Some(0),"{:?}: {}{}",result.failure,String::from_utf8_lossy(&result.stdout),String::from_utf8_lossy(&result.stderr));assert_eq!(fs::read(source).unwrap(),input);assert_eq!(fs::read(work.join("copy.bin")).unwrap(),input);
  }assert!(!directory.exists(),"private linker workspace must be cleaned up");
 }
 #[test]fn native_snapshot_locks_verified_bytes_and_cleans_up(){
  let identity=AppContainerSid::fresh().unwrap();let source=PathBuf::from(std::env::var("SystemRoot").unwrap()).join("System32/cmd.exe");let bytes=fs::read(source).unwrap();let digest=format!("sha256:{:x}",Sha256::digest(&bytes));
  let path;let directory;{let image=Image::new(&bytes,&digest,&identity).unwrap();path=image.path.clone();directory=image.directory.clone();assert_eq!(fs::read(&path).unwrap(),bytes);assert!(fs::write(&path,b"substitution").is_err());assert!(fs::rename(&directory,directory.with_extension("changed")).is_err());}
  assert!(!path.exists());assert!(!directory.exists());assert!(Image::new(&bytes,"sha256:wrong",&identity).is_err());
  let optional=u32::from_le_bytes(bytes[60..64].try_into().unwrap()) as usize+24;
  for(reserve,commit)in [(16_777_217u64,65536u64),(1048576,1048577),(0,0)]{let mut changed=bytes.clone();changed[optional+72..optional+80].copy_from_slice(&reserve.to_le_bytes());changed[optional+80..optional+88].copy_from_slice(&commit.to_le_bytes());let digest=format!("sha256:{:x}",Sha256::digest(&changed));assert!(Image::new(&changed,&digest,&identity).is_err());}
 }
 #[test]fn private_cross_linker_path_worker(){
  if std::env::var("KELFT_CROSS_PATH_PROBE").as_deref()!=Ok("1"){return;}
  #[link(name="kernel32")]unsafe extern "system"{fn GetModuleFileNameW(module:*mut std::ffi::c_void,file:*mut u16,size:u32)->u32;}
  let mut file=[0u16;32768];let n=unsafe{GetModuleFileNameW(ptr::null_mut(),file.as_mut_ptr(),file.len() as u32)} as usize;
  assert!(n>0&&n<file.len());let mut long=[0u16;32768];
  let n=unsafe{GetLongPathNameW(file.as_ptr(),long.as_mut_ptr(),long.len() as u32)} as usize;
  assert!(n>0&&n<long.len(),"LLVM startup path expansion: {}",io::Error::last_os_error());println!("cross-tool-long-path-ok");
 }
 #[test]fn cross_tool_storage_preserves_confinement_and_is_excluded_from_user_grants(){
  let system=std::env::var("SystemRoot").unwrap();let bytes=fs::read(std::env::current_exe().unwrap()).unwrap();let digest=format!("sha256:{:x}",Sha256::digest(&bytes));let identity=AppContainerSid::fresh().unwrap();
  let outside=temporary_directory().unwrap().join(format!("cross-outside-{}",std::process::id()));fs::write(&outside,b"private-user-data").unwrap();let directory;
  {let mut image=Image::cross_linker(&bytes,&digest,&identity).unwrap();directory=image.directory().to_path_buf();
   assert!(cross_linker_storage_overlap(directory.parent().unwrap()).unwrap());assert!(cross_linker_storage_overlap(&directory).unwrap());assert!(cross_linker_storage_overlap(&directory.join("work")).unwrap());
   assert!(!cross_linker_storage_overlap(&directory.parent().unwrap().join("ordinary-project")).unwrap());
   let input=b"pinned-linker-input";image.support("input.dat",input,&format!("sha256:{:x}",Sha256::digest(input))).unwrap();image.work_directory().unwrap();
   let limits=crate::windows_supervisor::Limits{wall_ms:10000,memory_bytes:268435456,output_bytes:65536};
   for (worker,env) in [
    ("private_cross_linker_path_worker",vec![("KELFT_CROSS_PATH_PROBE".into(),"1".into())]),
    ("private_linker_workspace_worker",vec![("KELFT_LINKER_WORKSPACE_PROBE".into(),"1".into())]),
    ("private_linker_role_worker",vec![("KELFT_LINKER_ROLE_PROBE".into(),"1".into()),("KELFT_LINKER_ROLE_EXPECT".into(),"none".into()),("KELFT_LINKER_ROLE_OUTSIDE".into(),outside.to_str().unwrap().into())])]{
    let args=vec!["--exact".into(),format!("windows_snapshot::tests::{worker}"),"--nocapture".into()];
    let result=crate::windows_supervisor::run(&image,&identity,&system,&args,limits,&env,vec![]).unwrap();
    assert_eq!(result.exit,Some(0),"{:?}: {}{}",result.failure,String::from_utf8_lossy(&result.stdout),String::from_utf8_lossy(&result.stderr));
   }
  }assert!(!directory.exists());fs::remove_file(outside).unwrap();
 }
}
