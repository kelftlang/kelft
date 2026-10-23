//! Private Windows x64/ARM64 process boundary. Filesystem authorization and
//! artifact/linker identity remain separate broker responsibilities. There is
//! no unrestricted-token fallback and no ambient environment inheritance.
use std::{io,mem,ptr,sync::Arc,time::{Duration,Instant}};
use windows_sys::Win32::{
 Foundation::{CloseHandle,DuplicateHandle,GetHandleInformation,GetLastError,SetLastError,HANDLE,HANDLE_FLAG_INHERIT,INVALID_HANDLE_VALUE,DUPLICATE_SAME_ACCESS,ERROR_INSUFFICIENT_BUFFER,ERROR_INVALID_DATA},
 Security::{self,PSID,SECURITY_CAPABILITIES},
 Storage::FileSystem::{GetFileType,FILE_TYPE_PIPE,FILE_TYPE_CHAR},
 System::{JobObjects::*,Threading::*,SystemServices::{SECURITY_APP_PACKAGE_BASE_RID,SECURITY_APP_PACKAGE_RID_COUNT},WindowsProgramming::PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT},
};
fn invalid(message:&'static str)->io::Error {io::Error::new(io::ErrorKind::InvalidInput,message)}
fn os_error()->io::Error {let code=unsafe{GetLastError()};io::Error::from_raw_os_error(if code==0{ERROR_INVALID_DATA}else{code} as i32)}
fn wide(value:&str)->io::Result<Vec<u16>> {
 if value.contains('\0'){return Err(invalid("NUL in worker argument"));}
 let mut out:Vec<u16>=value.encode_utf16().collect();if out.len()>=32767{return Err(invalid("worker argument exceeds Windows bound"));}out.push(0);Ok(out)
}
fn absolute(value:&str)->bool {let b=value.as_bytes();b.len()>=3&&b[0].is_ascii_alphabetic()&&b[1]==b':'&&b[2]==b'\\'}
/// Windows lowbox startup requires SystemRoot and LOCALAPPDATA even when the
/// worker never reads them. The private scratch path grants no filesystem
/// authority by itself; access still requires the LPAC token and broker.
pub fn environment(system_root:&str,private_scratch:&str)->io::Result<Vec<u16>> {
 if !absolute(system_root)||!absolute(private_scratch){return Err(invalid("absolute Windows system and scratch roots required"));}
 let mut result=Vec::new();
 for (name,value) in [("LOCALAPPDATA",private_scratch),("SystemDrive",&system_root[..2]),("SystemRoot",system_root),("TEMP",private_scratch),("TMP",private_scratch),("windir",system_root)] {
  result.extend(wide(&format!("{name}={value}"))?);
 }result.push(0);Ok(result)
}
struct OwnedHandle(HANDLE);
impl OwnedHandle {
 unsafe fn take(raw:HANDLE)->io::Result<Self>{if raw.is_null()||raw==INVALID_HANDLE_VALUE{Err(os_error())}else{Ok(Self(raw))}}
 unsafe fn inheritable_duplicate(raw:HANDLE)->io::Result<Self>{
  let mut duplicate=ptr::null_mut();
  if unsafe{DuplicateHandle(GetCurrentProcess(),raw,GetCurrentProcess(),&mut duplicate,0,1,DUPLICATE_SAME_ACCESS)}==0{return Err(os_error());}
  unsafe{Self::take(duplicate)}
 }
}
impl Drop for OwnedHandle {fn drop(&mut self){unsafe{CloseHandle(self.0);}}}
/// A random, process-specific package identity. Ordinary workers have no capabilities.
/// A fresh temporary profile is retained until its worker has terminated. It
/// grants no capabilities or project ACLs and is never reused across workers.
#[derive(Clone)]
pub struct AppContainerSid(Arc<Identity>);
struct Identity {sid:PSID,profile:Option<Vec<u16>>,registry_read:Option<Capability>}
struct Capability(PSID);
impl Drop for Capability{fn drop(&mut self){unsafe{windows_sys::Win32::Foundation::LocalFree(self.0);}}}
impl AppContainerSid {
 pub fn moniker(&self)->io::Result<String>{let name=self.0.profile.as_ref().ok_or_else(||invalid("private profile required"))?;String::from_utf16(&name[..name.len()-1]).map_err(|_|invalid("invalid private profile moniker"))}
 /// Only the measured SDK linker uses this role. The loader needs read access
 /// to system SxS registry state; compiler and candidate identities never do.
 pub(crate) fn fresh_linker()->io::Result<Self>{
  Self::fresh_registry_reader()
 }
 /// An explicit optional runtime may read the system loader/provider catalog.
 /// This confers no network, compiler, project or transaction authority.
 pub fn fresh_engine()->io::Result<Self>{Self::fresh_registry_reader()}
 fn fresh_registry_reader()->io::Result<Self>{
  let mut identity=Self::fresh()?;let name=wide("registryRead")?;
  let(mut groups,mut capabilities)=(ptr::null_mut(),ptr::null_mut());let(mut group_count,mut count)=(0,0);
  let ok=unsafe{Security::DeriveCapabilitySidsFromName(name.as_ptr(),&mut groups,&mut group_count,&mut capabilities,&mut count)};
  let error=if ok==0{Some(os_error())}else{None};
  // Windows allocates both arrays and each SID with LocalAlloc. Retain exactly
  // one capability SID; every other allocation is freed on success and failure.
  let mut retained=None;
  unsafe{
   if !groups.is_null(){for i in 0..group_count{windows_sys::Win32::Foundation::LocalFree(*groups.add(i as usize));}windows_sys::Win32::Foundation::LocalFree(groups.cast());}
   if !capabilities.is_null(){for i in 0..count{let sid=*capabilities.add(i as usize);if ok!=0&&count==1&&!sid.is_null()&&Security::IsValidSid(sid)!=0{retained=Some(Capability(sid));}else{windows_sys::Win32::Foundation::LocalFree(sid);}}windows_sys::Win32::Foundation::LocalFree(capabilities.cast());}
  }
  if let Some(error)=error{return Err(error);}let capability=retained.ok_or_else(||invalid("missing native registry-read capability"))?;
  Arc::get_mut(&mut identity.0).unwrap().registry_read=Some(capability);Ok(identity)
 }
 pub fn sddl(&self)->io::Result<String>{
  let mut text=ptr::null_mut();if unsafe{Security::Authorization::ConvertSidToStringSidW(self.0.sid,&mut text)}==0{return Err(os_error());}
  let result=(||{let mut length=0;while length<256&&unsafe{*text.add(length)}!=0{length+=1;}if length==256{return Err(invalid("AppContainer SID string exceeds bound"));}String::from_utf16(unsafe{std::slice::from_raw_parts(text,length)}).map_err(|_|invalid("invalid SID string"))})();
  unsafe{windows_sys::Win32::Foundation::LocalFree(text.cast());}result
 }
 /// Never reuse a package identity that could carry an earlier profile's ACLs
 /// or storage authority. Entropy failure is fatal; no PID/time fallback.
 pub fn fresh()->io::Result<Self>{
  // Windows profile monikers are limited to 64 characters. Keep 224 bits of
  // entropy while fitting the six-character prefix and hexadecimal encoding.
  let mut random=[0u8;28];getrandom::fill(&mut random).map_err(|error|io::Error::other(format!("private AppContainer entropy: {error}")))?;
  let mut name=String::from("kelft-");
  for byte in random {use std::fmt::Write;write!(&mut name,"{byte:02x}").unwrap();}
  let mut identity=Self::derive(&name)?;let name=wide(&name)?;let mut created=ptr::null_mut();
  let result=unsafe{Security::Isolation::CreateAppContainerProfile(name.as_ptr(),name.as_ptr(),name.as_ptr(),ptr::null(),0,&mut created)};
  if result!=0{if !created.is_null(){unsafe{Security::FreeSid(created);}}return Err(io::Error::other(format!("create private AppContainer profile: HRESULT {result:#010x}")));}
  Arc::get_mut(&mut identity.0).unwrap().profile=Some(name);
  if created.is_null(){return Err(invalid("missing created AppContainer identity"));}
  let matches=unsafe{Security::EqualSid(created,identity.0.sid)}!=0;unsafe{Security::FreeSid(created);}
  if !matches{return Err(invalid("created AppContainer identity differs"));}Ok(identity)
 }
 fn derive(name:&str)->io::Result<Self>{
  if !name.starts_with("kelft-")||name.len()>64||!name.bytes().all(|c|c.is_ascii_alphanumeric()||c==b'-'){return Err(invalid("private AppContainer name required"));}
  let name=wide(name)?;let mut raw=ptr::null_mut();
  let status=unsafe{Security::Isolation::DeriveAppContainerSidFromAppContainerName(name.as_ptr(),&mut raw)};
  if status!=0{if !raw.is_null(){unsafe{Security::FreeSid(raw);}}return Err(io::Error::other(format!("derive AppContainer identity: HRESULT {status:#010x}")));}
  if raw.is_null(){return Err(invalid("missing AppContainer identity"));}
  let sid=Self(Arc::new(Identity{sid:raw,profile:None,registry_read:None}));
  if unsafe{Security::IsValidSid(raw)}==0||unsafe{*Security::GetSidSubAuthorityCount(raw)}!=SECURITY_APP_PACKAGE_RID_COUNT as u8{return Err(invalid("invalid AppContainer identity"));}
  let authority=unsafe{&*Security::GetSidIdentifierAuthority(raw)};
  if authority.Value!=[0,0,0,0,0,15]||unsafe{*Security::GetSidSubAuthority(raw,0)}!=SECURITY_APP_PACKAGE_BASE_RID as u32{return Err(invalid("unexpected AppContainer authority"));}
  Ok(sid)
 }
}
impl Drop for Identity {fn drop(&mut self){unsafe{Security::FreeSid(self.sid);if let Some(name)=&self.profile{Security::Isolation::DeleteAppContainerProfile(name.as_ptr());}}}}
#[repr(C,align(16))]
#[derive(Clone,Copy)]
struct AttributeStorage([u8;16]);
struct Attributes {memory:Vec<AttributeStorage>,initialized:bool}
impl Attributes {
 fn new()->io::Result<Self>{
  let mut size=0;unsafe{SetLastError(0)};
  if unsafe{InitializeProcThreadAttributeList(ptr::null_mut(),4,0,&mut size)}!=0||unsafe{GetLastError()}!=ERROR_INSUFFICIENT_BUFFER||size==0||size>65536{return Err(invalid("invalid native startup attribute size"));}
  let mut list=Self{memory:vec![AttributeStorage([0;16]);size.div_ceil(mem::size_of::<AttributeStorage>())],initialized:false};
  if unsafe{InitializeProcThreadAttributeList(list.raw(),4,0,&mut size)}==0{return Err(os_error());}list.initialized=true;Ok(list)
 }
 fn raw(&mut self)->LPPROC_THREAD_ATTRIBUTE_LIST {self.memory.as_mut_ptr().cast()}
 unsafe fn set(&mut self,kind:u32,data:*const std::ffi::c_void,size:usize)->io::Result<()> {
  if unsafe{UpdateProcThreadAttribute(self.raw(),0,kind as usize,data,size,ptr::null_mut(),ptr::null())}==0{return Err(os_error());}Ok(())
 }
}
impl Drop for Attributes {fn drop(&mut self){if self.initialized{unsafe{DeleteProcThreadAttributeList(self.raw());}}}}
struct Job(OwnedHandle);
impl Drop for Job {fn drop(&mut self){unsafe{TerminateJobObject(self.0.0,125);}}}
fn pipe(raw:HANDLE,inheritable:bool)->bool{
 let mut flags=0;
 !raw.is_null()&&raw!=INVALID_HANDLE_VALUE&&unsafe{GetHandleInformation(raw,&mut flags)}!=0&&(!inheritable||flags&HANDLE_FLAG_INHERIT!=0)&&unsafe{GetFileType(raw)}==FILE_TYPE_PIPE
}
/// Borrowed pipe ends must remain valid through `start`; afterwards the parent
/// closes its copies of the child ends so pipe EOF remains observable. Extra ends already
/// have direction-limited access and HANDLE_FLAG_INHERIT; the exact handle list
/// excludes every other inheritable handle, including the job and broker keys.
pub struct Spawn<'a> {
 pub image:&'a str,pub command_line:&'a str,pub directory:&'a str,pub environment:&'a [u16],
 pub input:HANDLE,pub output:HANDLE,pub error:HANDLE,pub controls:&'a [HANDLE],pub identity:&'a AppContainerSid,
 pub memory_bytes:usize,pub timeout_ms:u32,
}
pub struct PausedWorker {job:Job,process:OwnedHandle,thread:OwnedHandle,pid:u32,started:Instant,timeout:Duration,active_limit:u32,_identity:AppContainerSid}
pub struct RunningWorker {job:Job,process:OwnedHandle,pid:u32,started:Instant,timeout:Duration,timed_out:bool,active_limit:u32,_identity:AppContainerSid}
#[derive(Debug,serde::Serialize)]
pub struct Usage {pub elapsed_ms:u64,pub active_process_limit:u32,pub peak_process_memory_bytes:usize,pub peak_job_memory_bytes:usize,pub process_commit_limit_bytes:usize,pub job_commit_limit_bytes:usize,pub user_cpu_100ns:u64,pub kernel_cpu_100ns:u64}
impl Spawn<'_> {
 /// The selected image and all parent directories are authenticated and held
 /// against write/delete by the outer artifact broker before this call.
 pub unsafe fn start(&self)->io::Result<PausedWorker>{
  unsafe{self.start_with_packages_policy(PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT)}
 }
 /// Trusted installed coordinator only. Caller must hold the attested package
 /// image and validate project/output arguments before selecting this role.
 pub(crate) unsafe fn start_installed(&self)->io::Result<PausedWorker>{unsafe{self.start_role(PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT,true)}}
 unsafe fn start_with_packages_policy(&self,packages:u32)->io::Result<PausedWorker>{
  unsafe{self.start_role(packages,false)}
 }
 unsafe fn start_role(&self,packages:u32,installed:bool)->io::Result<PausedWorker>{
  if !absolute(self.image)||!absolute(self.directory)||self.command_line.is_empty()||self.controls.len()>4||!(16777216..=1073741824).contains(&self.memory_bytes)||!(1..=600000).contains(&self.timeout_ms){return Err(invalid("invalid native worker request"));}
  if self.environment.len()<2||self.environment.len()>524288||!self.environment.ends_with(&[0,0])||self.environment[..self.environment.len()-1].windows(2).any(|s|s==[0,0]){return Err(invalid("explicit terminated native environment required"));}
  if !pipe(self.output,false)||!pipe(self.error,false)||self.controls.iter().any(|&h|!pipe(h,true)){return Err(invalid("native pipe handle required"));}
  if self.input.is_null()||self.input==INVALID_HANDLE_VALUE||![FILE_TYPE_PIPE,FILE_TYPE_CHAR].contains(&unsafe{GetFileType(self.input)}){return Err(invalid("private pipe or NUL input required"));}
  let image=wide(self.image)?;let directory=wide(self.directory)?;let mut command=wide(self.command_line)?;
  let job=Job(unsafe{OwnedHandle::take(CreateJobObjectW(ptr::null(),ptr::null()))}?);
  let mut limits=JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
  limits.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE|JOB_OBJECT_LIMIT_ACTIVE_PROCESS|JOB_OBJECT_LIMIT_PROCESS_MEMORY|JOB_OBJECT_LIMIT_JOB_MEMORY|JOB_OBJECT_LIMIT_PROCESS_TIME;
  limits.BasicLimitInformation.ActiveProcessLimit=if installed{128}else{1};limits.BasicLimitInformation.PerProcessUserTimeLimit=self.timeout_ms as i64*10000;
  limits.ProcessMemoryLimit=self.memory_bytes;limits.JobMemoryLimit=self.memory_bytes;
  if unsafe{SetInformationJobObject(job.0.0,JobObjectExtendedLimitInformation,(&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),mem::size_of_val(&limits) as u32)}==0{return Err(os_error());}
  let stdio=[unsafe{OwnedHandle::inheritable_duplicate(self.input)}?,unsafe{OwnedHandle::inheritable_duplicate(self.output)}?,unsafe{OwnedHandle::inheritable_duplicate(self.error)}?];
  let mut inherited:Vec<HANDLE>=stdio.iter().map(|h|h.0).collect();inherited.extend_from_slice(self.controls);
  let mut grants:Vec<Security::SID_AND_ATTRIBUTES>=self.identity.0.registry_read.as_ref().map(|capability|Security::SID_AND_ATTRIBUTES{Sid:capability.0,Attributes:windows_sys::Win32::System::SystemServices::SE_GROUP_ENABLED as u32}).into_iter().collect();
  let capabilities=SECURITY_CAPABILITIES{AppContainerSid:self.identity.0.sid,Capabilities:if grants.is_empty(){ptr::null_mut()}else{grants.as_mut_ptr()},CapabilityCount:grants.len() as u32,Reserved:0};
  let mut attributes=Attributes::new()?;
  // JOB_LIST assigns the job inside CreateProcess. A parent death cannot leave
  // a paused process between process creation and separate job assignment.
  unsafe{
   attributes.set(PROC_THREAD_ATTRIBUTE_JOB_LIST,(&job.0.0 as *const HANDLE).cast(),mem::size_of::<HANDLE>())?;
   attributes.set(PROC_THREAD_ATTRIBUTE_HANDLE_LIST,inherited.as_ptr().cast(),mem::size_of_val(inherited.as_slice()))?;
   if !installed{attributes.set(PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,(&capabilities as *const SECURITY_CAPABILITIES).cast(),mem::size_of_val(&capabilities))?;
   attributes.set(PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,(&packages as *const u32).cast(),mem::size_of_val(&packages))?;}
  }
  let mut startup=STARTUPINFOEXW::default();startup.StartupInfo.cb=mem::size_of::<STARTUPINFOEXW>() as u32;startup.StartupInfo.dwFlags=STARTF_USESTDHANDLES;
  startup.StartupInfo.hStdInput=stdio[0].0;startup.StartupInfo.hStdOutput=stdio[1].0;startup.StartupInfo.hStdError=stdio[2].0;startup.lpAttributeList=attributes.raw();
  let mut process=PROCESS_INFORMATION::default();let started=Instant::now();
  if unsafe{CreateProcessW(image.as_ptr(),command.as_mut_ptr(),ptr::null(),ptr::null(),1,CREATE_SUSPENDED|CREATE_NO_WINDOW|CREATE_UNICODE_ENVIRONMENT|EXTENDED_STARTUPINFO_PRESENT,self.environment.as_ptr().cast(),directory.as_ptr(),&startup.StartupInfo,&mut process)}==0{return Err(io::Error::other(format!("CreateProcessW restricted native worker: {}",os_error())));}
  // Own both returned handles before propagating either validation error.
  let process_handle=unsafe{OwnedHandle::take(process.hProcess)};
  let thread=unsafe{OwnedHandle::take(process.hThread)};
  let process_handle=process_handle?;let thread=thread?;
  let worker=PausedWorker{job,process:process_handle,thread,pid:process.dwProcessId,started,timeout:Duration::from_millis(self.timeout_ms as u64),active_limit:if installed{128}else{1},_identity:self.identity.clone()};let mut assigned=0;
  if unsafe{IsProcessInJob(worker.process.0,worker.job.0.0,&mut assigned)}==0{return Err(os_error());}if assigned==0{return Err(invalid("kernel did not assign the native worker job"));}
  Ok(worker)
 }
}
impl PausedWorker {
 pub fn process_id(&self)->u32 {self.pid}
 pub fn resume(self)->io::Result<RunningWorker>{
  let previous=unsafe{ResumeThread(self.thread.0)};if previous!=1{return Err(if previous==u32::MAX{os_error()}else{invalid("native worker suspension count changed")});}
  Ok(RunningWorker{job:self.job,process:self.process,pid:self.pid,started:self.started,timeout:self.timeout,timed_out:false,active_limit:self.active_limit,_identity:self._identity})
 }
}
impl RunningWorker {
 pub fn usage(&self)->io::Result<Usage>{
  let mut memory=JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();let mut accounting=JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
  if unsafe{QueryInformationJobObject(self.job.0.0,JobObjectExtendedLimitInformation,(&mut memory as *mut JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),mem::size_of_val(&memory) as u32,ptr::null_mut())}==0{return Err(os_error());}
  if unsafe{QueryInformationJobObject(self.job.0.0,JobObjectBasicAccountingInformation,(&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),mem::size_of_val(&accounting) as u32,ptr::null_mut())}==0{return Err(os_error());}
  if memory.BasicLimitInformation.LimitFlags&JOB_OBJECT_LIMIT_ACTIVE_PROCESS==0||memory.BasicLimitInformation.ActiveProcessLimit!=self.active_limit{return Err(invalid("native process-count limit missing"));}
  if accounting.TotalUserTime<0||accounting.TotalKernelTime<0{return Err(invalid("invalid native job accounting"));}
  if memory.BasicLimitInformation.LimitFlags&(JOB_OBJECT_LIMIT_PROCESS_MEMORY|JOB_OBJECT_LIMIT_JOB_MEMORY)!=(JOB_OBJECT_LIMIT_PROCESS_MEMORY|JOB_OBJECT_LIMIT_JOB_MEMORY)||memory.ProcessMemoryLimit==0||memory.JobMemoryLimit==0{return Err(invalid("native committed-memory limits missing"));}
  Ok(Usage{active_process_limit:memory.BasicLimitInformation.ActiveProcessLimit,elapsed_ms:self.started.elapsed().as_millis().try_into().map_err(|_|invalid("native elapsed time overflow"))?,peak_process_memory_bytes:memory.PeakProcessMemoryUsed,peak_job_memory_bytes:memory.PeakJobMemoryUsed,process_commit_limit_bytes:memory.ProcessMemoryLimit,job_commit_limit_bytes:memory.JobMemoryLimit,user_cpu_100ns:accounting.TotalUserTime as u64,kernel_cpu_100ns:accounting.TotalKernelTime as u64})
 }
 pub fn process_id(&self)->u32 {self.pid}
 pub fn try_exit(&mut self)->io::Result<Option<u32>>{
  if self.timed_out||self.started.elapsed()>=self.timeout{self.timed_out=true;self.terminate()?;return Err(io::Error::new(io::ErrorKind::TimedOut,"native worker deadline exceeded"));}
  match unsafe{WaitForSingleObject(self.process.0,0)}{
   0=>{let mut status=0;if unsafe{GetExitCodeProcess(self.process.0,&mut status)}==0{return Err(os_error());}Ok(Some(status))},
   258=>Ok(None),_=>Err(os_error()),
  }
 }
 pub fn terminate(&self)->io::Result<()>{if unsafe{TerminateJobObject(self.job.0.0,125)}==0{return Err(os_error());}if unsafe{WaitForSingleObject(self.process.0,5000)}!=0{return Err(io::Error::new(io::ErrorKind::TimedOut,"terminated native worker did not exit"));}Ok(())}
}

#[cfg(test)]
mod tests {
 use super::*;
 use std::fs;
 use windows_sys::Win32::{Foundation::ERROR_BROKEN_PIPE,Storage::FileSystem::{CreateFileW,ReadFile,FILE_GENERIC_READ,FILE_SHARE_READ,FILE_SHARE_WRITE,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL},System::Pipes::CreatePipe};
 #[test]
 fn explicit_windows_strings_are_bounded_before_native_calls(){
  assert_eq!(wide("hé😀").unwrap(),vec![104,233,0xd83d,0xde00,0]);
  assert!(wide("bad\0value").is_err());assert!(wide(&"x".repeat(32767)).is_err());
  assert!(absolute("C:\\project with spaces"));assert!(!absolute("relative"));assert!(!absolute("C:relative"));assert!(!absolute("\\\\server\\share"));
 }
 #[test]
 fn native_sdk_layout_is_64_bit(){
  assert_eq!(mem::size_of::<HANDLE>(),8);assert_eq!(mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>(),144);assert_eq!(mem::size_of::<STARTUPINFOEXW>(),112);
 }
 #[test]
 fn fresh_native_identity_obeys_the_windows_moniker_bound(){
  assert!(AppContainerSid::derive(&format!("kelft-{}","a".repeat(59))).is_err());
  let first=AppContainerSid::fresh().unwrap();let second=AppContainerSid::fresh().unwrap();
  assert_eq!(unsafe{Security::EqualSid(first.0.sid,second.0.sid)},0);
 }
 fn capture_pipe()->io::Result<(OwnedHandle,OwnedHandle)>{
  let(mut read,mut write)=(ptr::null_mut(),ptr::null_mut());
  if unsafe{CreatePipe(&mut read,&mut write,ptr::null(),4096)}==0{return Err(os_error());}
  let writer=unsafe{OwnedHandle::take(write)};
  let reader=unsafe{OwnedHandle::take(read)};
  Ok((reader?,writer?))
 }
 fn prepare(body:&str,timeout_ms:u32)->io::Result<(PausedWorker,OwnedHandle,OwnedHandle)>{prepare_kind(body,timeout_ms,true)}
 fn prepare_kind(body:&str,timeout_ms:u32,lpac:bool)->io::Result<(PausedWorker,OwnedHandle,OwnedHandle)>{
  // The OS-provided executable is accessible to AppContainers. No project ACL
  // or integrity label is changed just to let a worker reach this positive control.
  let system=std::env::var("SystemRoot").map_err(|_|invalid("SystemRoot is required"))?;
  let image=format!("{system}\\System32\\cmd.exe");let directory=format!("{system}\\System32");
  let environment=environment(&system,&directory)?;
  let identity=AppContainerSid::fresh()?;
  let null=wide("NUL")?;
  let input=unsafe{OwnedHandle::take(CreateFileW(null.as_ptr(),FILE_GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,ptr::null(),OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,ptr::null_mut()))}?;
  let(stdout,output)=capture_pipe()?;let(stderr,error)=capture_pipe()?;
  let command_line=format!("\"{image}\" /d /q /c {body}");
  let spawn=Spawn{image:&image,command_line:&command_line,directory:&directory,environment:&environment,input:input.0,output:output.0,error:error.0,controls:&[],identity:&identity,memory_bytes:268435456,timeout_ms};
  let worker=if lpac{unsafe{spawn.start()}?}else{unsafe{spawn.start_with_packages_policy(0)}?};
  // All child-end copies close before waiting or reading, including handles
  // owned here and temporary inheritable duplicates owned inside start().
  Ok((worker,stdout,stderr))
 }
 fn read_output(pipe:&OwnedHandle)->io::Result<String>{
  let mut output=Vec::new();let mut bytes=[0u8;4096];
  loop{
   let mut count=0;let success=unsafe{ReadFile(pipe.0,bytes.as_mut_ptr(),bytes.len() as u32,&mut count,ptr::null_mut())};
   if success==0{if unsafe{GetLastError()}==ERROR_BROKEN_PIPE{break;}return Err(os_error());}
   if count==0{break;}if output.len()+count as usize>65536{return Err(invalid("probe output exceeds bound"));}
   output.extend_from_slice(&bytes[..count as usize]);
  }
  // OS error messages use the runner code page; control assertions never
  // depend on a localized message, but preserve readable diagnostic bytes.
  Ok(String::from_utf8_lossy(&output).into_owned())
 }
 fn finish(worker:PausedWorker,out:OwnedHandle,err:OwnedHandle)->io::Result<(u32,String,String)>{
  let mut worker=worker.resume()?;
  let status=loop{if let Some(status)=worker.try_exit()?{break status;}std::thread::sleep(Duration::from_millis(5));};
  let stdout=read_output(&out)?;let stderr=read_output(&err)?;
  if stdout.len()+stderr.len()>65536{return Err(invalid("probe output exceeds bound"));}
  Ok((status,stdout,stderr))
 }
 #[test]
 fn native_lpac_positive_control_and_fresh_environment(){
  assert_eq!(std::env::var("KELFT_NATIVE_PROBE_AMBIENT").as_deref(),Ok("must-not-reach-worker"));
  let(worker,out,err)=prepare("if defined KELFT_NATIVE_PROBE_AMBIENT (exit /b 93) else (exit /b 42)",10000).unwrap();
  // Verify the kernel token before resuming, rather than infer restriction from
  // a denied file or trust that CreateProcess accepted the supplied attributes.
  let mut token=ptr::null_mut();assert_ne!(unsafe{OpenProcessToken(worker.process.0,Security::TOKEN_QUERY|Security::TOKEN_DUPLICATE,&mut token)},0);
  let token=unsafe{OwnedHandle::take(token)}.unwrap();let(mut value,mut returned)=(0u32,0u32);
  assert_ne!(unsafe{Security::GetTokenInformation(token.0,Security::TokenIsAppContainer,(&mut value as *mut u32).cast(),4,&mut returned)},0);
  assert_eq!(returned,4);assert_eq!(value,1);
  value=0;let queried=unsafe{Security::GetTokenInformation(token.0,Security::TokenIsLessPrivilegedAppContainer,(&mut value as *mut u32).cast(),4,&mut returned)};
  if queried!=0{assert_eq!(returned,4);assert_eq!(value,1);}else{assert_eq!(unsafe{GetLastError()},87,"unexpected LPAC token query error");eprintln!("LPAC token information class 46 is unsupported; independent access control comparison is required");}
  // Some kernels reject user-mode information class 46. Independently prove
  // the documented LPAC distinction: ALL APPLICATION PACKAGES grants access
  // to an ordinary AppContainer, but cannot grant it to this LPAC token.
  assert!(!all_application_packages_access(&token));
  let(control,control_out,control_err)=prepare_kind("exit /b 0",10000,false).unwrap();
  let mut ordinary=ptr::null_mut();assert_ne!(unsafe{OpenProcessToken(control.process.0,Security::TOKEN_QUERY|Security::TOKEN_DUPLICATE,&mut ordinary)},0);
  let ordinary=unsafe{OwnedHandle::take(ordinary)}.unwrap();assert!(all_application_packages_access(&ordinary));
  assert_eq!(finish(control,control_out,control_err).unwrap().0,0);
  let(status,out,err)=finish(worker,out,err).unwrap();assert_eq!(status,42,"{out}{err}");
 }
 fn all_application_packages_access(token:&OwnedHandle)->bool{
  let text=wide("O:SYG:SYD:(A;;0x1;;;WD)(A;;0x1;;;AC)").unwrap();let mut descriptor=ptr::null_mut();
  assert_ne!(unsafe{Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW(text.as_ptr(),1,&mut descriptor,ptr::null_mut())},0);
  let mut duplicate=ptr::null_mut();assert_ne!(unsafe{Security::DuplicateToken(token.0,Security::SecurityImpersonation,&mut duplicate)},0);
  let duplicate=unsafe{OwnedHandle::take(duplicate)}.unwrap();
  let mapping=Security::GENERIC_MAPPING{GenericRead:1,GenericWrite:2,GenericExecute:4,GenericAll:7};let mut privileges=[0usize;128];let mut length=mem::size_of_val(&privileges) as u32;let(mut granted,mut allowed)=(0,0);
  let result=unsafe{Security::AccessCheck(descriptor,duplicate.0,1,&mapping,privileges.as_mut_ptr().cast(),&mut length,&mut granted,&mut allowed)};
  unsafe{windows_sys::Win32::Foundation::LocalFree(descriptor);}assert_ne!(result,0,"AccessCheck failed: {}",io::Error::last_os_error());allowed!=0
 }
 #[test]
 fn native_lpac_cannot_write_an_ungranted_project(){
  let directory=std::env::temp_dir().join(format!("kelft-ungranted-{}",std::process::id()));fs::create_dir(&directory).unwrap();
  let output=directory.join("escape.txt");let body=format!("echo denied>\"{}\"",output.display());
  let(worker,out,err)=prepare(&body,10000).unwrap();let(status,_,_)=finish(worker,out,err).unwrap();
  assert_ne!(status,0);assert!(!output.exists());fs::remove_dir(directory).unwrap();
 }
 #[test]
 fn native_job_denies_a_second_process(){
  let system=std::env::var("SystemRoot").unwrap();
  let(worker,out,err)=prepare(&format!("\"{system}\\System32\\cmd.exe\" /d /q /c exit 0"),10000).unwrap();
  let(status,out,err)=finish(worker,out,err).unwrap();assert_ne!(status,0,"child process escaped the single-process job: {out}{err}");
 }
 #[test]
 fn native_deadline_terminates_and_reaps_the_worker(){
  let(worker,out,err)=prepare("for /l %i in (1,1,2147483647) do @rem bounded watchdog probe",100).unwrap();
  let mut worker=worker.resume().unwrap();
  let error=loop{match worker.try_exit(){Err(error)=>break error,Ok(None)=>std::thread::sleep(Duration::from_millis(5)),Ok(Some(status))=>panic!("watchdog control exited early: {status}")}};
  assert_eq!(error.kind(),io::ErrorKind::TimedOut);
  assert_eq!(unsafe{WaitForSingleObject(worker.process.0,5000)},0);drop((out,err));
 }
}
