//! Native helper launch with an explicit descriptor allowlist. No parent-wide
//! descriptor flags change, and sandbox setup never runs in a fork callback.
use std::{ffi::CString,fs::File,io,mem,os::{fd::{AsRawFd,FromRawFd,OwnedFd,RawFd},unix::{ffi::OsStrExt,process::ExitStatusExt}},path::Path,process::ExitStatus,ptr};
fn invalid(message:&'static str)->io::Error{io::Error::new(io::ErrorKind::InvalidInput,message)}
fn check(status:i32)->io::Result<()>{if status==0{Ok(())}else{Err(io::Error::from_raw_os_error(status))}}
struct Actions(libc::posix_spawn_file_actions_t);
impl Drop for Actions{fn drop(&mut self){unsafe{libc::posix_spawn_file_actions_destroy(&mut self.0);}}}
struct Attributes(libc::posix_spawnattr_t);
impl Drop for Attributes{fn drop(&mut self){unsafe{libc::posix_spawnattr_destroy(&mut self.0);}}}
fn pipe()->io::Result<(File,File)>{
 let mut fds=[-1;2];if unsafe{libc::pipe(fds.as_mut_ptr())}<0{return Err(io::Error::last_os_error());}
 let first=unsafe{File::from_raw_fd(fds[0])};let second=unsafe{File::from_raw_fd(fds[1])};
 for fd in fds{if unsafe{libc::fcntl(fd,libc::F_SETFD,libc::FD_CLOEXEC)}<0{return Err(io::Error::last_os_error());}}
 Ok((first,second))
}
#[derive(Clone,Copy,serde::Serialize)]#[serde(rename_all="camelCase")]
pub struct Usage{pub user_micros:u64,pub system_micros:u64,pub peak_resident_bytes:u64}
pub struct Child{pid:libc::pid_t,status:Option<ExitStatus>,reason:Option<String>,usage:Option<Usage>,pub stdin:Option<File>,pub stdout:Option<File>,pub stderr:Option<File>}
impl Child{
 pub fn id(&self)->u32{self.pid as u32}
 pub fn exit_reason(&self)->Option<&str>{self.reason.as_deref()}
 pub fn usage(&self)->Option<Usage>{self.usage}
 pub fn try_wait(&mut self)->io::Result<Option<ExitStatus>>{self.wait_with(libc::WNOHANG)}
 pub fn wait(&mut self)->io::Result<ExitStatus>{self.wait_with(0)?.ok_or_else(||io::Error::other("native helper wait returned no status"))}
 fn wait_with(&mut self,options:i32)->io::Result<Option<ExitStatus>>{
  if self.status.is_some(){return Ok(self.status);}let mut status=0;
  // Observe before reaping so a loader abort's kernel payload remains
  // available. Diagnostic failure never turns a failed execution into success.
  let mut info:libc::siginfo_t=unsafe{mem::zeroed()};
  loop{if unsafe{libc::waitid(libc::P_PID,self.pid as u32,&mut info,libc::WEXITED|libc::WNOWAIT|options)}==0{break;}let error=io::Error::last_os_error();if error.kind()!=io::ErrorKind::Interrupted{return Err(error);}}
  if info.si_pid==0{return Ok(None);}if info.si_code!=libc::CLD_EXITED{self.reason=Some(exit_reason(self.pid));}
  let mut usage:libc::rusage=unsafe{mem::zeroed()};
  loop{let result=unsafe{libc::wait4(self.pid,&mut status,options,&mut usage)};if result==self.pid{self.status=Some(ExitStatus::from_raw(status));let micros=|t:libc::timeval|->io::Result<u64>{if t.tv_sec<0||t.tv_usec<0||t.tv_usec>=1000000{return Err(invalid("native CPU usage differs"));}(t.tv_sec as u64).checked_mul(1000000).and_then(|n|n.checked_add(t.tv_usec as u64)).ok_or_else(||invalid("native CPU usage overflow"))};if usage.ru_maxrss<0{return Err(invalid("native resident measurement differs"));}self.usage=Some(Usage{user_micros:micros(usage.ru_utime)?,system_micros:micros(usage.ru_stime)?,peak_resident_bytes:usage.ru_maxrss as u64});return Ok(self.status);}if result==0{return Ok(None);}let error=io::Error::last_os_error();if error.kind()!=io::ErrorKind::Interrupted{return Err(error);}}
 }
 /// The child remains owned and unreaped until this call; its PID cannot be
 /// recycled. Arbitrary external PIDs are never accepted by this API.
 pub fn kill(&mut self)->io::Result<()>{if self.try_wait()?.is_some(){return Ok(());}if unsafe{libc::kill(self.pid,libc::SIGKILL)}<0{let error=io::Error::last_os_error();if error.raw_os_error()!=Some(libc::ESRCH){return Err(error);}}Ok(())}
}
impl Drop for Child{fn drop(&mut self){let _=self.kill();let _=self.wait();}}

/// Launch only a dedicated trusted helper. It must install its role boundary
/// before executing candidate bytes. Every descriptor outside this map closes
/// atomically in the child, including accidentally inheritable parent handles.
pub fn spawn(executable:&Path,args:&[String],environment:&[(String,String)],extra:&[(RawFd,RawFd)])->io::Result<Child>{
 if !executable.is_absolute()||args.len()>4096||environment.len()>32||extra.len()>16{return Err(invalid("bounded native helper launch required"));}
 let executable=CString::new(executable.as_os_str().as_bytes()).map_err(|_|invalid("helper path contains NUL"))?;
 let mut budget=1<<20;let mut encode=|text:&str|->io::Result<CString>{if text.len()>budget||text.len()>131064{return Err(invalid("native helper text bound"));}budget-=text.len();CString::new(text).map_err(|_|invalid("native helper text contains NUL"))};
 let mut arguments=vec![executable.clone()];for arg in args{arguments.push(encode(arg)?);}
 let mut keys=std::collections::HashSet::new();let mut variables=vec![];
 for(key,value)in environment{if key.is_empty()||key.contains('=')||!keys.insert(key){return Err(invalid("invalid helper environment key"));}variables.push(encode(&format!("{key}={value}"))?);}
 let argv:Vec<_>=arguments.iter().map(|s|s.as_ptr().cast_mut()).chain([ptr::null_mut()]).collect();
 let envp:Vec<_>=variables.iter().map(|s|s.as_ptr().cast_mut()).chain([ptr::null_mut()]).collect();
 let (stdin_read,stdin_write)=pipe()?;let(stdout_read,stdout_write)=pipe()?;let(stderr_read,stderr_write)=pipe()?;
 let mut mappings=vec![(stdin_read.as_raw_fd(),0),(stdout_write.as_raw_fd(),1),(stderr_write.as_raw_fd(),2)];mappings.extend_from_slice(extra);
 let mut destinations=std::collections::HashSet::new();let mut retained=vec![];
 for &(source,destination)in &mappings{
  if !(0..64).contains(&destination)||!destinations.insert(destination){return Err(invalid("descriptor destinations overlap or exceed bounds"));}
  // Move all sources above every destination without altering shared flags.
  let fd=unsafe{libc::fcntl(source,libc::F_DUPFD_CLOEXEC,64)};if fd<0{return Err(io::Error::last_os_error());}retained.push((unsafe{OwnedFd::from_raw_fd(fd)},destination));
 }
 let mut actions=unsafe{mem::zeroed()};check(unsafe{libc::posix_spawn_file_actions_init(&mut actions)})?;let mut actions=Actions(actions);
 for(source,destination)in &retained{check(unsafe{libc::posix_spawn_file_actions_adddup2(&mut actions.0,source.as_raw_fd(),*destination)})?;check(unsafe{libc::posix_spawn_file_actions_addclose(&mut actions.0,source.as_raw_fd())})?;}
 let mut attributes=unsafe{mem::zeroed()};check(unsafe{libc::posix_spawnattr_init(&mut attributes)})?;let mut attributes=Attributes(attributes);
 check(unsafe{libc::posix_spawnattr_setflags(&mut attributes.0,(libc::POSIX_SPAWN_CLOEXEC_DEFAULT|libc::POSIX_SPAWN_SETSIGMASK|libc::POSIX_SPAWN_SETSIGDEF) as i16)})?;
 let mut mask=unsafe{mem::zeroed()};check(unsafe{libc::sigemptyset(&mut mask)})?;check(unsafe{libc::posix_spawnattr_setsigmask(&mut attributes.0,&mask)})?;
 for signal in [libc::SIGINT,libc::SIGTERM,libc::SIGQUIT,libc::SIGHUP,libc::SIGPIPE]{check(unsafe{libc::sigaddset(&mut mask,signal)})?;}
 check(unsafe{libc::posix_spawnattr_setsigdefault(&mut attributes.0,&mask)})?;
 let mut architecture=match std::env::consts::ARCH{"x86_64"=>0x01000007,"aarch64"=>0x0100000c,_=>return Err(invalid("unsupported native helper architecture"))};let mut selected=0;
 check(unsafe{libc::posix_spawnattr_setbinpref_np(&mut attributes.0,1,&mut architecture,&mut selected)})?;if selected!=1{return Err(invalid("native CPU preference was not installed"));}
 let mut pid=0;check(unsafe{libc::posix_spawn(&mut pid,executable.as_ptr(),&actions.0,&attributes.0,argv.as_ptr(),envp.as_ptr())})?;
 Ok(Child{pid,status:None,reason:None,usage:None,stdin:Some(stdin_write),stdout:Some(stdout_read),stderr:Some(stderr_read)})
}

fn exit_reason(pid:libc::pid_t)->String{
 #[repr(C,packed)]struct Reason{namespace:u32,code:u64,flags:u64,size:u32,buffer:u64}
 #[link(name="proc")]unsafe extern "C"{fn proc_pidinfo(pid:i32,flavor:i32,arg:u64,buffer:*mut libc::c_void,size:i32)->i32;}
 let mut payload=[0u8;16384];let mut reason=Reason{namespace:0,code:0,flags:0,size:payload.len() as u32,buffer:payload.as_mut_ptr() as u64};
 let count=unsafe{proc_pidinfo(pid,24,0,(&mut reason as *mut Reason).cast(),mem::size_of::<Reason>() as i32)};
 if count!=mem::size_of::<Reason>() as i32{return format!("exit reason unavailable: {}",io::Error::last_os_error());}
 let namespace=reason.namespace;let code=reason.code;let flags=reason.flags;let size=(reason.size as usize).min(payload.len());
 let text:String=payload[..size].iter().map(|&b|if (32..127).contains(&b){b as char}else{' '}).collect();
 format!("namespace={namespace} code={code:#x} flags={flags:#x} payload={}",text.split_whitespace().collect::<Vec<_>>().join(" "))
}

#[cfg(test)]mod tests{
 use super::*;use std::io::{Read,Write};
 #[test]fn private_descriptor_worker(){
  if std::env::var("KELFT_DESCRIPTOR_WORKER").as_deref()!=Ok("1"){return;}
  assert!(std::env::var_os("KELFT_DESCRIPTOR_AMBIENT").is_none());
  let foreign:i32=std::env::var("KELFT_FOREIGN_DESCRIPTOR").unwrap().parse().unwrap();assert_eq!(unsafe{libc::fcntl(foreign,libc::F_GETFD)},-1,"unmapped inheritable descriptor reached helper");
  let mut channel=unsafe{File::from_raw_fd(9)};let mut data=[0;4];channel.read_exact(&mut data).unwrap();assert_eq!(data,[0,255,128,42]);
  channel.write_all(b"descriptor-positive").unwrap();println!("explicit-descriptor-map-ok");
 }
 #[test]fn explicit_map_closes_foreign_descriptors_and_preserves_parent_flags(){
  let(mut host,peer)=std::os::unix::net::UnixStream::pair().unwrap();host.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
  let foreign=unsafe{libc::fcntl(peer.as_raw_fd(),libc::F_DUPFD_CLOEXEC,63)};assert!(foreign>=63);let foreign=unsafe{OwnedFd::from_raw_fd(foreign)};
  assert_eq!(unsafe{libc::fcntl(foreign.as_raw_fd(),libc::F_SETFD,0)},0);let before=unsafe{libc::fcntl(peer.as_raw_fd(),libc::F_GETFD)};
  let args=["--exact","macos_process::tests::private_descriptor_worker","--nocapture"].map(String::from);let mut child=spawn(&std::env::current_exe().unwrap(),&args,&[("KELFT_DESCRIPTOR_WORKER".into(),"1".into()),("KELFT_FOREIGN_DESCRIPTOR".into(),foreign.as_raw_fd().to_string())],&[(peer.as_raw_fd(),9)]).unwrap();
  host.write_all(&[0,255,128,42]).unwrap();let mut data=[0;19];host.read_exact(&mut data).unwrap();assert_eq!(&data,b"descriptor-positive");
  let mut text=String::new();child.stdout.take().unwrap().read_to_string(&mut text).unwrap();assert!(child.wait().unwrap().success(),"{text}");assert!(text.contains("explicit-descriptor-map-ok"));assert_eq!(unsafe{libc::fcntl(peer.as_raw_fd(),libc::F_GETFD)},before);assert_eq!(unsafe{libc::fcntl(foreign.as_raw_fd(),libc::F_GETFD)},0);
 }
 #[test]fn unsafe_descriptor_maps_and_environment_keys_are_rejected(){
  let exe=std::env::current_exe().unwrap();let file=File::open(&exe).unwrap();
  for mapping in [vec![(file.as_raw_fd(),0)],vec![(file.as_raw_fd(),64)],vec![(file.as_raw_fd(),9),(file.as_raw_fd(),9)]]{assert!(spawn(&exe,&[],&[],&mapping).is_err());}
  for environment in [vec![("A=B".into(),"x".into())],vec![("A".into(),"1".into()),("A".into(),"2".into())]]{assert!(spawn(&exe,&[],&environment,&[]).is_err());}
 }
}
