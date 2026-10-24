//! Process requests use the existing authenticated worker and guardian.
use crate::{host_channel::{self,Process},macos_supervisor::{Host,Limits,ProcessConfiguration},macos_snapshot::Image,macos_filesystem_session::{self as session,Grant}};
use serde_json::{Value,json};
use std::{fs,io::{self,Read},os::unix::fs::OpenOptionsExt,path::Path,sync::{Arc,atomic::AtomicBool},time::Instant};
pub struct Installed{pub root:std::path::PathBuf,pub coordinator_sha256:String}

pub fn execute(host:&Host,base:&Path,request:&Process,profile:&str,grants:&[Grant],deadline:Instant,cancel:Arc<AtomicBool>,installed:Option<&Installed>)->Value{
 #[cfg(feature="installed-native")]
 if profile=="installed-kelft"{return installed_process(host,base,request,grants,deadline,cancel,installed);}
 #[cfg(not(feature="installed-native"))]let _=installed;
 if profile!="native"{return host_channel::process_error("UNSUPPORTED_HOST");}
 let remaining=deadline.saturating_duration_since(Instant::now()).as_millis().min(request.limits.timeout_ms as u128) as u64;
 if remaining==0{return json!({"schema":"kelft.process-result/1","status":"timeout","error":"deadline exceeded","exit":null,"signal":null,"stdoutHex":"","stderrHex":""});}
 let result=(||->io::Result<_>{
  let mut file=fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW|libc::O_CLOEXEC|libc::O_NONBLOCK).open(&request.executable)?;let meta=file.metadata()?;
  if !meta.is_file()||meta.len()>64<<20{return Err(io::Error::from(io::ErrorKind::PermissionDenied));}
  let mut bytes=vec![];Read::by_ref(&mut file).take((64<<20)+1).read_to_end(&mut bytes)?;
  use sha2::{Digest,Sha256};if format!("sha256:{:x}",Sha256::digest(&bytes))!=request.sha256{return Err(io::Error::from(io::ErrorKind::PermissionDenied));}
  let image=Image::new(&bytes,&request.sha256,base)?;
  let child=session::delegated(&request.read,&request.write,grants)?;let cwd=session::mapped_path(&request.cwd,false,grants)?;
  let environment=request.environment.iter().map(|(a,b)|(a.clone(),b.clone())).collect::<Vec<_>>();
  let output=request.limits.stdout_bytes.checked_add(request.limits.stderr_bytes).filter(|n|*n<=16<<20).ok_or_else(||io::Error::from(io::ErrorKind::Unsupported))?;
  session::run_process(host,&image,&request.args,Limits{wall_ms:remaining,output_bytes:output.max(1)},&child,&request.cwd,&environment,base,ProcessConfiguration{cwd,memory_bytes:request.limits.memory_bytes as u64},host_channel::unhex(&request.stdin_hex),cancel)
 })();
 match result{
  Err(error)=>json!({"schema":"kelft.process-result/1","status":"launch-error","error":match error.kind(){io::ErrorKind::PermissionDenied=>"EXECUTABLE_DENIED",io::ErrorKind::NotFound=>"ENOENT",io::ErrorKind::InvalidInput|io::ErrorKind::Unsupported=>"UNSUPPORTED_HOST_REQUEST",_=>"LAUNCH_FAILED"},"exit":null,"signal":null,"stdoutHex":"","stderrHex":""}),
  Ok(output)=>{
   let exceeded=output.stdout.len()>request.limits.stdout_bytes||output.stderr.len()>request.limits.stderr_bytes;
   let status=if exceeded{"resource-error"}else if output.failure.as_ref().is_some_and(|e|e.contains("deadline")){"timeout"}else if output.failure.is_some(){"resource-error"}else if output.signal.is_some(){"signaled"}else{"exited"};
   json!({"schema":"kelft.process-result/1","status":status,"error":output.failure.unwrap_or_default(),"exit":if status=="exited"{output.exit}else{None},"signal":if status=="signaled"{output.signal}else{None},"stdoutHex":host_channel::hex(&output.stdout[..output.stdout.len().min(request.limits.stdout_bytes)]),"stderrHex":host_channel::hex(&output.stderr[..output.stderr.len().min(request.limits.stderr_bytes)])})
  }
 }
}
#[cfg(feature="installed-native")]
fn installed_process(host:&Host,base:&Path,r:&Process,grants:&[Grant],deadline:Instant,cancel:Arc<AtomicBool>,context:Option<&Installed>)->Value{
 use std::{process::Stdio,os::unix::process::{CommandExt,ExitStatusExt},sync::atomic::Ordering,time::Duration};
 let result=(||->io::Result<_>{
  let context=context.ok_or_else(||io::Error::from(io::ErrorKind::PermissionDenied))?;let expected=context.root.join("bin/kelft");
  if Path::new(&r.executable)!=expected||r.sha256!=context.coordinator_sha256{return Err(io::Error::from(io::ErrorKind::PermissionDenied));}
  let mut file=fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW|libc::O_CLOEXEC|libc::O_NONBLOCK).open(&expected)?;if !file.metadata()?.is_file()||file.metadata()?.len()>64<<20{return Err(io::Error::from(io::ErrorKind::PermissionDenied));}let mut bytes=vec![];Read::by_ref(&mut file).take((64<<20)+1).read_to_end(&mut bytes)?;use sha2::{Digest,Sha256};if format!("sha256:{:x}",Sha256::digest(&bytes))!=r.sha256{return Err(io::Error::from(io::ErrorKind::PermissionDenied));}
  let target=crate::native_target::Target::current().map_err(io::Error::other)?;let contract=crate::native_resources::Contract::for_role(target,"compiler")?;
  if r.limits.memory_bytes as u64!=contract.memory.ceiling_bytes{return Err(io::Error::from(io::ErrorKind::Unsupported));}
  let deadline=deadline.min(Instant::now()+Duration::from_millis(r.limits.timeout_ms as u64));let mut project=crate::unix_installed_host::Project::new(r,grants,base,deadline)?;
  let mut command=host.installed_command(&context.root);command.env_clear().args(project.request.boundary_args(target).map_err(io::Error::other)?).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
  let memory=r.limits.memory_bytes as u64;unsafe{command.pre_exec(move||{let limit=libc::rlimit{rlim_cur:memory,rlim_max:memory};if libc::setrlimit(libc::RLIMIT_AS,&limit)!=0{return Err(io::Error::last_os_error());}Ok(())});}
  struct ChildGuard(std::process::Child);
  impl std::ops::Deref for ChildGuard{type Target=std::process::Child;fn deref(&self)->&Self::Target{&self.0}}
  impl std::ops::DerefMut for ChildGuard{fn deref_mut(&mut self)->&mut Self::Target{&mut self.0}}
  impl Drop for ChildGuard{fn drop(&mut self){let _=self.0.kill();let _=self.0.wait();}}
  let mut child=ChildGuard(command.spawn()?);let overflow=Arc::new(AtomicBool::new(false));
  let capture=|mut stream:Box<dyn Read+Send>,limit:usize,overflow:Arc<AtomicBool>|std::thread::spawn(move||->io::Result<Vec<u8>>{let mut bytes=vec![];let mut chunk=[0;65536];loop{let n=stream.read(&mut chunk)?;if n==0{break;}let take=n.min(limit.saturating_sub(bytes.len()));bytes.extend_from_slice(&chunk[..take]);if take<n{overflow.store(true,Ordering::Release);}}Ok(bytes)});
  let stdout=capture(Box::new(child.stdout.take().unwrap()),r.limits.stdout_bytes,overflow.clone());let stderr=capture(Box::new(child.stderr.take().unwrap()),r.limits.stderr_bytes,overflow.clone());let mut failure="";
  let exit=loop{if let Some(exit)=child.try_wait()?{break exit;}if Instant::now()>=deadline{failure="timeout";}else if overflow.load(Ordering::Acquire)||cancel.load(Ordering::Acquire){failure="resource-error";}if !failure.is_empty(){child.kill()?;break child.wait()?;}std::thread::sleep(Duration::from_millis(5));};
  let mut stdout=stdout.join().map_err(|_|io::Error::other("compiler capture panicked"))??;let mut stderr=stderr.join().map_err(|_|io::Error::other("compiler capture panicked"))??;if failure.is_empty()&&overflow.load(Ordering::Acquire){failure="resource-error";}
  if failure.is_empty()&&exit.success(){project.publish()?;}
  if failure.is_empty()&&project.request.json{let data=if stdout.is_empty(){Value::Null}else{serde_json::from_slice(&stdout).unwrap_or_else(|_|json!(String::from_utf8_lossy(&stdout)))};stdout=serde_json::to_vec(&json!({"schema":"kelft.command-result/1","status":if exit.success(){"success"}else{"failure"},"command":project.request.command,"host":target.id(),"target":target.id(),"emit":if project.request.command=="build"{Some(project.request.emit)}else{None},"data":data,"diagnostics":String::from_utf8_lossy(&stderr)}))?;stdout.push(b'\n');stderr.clear();if stdout.len()>r.limits.stdout_bytes{stdout.truncate(r.limits.stdout_bytes);failure="resource-error";}}
  let status=if !failure.is_empty(){failure}else if exit.signal().is_some(){"signaled"}else{"exited"};Ok(json!({"schema":"kelft.process-result/1","status":status,"error":failure,"exit":if status=="exited"{Some(if exit.success(){0}else{1})}else{None},"signal":if status=="signaled"{exit.signal()}else{None},"stdoutHex":host_channel::hex(&stdout),"stderrHex":host_channel::hex(&stderr)}))
 })();match result{Ok(value)=>value,Err(error)=>json!({"schema":"kelft.process-result/1","status":"launch-error","error":match error.kind(){io::ErrorKind::PermissionDenied=>"EXECUTABLE_DENIED",io::ErrorKind::NotFound=>"ENOENT",io::ErrorKind::Unsupported=>"UNSUPPORTED_HOST_REQUEST",_=>"LAUNCH_FAILED"},"exit":null,"signal":null,"stdoutHex":"","stderrHex":""})}
}
