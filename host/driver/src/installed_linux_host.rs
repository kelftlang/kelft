//! Private Linux host channel routed through the measured namespace supervisor.
use crate::{protocol::{self,WorkerRequest,ExecutionResult,Limits},native};
use kelft_wasi::{host_channel::{self,Policy,Process},unix_host::{Grant,Server},unix_filesystem::Broker};
use serde_json::{Value,json};
use std::{fs,io::{self,Read,Write,Seek},os::{fd::{AsRawFd,FromRawFd},unix::{fs::OpenOptionsExt,process::CommandExt,net::UnixStream}},path::Path,sync::{Arc,atomic::{AtomicBool,Ordering}},time::{Duration,Instant}};
type Error=Box<dyn std::error::Error>;
fn installed(r:&Process,grants:&[Grant],deadline:Instant,cancel:Arc<AtomicBool>)->Value{
 let deadline=deadline.min(Instant::now()+Duration::from_millis(r.limits.timeout_ms as u64));
 let result=(||->Result<_,Error>{
  let executable=fs::canonicalize(std::env::current_exe()?)?;
  if Path::new(&r.executable)!=executable||protocol::hash(&fs::read(&executable)?)!=r.sha256{return Err("EXECUTABLE_DENIED".into());}
  crate::installed_paths()?;
  let mut project=kelft_wasi::unix_installed_host::Project::new(r,grants,&native::private_temp_dir()?,deadline)?;
  let host=kelft_wasi::native_target::Target::current()?;let mut boundary=crate::boundary_command()?;
  let remaining=deadline.saturating_duration_since(Instant::now()).as_millis().min(r.limits.timeout_ms as u128) as u64;
  if remaining==0{return Err(io::Error::new(io::ErrorKind::TimedOut,"deadline exceeded").into());}
  let limits=Limits{timeout_ms:remaining,memory_bytes:r.limits.memory_bytes,stdout_bytes:r.limits.stdout_bytes,stderr_bytes:r.limits.stderr_bytes};
  boundary.command.env_clear().args(project.request.boundary_args(host)?)
   .arg("--host-memory-bytes").arg(limits.memory_bytes.to_string()).arg("--host-timeout-ms").arg(remaining.to_string())
   .arg("--host-stdout-bytes").arg(limits.stdout_bytes.to_string()).arg("--host-stderr-bytes").arg(limits.stderr_bytes.to_string()).stdin(std::process::Stdio::null());
  let parent=std::process::id() as i32;unsafe{boundary.command.pre_exec(move||{if libc::prctl(libc::PR_SET_PDEATHSIG,libc::SIGKILL)!=0||libc::getppid()!=parent{return Err(invalid("compiler boundary parent changed"));}Ok(())});}
  let mut out=native::run_with_cancel(&mut boundary.command,&limits,Some(&cancel))?;
  let code=out.exit.unwrap_or(125);let status=if out.failure.as_ref().is_some_and(|s|s.contains("timed out"))||code==124{"timeout"}else if out.failure.is_some()||matches!(code,122|125){"resource-error"}else{"exited"};
  if status=="exited"&&code==0{project.publish()?;}
  if project.request.json&&status=="exited"{
   let data=if out.stdout.is_empty(){Value::Null}else{serde_json::from_slice(&out.stdout).unwrap_or_else(|_|json!(String::from_utf8_lossy(&out.stdout)))};
   out.stdout=serde_json::to_vec(&json!({"schema":"kelft.command-result/1","status":if code==0{"success"}else{"failure"},"command":project.request.command,"host":host.id(),"target":host.id(),"emit":if project.request.command=="build"{Some(project.request.emit)}else{None},"data":data,"diagnostics":String::from_utf8_lossy(&out.stderr)}))?;out.stdout.push(b'\n');out.stderr.clear();
   if out.stdout.len()>limits.stdout_bytes{out.stdout.truncate(limits.stdout_bytes);out.failure=Some("process output limit exceeded".into());}
  }
  let status=if status=="exited"&&out.failure.is_some(){"resource-error"}else{status};
  Ok(json!({"schema":"kelft.process-result/1","status":status,"error":out.failure.unwrap_or_default(),"exit":if status=="exited"{Some(if code==0{0}else{1})}else{None},"signal":null,"stdoutHex":protocol::hex(&out.stdout),"stderrHex":protocol::hex(&out.stderr)}))
 })();match result{Ok(value)=>value,Err(e)=>{let timed=e.downcast_ref::<io::Error>().is_some_and(|e|e.kind()==io::ErrorKind::TimedOut);json!({"schema":"kelft.process-result/1","status":if timed{"timeout"}else{"launch-error"},"error":if e.to_string()=="EXECUTABLE_DENIED"{"EXECUTABLE_DENIED"}else{"LAUNCH_FAILED"},"exit":null,"signal":null,"stdoutHex":"","stderrHex":""})}}
}
fn invalid(s:impl ToString)->io::Error{io::Error::other(s.to_string())}
fn sealed(bytes:&[u8])->io::Result<fs::File>{let fd=unsafe{libc::syscall(libc::SYS_memfd_create,c"kelft-process-input".as_ptr(),3)};if fd<0{return Err(io::Error::last_os_error());}let mut f=unsafe{fs::File::from_raw_fd(fd as i32)};f.write_all(bytes)?;f.rewind()?;if unsafe{libc::fcntl(fd as i32,libc::F_ADD_SEALS,15)}<0{return Err(io::Error::last_os_error());}Ok(f)}
fn mapped(guest:&str,writing:bool,grants:&[Grant])->io::Result<std::path::PathBuf>{
 if !host_channel::normal(guest)||!guest.starts_with('/'){return Err(io::Error::from(io::ErrorKind::PermissionDenied));}
 let g=grants.iter().filter(|g|(if writing{g.write}else{g.read})&&host_channel::within(guest,&g.guest)).max_by_key(|g|g.guest.len()).ok_or(io::ErrorKind::PermissionDenied)?;
 Ok(if guest==g.guest{g.path.clone()}else{g.path.join(guest[g.guest.len()..].trim_start_matches('/'))})
}
fn child_grants(r:&Process,grants:&[Grant])->io::Result<Vec<Grant>>{
 let mut child=std::collections::BTreeMap::<String,Grant>::new();for(paths,writing)in[(&r.read,false),(&r.write,true)]{for guest in paths{let path=mapped(guest,writing,grants)?;let entry=child.entry(guest.clone()).or_insert(Grant{guest:guest.clone(),path,read:false,write:false});entry.read|=!writing;entry.write|=writing;}}Ok(child.into_values().collect())
}
fn process(r:&Process,profile:&str,grants:&[Grant],deadline:Instant,cancel:Arc<AtomicBool>)->Value{
 if r.limits.memory_bytes<16<<20||r.limits.memory_bytes>1<<30{return host_channel::process_error("UNSUPPORTED_HOST_REQUEST");}
 if profile=="installed-kelft"{if r.limits.memory_bytes!=1<<30{return host_channel::process_error("UNSUPPORTED_HOST_REQUEST");}return installed(r,grants,deadline,cancel);}
 if profile!="native"{return host_channel::process_error("UNSUPPORTED_HOST");}
 let remaining=deadline.saturating_duration_since(Instant::now()).as_millis().min(r.limits.timeout_ms as u128) as u64;
 if remaining==0{return json!({"schema":"kelft.process-result/1","status":"timeout","error":"deadline exceeded","exit":null,"signal":null,"stdoutHex":"","stderrHex":""});}
 let result=(||->Result<_,Error>{
  let mut image=fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW|libc::O_CLOEXEC|libc::O_NONBLOCK).open(&r.executable)?;
  if !image.metadata()?.is_file()||image.metadata()?.len()>64<<20{return Err("EXECUTABLE_DENIED".into());}let mut bytes=vec![];Read::by_ref(&mut image).take((64<<20)+1).read_to_end(&mut bytes)?;if protocol::hash(&bytes)!=r.sha256{return Err("EXECUTABLE_DENIED".into());}
  kelft_wasi::native_target::Target::current()?.validate_executable(&bytes)?;
  let child=child_grants(r,grants)?;let policy=Policy{read:r.read.clone(),write:r.write.clone(),execute:false,process:vec![]};
  candidate(Path::new(&r.executable),&r.sha256,&r.args,&Limits{timeout_ms:remaining,memory_bytes:r.limits.memory_bytes,stdout_bytes:r.limits.stdout_bytes,stderr_bytes:r.limits.stderr_bytes},child,policy,&r.cwd,&r.environment,host_channel::unhex(&r.stdin_hex),deadline,cancel)
 })();
 match result{Err(e)=>json!({"schema":"kelft.process-result/1","status":"launch-error","error":if e.downcast_ref::<io::Error>().is_some_and(|e|e.kind()==io::ErrorKind::NotFound){"ENOENT"}else if e.to_string()=="EXECUTABLE_DENIED"{"EXECUTABLE_DENIED"}else{"LAUNCH_FAILED"},"exit":null,"signal":null,"stdoutHex":"","stderrHex":""}),Ok((out,result))=>{
  let failure=result["boundaryFailure"].as_i64().unwrap_or(125);let signal=result["signal"].as_i64().unwrap_or(0);
  let launch_error=result["launchError"].as_i64().unwrap_or(0);
  let status=if launch_error!=0{"launch-error"}else if failure==124||out.failure.as_ref().is_some_and(|s|s.contains("timed out")){"timeout"}else if failure==122||signal==libc::SIGXCPU as i64||signal==libc::SIGXFSZ as i64||out.failure.is_some(){"resource-error"}else if signal>0{"signaled"}else if failure!=0{"launch-error"}else{"exited"};
  json!({"schema":"kelft.process-result/1","status":status,"error":out.failure.unwrap_or_else(||if failure!=0{format!("boundary status {failure}")}else{String::new()}),"exit":if status=="exited"{out.exit}else{None},"signal":if status=="signaled"{Some(signal)}else{None},"stdoutHex":protocol::hex(&out.stdout),"stderrHex":protocol::hex(&out.stderr)})
 }}
}
fn candidate(module:&Path,hash:&str,args:&[String],limits:&Limits,grants:Vec<Grant>,caller:Policy,cwd:&str,environment:&std::collections::BTreeMap<String,String>,input:Vec<u8>,deadline:Instant,cancel:Arc<AtomicBool>)->Result<(native::Output,Value),Error>{
 let root=crate::execution::PROJECT_ROOT.get().ok_or("candidate project authority missing")?;
 if input.len()>65536||!host_channel::normal(cwd)||!host_channel::within(cwd,"/project"){return Err("UNSUPPORTED_HOST_REQUEST".into());}
 let installed=fs::canonicalize(std::env::current_exe()?)?.parent().and_then(Path::parent).ok_or("installed root missing")?.to_path_buf();
 let temporary=fs::canonicalize(native::private_temp_dir()?)?;
 let mut broker=Broker::default();for writing in [false,true]{for g in &grants{if if writing{g.write}else{g.read}{let path=fs::canonicalize(&g.path)?;if g.guest!=kelft_wasi::native_target::guest_path(root,&path)?||temporary.starts_with(&path)||path.starts_with(&installed)||installed.starts_with(&path){return Err("candidate grant overlaps private or trusted state".into());}broker.add_root(&path,!writing,writing)?;}}}
 let mut server=Server::new(caller.clone(),grants.clone(),cwd.into())?;let(mut socket,client)=UnixStream::pair()?;socket.set_write_timeout(Some(Duration::from_millis(limits.timeout_ms)))?;let cleanup=socket.try_clone()?;
 let input=sealed(&input)?;let source=client.as_raw_fd();let input_fd=input.as_raw_fd();
 let mut boundary=crate::boundary_command()?;let command=&mut boundary.command;
 let mut nonce=[0;16];getrandom::fill(&mut nonce).map_err(|e|invalid(e.to_string()))?;let directory=temporary.join(format!("kelft-host-result-{}",protocol::hex(&nonce)));fs::create_dir(&directory)?;let result_file=directory.join("result.json");
 command.env_clear().arg("candidate-run").arg(module).arg("--project-root").arg(root).arg("--artifact-hash").arg(hash).arg("--result").arg(&result_file)
  .arg("--timeout-ms").arg(limits.timeout_ms.to_string()).arg("--memory-bytes").arg(limits.memory_bytes.to_string()).arg("--stdout-bytes").arg(limits.stdout_bytes.to_string()).arg("--stderr-bytes").arg(limits.stderr_bytes.to_string())
  .arg("--host-fd").arg("63").arg("--stdin-fd").arg("62").arg("--cwd").arg(cwd);
 for g in &grants{if g.read{command.arg("--read").arg(&g.path);}if g.write{command.arg("--write").arg(&g.path);}}
 for(k,v)in environment{command.arg("--environment").arg(format!("{k}={v}"));}
 command.arg("--policy").arg(json!({"execute":false,"read":caller.read,"write":caller.write}).to_string()).arg("--").args(args).stdin(std::process::Stdio::null());
 let parent=std::process::id() as i32;
 unsafe{command.pre_exec(move||{if libc::prctl(libc::PR_SET_PDEATHSIG,libc::SIGKILL)!=0||libc::getppid()!=parent{return Err(invalid("native boundary parent changed"));}if source==62||input_fd==63{return Err(invalid("reserved process descriptor collision"));}if source!=63&&libc::dup2(source,63)<0||input_fd!=62&&libc::dup2(input_fd,62)<0{return Err(io::Error::last_os_error());}if libc::fcntl(63,libc::F_SETFD,0)<0||libc::fcntl(62,libc::F_SETFD,0)<0{return Err(io::Error::last_os_error());}Ok(())});}
 let failed=cancel.clone();let process_cancel=cancel.clone();
 let result=std::thread::scope(|scope|->Result<_,Error>{
 let service=scope.spawn(move||{let mut output=socket.try_clone()?;let result=kelft_wasi::filesystem_channel::serve_host(&mut socket,&mut output,|r|broker.execute(r),|raw|server.dispatch(raw,|r,p,g|process(r,p,g,deadline,process_cancel.clone())));if result.is_err(){failed.store(true,Ordering::Release);}result});
 let out=native::run_with_cancel(command,limits,Some(&cancel));drop(client);let _=cleanup.shutdown(std::net::Shutdown::Both);let served=service.join().map_err(|_|"host service panicked")?;let out=out?;
 let value:Value=match fs::read(&result_file){Ok(bytes)=>serde_json::from_slice(&bytes)?,Err(_)if out.failure.is_some()=>json!({"boundaryFailure":if out.failure.as_ref().is_some_and(|s|s.contains("timed out")){124}else{122},"signal":0,"launchError":0}),Err(e)=>return Err(format!("candidate result: {e}; stderr {}",String::from_utf8_lossy(&out.stderr)).into())};
 if out.failure.is_none()&&value["boundaryFailure"]==0{served?;}Ok((out,value))
 });
 fs::remove_dir_all(&directory)?;result
}
pub fn execute(request:&WorkerRequest)->Result<ExecutionResult,Error>{
 let grants=request.mounts.iter().map(|m|Grant{guest:m.guest.clone(),path:m.host.clone(),read:m.read,write:m.write}).collect::<Vec<_>>();
 let expected=Policy{read:grants.iter().filter(|g|g.read).map(|g|g.guest.clone()).collect(),write:grants.iter().filter(|g|g.write).map(|g|g.guest.clone()).collect(),execute:false,process:vec![]};
 let caller=if request.configuration.starts_with('{'){serde_json::from_str::<Policy>(&request.configuration)?}else{expected.clone()};
 if !caller.validate()||caller.read!=expected.read||caller.write!=expected.write||caller.execute{return Err("candidate policy differs from mounted authority".into());}
 let deadline=Instant::now()+Duration::from_millis(request.limits.timeout_ms);
 let(out,result)=candidate(&request.module,&request.artifact_hash,&request.args,&request.limits,grants,caller,"/project",&Default::default(),vec![],deadline,Arc::new(AtomicBool::new(false)))?;
 let failure=out.failure.or_else(||if result["boundaryFailure"]!=0{Some(format!("native candidate boundary {}",result["boundaryFailure"]))}else{None});
 Ok(ExecutionResult{status:if failure.is_some(){"resource-error"}else{"exited"}.into(),artifact_hash:request.artifact_hash.clone(),exit:if failure.is_none(){out.exit}else{None},stdout_hex:protocol::hex(&out.stdout),stderr_hex:protocol::hex(&out.stderr),trap:None,error:failure})
}
