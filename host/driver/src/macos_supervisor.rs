//! Native role execution through dedicated helpers. Task rights and control
//! pipes remain outside the compiler/candidate descriptor namespace.
use crate::{macos_process::{self,Child},macos_snapshot::Image,macos_task::{self,Endpoint},macos_seatbelt::{self,Prepared,Role}};
use serde::{Deserialize,Serialize};
use std::{io::{self,BufRead,Read,Write},os::{fd::{RawFd,AsRawFd,FromRawFd},unix::process::CommandExt},path::{Path,PathBuf},process::Command,sync::{Arc,atomic::{AtomicBool,AtomicUsize,Ordering}},time::{Duration,Instant}};
fn invalid(message:&'static str)->io::Error{io::Error::new(io::ErrorKind::InvalidInput,message)}
#[derive(Clone,Copy)]pub struct Limits{pub wall_ms:u64,pub output_bytes:usize}
impl Limits{fn validate(self)->io::Result<()>{if self.wall_ms==0||self.wall_ms>600000||self.output_bytes==0||self.output_bytes>16<<20{return Err(invalid("native supervision bounds differ"));}Ok(())}}
pub struct Output{pub signal:Option<i32>,pub exit:Option<i32>,pub stdout:Vec<u8>,pub stderr:Vec<u8>,pub failure:Option<String>,pub elapsed_ms:u64,pub usage:Option<macos_process::Usage>}
#[derive(Serialize,Deserialize,Clone)]pub struct LinkerPaths{pub sdk:PathBuf,pub tools:PathBuf,pub object:PathBuf,pub output:PathBuf}
#[derive(Serialize,Deserialize,Clone)]pub struct ProcessConfiguration{pub cwd:PathBuf,pub memory_bytes:u64}
#[derive(Serialize,Deserialize)]struct Configuration{#[serde(default)]process:Option<ProcessConfiguration>,image:PathBuf,sha256:String,trusted_tool:bool,runtime:bool,engine_inputs:Vec<(PathBuf,String)>,role:String,args:Vec<String>,environment:Vec<(String,String)>,cpu_seconds:u64,linker:Option<LinkerPaths>}
pub struct Host{helper:Image}
impl Host{
 pub fn new(helper_bytes:&[u8],expected:&str,base:&Path)->io::Result<Self>{if unsafe{libc::geteuid()}==0{return Err(invalid("native role supervision requires an unprivileged owner"));}Ok(Self{helper:Image::new(helper_bytes,expected,base)?})}
 pub fn directory(&self)->&Path{self.helper.directory()}
 #[cfg(feature="installed-native")]
 pub(crate) fn installed_command(&self,root:&Path)->Command{let mut command=Command::new(self.helper.path());command.arg("--installed-root").arg(root).arg("--snapshot-boundary");command}
 /// Channels must already be authorized by the filesystem/artifact service.
 /// No session keys or coordinator receipts are serialized into Configuration.
 pub fn run(&self,image:&Image,role:Role,args:&[String],environment:&[(String,String)],channels:&[(RawFd,RawFd)],linker:Option<LinkerPaths>,limits:Limits,cancel:Option<&AtomicBool>)->io::Result<Output>{
  self.run_metered(image,role,args,environment,channels,linker,limits,cancel,Arc::new(AtomicUsize::new(0)))
 }
 pub(crate) fn run_metered(&self,image:&Image,role:Role,args:&[String],environment:&[(String,String)],channels:&[(RawFd,RawFd)],linker:Option<LinkerPaths>,limits:Limits,cancel:Option<&AtomicBool>,total:Arc<AtomicUsize>)->io::Result<Output>{
  self.run_internal(image,role,args,environment,channels,linker,limits,cancel,total,None)
 }
 pub fn run_process(&self,image:&Image,args:&[String],environment:&[(String,String)],channels:&[(RawFd,RawFd)],limits:Limits,cancel:&AtomicBool,process:ProcessConfiguration,input:Vec<u8>)->io::Result<Output>{
  if input.len()>65536{return Err(invalid("process stdin bound"));}self.run_internal(image,Role::Candidate,args,environment,channels,None,limits,Some(cancel),Arc::new(AtomicUsize::new(0)),Some((process,input)))
 }
 fn run_internal(&self,image:&Image,role:Role,args:&[String],environment:&[(String,String)],channels:&[(RawFd,RawFd)],linker:Option<LinkerPaths>,limits:Limits,cancel:Option<&AtomicBool>,total:Arc<AtomicUsize>,process:Option<(ProcessConfiguration,Vec<u8>)>)->io::Result<Output>{
  limits.validate()?;image.verify()?;self.helper.verify()?;
  if image.is_tool()&&role!=Role::Linker{return Err(invalid("trusted tools belong exclusively to the linker service"));}
  if image.is_runtime()!=matches!(role,Role::JavaScript|Role::Wasm){return Err(invalid("optional runtime snapshot and role differ"));}
  if cancel.is_some_and(|value|value.load(Ordering::Acquire)){return Ok(Output{signal:None,exit:None,stdout:vec![],stderr:vec![],failure:Some("native worker cancelled by parent".into()),elapsed_ms:0,usage:None});}
  if args.len()>4096||environment.len()>if process.is_some(){40}else{8}||channels.len()>2{return Err(invalid("bounded native role inputs required"));}
  let role_name=match role{Role::Compiler=>"compiler",Role::Candidate=>"candidate",Role::Linker=>"linker",Role::JavaScript=>"javascript",Role::Wasm=>"wasm"};
  let mut names=std::collections::HashSet::new();
  if process.is_some(){let custom=environment.iter().filter(|(k,_)|!k.starts_with("KELFT_")).cloned().collect::<std::collections::BTreeMap<_,_>>();if !crate::host_channel::environment(&custom){return Err(invalid("invalid process environment"));}}
  for(key,value)in environment{
   if process.is_some()&&!key.starts_with("KELFT_"){if !names.insert(key)||value.contains('\0')||value.len()>4096{return Err(invalid("invalid process environment"));}continue;}
   if key=="DYLD_LIBRARY_PATH"&&role==Role::Linker&&image.is_tool()&&linker.as_ref().is_some_and(|paths|paths.tools.join("lib").to_str()==Some(value.as_str())){if !names.insert(key)||value.contains('\0'){return Err(invalid("invalid measured tool library path"));}continue;}
   if matches!(key.as_str(),"KELFT_ENGINE_PROFILE"|"KELFT_FS_ROOTS")&&image.is_runtime(){if !names.insert(key)||value.contains('\0')||key=="KELFT_ENGINE_PROFILE"&&value!=&format!("{role_name}-kfs/1"){return Err(invalid("invalid optional engine configuration"));}continue;}
   if !names.insert(key)||value.contains('\0')||!matches!(key.as_str(),"KELFT_FS_REQUEST"|"KELFT_FS_RESPONSE"|"KELFT_FS_CWD"|"KELFT_CAPABILITIES"|"KELFT_ARTIFACT_REQUEST"|"KELFT_ARTIFACT_RESPONSE"){return Err(invalid("unapproved native role environment"));}
   if key.starts_with("KELFT_ARTIFACT_")&&role!=Role::Compiler{return Err(invalid("only the compiler receives an artifact channel"));}
   if matches!(key.as_str(),"KELFT_FS_REQUEST"|"KELFT_FS_RESPONSE"|"KELFT_ARTIFACT_REQUEST"|"KELFT_ARTIFACT_RESPONSE"){
    let fd=value.parse::<RawFd>().map_err(|_|invalid("explicit channel descriptor required"))?;if fd<3||!channels.iter().any(|(_,target)|*target==fd){return Err(invalid("channel descriptor is outside the inherited map"));}
   }
  }
  for(_,target)in channels{
   let keys=match *target{3=>["KELFT_FS_REQUEST","KELFT_FS_RESPONSE"],4 if role==Role::Compiler=>["KELFT_ARTIFACT_REQUEST","KELFT_ARTIFACT_RESPONSE"],_=>return Err(invalid("role cannot inherit this channel"))};
   for key in keys{if !environment.iter().any(|(name,value)|name==key&&value==&target.to_string()){return Err(invalid("inherited channel has no matching role configuration"));}}
  }
  if (role==Role::Linker)!=linker.is_some(){return Err(invalid("linker setup differs from role"));}
  let configuration=Configuration{process:process.as_ref().map(|(p,_)|p.clone()),image:image.path().into(),sha256:image.sha256().into(),trusted_tool:image.is_tool(),runtime:image.is_runtime(),engine_inputs:image.runtime_inputs(),role:role_name.into(),args:args.to_vec(),environment:environment.to_vec(),cpu_seconds:limits.wall_ms.div_ceil(1000),linker};
  let mut encoded=serde_json::to_vec(&configuration).map_err(io::Error::other)?;if encoded.len()>1<<20{return Err(invalid("native role configuration exceeds bound"));}encoded.push(b'\n');
  let start=Instant::now();let endpoint=Endpoint::new()?;
  let(mut setup_read,setup_write)=std::os::unix::net::UnixStream::pair()?;let mut inherited=channels.to_vec();inherited.push((setup_write.as_raw_fd(),61));
  let stdin_channel=if process.is_some(){Some(std::os::unix::net::UnixStream::pair()?)}else{None};if let Some((read,_))=&stdin_channel{inherited.push((read.as_raw_fd(),5));}
  let mut child=macos_process::spawn(self.helper.path(),&["--native-worker".into(),endpoint.name().into()],&[],&inherited)?;drop(setup_write);
  child.stdin.as_mut().ok_or_else(||invalid("worker control missing"))?.write_all(&encoded)?;
  let task=endpoint.receive(child.id(),child.id())?;
  let mut guardian=macos_process::spawn(self.helper.path(),&["--native-guardian".into(),std::process::id().to_string(),child.id().to_string()],&[],&[])?;
  let mut readiness=io::BufReader::new(guardian.stdout.take().ok_or_else(||invalid("guardian readiness missing"))?);
  task.export(&line(&mut readiness)?)?;if line(&mut readiness)?!="guardian-ready"{return Err(invalid("guardian readiness differs"));}
  // Until both authenticated owners exist, EOF leaves the helper unable to
  // exec untrusted bytes. The candidate subsequently receives only empty stdin.
  child.stdin.as_mut().ok_or_else(||invalid("worker control missing"))?.write_all(b"E")?;drop(child.stdin.take());
  let overflow=Arc::new(AtomicBool::new(false));
  let stdout=capture_metered(child.stdout.take().ok_or_else(||invalid("stdout capture missing"))?,limits.output_bytes,overflow.clone(),total.clone());
  let stderr=capture_metered(child.stderr.take().ok_or_else(||invalid("stderr capture missing"))?,limits.output_bytes,overflow.clone(),total);
  let process_mode=process.is_some();let writer=match (stdin_channel,process){(Some((read,mut write)),Some((_,input)))=>{drop(read);Some(std::thread::spawn(move||match write.write_all(&input){Ok(())=>Ok(()),Err(e)if e.kind()==io::ErrorKind::BrokenPipe=>Ok(()),Err(e)=>Err(e)}))},_=>None};
  let monitored=(||->io::Result<(std::process::ExitStatus,Option<String>)>{
   setup_read.set_read_timeout(Some(Duration::from_millis(limits.wall_ms.saturating_sub(start.elapsed().as_millis() as u64).max(1))))?;
   let mut setup=vec![];Read::by_ref(&mut setup_read).take(4097).read_to_end(&mut setup)?;
   if !setup.is_empty(){if setup.len()>4096||!setup.starts_with(b"KEX1"){return Err(invalid("native exec status channel is malformed"));}child.kill()?;return Ok((child.wait()?,Some(format!("native worker setup failed: {}",String::from_utf8_lossy(&setup[4..])))));}
   loop{
   let failure=if cancel.is_some_and(|value|value.load(Ordering::Acquire)){Some("native worker cancelled by parent")}
    else if start.elapsed()>=Duration::from_millis(limits.wall_ms){Some("native worker deadline exceeded")}
    else if overflow.load(Ordering::Acquire){Some("native worker capture bound exceeded")}
    else if guardian.try_wait()?.is_some(){Some("native guardian exited before worker")}
    else{None};
   if let Some(reason)=failure{let _=task.terminate();child.kill()?;return Ok((child.wait()?,Some(reason.into())));}
   if let Some(status)=child.try_wait()?{return Ok((status,None));}std::thread::sleep(Duration::from_millis(5));
  }})();
  if monitored.is_err(){let _=task.terminate();let _=child.kill();let _=child.wait();}
  drop(guardian.stdin.take());let guardian_result=wait_guardian(&mut guardian);
  let stdout=stdout.join().map_err(|_|io::Error::other("native stdout capture panicked"))??;
  let stderr=stderr.join().map_err(|_|io::Error::other("native stderr capture panicked"))??;
  if let Some(writer)=writer{writer.join().map_err(|_|io::Error::other("stdin writer panicked"))??;}
  let(status,mut failure)=monitored?;guardian_result?;image.verify()?;self.helper.verify()?;
  if overflow.load(Ordering::Acquire){failure=Some("native worker capture bound exceeded".into());}
  if !process_mode&&failure.is_none()&&!status.success()&&status.code().is_none(){failure=Some(format!("native worker interrupted: {status}: {:?}",child.exit_reason()));}
  use std::os::unix::process::ExitStatusExt;Ok(Output{signal:status.signal(),exit:if failure.is_none(){status.code()}else{None},stdout,stderr,failure,elapsed_ms:start.elapsed().as_millis() as u64,usage:child.usage()})
 }
}
#[cfg(test)]fn capture(input:impl Read+Send+'static,maximum:usize,overflow:Arc<AtomicBool>)->std::thread::JoinHandle<io::Result<Vec<u8>>>{capture_metered(input,maximum,overflow,Arc::new(AtomicUsize::new(0)))}
fn capture_metered(mut input:impl Read+Send+'static,maximum:usize,overflow:Arc<AtomicBool>,total:Arc<AtomicUsize>)->std::thread::JoinHandle<io::Result<Vec<u8>>>{std::thread::spawn(move||{
 let mut out=vec![];let mut chunk=[0;65536];loop{let count=match input.read(&mut chunk){Err(error)if error.kind()==io::ErrorKind::Interrupted=>continue,result=>result?};if count==0{return Ok(out);}let before=total.fetch_add(count,Ordering::AcqRel);let remaining=maximum.saturating_sub(before);out.extend_from_slice(&chunk[..count.min(remaining)]);if count>remaining{overflow.store(true,Ordering::Release);return Ok(out);}}
})}
fn line(input:&mut impl BufRead)->io::Result<String>{let mut text=String::new();let count=input.take(4097).read_line(&mut text)?;if count==0||count>4096||!text.ends_with('\n'){return Err(invalid("bounded trusted helper readiness required"));}Ok(text.trim_end_matches('\n').into())}
fn wait_guardian(child:&mut Child)->io::Result<()>{let start=Instant::now();loop{if let Some(status)=child.try_wait()?{if status.success(){return Ok(());}return Err(io::Error::other(format!("native guardian failed: {status}: {:?}",child.exit_reason())));}if start.elapsed()>Duration::from_secs(3){child.kill()?;child.wait()?;return Err(io::Error::new(io::ErrorKind::TimedOut,"native guardian cleanup exceeded deadline"));}std::thread::sleep(Duration::from_millis(5));}}

/// Internal entry points belong only to the measured native helper executable.
/// Return None for its public host/service commands.
pub fn helper(arguments:&[String])->io::Result<Option<()>>{
 match arguments{
  [mode,endpoint]if mode=="--native-worker"=>{
   if unsafe{libc::geteuid()}==0{return Err(invalid("native worker requires an unprivileged owner"));}
   if unsafe{libc::fcntl(61,libc::F_SETFD,libc::FD_CLOEXEC)}<0{return Err(io::Error::last_os_error());}
   let mut setup=unsafe{std::fs::File::from_raw_fd(61)};
   let attempted=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||->io::Result<Option<()>>{
   let mut input=io::stdin().lock();let mut encoded=String::new();let count=Read::by_ref(&mut input).take((1<<20)+2).read_line(&mut encoded)?;
   if count==0||count>(1<<20)+1||!encoded.ends_with('\n'){return Err(invalid("bounded native worker configuration required"));}
   let configuration:Configuration=serde_json::from_str(&encoded).map_err(io::Error::other)?;
   let image=std::fs::canonicalize(&configuration.image)?;if image!=configuration.image{return Err(invalid("private image path changed"));}
   let maximum=if configuration.runtime{256<<20}else{64<<20};let mut file=std::fs::File::open(&image)?;if file.metadata()?.len()>maximum{return Err(invalid("native image exceeds bound"));}let mut bytes=vec![];Read::by_ref(&mut file).take(maximum+1).read_to_end(&mut bytes)?;
   if configuration.trusted_tool{if configuration.role!="linker"||configuration.runtime{return Err(invalid("tool image is outside linker role"));}crate::macos_format::validate_tool(&bytes,crate::native_target::Target::current()?)?;}else{crate::macos_snapshot::validate_bounded(&bytes,maximum as usize)?;}
   use sha2::{Digest,Sha256};if format!("sha256:{:x}",Sha256::digest(&bytes))!=configuration.sha256{return Err(invalid("native worker image changed"));}drop(bytes);drop(file);
   let role=match configuration.role.as_str(){"compiler"=>Role::Compiler,"candidate"=>Role::Candidate,"linker"=>Role::Linker,"javascript"=>Role::JavaScript,"wasm"=>Role::Wasm,_=>return Err(invalid("native worker role differs"))};
   if configuration.runtime!=matches!(role,Role::JavaScript|Role::Wasm)||configuration.engine_inputs.len()>2||!configuration.runtime&&!configuration.engine_inputs.is_empty(){return Err(invalid("native runtime role differs"));}
   for(path,expected)in &configuration.engine_inputs{use std::os::unix::fs::{OpenOptionsExt,MetadataExt};if path.parent()!=image.parent(){return Err(invalid("engine input outside snapshot"));}let mut file=std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW|libc::O_CLOEXEC|libc::O_NONBLOCK).open(path)?;let metadata=file.metadata()?;if !metadata.is_file()||metadata.len()>64<<20||metadata.nlink()!=1||metadata.mode()&0o7777!=0o400||metadata.uid()!=unsafe{libc::geteuid()}{return Err(invalid("immutable engine input required"));}let mut bytes=vec![];Read::by_ref(&mut file).take((64<<20)+1).read_to_end(&mut bytes)?;if format!("sha256:{:x}",Sha256::digest(bytes))!=*expected{return Err(invalid("engine input changed"));}}
   macos_task::export_self(endpoint)?;let mut release=[0];input.read_exact(&mut release)?;if release!=[b'E']{return Err(invalid("protected native worker release missing"));}drop(input);
   let linker=configuration.linker.as_ref().map(|paths|macos_seatbelt::LinkerPaths{sdk:&paths.sdk,tools:&paths.tools,object:&paths.object,output:&paths.output});
   let limits=macos_seatbelt::Limits::native(configuration.cpu_seconds)?;let prepared=if configuration.runtime{if linker.is_some(){return Err(invalid("optional engine cannot receive linker inputs"));}std::env::set_current_dir(image.parent().ok_or_else(||invalid("private engine directory required"))?)?;Prepared::engine(role,&image,&configuration.engine_inputs.iter().map(|(path,_)|path.clone()).collect::<Vec<_>>(),limits)?}else if let Some(process)=&configuration.process{if role!=Role::Candidate{return Err(invalid("process role mismatch"));}std::env::set_current_dir(&process.cwd)?;if unsafe{libc::dup2(5,0)}<0{return Err(io::Error::last_os_error());}unsafe{libc::close(5)};Prepared::bounded_candidate(&image,&process.cwd,process.memory_bytes,configuration.cpu_seconds)?}else{Prepared::new(role,&image,linker,limits)?};prepared.enter()?;
   Err(Command::new(image).args(configuration.args).env_clear().envs(configuration.environment).exec())
   }));
   let result=attempted.unwrap_or_else(|_|Err(io::Error::other("native worker setup panicked")));
   if let Err(error)=&result{let text=error.to_string();let mut frame=b"KEX1".to_vec();frame.extend_from_slice(&text.as_bytes()[..text.len().min(4092)]);let _=setup.write_all(&frame);}
   result
  }
  [mode,sender,pid]if mode=="--native-guardian"=>{
   let sender=sender.parse().map_err(|_|invalid("guardian sender required"))?;let pid=pid.parse().map_err(|_|invalid("guardian task required"))?;
   let endpoint=Endpoint::new()?;println!("{}",endpoint.name());io::stdout().flush()?;let task=endpoint.receive(sender,pid)?;println!("guardian-ready");io::stdout().flush()?;
   let mut byte=[0];let _=io::stdin().read(&mut byte);task.terminate()?;task.wait_dead(Duration::from_secs(2))?;Ok(Some(()))
  }
  _=>Ok(None)
 }
}

#[cfg(test)]mod tests{
 use super::*;
 #[test]fn capture_stops_at_the_exact_bound_and_reports_overflow(){
  let overflow=Arc::new(AtomicBool::new(false));let result=capture(io::Cursor::new(vec![42;65537]),65536,overflow.clone()).join().unwrap().unwrap();assert_eq!(result,vec![42;65536]);assert!(overflow.load(Ordering::Acquire));
  let overflow=Arc::new(AtomicBool::new(false));let result=capture(io::Cursor::new(vec![42;65536]),65536,overflow.clone()).join().unwrap().unwrap();assert_eq!(result.len(),65536);assert!(!overflow.load(Ordering::Acquire));
 }
 #[test]fn supervision_bounds_cannot_be_implicitly_enlarged(){
  for limits in [Limits{wall_ms:0,output_bytes:1},Limits{wall_ms:600001,output_bytes:1},Limits{wall_ms:1,output_bytes:0},Limits{wall_ms:1,output_bytes:(16<<20)+1}]{assert!(limits.validate().is_err());}Limits{wall_ms:600000,output_bytes:16<<20}.validate().unwrap();
 }
 #[test]fn stdout_stderr_and_engine_sink_use_one_capture_budget(){
  let total=Arc::new(AtomicUsize::new(5));let overflow=Arc::new(AtomicBool::new(false));let bytes=capture_metered(io::Cursor::new(vec![42;4]),8,overflow.clone(),total.clone()).join().unwrap().unwrap();assert_eq!(bytes.len(),3);assert!(overflow.load(Ordering::Acquire));assert_eq!(total.load(Ordering::Acquire),9);
 }
}
