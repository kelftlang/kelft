//! KAR1 service owned by the compiler's parent. Candidate filesystem authority
//! is supplied independently; candidates never inherit the compiler channel.
use crate::{native_artifact_channel as channel,native_target::Target,macos_snapshot::Image,macos_supervisor::{Host,Limits,Output},macos_filesystem_session::{self as filesystem,Grant},macos_seatbelt::Role};
use sha2::{Digest,Sha256};
use std::{io::{self,Read,Write},os::fd::AsRawFd,path::{Path,PathBuf},sync::{Arc,atomic::{AtomicBool,Ordering}},time::Duration};
pub struct Service<'a>{host:&'a Host,base:&'a Path,authority:&'a [Grant],compiler_authority:&'a [Grant],linker:Option<&'a crate::macos_linker::Linker>,private:Vec<PathBuf>,cwd:&'a str,limits:Limits,cancel:Arc<AtomicBool>}
impl Service<'_>{
 pub fn execute(&self,request:channel::Request)->io::Result<channel::Response>{
  let reject=|status|Ok(channel::Response{status,stdout:vec![],stderr:vec![]});
  if self.cancel.load(Ordering::Acquire){return reject(-3);}
  if request.target==format!("linker-{}-v1",Target::current()?.id()){return match self.linker{Some(linker)=>linker.execute(self.host,self.base,&request,self.compiler_authority,&self.private,&self.cancel),None=>reject(-1)};}
  if request.target!=Target::current()?.artifact(){return reject(-1);}
  let grants=match filesystem::delegated(&request.read,&request.write,self.authority){Ok(value)=>value,Err(_)=>return reject(-2)};
  if crate::macos_snapshot::validate(&request.image).is_err(){return reject(-4);}
  let expected=format!("sha256:{:x}",Sha256::digest(&request.image));let image=Image::new(&request.image,&expected,self.base)?;
  let output=filesystem::run(self.host,&image,Role::Candidate,&request.args,self.limits,&grants,self.cwd,&[],&[],None,&self.private,self.cancel.clone())?;
  if output.failure.is_some()||std::str::from_utf8(&output.stdout).is_err()||std::str::from_utf8(&output.stderr).is_err(){return reject(-3);}
  Ok(channel::Response{status:output.exit.ok_or_else(||io::Error::other("native candidate exit missing"))?,stdout:output.stdout,stderr:output.stderr})
 }
 pub fn serve(&self,input:&mut impl Read,output:&mut impl Write)->io::Result<()>{while let Some(request)=channel::read_request(input)?{channel::write_response(output,&self.execute(request)?)?;}Ok(())}
}
pub fn run_compiler(host:&Host,image:&Image,base:&Path,args:&[String],compiler_limits:Limits,candidate_limits:Limits,compiler_grants:&[Grant],program_grants:&[Grant],cwd:&str,private:&[PathBuf])->io::Result<Output>{
 run_compiler_with_linker(host,image,base,args,compiler_limits,candidate_limits,compiler_grants,program_grants,cwd,private,None)
}
pub fn run_compiler_with_linker(host:&Host,image:&Image,base:&Path,args:&[String],compiler_limits:Limits,candidate_limits:Limits,compiler_grants:&[Grant],program_grants:&[Grant],cwd:&str,private:&[PathBuf],linker:Option<&crate::macos_linker::Linker>)->io::Result<Output>{
 filesystem::guest_name(cwd)?;let(mut requests,client)=std::os::unix::net::UnixStream::pair()?;let timeout=Some(Duration::from_millis(compiler_limits.wall_ms.max(1)));requests.set_write_timeout(timeout)?;
 let cleanup=requests.try_clone()?;let cancel=Arc::new(AtomicBool::new(false));let mut protected=private.to_vec();protected.push(image.directory().into());if let Some(linker)=linker{protected.extend(linker.protected().map(Path::to_path_buf));}
 std::thread::scope(|scope|{
  let compiler_private=protected.clone();let service=Service{host,base,authority:program_grants,compiler_authority:compiler_grants,linker,private:protected,cwd,limits:candidate_limits,cancel:cancel.clone()};let poisoned=cancel.clone();
  let thread=scope.spawn(move||{let mut responses=requests.try_clone()?;let result=service.serve(&mut requests,&mut responses);if result.is_err(){poisoned.store(true,Ordering::Release);}result});
  let env=[("KELFT_ARTIFACT_REQUEST".into(),"4".into()),("KELFT_ARTIFACT_RESPONSE".into(),"4".into())];
  let result=filesystem::run(host,image,Role::Compiler,args,compiler_limits,compiler_grants,cwd,&env,&[(client.as_raw_fd(),4)],None,&compiler_private,cancel.clone());
  cancel.store(true,Ordering::Release);drop(client);let shutdown=cleanup.shutdown(std::net::Shutdown::Both);let served=thread.join().map_err(|_|io::Error::other("native artifact service panicked"))?;
  if let Err(error)=shutdown{if error.raw_os_error()!=Some(libc::ENOTCONN){return Err(error);}}
  match result{Ok(output)if output.failure.is_some()=>Ok(output),Ok(output)=>{served?;Ok(output)},Err(error)=>Err(error)}
 })
}
