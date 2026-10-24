//! Parent-owned KAR1 service. Only a compiler receives this channel; candidates
//! receive capture pipes and explicitly granted filesystem roots, never the
//! compiler channel, compiler source grants or transaction keys.
use crate::{native_artifact_channel as channel,native_target::Target,windows_process::AppContainerSid,windows_snapshot::Image,windows_supervisor::{self,Limits}};
use sha2::{Digest,Sha256};
use std::{io::{self,Read,Write},sync::{Arc,atomic::{AtomicBool,Ordering}}};

/// Standalone candidate route for development collectors. It authenticates the
/// image and grants no source roots, linker access or compiler-channel handles.
pub fn run_candidate(bytes:&[u8],expected:&str,system_root:&str,args:&[String],limits:Limits)->io::Result<windows_supervisor::Output>{
 let identity=AppContainerSid::fresh()?;let image=Image::new(bytes,expected,&identity).map_err(|error|role_error("candidate snapshot",expected,error))?;
 crate::windows_filesystem_session::run(&image,&identity,system_root,args,limits,&[],std::path::Path::new(system_root),&[],vec![],None).map_err(|error|role_error("candidate execution",expected,error))
}

/// Explicit compiler role. The authenticated image receives the artifact
/// channel; the nested candidate branch never receives those handles.
pub fn run_compiler(bytes:&[u8],expected:&str,system_root:&str,args:&[String],compiler_limits:Limits,candidate_limits:Limits)->io::Result<windows_supervisor::Output>{
 run_compiler_role(bytes,expected,system_root,args,compiler_limits,candidate_limits,None,None,None)
}
pub fn run_compiler_with_filesystem(bytes:&[u8],expected:&str,system_root:&str,args:&[String],compiler_limits:Limits,candidate_limits:Limits,grants:&[crate::windows_filesystem_session::Grant],program_grants:&[crate::windows_filesystem_session::Grant],cwd:&std::path::Path)->io::Result<windows_supervisor::Output>{
 run_compiler_role(bytes,expected,system_root,args,compiler_limits,candidate_limits,Some((grants,program_grants,cwd)),None,None)
}
pub fn run_compiler_with_services(bytes:&[u8],expected:&str,system_root:&str,args:&[String],compiler_limits:Limits,candidate_limits:Limits,grants:&[crate::windows_filesystem_session::Grant],program_grants:&[crate::windows_filesystem_session::Grant],cwd:&std::path::Path,linker:Option<crate::windows_linker::Linker>)->io::Result<windows_supervisor::Output>{
 run_compiler_role(bytes,expected,system_root,args,compiler_limits,candidate_limits,Some((grants,program_grants,cwd)),linker,None)
}
pub fn run_compiler_mapped(bytes:&[u8],expected:&str,system_root:&str,args:&[String],compiler_limits:Limits,candidate_limits:Limits,grants:&[crate::windows_filesystem_session::MappedGrant],program_grants:&[crate::windows_filesystem_session::MappedGrant],cwd:&str,linker:Option<crate::windows_linker::Linker>)->io::Result<windows_supervisor::Output>{
 run_compiler_role(bytes,expected,system_root,args,compiler_limits,candidate_limits,None,linker,Some((grants,program_grants,cwd)))
}
fn run_compiler_role(bytes:&[u8],expected:&str,system_root:&str,args:&[String],compiler_limits:Limits,candidate_limits:Limits,filesystem:Option<(&[crate::windows_filesystem_session::Grant],&[crate::windows_filesystem_session::Grant],&std::path::Path)>,linker:Option<crate::windows_linker::Linker>,mappings:Option<(&[crate::windows_filesystem_session::MappedGrant],&[crate::windows_filesystem_session::MappedGrant],&str)>)->io::Result<windows_supervisor::Output>{
 let identity=AppContainerSid::fresh()?;let image=Image::new(bytes,expected,&identity).map_err(|error|role_error("compiler snapshot",expected,error))?;
 let cancel=Arc::new(AtomicBool::new(false));let mut service=Service::new(system_root.into(),cancel.clone(),candidate_limits);
 service.linker=linker;
 if let Some((grants,_,_))=filesystem{service.linker_authority=grants.iter().filter(|grant|grant.write).cloned().collect();}
 service.protected.push(image.directory().to_path_buf());
 if let Some((grants,program,cwd))=mappings{crate::windows_filesystem_session::guest_name(cwd)?;service.linker_authority=grants.iter().filter(|mapping|mapping.grant.write).map(|mapping|mapping.grant.clone()).collect();service.linker_mappings=Some(grants.to_vec());service.program_mappings=Some(program.to_vec());service.guest_cwd=Some(cwd.into());for mapping in program{let grant=&mapping.grant;if crate::windows_filesystem_session::within(image.directory(),&grant.path)?||crate::windows_filesystem_session::within(&grant.path,image.directory())?{return Err(io::Error::from(io::ErrorKind::PermissionDenied));}service.authority_roots.add_root(&grant.path,grant.read,grant.write)?;}}
 if let Some((_,program_grants,cwd))=filesystem{service.authority=program_grants.to_vec();service.cwd=cwd.to_path_buf();for grant in program_grants{if crate::windows_filesystem_session::within(image.directory(),&grant.path)?||crate::windows_filesystem_session::within(&grant.path,image.directory())?{return Err(io::Error::from(io::ErrorKind::PermissionDenied));}let path=crate::windows_filesystem_session::normalized(&grant.path)?;service.authority_roots.add_root(std::path::Path::new(&path),grant.read,grant.write)?;}}
 let(mut requests,request_write)=windows_supervisor::pipe()?;let(response_read,mut responses)=windows_supervisor::pipe()?;
 let thread=std::thread::Builder::new().name("kelft-artifact-service".into()).spawn(move||service.serve_compiler(&mut requests,&mut responses))?;
 let controls=vec![("KELFT_ARTIFACT_REQUEST".into(),request_write),("KELFT_ARTIFACT_RESPONSE".into(),response_read)];
 let result=if let Some((grants,_,cwd))=mappings{crate::windows_filesystem_session::run_mapped(&image,&identity,system_root,args,compiler_limits,grants,cwd,&[],controls,None)}else if let Some((grants,_,cwd))=filesystem{crate::windows_filesystem_session::run(&image,&identity,system_root,args,compiler_limits,grants,cwd,&[],controls,None)}else{windows_supervisor::run(&image,&identity,system_root,args,compiler_limits,&[],controls)};
 cancel.store(true,Ordering::Release);
 let service=thread.join().map_err(|_|io::Error::other("artifact service panicked"))?;
 // A compiler death can truncate its frame or close the response pipe. Preserve
 // the compiler's boundary failure; otherwise a protocol error is fatal.
 match result{Ok(output)if output.failure.is_some()=>Ok(output),Ok(output)=>{service?;Ok(output)},Err(error)=>Err(role_error("compiler execution",expected,error))}
}

fn role_error(role:&str,hash:&str,error:io::Error)->io::Error{io::Error::new(error.kind(),format!("{role} {hash}: {error}"))}

pub struct Service {system_root:String,cancel:Arc<AtomicBool>,limits:Limits,authority:Vec<crate::windows_filesystem_session::Grant>,authority_roots:crate::windows_filesystem::Broker,protected:Vec<std::path::PathBuf>,cwd:std::path::PathBuf,linker:Option<crate::windows_linker::Linker>,linker_authority:Vec<crate::windows_filesystem_session::Grant>,linker_mappings:Option<Vec<crate::windows_filesystem_session::MappedGrant>>,program_mappings:Option<Vec<crate::windows_filesystem_session::MappedGrant>>,guest_cwd:Option<String>}
impl Service {
 pub fn new(system_root:String,cancel:Arc<AtomicBool>,limits:Limits)->Self{let cwd=std::path::PathBuf::from(&system_root);Self{system_root,cancel,limits,authority:vec![],authority_roots:crate::windows_filesystem::Broker::default(),protected:vec![],cwd,linker:None,linker_authority:vec![],linker_mappings:None,program_mappings:None,guest_cwd:None}}
 pub fn execute(&self,mut request:channel::Request)->io::Result<channel::Response>{
  let reject=|status|Ok(channel::Response{status,stdout:vec![],stderr:vec![]});
  if self.cancel.load(Ordering::Acquire){return reject(-3);}
  if request.target==format!("linker-{}-v1",Target::current()?.id()){
   if let Some(mappings)=&self.linker_mappings{if request.args.len()!=2||!request.read.is_empty()||request.write!=[request.args[0].clone()]{return reject(-2);}let path=match crate::windows_filesystem_session::mapped_path(&request.args[0],true,mappings){Ok(grant)=>grant.path,Err(_)=>return reject(-2)};let path=crate::windows_filesystem_session::normalized(&path)?;request.args[0]=path.clone();request.write=vec![path];}
   return match &self.linker{Some(linker)=>linker.execute(&request,&self.system_root,&self.cancel,&self.linker_authority,&self.protected),None=>reject(-1)};
  }
  if request.target!=Target::current()?.artifact(){return reject(-1);}
  let mapped=match &self.program_mappings{Some(mappings)=>match crate::windows_filesystem_session::delegated_mapped(&request.read,&request.write,mappings){Ok(value)=>Some(value),Err(_)=>return reject(-2)},None=>None};
  let grants=if let Some(mapped)=&mapped{mapped.iter().map(|mapping|mapping.grant.clone()).collect()}else{match crate::windows_filesystem_session::delegated(&request.read,&request.write,&self.authority){Ok(value)=>value,Err(_)=>return reject(-2)}};
  if crate::windows_snapshot::validate(&request.image).is_err(){return reject(-4);}
  let identity=AppContainerSid::fresh()?;
  let hash=format!("sha256:{:x}",Sha256::digest(&request.image));
  let image=Image::new(&request.image,&hash,&identity).map_err(|error|role_error("candidate snapshot",&hash,error))?;
  for grant in &grants{for private in self.protected.iter().map(std::path::PathBuf::as_path).chain([image.directory()]){if crate::windows_filesystem_session::within(private,&grant.path)?||crate::windows_filesystem_session::within(&grant.path,private)?{return reject(-2);}}}
  let result=if let Some(mapped)=&mapped{crate::windows_filesystem_session::run_mapped(&image,&identity,&self.system_root,&request.args,self.limits,mapped,self.guest_cwd.as_deref().ok_or_else(||io::Error::other("missing candidate guest cwd"))?,&[],vec![],Some(&self.cancel))}else{crate::windows_filesystem_session::run(&image,&identity,&self.system_root,&request.args,self.limits,&grants,&self.cwd,&[],vec![],Some(&self.cancel))}.map_err(|error|role_error("candidate execution",&hash,error))?;
  if result.failure.is_some(){return reject(-3);}
  if std::str::from_utf8(&result.stdout).is_err()||std::str::from_utf8(&result.stderr).is_err(){return reject(-3);}
  Ok(channel::Response{status:result.exit.ok_or_else(||io::Error::other("native artifact missing exit"))? as i32,stdout:result.stdout,stderr:result.stderr})
 }
 /// The caller owns the compiler's pipe ends and lifetime. A malformed frame
 /// poisons the connection. Cancellation terminates an in-flight candidate.
 pub fn serve_compiler(&self,input:&mut impl Read,output:&mut impl Write)->io::Result<()>{
  while let Some(request)=channel::read_request(input)?{
   let response=self.execute(request)?;channel::write_response(output,&response)?;
  }Ok(())
 }
}

#[cfg(test)]mod tests {
 use super::*;
 use std::{fs::File,os::windows::io::FromRawHandle};
 fn inherited(name:&str)->File{unsafe{File::from_raw_handle(std::env::var(name).unwrap().parse::<usize>().unwrap() as _)}}
 fn request(image:Vec<u8>,args:&[&str])->channel::Request{channel::Request{target:Target::current().unwrap().artifact().into(),args:args.iter().map(|s|s.to_string()).collect(),read:vec![],write:vec![],image}}
 #[test]fn private_compiler_worker(){
  if std::env::var_os("KELFT_ARTIFACT_REQUEST").is_none(){return;}
  let mut output=inherited("KELFT_ARTIFACT_REQUEST");let mut input=inherited("KELFT_ARTIFACT_RESPONSE");
  if let Ok(root)=std::env::var("KELFT_FS_CWD"){
   use crate::filesystem_channel::{self as rpc,Operation,Request};let mut fs_out=inherited("KELFT_FS_REQUEST");let mut fs_in=inherited("KELFT_FS_RESPONSE");
   let request=Request{sequence:1,operation:Operation::OpenRead,handle:1,path:"input".into(),amount:0,data:vec![]};rpc::write_request(&mut fs_out,&request).unwrap();let opened=rpc::read_response(&mut fs_in,1).unwrap();assert_eq!(opened.status,0);assert_eq!(opened.data,3u64.to_le_bytes());
   let request=Request{sequence:2,operation:Operation::Read,handle:opened.value,path:String::new(),amount:3,data:vec![]};rpc::write_request(&mut fs_out,&request).unwrap();assert_eq!(rpc::read_response(&mut fs_in,2).unwrap().data,[0,255,128]);
   let request=Request{sequence:3,operation:Operation::Close,handle:opened.value,path:String::new(),amount:0,data:vec![]};rpc::write_request(&mut fs_out,&request).unwrap();assert_eq!(rpc::read_response(&mut fs_in,3).unwrap().status,0);
   let mut denied=self::request(vec![],&[]);denied.read.push(root);channel::write_request(&mut output,&denied).unwrap();assert_eq!(channel::read_response(&mut input).unwrap().status,-2,"compiler source authority must not become program authority");
  }
  let bytes=std::fs::read(std::path::Path::new(&std::env::var("SystemRoot").unwrap()).join("System32/cmd.exe")).expect("OS image read positive control");
  channel::write_request(&mut output,&request(bytes,&["/d","/q","/c","if defined KELFT_ARTIFACT_REQUEST (exit /b 93) else (echo compiler-channel-candidate-ok& exit /b 42)"])).unwrap();
  let response=channel::read_response(&mut input).unwrap();assert_eq!(response.status,42);assert_eq!(response.stdout,b"compiler-channel-candidate-ok\r\n");assert!(response.stderr.is_empty());
  let mut denied=request(vec![],&[]);denied.target="linker-windows-x86_64-v1".into();channel::write_request(&mut output,&denied).unwrap();assert_eq!(channel::read_response(&mut input).unwrap().status,-1);
  println!("native-compiler-artifact-channel-ok");
 }
 #[test]fn private_malformed_compiler_worker(){
  if std::env::var_os("KELFT_ARTIFACT_REQUEST").is_none(){return;}
  inherited("KELFT_ARTIFACT_REQUEST").write_all(b"BAD!").unwrap();
 }
 #[test]fn native_compiler_channel_runs_separate_candidates_and_poisoned_frames_fail(){
  let system=std::env::var("SystemRoot").unwrap();let bytes=std::fs::read(std::env::current_exe().unwrap()).unwrap();let hash=format!("sha256:{:x}",Sha256::digest(&bytes));let limits=Limits{wall_ms:15000,memory_bytes:268435456,output_bytes:65536};
  let args=["--exact","windows_artifact::tests::private_compiler_worker","--nocapture"].map(String::from);let result=run_compiler(&bytes,&hash,&system,&args,limits,limits).unwrap();assert_eq!(result.exit,Some(0),"{:?}: {}{}",result.failure,String::from_utf8_lossy(&result.stdout),String::from_utf8_lossy(&result.stderr));assert!(String::from_utf8_lossy(&result.stdout).contains("native-compiler-artifact-channel-ok"));
  let mut entropy=[0;16];getrandom::fill(&mut entropy).unwrap();let root=std::env::temp_dir().join(format!("kelft-role-fs-{:x}",u128::from_le_bytes(entropy)));std::fs::create_dir(&root).unwrap();std::fs::write(root.join("input"),[0,255,128]).unwrap();let grants=[crate::windows_filesystem_session::Grant{path:root.clone(),read:true,write:false}];
  let result=run_compiler_with_filesystem(&bytes,&hash,&system,&args,limits,limits,&grants,&[],&root).unwrap();assert_eq!(result.exit,Some(0),"{:?}: {}{}",result.failure,String::from_utf8_lossy(&result.stdout),String::from_utf8_lossy(&result.stderr));std::fs::remove_dir_all(root).unwrap();
  let args=["--exact","windows_artifact::tests::private_malformed_compiler_worker","--nocapture"].map(String::from);assert!(run_compiler(&bytes,&hash,&system,&args,limits,limits).is_err());
 }
 #[test]fn parent_cancellation_terminates_an_in_flight_native_artifact(){
  let system=std::env::var("SystemRoot").unwrap();let bytes=std::fs::read(std::path::Path::new(&system).join("System32/cmd.exe")).unwrap();let identity=AppContainerSid::fresh().unwrap();let hash=format!("sha256:{:x}",Sha256::digest(&bytes));let image=Image::new(&bytes,&hash,&identity).unwrap();
  let cancel=AtomicBool::new(false);let start=std::time::Instant::now();std::thread::scope(|scope|{
   scope.spawn(||{std::thread::sleep(std::time::Duration::from_millis(200));cancel.store(true,Ordering::Release);});
   let args=["/d","/q","/c","for /l %i in (1,1,2147483647) do @rem cancelled"].map(String::from);let result=windows_supervisor::run_cancellable(&image,&identity,&system,&args,Limits{wall_ms:15000,memory_bytes:268435456,output_bytes:65536},&[],vec![],Some(&cancel)).unwrap();assert_eq!(result.failure.as_deref(),Some("native worker cancelled by parent"));assert!(result.exit.is_none());
  });assert!(start.elapsed()<std::time::Duration::from_secs(5));
 }
 #[test]fn native_artifact_service_executes_and_refuses_other_roles_roots_and_images(){
  let system=std::env::var("SystemRoot").unwrap();let bytes=std::fs::read(std::path::Path::new(&system).join("System32/cmd.exe")).unwrap();
  let cancel=Arc::new(AtomicBool::new(false));let service=Service::new(system,cancel.clone(),Limits{wall_ms:10000,memory_bytes:268435456,output_bytes:65536});
  let args=["/d","/q","/c","if defined KELFT_ARTIFACT_REQUEST (exit /b 93) else (echo artifact-service-ok& exit /b 42)"];
  let mut wire=vec![];channel::write_request(&mut wire,&request(bytes.clone(),&args)).unwrap();let mut response=vec![];service.serve_compiler(&mut wire.as_slice(),&mut response).unwrap();let response=channel::read_response(&mut response.as_slice()).unwrap();assert_eq!(response.status,42);assert_eq!(response.stdout,b"artifact-service-ok\r\n");assert!(response.stderr.is_empty());
  let mut changed=request(bytes.clone(),&args);changed.target="linker-windows-x86_64-v1".into();assert_eq!(service.execute(changed).unwrap().status,-1);
  let mut changed=request(bytes.clone(),&args);changed.read.push("C:\\".into());assert_eq!(service.execute(changed).unwrap().status,-2);
  assert_eq!(service.execute(request(vec![0;512],&[])).unwrap().status,-4);
  cancel.store(true,Ordering::Release);assert_eq!(service.execute(request(bytes,&args)).unwrap().status,-3);
 }
}
