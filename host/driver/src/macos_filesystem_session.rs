//! One role's retained filesystem roots, independent of its execution channel.
//! Guest names never enter host path parsing without an explicit mapping.
use crate::{unix_filesystem::Broker,macos_snapshot::Image,macos_supervisor::{Host,Limits,Output,LinkerPaths},macos_seatbelt::Role};
use std::{io,os::fd::{AsRawFd,RawFd},path::{Path,PathBuf},sync::{Arc,atomic::{AtomicBool,Ordering}},time::Duration};
pub use crate::unix_host::Grant;
fn invalid(message:&'static str)->io::Error{io::Error::new(io::ErrorKind::InvalidInput,message)}
pub fn guest_name(name:&str)->io::Result<&str>{
 if !name.starts_with('/')||name.contains(['\\',':','\0'])||name!="/"&&name[1..].split('/').any(|part|part.is_empty()||matches!(part,"."|"..")){return Err(invalid("normalized absolute guest name required"));}Ok(name)
}
fn host_name(path:&Path)->io::Result<&str>{let text=path.to_str().ok_or_else(||invalid("Unicode host path required"))?;if !path.is_absolute()||text=="/"||text.contains('\0')||text[1..].split('/').any(|part|part.is_empty()||matches!(part,"."|"..")){return Err(invalid("normalized host path required"));}Ok(text)}
pub fn mapped_path(name:&str,writing:bool,grants:&[Grant])->io::Result<PathBuf>{
 guest_name(name)?;let mut selected:Option<(&Grant,&str)>=None;
 for grant in grants{guest_name(&grant.guest)?;host_name(&grant.path)?;if !(if writing{grant.write}else{grant.read}){continue;}
  let tail=if name==grant.guest{Some("")}else if grant.guest=="/"{Some(&name[1..])}else{name.strip_prefix(&grant.guest).and_then(|value|value.strip_prefix('/'))};
  if let Some(tail)=tail{if selected.is_none_or(|(old,_)|grant.guest.len()>old.guest.len()){selected=Some((grant,tail));}}
 }
 let(grant,tail)=selected.ok_or_else(||io::Error::from(io::ErrorKind::PermissionDenied))?;let mut path=grant.path.clone();for component in tail.split('/').filter(|part|!part.is_empty()){path.push(component);}host_name(&path)?;Ok(path)
}
pub fn delegated(read:&[String],write:&[String],authority:&[Grant])->io::Result<Vec<Grant>>{
 if read.len()+write.len()>128{return Err(invalid("filesystem root budget exceeded"));}let mut grants=std::collections::BTreeMap::<String,Grant>::new();
 for(paths,writing)in [(read,false),(write,true)]{for guest in paths{let path=mapped_path(guest,writing,authority)?;if let Some(old)=grants.get_mut(guest){if old.path!=path{return Err(invalid("inconsistent read/write guest mapping"));}old.read|=!writing;old.write|=writing;}else{grants.insert(guest.clone(),Grant{guest:guest.clone(),path,read:!writing,write:writing});}}}Ok(grants.into_values().collect())
}
fn protected(path:&Path,private:&Path)->bool{path.starts_with(private)||private.starts_with(path)}
pub fn run(host:&Host,image:&Image,role:Role,args:&[String],limits:Limits,grants:&[Grant],cwd:&str,environment:&[(String,String)],channels:&[(RawFd,RawFd)],linker:Option<LinkerPaths>,private:&[PathBuf],cancel:Arc<AtomicBool>)->io::Result<Output>{
 run_policy(host,image,role,args,limits,grants,cwd,environment,channels,linker,private,cancel,None,None)
}
pub fn run_process(host:&Host,image:&Image,args:&[String],limits:Limits,grants:&[Grant],cwd:&str,environment:&[(String,String)],_base:&Path,process:crate::macos_supervisor::ProcessConfiguration,input:Vec<u8>,cancel:Arc<AtomicBool>)->io::Result<Output>{
 run_policy(host,image,Role::Candidate,args,limits,grants,cwd,environment,&[],None,&[],cancel,None,Some((process,input)))
}
pub fn run_policy(host:&Host,image:&Image,role:Role,args:&[String],limits:Limits,grants:&[Grant],cwd:&str,environment:&[(String,String)],channels:&[(RawFd,RawFd)],linker:Option<LinkerPaths>,private:&[PathBuf],cancel:Arc<AtomicBool>,policy:Option<crate::host_channel::Policy>,process:Option<(crate::macos_supervisor::ProcessConfiguration,Vec<u8>)>)->io::Result<Output>{
 run_policy_context(host,image,role,args,limits,grants,cwd,environment,channels,linker,private,cancel,policy,process,None)
}
pub fn run_policy_context(host:&Host,image:&Image,role:Role,args:&[String],limits:Limits,grants:&[Grant],cwd:&str,environment:&[(String,String)],channels:&[(RawFd,RawFd)],linker:Option<LinkerPaths>,private:&[PathBuf],cancel:Arc<AtomicBool>,policy:Option<crate::host_channel::Policy>,process:Option<(crate::macos_supervisor::ProcessConfiguration,Vec<u8>)>,installed:Option<&crate::macos_host::Installed>)->io::Result<Output>{
 guest_name(cwd)?;if grants.len()>128{return Err(invalid("filesystem mapping budget exceeded"));}let mut seen=std::collections::HashSet::new();let mut ordered=grants.to_vec();ordered.sort_by_key(|grant|std::cmp::Reverse(grant.guest.len()));
 for grant in &ordered{
  guest_name(&grant.guest)?;host_name(&grant.path)?;if !seen.insert(grant.guest.clone())||!grant.read&&!grant.write{return Err(invalid("duplicate or empty guest mapping"));}
  for root in private.iter().map(PathBuf::as_path).chain([host.directory(),image.directory()]){host_name(root)?;if protected(&grant.path,root){return Err(io::Error::from(io::ErrorKind::PermissionDenied));}}
 }
 let mut broker=Broker::default();let(mut read,mut write)=(vec![],vec![]);
 // KFS1 root tokens follow read roots first, then write roots. A mapping that
 // allows both operations still receives separately authorized root handles.
 for writing in [false,true]{for grant in &ordered{if if writing{grant.write}else{grant.read}{broker.add_root(&grant.path,!writing,writing)?;if writing{write.push(grant.guest.clone());}else{read.push(grant.guest.clone());}}}}
 let(mut server,client)=std::os::unix::net::UnixStream::pair()?;let timeout=Some(Duration::from_millis(limits.wall_ms.max(1)));server.set_write_timeout(timeout)?;let cleanup=server.try_clone()?;let failed=cancel.clone();
 let expected=crate::host_channel::Policy{read:read.clone(),write:write.clone(),execute:false,process:vec![]};let caller=policy.unwrap_or(expected.clone());if caller.read.iter().collect::<std::collections::BTreeSet<_>>()!=expected.read.iter().collect::<std::collections::BTreeSet<_>>()||caller.write.iter().collect::<std::collections::BTreeSet<_>>()!=expected.write.iter().collect::<std::collections::BTreeSet<_>>()||caller.execute{return Err(io::Error::from(io::ErrorKind::PermissionDenied));}
 let mut services=crate::unix_host::Server::new(caller,ordered.clone(),cwd.into())?;let deadline=std::time::Instant::now()+Duration::from_millis(limits.wall_ms);let process_cancel=cancel.clone();let base=image.directory().parent().ok_or_else(||invalid("snapshot parent missing"))?;
 std::thread::scope(|scope|{
 let service=std::thread::Builder::new().name("kelft-filesystem-service".into()).spawn_scoped(scope,move||{let mut output=server.try_clone()?;let result=crate::filesystem_channel::serve_host(&mut server,&mut output,|request|broker.execute(request),|raw|services.dispatch(raw,|r,profile,grants|crate::macos_host::execute(host,base,r,profile,grants,deadline,process_cancel.clone(),installed)));if result.is_err(){failed.store(true,Ordering::Release);}result})?;
 let mut env=environment.to_vec();env.extend([("KELFT_FS_REQUEST".into(),"3".into()),("KELFT_FS_RESPONSE".into(),"3".into()),("KELFT_FS_CWD".into(),cwd.into()),("KELFT_CAPABILITIES".into(),serde_json::json!({"execute":false,"read":read,"write":write}).to_string())]);
 let mut inherited=channels.to_vec();inherited.push((client.as_raw_fd(),3));let result=if let Some((configuration,input))=process{host.run_process(image,args,&env,&inherited,limits,&cancel,configuration,input)}else{host.run(image,role,args,&env,&inherited,linker,limits,Some(&cancel))};drop(client);
 let shutdown=cleanup.shutdown(std::net::Shutdown::Both);let served=service.join().map_err(|_|io::Error::other("native filesystem service panicked"))?;
 if let Err(error)=shutdown{if error.raw_os_error()!=Some(libc::ENOTCONN){return Err(error);}}
 match result{Ok(output)if output.failure.is_some()=>Ok(output),Ok(output)=>{served?;Ok(output)},Err(error)=>Err(error)}
 })
}
#[cfg(test)]mod tests{
 use super::*;
 #[test]fn mappings_preserve_host_names_and_operation_specific_roots(){
  let grants=[Grant{guest:"/project".into(),path:"/private/source h\u{e9} space".into(),read:true,write:false},Grant{guest:"/out".into(),path:"/private/output".into(),read:false,write:true}];
  assert_eq!(mapped_path("/project/a",false,&grants).unwrap(),PathBuf::from("/private/source h\u{e9} space/a"));assert_eq!(mapped_path("/out/new",true,&grants).unwrap(),PathBuf::from("/private/output/new"));
  for name in ["C:\\source","/project/../secret","/projectSibling/a","/project//a","/project/C:evil","/project/a\\b"]{assert!(mapped_path(name,false,&grants).is_err());}
  assert!(mapped_path("/project/a",true,&grants).is_err());assert!(mapped_path("/out/a",false,&grants).is_err());assert!(delegated(&["/project/a".into()],&[],&grants).is_ok());assert!(delegated(&["/".into()],&[],&grants).is_err());
 }
 #[test]fn private_state_overlap_is_denied_in_both_directions(){assert!(protected(Path::new("/private/tmp"),Path::new("/private/tmp/image")));assert!(protected(Path::new("/private/tmp/image/secret"),Path::new("/private/tmp/image")));assert!(!protected(Path::new("/private/tmp/imageSibling"),Path::new("/private/tmp/image")));}
}
