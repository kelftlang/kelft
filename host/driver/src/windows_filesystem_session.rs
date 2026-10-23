//! Parent-owned filesystem authority and KFS1 lifetime for one restricted role.
use crate::{windows_filesystem::Broker,windows_process::AppContainerSid,windows_snapshot::Image,windows_supervisor::{self,Limits,Output}};
use std::{io,path::{Path,PathBuf},sync::atomic::AtomicBool};
use windows_sys::Win32::Globalization::CompareStringOrdinal;
#[derive(Clone)]pub struct Grant {pub path:PathBuf,pub read:bool,pub write:bool}
#[derive(Clone)]pub struct MappedGrant {pub grant:Grant,pub guest:String}
/// Guest validation is independent of the Windows host-path parser. Drive,
/// device, traversal and backslash names never enter guest lexical operations.
pub fn guest_name(name:&str)->io::Result<&str>{
 if !name.starts_with('/')||name.contains(['\\',':','\0'])||name!="/"&&name[1..].split('/').any(|part|part.is_empty()||matches!(part,"."|"..")){return Err(io::Error::new(io::ErrorKind::InvalidInput,"normalized absolute guest name required"));}Ok(name)
}
pub fn mapped_path(name:&str,writing:bool,mappings:&[MappedGrant])->io::Result<Grant>{
 guest_name(name)?;let mut selected:Option<(&MappedGrant,&str)>=None;
 for mapping in mappings{guest_name(&mapping.guest)?;if !(if writing{mapping.grant.write}else{mapping.grant.read}){continue;}
  let tail=if name==mapping.guest{Some("")}else if mapping.guest=="/"{Some(&name[1..])}else{name.strip_prefix(&mapping.guest).and_then(|tail|tail.strip_prefix('/'))};
  if let Some(tail)=tail{if selected.is_none_or(|(old,_)|mapping.guest.len()>old.guest.len()){selected=Some((mapping,tail));}}
 }
 let(mapping,tail)=selected.ok_or_else(||io::Error::from(io::ErrorKind::PermissionDenied))?;let mut path=mapping.grant.path.clone();for component in tail.split('/').filter(|part|!part.is_empty()){path.push(component);}normalized(&path)?;
 Ok(Grant{path,read:!writing,write:writing})
}
pub fn delegated_mapped(read:&[String],write:&[String],mappings:&[MappedGrant])->io::Result<Vec<MappedGrant>>{
 if read.len()+write.len()>128{return Err(io::Error::other("mapped filesystem root budget"));}let mut roots=std::collections::BTreeMap::<String,MappedGrant>::new();
 for(paths,writing)in [(read,false),(write,true)]{for name in paths{let grant=mapped_path(name,writing,mappings)?;if let Some(old)=roots.get_mut(name){if normalized(&old.grant.path)?!=normalized(&grant.path)?{return Err(io::Error::other("inconsistent guest mapping"));}old.grant.read|=grant.read;old.grant.write|=grant.write;}else{roots.insert(name.clone(),MappedGrant{grant,guest:name.clone()});}}}Ok(roots.into_values().collect())
}
pub fn normalized(path:&Path)->io::Result<String>{
 let text=path.to_str().ok_or_else(||io::Error::other("Unicode Windows grant required"))?.replace('/',"\\");let text=text.strip_prefix("\\\\?\\").unwrap_or(&text).to_string();let b=text.as_bytes();
 if b.len()<3||!b[0].is_ascii_alphabetic()||b[1]!=b':'||b[2]!=b'\\'||text.contains('\0')||text[3..].split('\\').any(|p|p=="."||p==".."||p.is_empty()&&text.len()>3){return Err(io::Error::other("normalized local Windows grant required"));}Ok(text)
}
pub fn within(path:&Path,root:&Path)->io::Result<bool>{
 let path=normalized(path)?;let root=normalized(root)?;let p:Vec<u16>=path.encode_utf16().collect();let r:Vec<u16>=root.encode_utf16().collect();
 if p.len()<r.len(){return Ok(false);}let equal=unsafe{CompareStringOrdinal(p.as_ptr(),r.len() as i32,r.as_ptr(),r.len() as i32,1)};if equal==0{return Err(io::Error::last_os_error());}
 Ok(equal==2&&(p.len()==r.len()||r.last()==Some(&(b'\\' as u16))||p.get(r.len())==Some(&(b'\\' as u16))))
}
pub fn delegated(read:&[String],write:&[String],authority:&[Grant])->io::Result<Vec<Grant>>{
 if read.len()+write.len()>128{return Err(io::Error::other("filesystem root budget"));}let mut grants=vec![];
 for(paths,writing)in [(read,false),(write,true)]{for path in paths{let path=PathBuf::from(normalized(Path::new(path))?);let mut allowed=false;for grant in authority{if (if writing{grant.write}else{grant.read})&&within(&path,&grant.path)?{allowed=true;break;}}if !allowed{return Err(io::Error::from(io::ErrorKind::PermissionDenied));}grants.push(Grant{path,read:!writing,write:writing});}}Ok(grants)
}
pub fn run(image:&Image,identity:&AppContainerSid,system:&str,args:&[String],limits:Limits,grants:&[Grant],cwd:&Path,environment:&[(String,String)],controls:Vec<(String,std::fs::File)>,cancel:Option<&AtomicBool>)->io::Result<Output>{
 run_named(image,identity,system,args,limits,grants,None,normalized(cwd)?,environment,controls,cancel,None,None)
}
pub fn run_mapped(image:&Image,identity:&AppContainerSid,system:&str,args:&[String],limits:Limits,mappings:&[MappedGrant],cwd:&str,environment:&[(String,String)],controls:Vec<(String,std::fs::File)>,cancel:Option<&AtomicBool>)->io::Result<Output>{
 run_mapped_policy(image,identity,system,args,limits,mappings,cwd,environment,controls,cancel,None,None)
}
pub fn run_mapped_policy(image:&Image,identity:&AppContainerSid,system:&str,args:&[String],limits:Limits,mappings:&[MappedGrant],cwd:&str,environment:&[(String,String)],controls:Vec<(String,std::fs::File)>,cancel:Option<&AtomicBool>,policy:Option<crate::host_channel::Policy>,installed:Option<crate::windows_host::Installed>)->io::Result<Output>{
 guest_name(cwd)?;let mut seen=std::collections::HashSet::new();let mut grants=vec![];let mut names=vec![];
 if mappings.len()>128{return Err(io::Error::other("mapped filesystem root budget"));}
 let mut ordered=mappings.to_vec();ordered.sort_by_key(|mapping|std::cmp::Reverse(mapping.guest.len()));
 for mapping in &ordered{guest_name(&mapping.guest)?;if !seen.insert(mapping.guest.clone()){return Err(io::Error::other("duplicate mapped guest root"));}grants.push(mapping.grant.clone());names.push(mapping.guest.clone());}
 run_named(image,identity,system,args,limits,&grants,Some(&names),cwd.into(),environment,controls,cancel,policy,installed)
}
pub fn run_input(image:&Image,identity:&AppContainerSid,system:&str,args:&[String],limits:Limits,mappings:&[MappedGrant],cwd:&str,environment:&[(String,String)],input:Vec<u8>,directory:&str)->io::Result<Output>{
 guest_name(cwd)?;let mut broker=Broker::default();let(mut read,mut write)=(vec![],vec![]);let mut ordered=mappings.to_vec();ordered.sort_by_key(|m|std::cmp::Reverse(m.guest.len()));
 for writing in [false,true]{for mapping in &ordered{if if writing{mapping.grant.write}else{mapping.grant.read}{broker.add_root(&mapping.grant.path,!writing,writing)?;if writing{write.push(mapping.guest.clone());}else{read.push(mapping.guest.clone());}}}}
 let(mut requests,child_write)=windows_supervisor::pipe()?;let(child_read,mut responses)=windows_supervisor::pipe()?;
 let service=std::thread::Builder::new().name("kelft-child-filesystem".into()).spawn(move||broker.serve(&mut requests,&mut responses))?;
 let mut env=environment.to_vec();env.push(("KELFT_CAPABILITIES".into(),serde_json::json!({"execute":false,"read":read,"write":write}).to_string()));env.push(("KELFT_FS_CWD".into(),cwd.into()));
 let result=windows_supervisor::run_with_input(image,identity,system,args,limits,&env,vec![("KELFT_FS_REQUEST".into(),child_write),("KELFT_FS_RESPONSE".into(),child_read)],input,directory);let served=service.join().map_err(|_|io::Error::other("child filesystem service panicked"))?;match result{Ok(output)if output.failure.is_some()=>Ok(output),Ok(output)=>{served?;Ok(output)},Err(error)=>Err(error)}
}
fn run_named(image:&Image,identity:&AppContainerSid,system:&str,args:&[String],limits:Limits,grants:&[Grant],names:Option<&[String]>,cwd:String,environment:&[(String,String)],mut controls:Vec<(String,std::fs::File)>,cancel:Option<&AtomicBool>,policy:Option<crate::host_channel::Policy>,installed:Option<crate::windows_host::Installed>)->io::Result<Output>{
 let mut broker=Broker::default();let(mut read,mut write)=(vec![],vec![]);
 for writing in [false,true]{for(index,grant)in grants.iter().enumerate(){if if writing{grant.write}else{grant.read}{let path=normalized(&grant.path)?;broker.add_root(Path::new(&path),!writing,writing)?;let name=names.map_or(path,|names|names[index].clone());if writing{write.push(name);}else{read.push(name);}}}}
 let(mut requests,child_write)=windows_supervisor::pipe()?;let(child_read,mut responses)=windows_supervisor::pipe()?;
 let host=if let Some(names)=names{let expected=crate::host_channel::Policy{read:read.clone(),write:write.clone(),execute:false,process:vec![]};let caller=policy.unwrap_or(expected.clone());if caller.read.iter().collect::<std::collections::BTreeSet<_>>()!=expected.read.iter().collect::<std::collections::BTreeSet<_>>()||caller.write.iter().collect::<std::collections::BTreeSet<_>>()!=expected.write.iter().collect::<std::collections::BTreeSet<_>>()||caller.execute{return Err(io::Error::new(io::ErrorKind::PermissionDenied,"host policy differs from filesystem authority"));}let mappings=grants.iter().zip(names).map(|(grant,name)|MappedGrant{grant:grant.clone(),guest:name.clone()}).collect();{let mut host=crate::windows_host::Host::new(caller,mappings,cwd.clone(),system.into(),limits.wall_ms)?;host.installed=installed;Some(host)}}else{None};
 let service=std::thread::Builder::new().name("kelft-filesystem-service".into()).spawn(move||match host{Some(mut host)=>crate::filesystem_channel::serve_host(&mut requests,&mut responses,|r|broker.execute(r),|r|host.dispatch(r)),None=>broker.serve(&mut requests,&mut responses)})?;
 controls.push(("KELFT_FS_REQUEST".into(),child_write));controls.push(("KELFT_FS_RESPONSE".into(),child_read));
 let mut env=environment.to_vec();env.push(("KELFT_CAPABILITIES".into(),serde_json::json!({"execute":false,"read":read,"write":write}).to_string()));env.push(("KELFT_FS_CWD".into(),cwd));
 let result=windows_supervisor::run_cancellable(image,identity,system,args,limits,&env,controls,cancel);let served=service.join().map_err(|_|io::Error::other("filesystem service panicked"))?;
 match result{Ok(output)if output.failure.is_some()=>Ok(output),Ok(output)=>{served?;Ok(output)},Err(error)=>Err(error)}
}
#[cfg(test)]mod tests{use super::*;
 #[test]fn private_guest_filesystem_worker(){
  if std::env::var("KELFT_GUEST_FS_PROBE").as_deref()!=Ok("1"){return;}
  use std::os::windows::io::FromRawHandle;use crate::filesystem_channel::{self as rpc,Operation,Request};
  assert_eq!(std::env::var("KELFT_FS_CWD").unwrap(),"/project");let policy:serde_json::Value=serde_json::from_str(&std::env::var("KELFT_CAPABILITIES").unwrap()).unwrap();assert_eq!(policy,serde_json::json!({"execute":false,"read":["/project/data/input"],"write":[]}));
  let inherited=|name:&str|unsafe{std::fs::File::from_raw_handle(std::env::var(name).unwrap().parse::<usize>().unwrap() as _)};let mut output=inherited("KELFT_FS_REQUEST");let mut input=inherited("KELFT_FS_RESPONSE");
  rpc::write_request(&mut output,&Request{sequence:1,operation:Operation::OpenRead,handle:1,path:".".into(),amount:0,data:vec![]}).unwrap();let opened=rpc::read_response(&mut input,1).unwrap();assert_eq!(opened.status,0);
  rpc::write_request(&mut output,&Request{sequence:2,operation:Operation::Read,handle:opened.value,path:String::new(),amount:3,data:vec![]}).unwrap();assert_eq!(rpc::read_response(&mut input,2).unwrap().data,[0,255,128]);
  rpc::write_request(&mut output,&Request{sequence:3,operation:Operation::Close,handle:opened.value,path:String::new(),amount:0,data:vec![]}).unwrap();assert_eq!(rpc::read_response(&mut input,3).unwrap().status,0);
  rpc::write_request(&mut output,&Request{sequence:4,operation:Operation::OpenWrite,handle:1,path:".".into(),amount:0,data:vec![]}).unwrap();assert_ne!(rpc::read_response(&mut input,4).unwrap().status,0);
  assert!(std::fs::read(std::env::var("KELFT_GUEST_FS_OUTSIDE").unwrap()).is_err());println!("native-mapped-filesystem-ok");
 }
 #[test]fn native_guest_broker_uses_retained_host_handles_and_exposes_only_guest_names(){
  use sha2::{Digest,Sha256};let system=std::env::var("SystemRoot").unwrap();let bytes=std::fs::read(std::env::current_exe().unwrap()).unwrap();let digest=format!("sha256:{:x}",Sha256::digest(&bytes));let identity=AppContainerSid::fresh().unwrap();let image=Image::new(&bytes,&digest,&identity).unwrap();let root=image.directory().with_extension("guest-data");std::fs::create_dir(&root).unwrap();let input=root.join("input");std::fs::write(&input,[0,255,128]).unwrap();
  let grants=[MappedGrant{guest:"/project/data/input".into(),grant:Grant{path:input.clone(),read:true,write:false}}];let environment=[("KELFT_GUEST_FS_PROBE".into(),"1".into()),("KELFT_GUEST_FS_OUTSIDE".into(),input.to_str().unwrap().into())];let args=["--exact","windows_filesystem_session::tests::private_guest_filesystem_worker","--nocapture"].map(String::from);
  let result=run_mapped(&image,&identity,&system,&args,Limits{wall_ms:10000,memory_bytes:268435456,output_bytes:65536},&grants,"/project",&environment,vec![],None).unwrap();assert_eq!(result.exit,Some(0),"{:?}: {}{}",result.failure,String::from_utf8_lossy(&result.stdout),String::from_utf8_lossy(&result.stderr));assert!(String::from_utf8_lossy(&result.stdout).contains("native-mapped-filesystem-ok"));std::fs::remove_dir_all(root).unwrap();
 }
 #[test]fn guest_mapping_preserves_host_paths_and_operation_authority(){let mappings=[MappedGrant{guest:"/project".into(),grant:Grant{path:"C:\\Private hé".into(),read:true,write:false}},MappedGrant{guest:"/out".into(),grant:Grant{path:"D:\\Output".into(),read:false,write:true}}];assert_eq!(mapped_path("/project/a",false,&mappings).unwrap().path,PathBuf::from("C:\\Private hé\\a"));assert_eq!(mapped_path("/out/file",true,&mappings).unwrap().path,PathBuf::from("D:\\Output\\file"));for path in ["C:\\Private","/project/../secret","/project//a","/project/a\\b","/project/C:evil","/project/.","/project/","/projectSibling/a"]{assert!(mapped_path(path,false,&mappings).is_err(),"{path}");}assert!(mapped_path("/project/file",true,&mappings).is_err());assert!(mapped_path("/out/file",false,&mappings).is_err());}
 #[test]fn windows_delegation_keeps_read_write_and_component_boundaries(){let grants=[Grant{path:"C:\\Private".into(),read:true,write:false}];assert!(delegated(&["c:/PRIVATE/hé".into()],&[],&grants).is_ok());for path in ["C:/PrivateSibling","C:/Private/../other","D:/Private"]{assert!(delegated(&[path.into()],&[],&grants).is_err());}assert!(delegated(&[],&["C:/Private/output".into()],&grants).is_err());}
}
