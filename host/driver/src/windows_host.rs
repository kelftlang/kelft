//! Parent-owned host services for a restricted candidate. Native image bytes and
//! ancestor handles remain held until its job has terminated.
use crate::{host_channel::{self,Policy,Process,Filesystem},windows_filesystem::Broker,windows_filesystem_session::{self as session,MappedGrant},windows_process::AppContainerSid,windows_snapshot::Image,windows_supervisor::Limits};
use serde_json::{Value,json};
use std::{fs,io::{self,Read},os::windows::fs::{OpenOptionsExt,MetadataExt},path::{Path,PathBuf},time::{Duration,Instant}};
#[derive(Clone)]pub struct Installed {pub root:PathBuf,pub coordinator_sha256:String}
pub struct Host {caller:Policy,mappings:Vec<MappedGrant>,roots:Vec<(String,u64,bool,bool)>,broker:Broker,cwd:String,system:String,deadline:Instant,calls:usize,pub(crate) installed:Option<Installed>}
impl Host {
 pub fn new(caller:Policy,mappings:Vec<MappedGrant>,cwd:String,system:String,wall_ms:u32)->io::Result<Self>{
  if !caller.validate(){return Err(io::Error::new(io::ErrorKind::InvalidInput,"invalid host capability policy"));}let mut broker=Broker::default();let mut roots=vec![];
  for mapping in &mappings{let token=broker.add_root(&mapping.grant.path,mapping.grant.read,mapping.grant.write)?;roots.push((mapping.guest.clone(),token,mapping.grant.read,mapping.grant.write));}
  Ok(Self{caller,mappings,roots,broker,cwd,system,deadline:Instant::now()+Duration::from_millis(wall_ms as u64),calls:0,installed:None})
 }
 #[cfg(feature="installed-native")]
 fn installed_arguments(&self,r:&Process)->io::Result<(Vec<String>,String,Broker)>{
  let denied=||io::Error::new(io::ErrorKind::PermissionDenied,"installed command authority denied");let context=self.installed.as_ref().ok_or_else(denied)?;let expected=context.root.join("bin/kelft.exe");
  if r.sha256!=context.coordinator_sha256||!session::within(Path::new(&r.executable),&expected)?||!session::within(&expected,Path::new(&r.executable))?{return Err(denied());}
  let parsed=crate::installed_request::parse(&r.args,crate::native_target::Target::current().map_err(io::Error::other)?,Path::new(&r.cwd)).map_err(|_|denied())?;
  if !matches!(parsed.command.as_str(),"check"|"build")||parsed.options.keys().any(|k|!matches!(k.as_str(),"--project-root"|"-o"|"--emit")){return Err(denied());}
  let project=parsed.options.get("--project-root").ok_or_else(denied)?;let guest=if project.starts_with('/'){project.clone()}else{format!("{}/{project}",r.cwd)};
  if !host_channel::normal(&guest)||!r.read.iter().any(|root|host_channel::within(&guest,root)){return Err(denied());}
  let project=session::mapped_path(&guest,false,&self.mappings)?.path;let mut pins=Broker::default();pins.add_root(&project,true,false)?;
  let source=if parsed.source.starts_with('/'){parsed.source.clone()}else{format!("{}/{}",r.cwd,parsed.source)};
  if !host_channel::normal(&source)||!host_channel::within(&source,&guest){return Err(denied());}let source=session::mapped_path(&source,false,&self.mappings)?.path;
  let mut arguments=vec![parsed.command,session::normalized(&source)?,"--project-root".into(),session::normalized(&project)?];
  if let Some(output)=parsed.options.get("-o"){let output=if output.starts_with('/'){output.clone()}else{format!("{}/{output}",r.cwd)};if !host_channel::normal(&output)||!r.write.iter().any(|root|host_channel::within(&output,root)){return Err(denied());}let output=session::mapped_path(&output,true,&self.mappings)?.path;arguments.extend(["-o".into(),session::normalized(&output)?]);}
  if let Some(emit)=parsed.options.get("--emit"){arguments.extend(["--emit".into(),emit.clone()]);}if parsed.json{arguments.push("--json".into());}
  let cwd=session::mapped_path(&r.cwd,false,&self.mappings)?.path;pins.add_root(&cwd,true,false)?;Ok((arguments,session::normalized(&cwd)?,pins))
 }
 fn path(&self,path:&str,writing:bool,maximum:&Policy)->Result<(String,u64,String),&'static str>{
  let path=if path.starts_with('/'){path.into()}else{format!("{}/{path}",self.cwd)};if !host_channel::normal(&path)||!path.starts_with('/'){return Err("DENIED");}
  let allowed=if writing{&maximum.write}else{&maximum.read};let caller=if writing{&self.caller.write}else{&self.caller.read};if !allowed.iter().any(|r|host_channel::within(&path,r))||!caller.iter().any(|r|host_channel::within(&path,r)){return Err("DENIED");}
  let root=self.roots.iter().filter(|(name,_,read,write)|(if writing{*write}else{*read})&&host_channel::within(&path,name)).max_by_key(|(name,_,_,_)|name.len()).ok_or("DENIED")?;
  let relative=if path==root.0{".".into()}else{path[root.0.len()..].trim_start_matches('/').into()};Ok((path,root.1,relative))
 }
 fn filesystem(&mut self,request:Value,writing:bool,maximum:&Policy)->Value {
  let run=(||->Result<Value,String>{
   let r:Filesystem=serde_json::from_value(request).map_err(|_|"INVALID_REQUEST")?;if r.schema!="kelft.filesystem-request/1"||writing!=matches!(r.operation.as_str(),"temporary"|"rename"|"remove"){return Err("INVALID_REQUEST".into());}
   let(path,token,relative)=self.path(&r.path,writing,maximum).map_err(str::to_owned)?;
   let map_error=|e:io::Error|match e.kind(){io::ErrorKind::PermissionDenied=>"DENIED".into(),io::ErrorKind::NotFound=>"ENOENT".into(),io::ErrorKind::AlreadyExists=>"EEXIST".into(),io::ErrorKind::NotADirectory=>"ENOTDIR".into(),io::ErrorKind::DirectoryNotEmpty=>"ENOTEMPTY".into(),io::ErrorKind::InvalidInput=>"INVALID_REQUEST".into(),_=>"IO_ERROR".into()};
   match r.operation.as_str(){
    "list" if r.destination.is_none()&&r.prefix.is_none()&&r.recursive.is_none()=>Ok(json!(self.broker.host_list(token,&relative).map_err(map_error)?)),
    "metadata" if r.destination.is_none()&&r.prefix.is_none()&&r.recursive.is_none()=>self.broker.host_metadata(token,&relative).map_err(map_error),
    "temporary" if r.destination.is_none()&&r.recursive.is_none()=>{let name=self.broker.host_temporary(token,&relative,r.prefix.as_deref().ok_or("INVALID_REQUEST")?).map_err(map_error)?;Ok(json!(format!("{path}/{name}")))},
    "rename" if r.prefix.is_none()&&r.recursive.is_none()=>{let(destination,target,tail)=self.path(r.destination.as_deref().ok_or("INVALID_REQUEST")?,true,maximum).map_err(str::to_owned)?;if self.roots.iter().any(|(root,_,_,_)|root==&path||root==&destination)||maximum.write.iter().any(|r|r==&path||r==&destination){return Err("DENIED".into());}self.broker.host_rename(token,&relative,target,&tail).map_err(map_error)?;Ok(json!(true))},
    "remove" if r.prefix.is_none()&&r.destination.is_none()=>{if self.roots.iter().any(|(root,_,_,_)|root==&path)||maximum.write.iter().any(|r|r==&path){return Err("DENIED".into());}self.broker.host_remove(token,&relative,r.recursive.ok_or("INVALID_REQUEST")?).map_err(map_error)?;Ok(json!(true))},
    _=>Err("INVALID_REQUEST".into())
   }
  })();match run{Ok(value)=>json!({"schema":"kelft.filesystem-result/1","error":"","value":value}),Err(error)=>host_channel::filesystem_error(&error)}
 }
 fn process(&mut self,request:Value,maximum:&Policy)->Value {
  let request:Process=match serde_json::from_value(request){Ok(r)=>r,Err(_)=>return host_channel::process_error("INVALID_REQUEST")};
  let grant=match host_channel::authorize(maximum,&self.caller,&request){Ok(g)=>g,Err(e)=>return host_channel::process_error(e)};
  if maximum.grant(&request).is_none_or(|g|g.profile!=grant.profile){return host_channel::process_error("PROCESS_DENIED");}
  let installed=grant.profile=="installed-kelft";
  #[cfg(not(feature="installed-native"))]if installed{return host_channel::process_error("UNSUPPORTED_HOST");}
  let remaining=self.deadline.saturating_duration_since(Instant::now()).as_millis().min(request.limits.timeout_ms as u128) as u32;
  if remaining==0{return json!({"schema":"kelft.process-result/1","status":"timeout","error":"deadline exceeded","exit":null,"signal":null,"stdoutHex":"","stderrHex":""});}
  let result=(||->io::Result<_>{
   if request.limits.memory_bytes<16<<20||request.limits.stdout_bytes+request.limits.stderr_bytes>16<<20{return Err(io::Error::new(io::ErrorKind::InvalidInput,"unsupported native limits"));}
   let executable=session::normalized(Path::new(&request.executable))?;let path=Path::new(&executable);let mut pins=Broker::default();pins.add_root(path,true,false)?;
   let mut file=fs::OpenOptions::new().read(true).share_mode(1).custom_flags(0x00200000).open(path)?;let metadata=file.metadata()?;
   if !metadata.is_file()||metadata.file_attributes()&0x400!=0||metadata.len()>64<<20{return Err(io::Error::new(io::ErrorKind::PermissionDenied,"invalid executable"));}
   let mut bytes=vec![];Read::by_ref(&mut file).take((64<<20)+1).read_to_end(&mut bytes)?;use sha2::{Digest,Sha256};if format!("sha256:{:x}",Sha256::digest(&bytes))!=request.sha256{return Err(io::Error::new(io::ErrorKind::PermissionDenied,"executable identity changed"));}
   let identity=AppContainerSid::fresh()?;let image=Image::new(&bytes,&request.sha256,&identity)?;
   let mappings=session::delegated_mapped(&request.read,&request.write,&self.mappings)?;
   let environment=request.environment.iter().map(|(k,v)|(k.clone(),v.clone())).collect::<Vec<_>>();
   let limits=Limits{wall_ms:remaining,memory_bytes:request.limits.memory_bytes,output_bytes:request.limits.stdout_bytes+request.limits.stderr_bytes};
   #[cfg(feature="installed-native")]if installed{let(arguments,cwd,_held)=self.installed_arguments(&request)?;let executable=session::normalized(path)?;return crate::windows_supervisor::run_installed(&image,&identity,&self.system,&executable,&cwd,&arguments,limits,&environment,host_channel::unhex(&request.stdin_hex));}
   let directory=session::mapped_path(&request.cwd,false,&self.mappings)?.path;pins.add_root(&directory,true,false)?;let directory=session::normalized(&directory)?;
   session::run_input(&image,&identity,&self.system,&request.args,limits,&mappings,&request.cwd,&environment,host_channel::unhex(&request.stdin_hex),&directory)
  })();
  match result{
   Err(error)=>json!({"schema":"kelft.process-result/1","status":"launch-error","error":match error.kind(){io::ErrorKind::PermissionDenied=>"EXECUTABLE_DENIED",io::ErrorKind::NotFound=>"ENOENT",io::ErrorKind::InvalidInput=>"UNSUPPORTED_HOST_REQUEST",_=>"LAUNCH_FAILED"},"exit":null,"signal":null,"stdoutHex":"","stderrHex":""}),
   Ok(output)=>{let exceeded=output.stdout.len()>request.limits.stdout_bytes||output.stderr.len()>request.limits.stderr_bytes;let status=if exceeded{"resource-error"}else if output.failure.as_ref().is_some_and(|e|e.contains("deadline")){"timeout"}else if output.failure.is_some(){"resource-error"}else{"exited"};json!({"schema":"kelft.process-result/1","status":status,"error":output.failure.unwrap_or_default(),"exit":if status=="exited"{output.exit}else{None},"signal":null,"stdoutHex":host_channel::hex(&output.stdout[..output.stdout.len().min(request.limits.stdout_bytes)]),"stderrHex":host_channel::hex(&output.stderr[..output.stderr.len().min(request.limits.stderr_bytes)])})}
  }
 }
 pub fn dispatch(&mut self,raw:&str)->io::Result<Vec<u8>> {
  self.calls+=1;if self.calls>4096{return Err(io::Error::new(io::ErrorKind::InvalidData,"host request budget"));}
  let envelope=host_channel::decode(raw).map_err(|_|io::Error::new(io::ErrorKind::InvalidData,"malformed host request"))?;
  if envelope.schema!="kelft.host-request/1"||!envelope.maximum.validate(){return Err(io::Error::new(io::ErrorKind::InvalidData,"invalid host envelope"));}
  let result=match envelope.kind.as_str(){"process"=>self.process(envelope.request,&envelope.maximum),"filesystem-read"=>self.filesystem(envelope.request,false,&envelope.maximum),"filesystem-write"=>self.filesystem(envelope.request,true,&envelope.maximum),_=>return Err(io::Error::new(io::ErrorKind::InvalidData,"unknown host operation"))};
  serde_json::to_vec(&result).map_err(io::Error::other)
 }
}
#[cfg(test)]mod tests{
 use super::*;
 #[test]fn extended_filesystem_uses_retained_roots_and_never_overwrites(){
  let mut nonce=[0;16];getrandom::fill(&mut nonce).unwrap();let root=std::env::temp_dir().join(format!("kelft-host-{}",host_channel::hex(&nonce)));fs::create_dir(&root).unwrap();
  let policy:Policy=serde_json::from_value(json!({"read":["/project"],"write":["/project"],"execute":false})).unwrap();let grant=MappedGrant{guest:"/project".into(),grant:session::Grant{path:root.clone(),read:true,write:true}};
  {let mut host=Host::new(policy.clone(),vec![grant],"/project".into(),std::env::var("SystemRoot").unwrap(),30000).unwrap();
   let mut call=|request:Value,writing:bool|->Value{let raw=json!({"schema":"kelft.host-request/1","kind":if writing{"filesystem-write"}else{"filesystem-read"},"maximum":policy,"request":request}).to_string();serde_json::from_slice(&host.dispatch(&raw).unwrap()).unwrap()};
   let temporary=call(json!({"schema":"kelft.filesystem-request/1","operation":"temporary","path":"/project","prefix":"probe-"}),true);assert_eq!(temporary["error"],"");let dir=temporary["value"].as_str().unwrap().to_owned();let actual=root.join(dir.strip_prefix("/project/").unwrap());
   fs::write(actual.join("a"),[0,255,128]).unwrap();fs::write(actual.join("b"),b"preserved").unwrap();
   let result=call(json!({"schema":"kelft.filesystem-request/1","operation":"list","path":dir}),false);assert_eq!(result["value"],json!(["a","b"]));
   assert_eq!(call(json!({"schema":"kelft.filesystem-request/1","operation":"metadata","path":format!("{dir}/a")}),false)["value"],json!({"kind":"file","sizeBytes":"3"}));
   assert_eq!(call(json!({"schema":"kelft.filesystem-request/1","operation":"rename","path":format!("{dir}/a"),"destination":format!("{dir}/b")}),true)["error"],"EEXIST");assert_eq!(fs::read(actual.join("b")).unwrap(),b"preserved");
   let renamed=call(json!({"schema":"kelft.filesystem-request/1","operation":"rename","path":format!("{dir}/a"),"destination":format!("{dir}/c")}),true);assert_eq!(renamed["error"],"","{renamed}");assert!(!actual.join("a").exists());
   assert_ne!(call(json!({"schema":"kelft.filesystem-request/1","operation":"remove","path":dir,"recursive":false}),true)["error"],"");
   assert_eq!(call(json!({"schema":"kelft.filesystem-request/1","operation":"remove","path":dir,"recursive":true}),true)["error"],"");assert!(!actual.exists());
   assert_eq!(call(json!({"schema":"kelft.filesystem-request/1","operation":"remove","path":"/project","recursive":true}),true)["error"],"DENIED");
   assert_eq!(call(json!({"schema":"kelft.filesystem-request/1","operation":"list","path":"/project/../outside"}),false)["error"],"DENIED");
  }fs::remove_dir(root).unwrap();
 }
 #[test]#[ignore="requires the explicitly prepared kelft-host-probe executable"]fn process_broker_preserves_binary_io_and_enforces_deadlines(){
  use sha2::{Digest,Sha256};let executable=std::env::var("KELFT_HOST_PROBE").expect("build kelft-host-probe and set KELFT_HOST_PROBE for this targeted test");let executable=executable.replace('\\',"/");let bytes=fs::read(&executable).unwrap();let sha256=format!("sha256:{:x}",Sha256::digest(&bytes));let limits=json!({"timeoutMs":30000,"memoryBytes":268435456,"stdoutBytes":65536,"stderrBytes":65536});
  let policy:Policy=serde_json::from_value(json!({"read":[],"write":[],"process":[{"executable":executable,"sha256":sha256,"cwd":["/project"],"environment":{"MODE":"test"},"read":[],"write":[],"limits":limits}]})).unwrap();let normalized=session::normalized(Path::new(&executable)).unwrap();let cwd=Path::new(&normalized).parent().unwrap().to_path_buf();let mappings=vec![MappedGrant{guest:"/project".into(),grant:session::Grant{path:cwd,read:true,write:false}}];let mut host=Host::new(policy.clone(),mappings,"/project".into(),std::env::var("SystemRoot").unwrap(),30000).unwrap();
  let request=json!({"schema":"kelft.process-request/1","executable":executable,"sha256":sha256,"args":["binary"],"cwd":"/project","environment":{"MODE":"test"},"stdinHex":"00ff800d0a","read":[],"write":[],"limits":limits});
  let mut call=|request:Value|->Value{serde_json::from_slice(&host.dispatch(&json!({"schema":"kelft.host-request/1","kind":"process","maximum":policy,"request":request}).to_string()).unwrap()).unwrap()};
  let output=call(request.clone());assert_eq!(output["status"],"exited","{output}");assert_eq!(output["exit"],7);assert_eq!(output["stdoutHex"],"00ff800d0a");assert_eq!(output["stderrHex"],"ff0080");
  let mut r=request.clone();r["args"]=json!(["wait"]);r["limits"]["timeoutMs"]=json!(1000);let output=call(r);assert_eq!(output["status"],"timeout","{output}");assert_eq!(output["stdoutHex"],host_channel::hex(b"started\n"));
  let mut r=request;r["args"]=json!(["flood"]);r["limits"]["stdoutBytes"]=json!(32);r["limits"]["stderrBytes"]=json!(0);let output=call(r);assert_eq!(output["status"],"resource-error","{output}");assert_eq!(output["stdoutHex"].as_str().unwrap().len(),64);
 }
}
#[cfg(test)]mod adversarial_tests{
 use super::*;
 #[test]fn listing_rejects_unrepresentable_names_and_metadata_preserves_large_sizes(){
  use std::os::windows::{ffi::OsStringExt,io::AsRawHandle};
  #[link(name="kernel32")]unsafe extern "system"{fn DeviceIoControl(device:*mut std::ffi::c_void,code:u32,input:*const std::ffi::c_void,input_size:u32,output:*mut std::ffi::c_void,output_size:u32,returned:*mut u32,overlapped:*mut std::ffi::c_void)->i32;}
  let mut nonce=[0;16];getrandom::fill(&mut nonce).unwrap();let root=std::env::temp_dir().join(format!("kelft-host-names-{}",host_channel::hex(&nonce)));fs::create_dir(&root).unwrap();
  let large=fs::File::create(root.join("large")).unwrap();let mut returned=0;assert_ne!(unsafe{DeviceIoControl(large.as_raw_handle(),0x900c4,std::ptr::null(),0,std::ptr::null_mut(),0,&mut returned,std::ptr::null_mut())},0);large.set_len(4294967303).unwrap();drop(large);
  let bad=std::ffi::OsString::from_wide(&[b'b' as u16,0xd800]);fs::write(root.join(&bad),b"retained").unwrap();
  {let mut broker=Broker::default();let token=broker.add_root(&root,true,false).unwrap();assert_eq!(broker.host_metadata(token,"large").unwrap()["sizeBytes"],"4294967303");assert_eq!(broker.host_list(token,".").unwrap_err().kind(),io::ErrorKind::InvalidInput);}
  fs::remove_file(root.join(bad)).unwrap();fs::remove_file(root.join("large")).unwrap();fs::remove_dir(root).unwrap();
 }
 #[test]fn filesystem_cannot_exceed_caller_policy_even_with_retained_cwd(){
  let mut nonce=[0;16];getrandom::fill(&mut nonce).unwrap();let root=std::env::temp_dir().join(format!("kelft-host-caller-{}",host_channel::hex(&nonce)));fs::create_dir(&root).unwrap();fs::write(root.join("sentinel"),b"preserved").unwrap();
  {let caller:Policy=serde_json::from_value(json!({"read":[],"write":[]})).unwrap();let mapping=MappedGrant{guest:"/project".into(),grant:session::Grant{path:root.clone(),read:true,write:true}};let mut host=Host::new(caller,vec![mapping],"/project".into(),std::env::var("SystemRoot").unwrap(),1000).unwrap();for (kind,request)in[("filesystem-read",json!({"schema":"kelft.filesystem-request/1","operation":"list","path":"/project"})),("filesystem-write",json!({"schema":"kelft.filesystem-request/1","operation":"remove","path":"/project/sentinel","recursive":false}))]{let result:Value=serde_json::from_slice(&host.dispatch(&json!({"schema":"kelft.host-request/1","kind":kind,"maximum":{"read":["/project"],"write":["/project"]},"request":request}).to_string()).unwrap()).unwrap();assert_eq!(result["error"],"DENIED");}}
  assert_eq!(fs::read(root.join("sentinel")).unwrap(),b"preserved");fs::remove_file(root.join("sentinel")).unwrap();fs::remove_dir(root).unwrap();
 }
}
