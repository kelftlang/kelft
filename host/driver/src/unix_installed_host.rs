//! Bounded project snapshots for parent-owned installed compiler requests.
//! Only broker-authorized bytes cross into the compiler's private project.
use crate::{host_channel::{self,Process},installed_request, native_target::Target,unix_host::Grant,unix_filesystem::Broker,filesystem_channel::{Operation,Request}};
use std::{fs,io,path::{Path,PathBuf},time::Instant};
fn denied()->io::Error{io::Error::from(io::ErrorKind::PermissionDenied)}
fn mapped(name:&str,write:bool,grants:&[Grant])->io::Result<PathBuf>{
 if !host_channel::normal(name)||!name.starts_with('/'){return Err(denied());}
 let g=grants.iter().filter(|g|(if write{g.write}else{g.read})&&host_channel::within(name,&g.guest)).max_by_key(|g|g.guest.len()).ok_or_else(denied)?;
 Ok(if name==g.guest{g.path.clone()}else{g.path.join(&name[g.guest.len()+1..])})
}
#[cfg(test)]mod tests{
 use super::*;
 fn fixture()->(PathBuf,Process,Vec<Grant>){
  let mut nonce=[0;16];getrandom::fill(&mut nonce).unwrap();let root=std::env::temp_dir().join(format!("kelft-installed-test-{}",host_channel::hex(&nonce)));fs::create_dir(&root).unwrap();fs::create_dir(root.join("project")).unwrap();fs::write(root.join("project/main.kelft"),b"fn main()->i32 {return 7;}").unwrap();fs::write(root.join("sentinel"),b"preserved").unwrap();
  let request=serde_json::from_value(serde_json::json!({"schema":"kelft.process-request/1","executable":"/package/bin/kelft","sha256":format!("sha256:{}","0".repeat(64)),"args":["build","/project/main.kelft","--project-root","/project","-o","/project/program"],"cwd":"/project","environment":{},"stdinHex":"","read":["/project"],"write":["/project"],"limits":{"timeoutMs":30000,"memoryBytes":268435456,"stdoutBytes":65536,"stderrBytes":65536}})).unwrap();let grants=vec![Grant{guest:"/project".into(),path:root.join("project"),read:true,write:true}];(root,request,grants)
 }
 #[test]fn snapshot_is_independent_and_publication_retains_output_identity(){
  let(root,r,grants)=fixture();{
   let mut p=Project::new(&r,&grants,&root,Instant::now()+std::time::Duration::from_secs(30)).unwrap();let source=fs::read(&p.request.source).unwrap();fs::write(root.join("project/main.kelft"),b"changed").unwrap();assert_eq!(fs::read(&p.request.source).unwrap(),source);
   fs::write(p.directory.join("artifact"),b"native-image").unwrap();p.publish().unwrap();assert_eq!(fs::read(root.join("project/program")).unwrap(),b"native-image");
  }assert_eq!(fs::read(root.join("sentinel")).unwrap(),b"preserved");fs::remove_dir_all(root).unwrap();
 }
 #[test]fn symlinks_and_ungranted_outputs_are_rejected_before_publication(){
  let(root,mut r,grants)=fixture();let deadline=Instant::now()+std::time::Duration::from_secs(30);
  std::os::unix::fs::symlink(root.join("sentinel"),root.join("project/escape")).unwrap();assert!(Project::new(&r,&grants,&root,deadline).is_err());fs::remove_file(root.join("project/escape")).unwrap();
  *r.args.last_mut().unwrap()="/outside/sentinel".into();assert!(Project::new(&r,&grants,&root,deadline).is_err());assert_eq!(fs::read(root.join("sentinel")).unwrap(),b"preserved");assert!(!root.join("project/program").exists());fs::remove_dir_all(root).unwrap();
 }
 #[test]fn output_replacement_and_package_control_flags_are_denied(){
  let(root,mut r,grants)=fixture();let deadline=Instant::now()+std::time::Duration::from_secs(30);fs::write(root.join("project/program"),b"original").unwrap();{
   let mut p=Project::new(&r,&grants,&root,deadline).unwrap();fs::rename(root.join("project/program"),root.join("project/old")).unwrap();fs::write(root.join("project/program"),b"replacement").unwrap();fs::write(p.directory.join("artifact"),b"new").unwrap();assert!(p.publish().is_err());assert_eq!(fs::read(root.join("project/program")).unwrap(),b"replacement");
  }r.args.extend(["--capabilities".into(),"/project/policy.json".into()]);assert!(Project::new(&r,&grants,&root,deadline).is_err());fs::remove_dir_all(root).unwrap();
 }
}
fn guest(value:&str,cwd:&str)->io::Result<String>{let name=if value.starts_with('/'){value.into()}else{format!("{cwd}/{value}")};if !host_channel::normal(&name){return Err(denied());}Ok(name)}
fn operation(broker:&mut Broker,op:Operation,handle:u64,path:&str,amount:u32,data:Vec<u8>)->io::Result<(u64,Vec<u8>)>{broker.execute(&Request{sequence:1,operation:op,handle,path:path.into(),amount,data})}
pub struct Project{pub directory:PathBuf,pub request:installed_request::Request,output:Option<(Broker,u64)>,pub deadline:Instant}
impl Drop for Project{fn drop(&mut self){let _=fs::remove_dir_all(&self.directory);}}
impl Project{
 pub fn new(r:&Process,grants:&[Grant],base:&Path,deadline:Instant)->io::Result<Self>{
  if !r.stdin_hex.is_empty()||!r.environment.is_empty(){return Err(denied());}
  let mut request=installed_request::parse(&r.args,Target::current().map_err(io::Error::other)?,Path::new(&r.cwd)).map_err(|_|denied())?;
  if !matches!(request.command.as_str(),"check"|"build")||request.options.keys().any(|k|!matches!(k.as_str(),"--project-root"|"-o"|"--emit")){return Err(denied());}
  let root=guest(&request.options["--project-root"],&r.cwd)?;
  if !r.read.iter().any(|p|host_channel::within(&root,p)){return Err(denied());}
  let source=guest(&request.source,&r.cwd)?;if !host_channel::within(&source,&root)||source==root{return Err(denied());}
  let path=mapped(&root,false,grants)?;let mut reader=Broker::default();let token=reader.add_root(&path,true,false)?;
  let output=if let Some(name)=request.options.get("-o"){
   let name=guest(name,&r.cwd)?;if !r.write.iter().any(|p|host_channel::within(&name,p))||name.ends_with(".kelft"){return Err(denied());}
   let path=mapped(&name,true,grants)?;let mut broker=Broker::default();let token=broker.add_root(&path,false,true)?;Some((broker,token))
  }else{None};
  let mut nonce=[0;16];getrandom::fill(&mut nonce).map_err(|e|io::Error::other(e.to_string()))?;let directory=base.join(format!("kelft-installed-project-{}",host_channel::hex(&nonce)));std::os::unix::fs::DirBuilderExt::mode(&mut fs::DirBuilder::new(),0o700).create(&directory)?;
  let mut project=Self{directory,request:request.clone(),output,deadline};fs::create_dir(project.directory.join("project"))?;
  let mut pending=vec![(String::from("."),0usize)];let(mut count,mut total)=(0usize,0u64);
  while let Some((relative,depth))=pending.pop(){
   if depth>64||Instant::now()>=deadline{return Err(io::Error::new(io::ErrorKind::TimedOut,"project snapshot deadline"));}
   for name in reader.host_list(token,&relative)?{
    count+=1;if count>4096{return Err(io::Error::other("project snapshot entry bound"));}
    let relative=if relative=="."{name}else{format!("{relative}/{name}")};let metadata=reader.host_metadata(token,&relative)?;let target=project.directory.join("project").join(&relative);
    match metadata["kind"].as_str(){Some("directory")=>{fs::create_dir(&target)?;pending.push((relative,depth+1));},Some("file")=>{
     let size=metadata["sizeBytes"].as_str().and_then(|s|s.parse::<u64>().ok()).ok_or_else(denied)?;total=total.checked_add(size).ok_or_else(denied)?;if total>64<<20{return Err(io::Error::other("project snapshot byte bound"));}
     let(handle,_)=operation(&mut reader,Operation::OpenRead,token,&relative,0,vec![])?;let mut file=fs::File::create(target)?;let mut consumed=0u64;
     loop{if Instant::now()>=deadline{return Err(io::Error::new(io::ErrorKind::TimedOut,"project snapshot deadline"));}let(_,bytes)=operation(&mut reader,Operation::Read,handle,"",65536,vec![])?;if bytes.is_empty(){break;}consumed+=bytes.len() as u64;if consumed>size{return Err(denied());}std::io::Write::write_all(&mut file,&bytes)?;}
     operation(&mut reader,Operation::Close,handle,"",0,vec![])?;if consumed!=size{return Err(denied());}
    },_=>return Err(denied())}
   }
  }
  request.source=project.directory.join("project").join(&source[root.len()+1..]).to_str().ok_or_else(denied)?.into();request.options.insert("--project-root".into(),project.directory.join("project").to_str().ok_or_else(denied)?.into());
  if project.output.is_some(){request.options.insert("-o".into(),project.directory.join("artifact").to_str().ok_or_else(denied)?.into());}project.request=request;Ok(project)
 }
 pub fn publish(&mut self)->io::Result<()>{
  if let Some((broker,root))=&mut self.output{
   if Instant::now()>=self.deadline{return Err(io::Error::new(io::ErrorKind::TimedOut,"publication deadline"));}
   let path=self.directory.join("artifact");let meta=fs::symlink_metadata(&path)?;if !meta.is_file()||meta.len()>64<<20{return Err(denied());}
   let mut file=fs::File::open(path)?;let(handle,_)=operation(broker,Operation::OpenWrite,*root,".",0,vec![])?;let mut buffer=[0;65536];
   loop{let n=std::io::Read::read(&mut file,&mut buffer)?;if n==0{break;}operation(broker,Operation::Write,handle,"",n as u32,buffer[..n].into())?;}
   if self.request.emit=="executable"{broker.executable(handle)?;}operation(broker,Operation::Close,handle,"",0,vec![])?;
  }Ok(())
 }
}
