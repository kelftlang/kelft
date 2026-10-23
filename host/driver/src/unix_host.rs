//! Parent-owned Unix host protocol. OS supervision remains platform specific.
use crate::{host_channel::{self,Policy,Process,Filesystem},unix_filesystem::Broker};
use serde_json::{Value,json};
use std::{io,path::PathBuf};

#[derive(Clone)]pub struct Grant{pub guest:String,pub path:PathBuf,pub read:bool,pub write:bool}
pub struct Server{pub caller:Policy,pub grants:Vec<Grant>,roots:Vec<(String,u64,bool,bool)>,broker:Broker,cwd:String,calls:usize}
impl Server{
 pub fn new(caller:Policy,grants:Vec<Grant>,cwd:String)->io::Result<Self>{
  if !caller.validate()||!host_channel::normal(&cwd)||!cwd.starts_with('/'){return Err(io::Error::new(io::ErrorKind::InvalidInput,"invalid host policy"));}
  let mut broker=Broker::default();let mut roots=vec![];for grant in &grants{if !grant.guest.starts_with('/')||!host_channel::normal(&grant.guest){return Err(io::Error::from(io::ErrorKind::InvalidInput));}let token=broker.add_root(&grant.path,grant.read,grant.write)?;roots.push((grant.guest.clone(),token,grant.read,grant.write));}
  Ok(Self{caller,grants,roots,broker,cwd,calls:0})
 }
 fn path(&self,path:&str,writing:bool,maximum:&Policy)->Result<(String,u64,String),&'static str>{
  let path=if path.starts_with('/'){path.to_owned()}else{format!("{}/{path}",self.cwd)};
  if !path.starts_with('/')||!host_channel::normal(&path){return Err("DENIED");}
  let allowed=if writing{&maximum.write}else{&maximum.read};let caller=if writing{&self.caller.write}else{&self.caller.read};if !allowed.iter().any(|r|host_channel::within(&path,r))||!caller.iter().any(|r|host_channel::within(&path,r)){return Err("DENIED");}
  let root=self.roots.iter().filter(|(name,_,read,write)|(if writing{*write}else{*read})&&host_channel::within(&path,name)).max_by_key(|(name,_,_,_)|name.len()).ok_or("DENIED")?;
  let tail=if path==root.0{".".into()}else{path[root.0.len()..].trim_start_matches('/').into()};Ok((path,root.1,tail))
 }
 fn filesystem(&self,request:Value,writing:bool,maximum:&Policy)->Value{
  let result=(||->Result<Value,String>{
   let r:Filesystem=serde_json::from_value(request).map_err(|_|"INVALID_REQUEST")?;
   if r.schema!="kelft.filesystem-request/1"||writing!=matches!(r.operation.as_str(),"temporary"|"rename"|"remove"){return Err("INVALID_REQUEST".into());}
   let(path,token,relative)=self.path(&r.path,writing,maximum).map_err(str::to_owned)?;
   let error=|e:io::Error|match e.kind(){io::ErrorKind::PermissionDenied=>"DENIED".into(),io::ErrorKind::NotFound=>"ENOENT".into(),io::ErrorKind::AlreadyExists=>"EEXIST".into(),io::ErrorKind::NotADirectory=>"ENOTDIR".into(),io::ErrorKind::DirectoryNotEmpty=>"ENOTEMPTY".into(),io::ErrorKind::InvalidInput=>"INVALID_REQUEST".into(),_ if e.raw_os_error()==Some(libc::ELOOP)=>"DENIED".into(),_=>"IO_ERROR".into()};
   let protected=|p:&str|self.roots.iter().any(|(r,_,_,_)|r==p)||maximum.write.iter().any(|r|r==p);
   match r.operation.as_str(){
    "list" if r.destination.is_none()&&r.prefix.is_none()&&r.recursive.is_none()=>Ok(json!(self.broker.host_list(token,&relative).map_err(error)?)),
    "metadata" if r.destination.is_none()&&r.prefix.is_none()&&r.recursive.is_none()=>self.broker.host_metadata(token,&relative).map_err(error),
    "temporary" if r.destination.is_none()&&r.recursive.is_none()=>Ok(json!(format!("{path}/{}",self.broker.host_temporary(token,&relative,r.prefix.as_deref().ok_or("INVALID_REQUEST")?).map_err(error)?))),
    "rename" if r.prefix.is_none()&&r.recursive.is_none()=>{let(dest,target,leaf)=self.path(r.destination.as_deref().ok_or("INVALID_REQUEST")?,true,maximum).map_err(str::to_owned)?;if protected(&path)||protected(&dest){return Err("DENIED".into());}self.broker.host_rename(token,&relative,target,&leaf).map_err(error)?;Ok(json!(true))},
    "remove" if r.prefix.is_none()&&r.destination.is_none()=>{if protected(&path){return Err("DENIED".into());}self.broker.host_remove(token,&relative,r.recursive.ok_or("INVALID_REQUEST")?).map_err(error)?;Ok(json!(true))},
    _=>Err("INVALID_REQUEST".into())
   }
  })();match result{Ok(value)=>json!({"schema":"kelft.filesystem-result/1","error":"","value":value}),Err(e)=>host_channel::filesystem_error(&e)}
 }
 pub fn dispatch(&mut self,raw:&str,mut execute:impl FnMut(&Process,&str,&[Grant])->Value)->io::Result<Vec<u8>>{
  self.calls+=1;if self.calls>4096{return Err(io::Error::new(io::ErrorKind::InvalidData,"host call budget"));}
  let e=host_channel::decode(raw).map_err(|_|io::Error::new(io::ErrorKind::InvalidData,"malformed host envelope"))?;
  if e.schema!="kelft.host-request/1"||!e.maximum.validate(){return Err(io::Error::new(io::ErrorKind::InvalidData,"invalid host envelope"));}
  let result=match e.kind.as_str(){
   "filesystem-read"=>self.filesystem(e.request,false,&e.maximum),"filesystem-write"=>self.filesystem(e.request,true,&e.maximum),
   "process"=>match serde_json::from_value::<Process>(e.request){Err(_)=>host_channel::process_error("INVALID_REQUEST"),Ok(r)=>match host_channel::authorize(&e.maximum,&self.caller,&r){Err(error)=>host_channel::process_error(error),Ok(grant)=>execute(&r,&grant.profile,&self.grants)}},
   _=>return Err(io::Error::new(io::ErrorKind::InvalidData,"unknown host operation"))
  };serde_json::to_vec(&result).map_err(io::Error::other)
 }
}
