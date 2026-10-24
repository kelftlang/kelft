//! WASI preview1 files use opaque KFS1 roots. No OS directory is preopened.
use crate::filesystem_channel::{self as wire,Operation,Request,Response};
use serde::Deserialize;use std::{collections::BTreeMap,io::{self,Read,Write},sync::{Arc,Mutex}};
use wasmtime::{Caller,Config,Engine,Linker,Memory,Module,Store,StoreLimits,StoreLimitsBuilder};
use wasmtime_wasi::{WasiCtxBuilder,p1::{self,WasiP1Ctx}};
type Error=wasmtime::Error;
#[derive(Deserialize,Clone)]#[serde(deny_unknown_fields)]pub struct Root{pub guest:String,pub handle:String,pub read:bool,pub write:bool}
#[derive(Clone)]pub struct Client{inner:Arc<Mutex<Session>>}
struct Session{input:Box<dyn Read+Send>,output:Box<dyn Write+Send>,sequence:u64,failed:bool}
impl Client{
 pub fn new(input:impl Read+Send+'static,output:impl Write+Send+'static)->Self{Self{inner:Arc::new(Mutex::new(Session{input:Box::new(input),output:Box::new(output),sequence:1,failed:false}))}}
 fn call(&mut self,operation:Operation,handle:u64,path:&str,amount:u32,data:Vec<u8>)->Result<Response,Error>{
  self.inner.lock().map_err(|_|Error::msg("engine filesystem lock poisoned"))?.call(operation,handle,path,amount,data)
 }
 pub fn stderr(&mut self,bytes:&[u8])->Result<(),Error>{for chunk in bytes.chunks(65536){let response=self.call(Operation::Write,u64::MAX,"",chunk.len() as u32,chunk.to_vec())?;if response.status!=0||response.value!=chunk.len() as u64||!response.data.is_empty(){return Err(Error::msg("engine stderr transfer differs"));}}Ok(())}
}
impl Session{
 fn call(&mut self,operation:Operation,handle:u64,path:&str,amount:u32,data:Vec<u8>)->Result<Response,Error>{
  if self.failed{return Err(Error::msg("poisoned engine filesystem session"));}let request=Request{sequence:self.sequence,operation,handle,path:path.into(),amount,data};
  let result=(||{wire::write_request(&mut self.output,&request)?;wire::read_response(&mut self.input,self.sequence)})();
  match result{Ok(response)=>{if let Some(next)=self.sequence.checked_add(1){self.sequence=next;Ok(response)}else{self.failed=true;Err(Error::msg("engine sequence exhausted"))}},Err(error)=>{self.failed=true;Err(error.into())}}
 }
}
#[cfg(test)]mod tests{
 use super::*;use std::sync::{Arc,Mutex};
 struct Count(Arc<Mutex<Vec<u8>>>);impl Write for Count{fn write(&mut self,bytes:&[u8])->io::Result<usize>{self.0.lock().unwrap().extend_from_slice(bytes);Ok(bytes.len())}fn flush(&mut self)->io::Result<()>{Ok(())}}
 #[test]fn malformed_broker_responses_poison_before_any_followup_request(){
  let mut valid=vec![];wire::write_response(&mut valid,&Response{sequence:1,status:0,value:1,data:vec![]}).unwrap();
  for response in [valid[..valid.len()-1].to_vec(),{let mut frame=valid.clone();frame[4..12].copy_from_slice(&2u64.to_le_bytes());frame},{let mut frame=valid.clone();frame[12..16].copy_from_slice(&(-1i32).to_le_bytes());frame}]{let sent=Arc::new(Mutex::new(vec![]));let mut client=Client::new(io::Cursor::new(response),Count(sent.clone()));assert!(client.call(Operation::Metadata,1,"file",0,vec![]).is_err());let previous=sent.lock().unwrap().clone();assert!(client.call(Operation::OpenRead,1,"another",0,vec![]).is_err());assert_eq!(*sent.lock().unwrap(),previous);}
 }
}
struct File{token:u64,size:u64,read:bool,write:bool,position:u64}
struct State{wasi:WasiP1Ctx,limits:StoreLimits,client:Client,roots:Vec<Root>,files:BTreeMap<u32,File>,next:u32,output:usize}
fn memory(caller:&mut Caller<'_,State>)->Result<Memory,Error>{caller.get_export("memory").and_then(|value|value.into_memory()).ok_or_else(||Error::msg("WASI memory export required"))}
fn range(caller:&mut Caller<'_,State>,pointer:i32,length:u32)->Result<(Memory,usize),Error>{let memory=memory(caller)?;let at=pointer as u32 as usize;let end=at.checked_add(length as usize).ok_or_else(||Error::msg("WASI memory range overflow"))?;if end>memory.data_size(&*caller){return Err(Error::msg("WASI memory range outside instance"));}Ok((memory,at))}
fn bytes(caller:&mut Caller<'_,State>,pointer:i32,length:u32)->Result<Vec<u8>,Error>{let(memory,at)=range(caller,pointer,length)?;Ok(memory.data(&*caller)[at..at+length as usize].into())}
fn put(caller:&mut Caller<'_,State>,pointer:i32,bytes:&[u8])->Result<(),Error>{let(memory,at)=range(caller,pointer,bytes.len().try_into()?)?;memory.write(caller,at,bytes)?;Ok(())}
fn errno(status:i32)->i32{match status{0=>0,-1=>63,-2=>44,-3=>20,-4=>28,-6=>54,-7=>31,_=>29}}
fn root(caller:&Caller<'_,State>,fd:i32)->Option<Root>{fd.checked_sub(3).and_then(|index|caller.data().roots.get(index as usize)).cloned()}
fn relative(caller:&mut Caller<'_,State>,pointer:i32,length:i32)->Result<String,Error>{if length<0||length as usize>wire::PATH_LIMIT{return Err(Error::msg("WASI path exceeds bound"));}let name=String::from_utf8(bytes(caller,pointer,length as u32)?)?;wire::validate_relative(&name)?;Ok(name)}
fn stat(kind:u64,size:u64)->[u8;64]{let mut out=[0u8;64];out[16]=if kind==2{3}else{4};out[24..32].copy_from_slice(&1u64.to_le_bytes());out[32..40].copy_from_slice(&size.to_le_bytes());out}
fn iovecs(caller:&mut Caller<'_,State>,pointer:i32,count:i32)->Result<Vec<(i32,u32)>,Error>{
 if !(0..=1024).contains(&count){return Err(Error::msg("WASI iovec budget"));}let table=bytes(caller,pointer,(count as u32)*8)?;let mut result=vec![];let mut total=0usize;
 for entry in table.chunks_exact(8){let at=i32::from_le_bytes(entry[..4].try_into()?);let length=u32::from_le_bytes(entry[4..].try_into()?);range(caller,at,length)?;total=total.checked_add(length as usize).ok_or_else(||Error::msg("WASI iovec length overflow"))?;if total>64<<20{return Err(Error::msg("WASI transfer exceeds bound"));}result.push((at,length));}Ok(result)
}
pub fn execute(module_bytes:&[u8],args:&[String],roots:Vec<Root>,client:Client)->Result<i32,Error>{
 if module_bytes.is_empty()||module_bytes.len()>64<<20||args.len()>4096||args.iter().map(String::len).sum::<usize>()>1<<20||roots.len()>128{return Err(Error::msg("bounded engine inputs required"));}
 let mut seen=std::collections::HashSet::new();let mut configuration="1c8:/project".to_owned();for root in &roots{
  if !root.guest.starts_with('/')||root.guest=="/"||root.guest.contains(['\\',':','\0'])||root.guest[1..].split('/').any(|s|s.is_empty()||matches!(s,"."|".."))||!seen.insert(&root.guest)||!root.read&&!root.write{return Err(Error::msg("invalid engine preopen mapping"));}
  let token=root.handle.parse::<u64>()?;if token==0||token==u64::MAX{return Err(Error::msg("invalid engine root token"));}for(allowed,kind)in [(root.read,'r'),(root.write,'w')]{if allowed{configuration.push_str(&format!("{kind}{}:{}",root.guest.len(),root.guest));}}
 }
 let mut config=Config::new();config.wasm_multi_memory(false).wasm_memory64(false).memory_reservation(256<<20).memory_guard_size(65536).async_stack_size(16<<20).max_wasm_stack(8<<20);
 let engine=Engine::new(&config)?;let module=Module::new(&engine,module_bytes)?;
 const ALLOWED:&[&str]=&["args_get","args_sizes_get","environ_get","environ_sizes_get","fd_write","fd_read","fd_close","fd_seek","fd_fdstat_get","fd_filestat_get","fd_prestat_get","fd_prestat_dir_name","path_open","path_readlink","path_filestat_get","path_create_directory","proc_exit"];
 for import in module.imports(){if import.module()!="wasi_snapshot_preview1"||!ALLOWED.contains(&import.name())||!matches!(import.ty(),wasmtime::ExternType::Func(_)){return Err(Error::msg("unsupported optional engine import"));}}
 let mut wasi=WasiCtxBuilder::new();wasi.arg("program.wasm").args(args).env("KELFT_WASI_CAPABILITIES",&configuration);
 let state=State{wasi:wasi.build_p1(),limits:StoreLimitsBuilder::new().memory_size(256<<20).instances(1).memories(1).build(),client,roots,files:BTreeMap::new(),next:1024,output:0};let mut store=Store::new(&engine,state);store.limiter(|state|&mut state.limits);
 let mut linker=Linker::new(&engine);p1::add_to_linker_sync(&mut linker,|state:&mut State|&mut state.wasi)?;linker.allow_shadowing(true);let ns="wasi_snapshot_preview1";
 linker.func_wrap(ns,"proc_exit",|status:i32|->Result<(),Error>{if !(0..=255).contains(&status){return Err(Error::msg("exit outside Kelft range"));}Err(wasmtime_wasi::I32Exit(status).into())})?;
 linker.func_wrap(ns,"fd_prestat_get",|mut caller:Caller<'_,State>,fd:i32,out:i32|->Result<i32,Error>{let Some(root)=root(&caller,fd)else{return Ok(8)};let mut result=[0;8];result[4..].copy_from_slice(&(root.guest.len() as u32).to_le_bytes());put(&mut caller,out,&result)?;Ok(0)})?;
 linker.func_wrap(ns,"fd_prestat_dir_name",|mut caller:Caller<'_,State>,fd:i32,out:i32,length:i32|->Result<i32,Error>{let Some(root)=root(&caller,fd)else{return Ok(8)};if length<0||(length as usize)<root.guest.len(){return Ok(37)}put(&mut caller,out,root.guest.as_bytes())?;Ok(0)})?;
 linker.func_wrap(ns,"path_open",|mut caller:Caller<'_,State>,fd:i32,lookup:i32,path:i32,length:i32,flags:i32,rights:i64,inherit:i64,fdflags:i32,out:i32|->Result<i32,Error>{
  range(&mut caller,out,4)?;let Some(root)=root(&caller,fd)else{return Ok(8)};if lookup&!1!=0||inherit!=0||fdflags!=0{return Ok(76)}let name=relative(&mut caller,path,length)?;let reading=rights==2097154;let writing=rights==64;
  let operation=if reading&&root.read&&flags==0{Operation::OpenRead}else if writing&&root.write&&matches!(flags,9|5){if flags==5{Operation::CreateNew}else{Operation::OpenWrite}}else{return Ok(76)};
  if caller.data().files.len()>=128{return Ok(33)}let response=caller.data_mut().client.call(operation,root.handle.parse()?,&name,0,vec![])?;if response.status!=0{return Ok(errno(response.status))}if response.value==0||reading&&response.data.len()!=8||writing&&!response.data.is_empty(){return Err(Error::msg("broker open response differs"));}
  let size=if reading{u64::from_le_bytes(response.data.as_slice().try_into()?)}else{0};if size>64<<20{return Err(Error::msg("broker file exceeds bound"));}let id=caller.data().next;caller.data_mut().next=id.checked_add(1).ok_or_else(||Error::msg("engine descriptor budget"))?;caller.data_mut().files.insert(id,File{token:response.value,size,read:reading,write:writing,position:0});put(&mut caller,out,&id.to_le_bytes())?;Ok(0)
 })?;
 linker.func_wrap(ns,"fd_close",|mut caller:Caller<'_,State>,fd:i32|->Result<i32,Error>{let Some(file)=caller.data_mut().files.remove(&(fd as u32))else{return Ok(8)};let response=caller.data_mut().client.call(Operation::Close,file.token,"",0,vec![])?;Ok(errno(response.status))})?;
 linker.func_wrap(ns,"fd_filestat_get",|mut caller:Caller<'_,State>,fd:i32,out:i32|->Result<i32,Error>{let Some(file)=caller.data().files.get(&(fd as u32))else{return Ok(8)};if !file.read{return Ok(76)}let result=stat(1,file.size);put(&mut caller,out,&result)?;Ok(0)})?;
 linker.func_wrap(ns,"path_create_directory",|mut caller:Caller<'_,State>,fd:i32,path:i32,length:i32|->Result<i32,Error>{let Some(root)=root(&caller,fd)else{return Ok(8)};if !root.write{return Ok(76)}let name=relative(&mut caller,path,length)?;let response=caller.data_mut().client.call(Operation::CreateDirectory,root.handle.parse()?,&name,0,vec![])?;Ok(errno(response.status))})?;
 linker.func_wrap(ns,"path_readlink",|mut caller:Caller<'_,State>,fd:i32,path:i32,length:i32,out:i32,size:i32,used:i32|->Result<i32,Error>{if size<0{return Ok(28)}range(&mut caller,out,size as u32)?;range(&mut caller,used,4)?;let Some(root)=root(&caller,fd)else{return Ok(8)};let name=relative(&mut caller,path,length)?;let response=caller.data_mut().client.call(Operation::Metadata,root.handle.parse()?,&name,0,vec![])?;Ok(if response.status==0{28}else{errno(response.status)})})?;
 linker.func_wrap(ns,"path_filestat_get",|mut caller:Caller<'_,State>,fd:i32,flags:i32,path:i32,length:i32,out:i32|->Result<i32,Error>{range(&mut caller,out,64)?;if flags&!1!=0{return Ok(28)}let Some(root)=root(&caller,fd)else{return Ok(8)};let name=relative(&mut caller,path,length)?;let token=root.handle.parse()?;let response=caller.data_mut().client.call(Operation::Metadata,token,&name,0,vec![])?;if response.status!=0{return Ok(errno(response.status))}let mut size=0;if response.value==1{if !root.read{return Ok(76)}let opened=caller.data_mut().client.call(Operation::OpenRead,token,&name,0,vec![])?;if opened.status!=0{return Ok(errno(opened.status))}if opened.value==0||opened.data.len()!=8{return Err(Error::msg("broker stat response differs"));}size=u64::from_le_bytes(opened.data.as_slice().try_into()?);let closed=caller.data_mut().client.call(Operation::Close,opened.value,"",0,vec![])?;if closed.status!=0{return Ok(errno(closed.status))}}else if response.value!=2{return Err(Error::msg("broker metadata kind differs"));}put(&mut caller,out,&stat(response.value,size))?;Ok(0)})?;
 // The fixed Kelft opens request FD_READ/FD_FILESTAT_GET or FD_WRITE, never
 // FD_SEEK or FD_TELL. Reporting an offset must respect those actual rights.
 linker.func_wrap(ns,"fd_seek",|caller:Caller<'_,State>,fd:i32,_offset:i64,_whence:i32,_out:i32|->i32{if caller.data().files.contains_key(&(fd as u32)){76}else{8}})?;
 linker.func_wrap(ns,"fd_fdstat_get",|mut caller:Caller<'_,State>,fd:i32,out:i32|->Result<i32,Error>{let mut result=[0u8;24];if let Some(file)=caller.data().files.get(&(fd as u32)){result[0]=4;result[8..16].copy_from_slice(&(if file.read{2097154u64}else{64u64}).to_le_bytes());}else if let Some(root)=root(&caller,fd){result[0]=3;let base=8192u64|32768|if root.read{262144}else{0}|if root.write{512|1024|524288}else{0};let inherit=if root.read{2097154u64}else{0}|if root.write{64}else{0};result[8..16].copy_from_slice(&base.to_le_bytes());result[16..24].copy_from_slice(&inherit.to_le_bytes());}else if matches!(fd,1|2){result[0]=2;result[8..16].copy_from_slice(&64u64.to_le_bytes());}else{return Ok(8)}put(&mut caller,out,&result)?;Ok(0)})?;
 linker.func_wrap(ns,"fd_read",|mut caller:Caller<'_,State>,fd:i32,iov:i32,count:i32,out:i32|->Result<i32,Error>{
  range(&mut caller,out,4)?;let iovecs=iovecs(&mut caller,iov,count)?;let Some(file)=caller.data().files.get(&(fd as u32))else{return Ok(8)};if !file.read{return Ok(76)}let token=file.token;let mut total=0u32;
  'transfer:for(pointer,size)in iovecs{let mut at=0;while at<size{let amount=(size-at).min(65536);let response=caller.data_mut().client.call(Operation::Read,token,"",amount,vec![])?;if response.status!=0{return Ok(errno(response.status))}if response.value!=response.data.len() as u64||response.data.len()>amount as usize{return Err(Error::msg("broker read response differs"));}let n=response.data.len() as u32;put(&mut caller,(pointer as u32+at)as i32,&response.data)?;at+=n;total+=n;if n<amount{break 'transfer;}}}caller.data_mut().files.get_mut(&(fd as u32)).unwrap().position+=total as u64;put(&mut caller,out,&total.to_le_bytes())?;Ok(0)
 })?;
 linker.func_wrap(ns,"fd_write",|mut caller:Caller<'_,State>,fd:i32,iov:i32,count:i32,out:i32|->Result<i32,Error>{
  range(&mut caller,out,4)?;let iovecs=iovecs(&mut caller,iov,count)?;let token=if fd==1||fd==2{None}else{let Some(file)=caller.data().files.get(&(fd as u32))else{return Ok(8)};if !file.write{return Ok(76)}Some(file.token)};let mut total=0u32;
  for(pointer,size)in iovecs{let mut at=0;while at<size{let n=(size-at).min(65536);let data=bytes(&mut caller,(pointer as u32+at)as i32,n)?;if let Some(token)=token{let response=caller.data_mut().client.call(Operation::Write,token,"",n,data)?;if response.status!=0{return Ok(errno(response.status))}if response.value!=n as u64||!response.data.is_empty(){return Err(Error::msg("broker write response differs"));}}else{caller.data_mut().output=caller.data().output.checked_add(n as usize).ok_or_else(||Error::msg("engine output overflow"))?;if caller.data().output>16<<20{return Err(Error::msg("engine output exceeds bound"));}if fd==1{io::stdout().write_all(&data)?;}else{caller.data_mut().client.stderr(&data)?;}}at+=n;total+=n;}}
  if token.is_some(){let file=caller.data_mut().files.get_mut(&(fd as u32)).unwrap();file.position+=total as u64;file.size=file.size.max(file.position);}put(&mut caller,out,&total.to_le_bytes())?;Ok(0)
 })?;
 linker.allow_shadowing(false);let instance=linker.instantiate(&mut store,&module)?;let entry=instance.get_typed_func::<(),()>(&mut store,"_start")?;match entry.call(&mut store,()){Ok(())=>Ok(0),Err(error)=>if let Some(exit)=error.downcast_ref::<wasmtime_wasi::I32Exit>(){Ok(exit.0)}else{Err(error)}}
}
