//! Bounded, synchronous filesystem RPC over inherited private pipes.
//! Handles are connection-local tokens, never OS descriptors. Malformed frames
//! poison the connection; callers must close it and terminate its worker.
use std::io::{self, Read, Write};
pub const TRANSFER_LIMIT: usize = 64 << 10;
pub const PATH_LIMIT: usize = 131064;
pub const HOST_LIMIT: usize = 4 << 20;
pub const HANDLE_LIMIT: usize = 128;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Operation { OpenRead=1, OpenWrite=2, CreateNew=3, Read=4, Write=5, Close=6, CreateDirectory=7, Metadata=8, HostRequest=9, HostContinue=10 }
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {pub sequence:u64, pub operation:Operation, pub handle:u64, pub path:String, pub amount:u32, pub data:Vec<u8>}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {pub sequence:u64, pub status:i32, pub value:u64, pub data:Vec<u8>}
fn invalid(message:&'static str)->io::Error {io::Error::new(io::ErrorKind::InvalidData,message)}
fn u32_at(input:&mut impl Read)->io::Result<u32>{let mut b=[0;4];input.read_exact(&mut b)?;Ok(u32::from_le_bytes(b))}
fn u64_at(input:&mut impl Read)->io::Result<u64>{let mut b=[0;8];input.read_exact(&mut b)?;Ok(u64::from_le_bytes(b))}
fn magic(input:&mut impl Read,expected:&[u8;4])->io::Result<bool>{
 let mut b=[0;4];loop{match input.read(&mut b[..1]){Ok(0)=>return Ok(false),Ok(1)=>break,Err(e)if e.kind()==io::ErrorKind::Interrupted=>continue,Err(e)=>return Err(e),_=>unreachable!()}}
 input.read_exact(&mut b[1..])?;if &b!=expected{return Err(invalid("filesystem frame signature"));}Ok(true)
}
pub fn validate_relative(path:&str)->io::Result<()> {
 if path=="."{return Ok(());}
 if path.is_empty()||path.len()>PATH_LIMIT||path.contains(['\\',':','\0'])||path.split('/').count()>4096||path.split('/').any(|p|p.is_empty()||p=="."||p=="..") {return Err(invalid("filesystem path must contain normal relative components"));}Ok(())
}
impl Request {
 pub fn validate(&self)->io::Result<()> {
  if self.sequence==0||self.handle==0||self.data.len()>TRANSFER_LIMIT||self.amount as usize>TRANSFER_LIMIT{return Err(invalid("filesystem request bounds"));}
  match self.operation {
   Operation::HostRequest=>{if self.handle!=1||self.path.is_empty()||self.path.len()>HOST_LIMIT||self.amount!=0||!self.data.is_empty(){return Err(invalid("invalid host request envelope"));}},
   Operation::HostContinue=>{if self.handle!=1||!self.path.is_empty()||self.amount!=0||!self.data.is_empty(){return Err(invalid("invalid host continuation"));}},
   Operation::OpenRead|Operation::OpenWrite|Operation::CreateNew|Operation::CreateDirectory|Operation::Metadata=>{validate_relative(&self.path)?;if self.amount!=0||!self.data.is_empty(){return Err(invalid("unexpected filesystem payload"));}}
   Operation::Read=>{if !self.path.is_empty()||!self.data.is_empty(){return Err(invalid("unexpected read payload"));}}
   Operation::Write=>{if !self.path.is_empty()||self.amount as usize!=self.data.len(){return Err(invalid("write length differs"));}}
   Operation::Close=>{if !self.path.is_empty()||self.amount!=0||!self.data.is_empty(){return Err(invalid("unexpected close payload"));}}
  } Ok(())
 }
}
pub fn read_request(input:&mut impl Read)->io::Result<Option<Request>> {
 if !magic(input,b"KFS1")? {return Ok(None);}
 let sequence=u64_at(input)?;let operation=match u32_at(input)?{1=>Operation::OpenRead,2=>Operation::OpenWrite,3=>Operation::CreateNew,4=>Operation::Read,5=>Operation::Write,6=>Operation::Close,7=>Operation::CreateDirectory,8=>Operation::Metadata,9=>Operation::HostRequest,10=>Operation::HostContinue,_=>return Err(invalid("unknown filesystem operation"))};
 let handle=u64_at(input)?;let length=u32_at(input)? as usize;let amount=u32_at(input)?;
 if length>if operation==Operation::HostRequest{HOST_LIMIT}else{PATH_LIMIT}||amount as usize>TRANSFER_LIMIT{return Err(invalid("filesystem frame exceeds bound"));}
 let mut path=vec![0;length];input.read_exact(&mut path)?;
 let path=String::from_utf8(path).map_err(|_|invalid("filesystem path UTF-8"))?;
 let mut data=vec![0;if operation==Operation::Write {amount as usize}else{0}];input.read_exact(&mut data)?;
 let request=Request{sequence,operation,handle,path,amount,data};request.validate()?;Ok(Some(request))
}
pub fn write_request(output:&mut impl Write,request:&Request)->io::Result<()> {
 request.validate()?;output.write_all(b"KFS1")?;output.write_all(&request.sequence.to_le_bytes())?;
 output.write_all(&(request.operation as u32).to_le_bytes())?;output.write_all(&request.handle.to_le_bytes())?;
 output.write_all(&(request.path.len() as u32).to_le_bytes())?;output.write_all(&request.amount.to_le_bytes())?;
 output.write_all(request.path.as_bytes())?;output.write_all(&request.data)?;output.flush()
}
impl Response {fn validate(&self)->io::Result<()> {if self.sequence==0||!(-7..=0).contains(&self.status)||self.data.len()>TRANSFER_LIMIT||self.status!=0&&(self.value!=0||!self.data.is_empty()){return Err(invalid("filesystem response bounds"));}Ok(())}}
pub fn read_response(input:&mut impl Read,sequence:u64)->io::Result<Response> {
 if !magic(input,b"KFR1")?{return Err(invalid("missing filesystem response"));}
 let actual=u64_at(input)?;let status=u32_at(input)? as i32;let value=u64_at(input)?;let size=u32_at(input)? as usize;
 if actual!=sequence||size>TRANSFER_LIMIT{return Err(invalid("filesystem response sequence or length differs"));}
 let mut data=vec![0;size];input.read_exact(&mut data)?;let result=Response{sequence:actual,status,value,data};result.validate()?;Ok(result)
}
pub fn write_response(output:&mut impl Write,response:&Response)->io::Result<()> {
 response.validate()?;output.write_all(b"KFR1")?;output.write_all(&response.sequence.to_le_bytes())?;
 output.write_all(&response.status.to_le_bytes())?;output.write_all(&response.value.to_le_bytes())?;
 output.write_all(&(response.data.len() as u32).to_le_bytes())?;output.write_all(&response.data)?;output.flush()
}
/// A transport session enforces replay/order checks before invoking a broker.
pub fn serve(input:&mut impl Read,output:&mut impl Write,mut operation:impl FnMut(&Request)->io::Result<(u64,Vec<u8>)>)->io::Result<()> {
 let mut expected=1u64;
 while let Some(request)=read_request(input)? {
  if request.sequence!=expected {return Err(invalid("filesystem request sequence differs"));}
  expected=expected.checked_add(1).ok_or_else(||invalid("filesystem sequence exhausted"))?;
  let response=match operation(&request) {Ok((value,data))=>Response{sequence:request.sequence,status:0,value,data},Err(error)if error.kind()==io::ErrorKind::InvalidData=>return Err(error),Err(error)=>Response{sequence:request.sequence,status:match error.kind(){io::ErrorKind::PermissionDenied=>-1,io::ErrorKind::NotFound=>-2,io::ErrorKind::AlreadyExists=>-3,io::ErrorKind::InvalidInput=>-4,io::ErrorKind::NotADirectory=>-6,io::ErrorKind::IsADirectory=>-7,_=>-5},value:0,data:vec![]}};
  write_response(output,&response)?;
 } Ok(())
}
/// Additive host envelopes share ordering with KFS1; old operations retain their
/// exact frames. One bounded response is drained before another request starts.
pub fn serve_host(input:&mut impl Read,output:&mut impl Write,mut filesystem:impl FnMut(&Request)->io::Result<(u64,Vec<u8>)>,mut host:impl FnMut(&str)->io::Result<Vec<u8>>)->io::Result<()> {
 let mut pending=Vec::new();let mut offset=0usize;
 serve(input,output,|request|{
  if request.operation==Operation::HostRequest {
   if offset<pending.len(){return Err(invalid("host response was not drained"));}
   pending=host(&request.path)?;offset=0;if pending.len()>((64<<20)+65536){return Err(invalid("host response exceeds bound"));}
   let total=pending.len();let end=total.min(TRANSFER_LIMIT);let chunk=pending[..end].to_vec();offset=end;return Ok((total as u64,chunk));
  }
  if request.operation==Operation::HostContinue {
   if offset>=pending.len(){return Err(invalid("unexpected host continuation"));}let end=(offset+TRANSFER_LIMIT).min(pending.len());let chunk=pending[offset..end].to_vec();offset=end;if offset==pending.len(){pending.clear();offset=0;}return Ok((0,chunk));
  }
  if offset<pending.len(){return Err(invalid("host response was not drained"));}filesystem(request)
 })
}
#[cfg(test)]mod tests {
 use super::*;
 fn request()->Request {Request{sequence:1,operation:Operation::OpenRead,handle:1,path:"hé 😀/file".into(),amount:0,data:vec![]}}
 #[test]fn exact_binary_frames_and_unicode_round_trip(){let req=request();let mut bytes=vec![];write_request(&mut bytes,&req).unwrap();assert_eq!(read_request(&mut bytes.as_slice()).unwrap(),Some(req));let response=Response{sequence:1,status:0,value:3,data:vec![0,255,128]};bytes.clear();write_response(&mut bytes,&response).unwrap();assert_eq!(read_response(&mut bytes.as_slice(),1).unwrap(),response);}
 #[test]fn invalid_requests_never_write_partial_frames(){for path in ["../escape","/absolute","C:/drive","a\\b","a//b","./a","a/../b","a\0b"]{let mut req=request();req.path=path.into();let mut out=vec![];assert!(write_request(&mut out,&req).is_err());assert!(out.is_empty());}let mut req=request();req.operation=Operation::Write;req.path.clear();req.amount=1;assert!(req.validate().is_err());}
 #[test]fn truncated_frames_and_large_lengths_are_rejected(){let mut bytes=vec![];write_request(&mut bytes,&request()).unwrap();for n in 1..bytes.len(){assert!(read_request(&mut &bytes[..n]).is_err(),"{n}");}bytes[24..28].copy_from_slice(&u32::MAX.to_le_bytes());assert!(read_request(&mut bytes.as_slice()).is_err());}
 #[test]fn replayed_requests_cannot_reach_the_filesystem(){let mut bytes=vec![];write_request(&mut bytes,&request()).unwrap();write_request(&mut bytes,&request()).unwrap();let mut calls=0;assert!(serve(&mut bytes.as_slice(),&mut vec![],|_|{calls+=1;Ok((9,vec![]))}).is_err());assert_eq!(calls,1);}
 #[test]fn error_details_do_not_leak_host_paths(){let mut bytes=vec![];write_request(&mut bytes,&request()).unwrap();let mut out=vec![];serve(&mut bytes.as_slice(),&mut out,|_|Err(io::Error::new(io::ErrorKind::PermissionDenied,"private host path"))).unwrap();let result=read_response(&mut out.as_slice(),1).unwrap();assert_eq!(result.status,-1);assert!(result.data.is_empty());assert!(read_response(&mut out.as_slice(),2).is_err());}
 #[test]fn host_responses_drain_in_order_before_filesystem_effects(){
  let host=Request{sequence:1,operation:Operation::HostRequest,handle:1,path:"{}".into(),amount:0,data:vec![]};
  let continuation=Request{sequence:2,operation:Operation::HostContinue,path:String::new(),..host.clone()};
  let mut ordinary=request();ordinary.sequence=3;let mut input=vec![];
  for frame in [&host,&continuation,&ordinary]{write_request(&mut input,frame).unwrap();}
  let payload=vec![42;TRANSFER_LIMIT+3];let(mut output,mut effects,mut calls)=(vec![],0,0);
  serve_host(&mut input.as_slice(),&mut output,|_|{effects+=1;Ok((0,vec![]))},|_|{calls+=1;Ok(payload.clone())}).unwrap();
  let mut bytes=output.as_slice();let first=read_response(&mut bytes,1).unwrap();let second=read_response(&mut bytes,2).unwrap();assert_eq!(first.value,payload.len() as u64);assert_eq!([first.data,second.data].concat(),payload);assert_eq!(read_response(&mut bytes,3).unwrap().status,0);assert_eq!((effects,calls),(1,1));
  input.clear();ordinary.sequence=2;for frame in [&host,&ordinary]{write_request(&mut input,frame).unwrap();}effects=0;
  assert!(serve_host(&mut input.as_slice(),&mut vec![],|_|{effects+=1;Ok((0,vec![]))},|_|Ok(payload.clone())).is_err());assert_eq!(effects,0);
 }
 #[test]fn malformed_host_sessions_stop_before_followup_effects(){
  let host=Request{sequence:1,operation:Operation::HostRequest,handle:1,path:"{}".into(),amount:0,data:vec![]};let mut ordinary=request();ordinary.sequence=2;let mut input=vec![];
  for frame in [&host,&ordinary]{write_request(&mut input,frame).unwrap();}let mut effects=0;
  assert!(serve_host(&mut input.as_slice(),&mut vec![],|_|{effects+=1;Ok((0,vec![]))},|_|Err(invalid("malformed host envelope"))).is_err());assert_eq!(effects,0);
  let continuation=Request{operation:Operation::HostContinue,path:String::new(),..host};input.clear();write_request(&mut input,&continuation).unwrap();
  assert!(serve_host(&mut input.as_slice(),&mut vec![],|_|{effects+=1;Ok((0,vec![]))},|_|Ok(vec![])).is_err());assert_eq!(effects,0);
 }
}
