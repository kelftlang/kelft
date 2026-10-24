//! Optional engine transport over its standard input/error pipes. Filesystem
//! tokens remain parent-owned; a reserved sink delegates stderr writes only.
use crate::filesystem_channel::{self as rpc,Operation,Request};
use std::{io,sync::{Arc,atomic::{AtomicBool,AtomicUsize,Ordering}}};
pub const STDERR_TOKEN:u64=u64::MAX;
pub fn serve(input:&mut impl io::Read,output:&mut impl io::Write,maximum:usize,total:Arc<AtomicUsize>,failed:Arc<AtomicBool>,mut filesystem:impl FnMut(&Request)->io::Result<(u64,Vec<u8>)>)->io::Result<Vec<u8>>{
 let mut stderr=vec![];
 let result=rpc::serve(input,output,|request|{
  if failed.load(Ordering::Acquire){return Err(io::Error::other("engine channel is closed"));}
  if request.handle!=STDERR_TOKEN{return filesystem(request);}
  if request.operation!=Operation::Write{return Err(io::ErrorKind::PermissionDenied.into());}
  let before=total.fetch_add(request.data.len(),Ordering::AcqRel);if before>maximum||request.data.len()>maximum-before{failed.store(true,Ordering::Release);return Err(io::Error::other("engine capture bound exceeded"));}
  stderr.extend_from_slice(&request.data);Ok((request.data.len() as u64,vec![]))
 });
 if result.is_err(){failed.store(true,Ordering::Release);}result?;Ok(stderr)
}
#[cfg(test)]mod tests{
 use super::*;use std::sync::atomic::Ordering;
 #[test]fn engine_stderr_sink_cannot_delegate_filesystem_or_read_authority(){
  let mut input=vec![];for(sequence,operation,data)in [(1,Operation::Read,vec![]),(2,Operation::Write,b"stderr".to_vec())]{rpc::write_request(&mut input,&Request{sequence,operation,handle:STDERR_TOKEN,path:String::new(),amount:if operation==Operation::Read{1}else{data.len() as u32},data}).unwrap();}
  let mut output=vec![];let failed=Arc::new(AtomicBool::new(false));let captured=serve(&mut input.as_slice(),&mut output,6,Arc::new(AtomicUsize::new(0)),failed.clone(),|_|panic!("stderr token reached filesystem broker")).unwrap();assert_eq!(captured,b"stderr");let mut bytes=output.as_slice();assert_eq!(rpc::read_response(&mut bytes,1).unwrap().status,-1);assert_eq!(rpc::read_response(&mut bytes,2).unwrap().value,6);assert!(!failed.load(Ordering::Acquire));
 }
 #[test]fn engine_stderr_and_stdout_share_one_capture_budget_and_partial_frames_poison(){
  let mut frame=vec![];rpc::write_request(&mut frame,&Request{sequence:1,operation:Operation::Write,handle:STDERR_TOKEN,path:String::new(),amount:2,data:b"xx".to_vec()}).unwrap();let failed=Arc::new(AtomicBool::new(false));let captured=serve(&mut frame.as_slice(),&mut vec![],6,Arc::new(AtomicUsize::new(5)),failed.clone(),|_|unreachable!()).unwrap();assert!(captured.is_empty());assert!(failed.load(Ordering::Acquire));
  for bytes in [b"raw engine stderr".as_slice(),&frame[..frame.len()-1]]{let failed=Arc::new(AtomicBool::new(false));assert!(serve(&mut bytes.as_ref(),&mut vec![],65536,Arc::new(AtomicUsize::new(0)),failed.clone(),|_|unreachable!()).is_err());assert!(failed.load(Ordering::Acquire));}
 }
}
