//! Development-only network controls independent of Winsock catalog loading.
//! This is not a production transport and grants no additional worker capability.
use std::{ffi::c_void, io, mem, net::SocketAddrV4, ptr};
use windows_sys::Win32::{Foundation::{HANDLE,CloseHandle},System::Threading::{CreateEventW,WaitForSingleObject}};

#[repr(C)]struct Unicode { length:u16, maximum:u16, buffer:*const u16 }
#[repr(C)]struct Attributes { length:u32, root:HANDLE, name:*const Unicode, flags:u32, security:*const c_void, quality:*const c_void }
#[repr(C)]#[derive(Default)]struct IoStatus { status:usize, information:usize }
#[link(name="ntdll")]unsafe extern "system" {
 fn NtCreateFile(handle:*mut HANDLE,access:u32,attributes:*const Attributes,status:*mut IoStatus,size:*const i64,file_attributes:u32,sharing:u32,disposition:u32,options:u32,ea:*const c_void,ea_length:u32)->i32;
 fn NtDeviceIoControlFile(handle:HANDLE,event:HANDLE,apc:*const c_void,context:*const c_void,status:*mut IoStatus,code:u32,input:*const c_void,input_length:u32,output:*mut c_void,output_length:u32)->i32;
 fn NtCancelIoFileEx(handle:HANDLE,request:*const IoStatus,status:*mut IoStatus)->i32;
}
struct Handle(HANDLE);
impl Drop for Handle { fn drop(&mut self) { unsafe { CloseHandle(self.0); } } }
#[derive(Debug,serde::Serialize)]
pub struct Observation { pub stage:&'static str, pub status:u32, pub connected:bool, pub authorization_denied:bool }
fn observation(stage:&'static str,status:i32)->Observation {
 Observation{stage,status:status as u32,connected:stage=="connect"&&status==0,authorization_denied:status as u32==0xc0000022}
}
struct Operation { status:IoStatus, input:Vec<u8>, output:[u8;128], _event:Handle }
fn control(socket:&Handle,code:u32,input:Vec<u8>)->io::Result<i32> {
 let event=unsafe{CreateEventW(ptr::null(),0,0,ptr::null())};if event.is_null(){return Err(io::Error::last_os_error());}
 let mut operation=Box::new(Operation{status:IoStatus::default(),input,output:[0;128],_event:Handle(event)});
 let status=unsafe{NtDeviceIoControlFile(socket.0,event,ptr::null(),ptr::null(),&mut operation.status,code,operation.input.as_ptr().cast(),operation.input.len() as u32,operation.output.as_mut_ptr().cast(),operation.output.len() as u32)};
 if status!=0x103{return Ok(status);}
 if unsafe{WaitForSingleObject(event,2000)}==0{return Ok(operation.status.status as i32);}
 let mut cancelled=IoStatus::default();unsafe{NtCancelIoFileEx(socket.0,&operation.status,&mut cancelled);}
 if unsafe{WaitForSingleObject(event,2000)}!=0 {
  // Pending kernel I/O must never retain pointers into freed storage. This
  // bounded diagnostic issues at most two operations per endpoint. Retain this
  // allocation until process teardown rather than freeing a live I/O buffer.
  mem::forget(operation);
 }
 Err(io::Error::new(io::ErrorKind::TimedOut,"native network control did not complete"))
}

fn create_endpoint(family:u32,kind:u32,protocol:u32)->io::Result<Result<Handle,i32>> {
 let name:Vec<u16>="\\Device\\Afd\\Endpoint".encode_utf16().collect();
 let unicode=Unicode{length:(name.len()*2) as u16,maximum:(name.len()*2) as u16,buffer:name.as_ptr()};
 let attributes=Attributes{length:mem::size_of::<Attributes>() as u32,root:ptr::null_mut(),name:&unicode,flags:0x40,security:ptr::null(),quality:ptr::null()};
 // FILE_FULL_EA_INFORMATION header, NUL-terminated AFD packet name and the
 // fixed six-word TLI open packet plus its empty UTF-16 transport name.
 let mut ea=vec![0u8;52];ea[5]=15;ea[6..8].copy_from_slice(&28u16.to_le_bytes());ea[8..24].copy_from_slice(b"AfdOpenPacketXX\0");
 for(at,value)in [(24,0x01000000u32),(32,family),(36,kind),(40,protocol)]{ea[at..at+4].copy_from_slice(&value.to_le_bytes());}
 let mut handle=ptr::null_mut();let mut iosb=IoStatus::default();
 let status=unsafe{NtCreateFile(&mut handle,0xc0100000,&attributes,&mut iosb,ptr::null(),0,3,3,0,ea.as_ptr().cast(),ea.len() as u32)};
 if status!=0{return Ok(Err(status));}
 if handle.is_null(){return Err(io::Error::other("native endpoint handle missing"));}Ok(Ok(Handle(handle)))
}
#[derive(Clone,Copy,Debug)]pub enum Endpoint{Tcp4,Tcp6,Udp4,Udp6}
impl Endpoint{
 pub const ALL:[Self;4]=[Self::Tcp4,Self::Tcp6,Self::Udp4,Self::Udp6];
 pub fn id(self)->&'static str{match self{Self::Tcp4=>"ipv4-tcp",Self::Tcp6=>"ipv6-tcp",Self::Udp4=>"ipv4-udp",Self::Udp6=>"ipv6-udp"}}
 fn fields(self)->(u32,u32,u32){match self{Self::Tcp4=>(2,1,6),Self::Tcp6=>(23,1,6),Self::Udp4=>(2,2,17),Self::Udp6=>(23,2,17)}}
}
#[derive(Debug,serde::Serialize)]pub struct EndpointObservation{pub profile:&'static str,pub status:u32,pub opened:bool,pub authorization_denied:bool}
pub fn open_endpoint(profile:Endpoint)->io::Result<EndpointObservation>{let(family,kind,protocol)=profile.fields();let result=create_endpoint(family,kind,protocol)?;let status=match result{Ok(_)=>0,Err(status)=>status as u32};Ok(EndpointObservation{profile:profile.id(),status,opened:status==0,authorization_denied:status==0xc0000022})}
/// Fixed IPv4/TCP TLI endpoint. A successful host connect and independent
/// listener accept are required before any restricted result is evidence.
pub fn connect(address:SocketAddrV4)->io::Result<Observation> {
 let socket=match create_endpoint(2,1,6)?{Ok(socket)=>socket,Err(status)=>return Ok(observation("open",status))};
 let mut bind=vec![0u8;20];bind[..4].copy_from_slice(&2u32.to_le_bytes());bind[4..6].copy_from_slice(&2u16.to_le_bytes());
 let status=control(&socket,0x12003,bind)?;if status!=0{return Ok(observation("bind",status));}
 // AFD_CONNECT_JOIN_INFO_TL: SanActive, two naturally aligned 64-bit handles,
 // then the SDK's 16-byte SOCKADDR_IN representation (no TDI address fallback).
 let mut request=vec![0u8;40];request[24..26].copy_from_slice(&2u16.to_le_bytes());request[26..28].copy_from_slice(&address.port().to_be_bytes());request[28..32].copy_from_slice(&address.ip().octets());
 Ok(observation("connect",control(&socket,0x12007,request)?))
}

#[cfg(test)]mod tests {
 use super::*;
 #[test]fn all_four_endpoint_profiles_have_successful_native_host_opens(){for profile in Endpoint::ALL{let result=open_endpoint(profile).unwrap();assert!(result.opened,"{result:?}");}}
 #[test]fn private_endpoint_worker(){if std::env::var("KELFT_NETWORK_ENDPOINT_WORKER").as_deref()!=Ok("1"){return;}for profile in Endpoint::ALL{let result=open_endpoint(profile).unwrap();assert!(result.authorization_denied,"{result:?}");println!("{}-endpoint-authorization-denied",profile.id());}}
 #[test]fn lpac_denies_ipv4_ipv6_tcp_udp_endpoint_creation_with_host_positives(){
  use crate::{windows_process::AppContainerSid,windows_snapshot::Image,windows_supervisor::{self,Limits}};use sha2::{Digest,Sha256};
  for profile in Endpoint::ALL{assert!(open_endpoint(profile).unwrap().opened);}
  let bytes=std::fs::read(std::env::current_exe().unwrap()).unwrap();for registry_read in [false,true]{let identity=if registry_read{AppContainerSid::fresh_engine()}else{AppContainerSid::fresh()}.unwrap();let image=Image::new(&bytes,&format!("sha256:{:x}",Sha256::digest(&bytes)),&identity).unwrap();
  let result=windows_supervisor::run(&image,&identity,&std::env::var("SystemRoot").unwrap(),&["--exact".into(),"windows_network_probe::tests::private_endpoint_worker".into(),"--nocapture".into()],Limits{wall_ms:15000,memory_bytes:268435456,output_bytes:65536},&[("KELFT_NETWORK_ENDPOINT_WORKER".into(),"1".into())],vec![]).unwrap();
  assert_eq!(result.exit,Some(0),"{:?}: {}{}",result.failure,String::from_utf8_lossy(&result.stdout),String::from_utf8_lossy(&result.stderr));assert!(result.failure.is_none());for profile in Endpoint::ALL{assert!(String::from_utf8_lossy(&result.stdout).contains(&format!("{}-endpoint-authorization-denied",profile.id())));assert!(open_endpoint(profile).unwrap().opened);}}
 }
 #[test]fn native_network_structures_have_the_64_bit_system_abi(){
  assert_eq!(mem::size_of::<Unicode>(),16);assert_eq!(mem::size_of::<Attributes>(),48);assert_eq!(mem::size_of::<IoStatus>(),16);
  assert_eq!(mem::offset_of!(Attributes,name),16);assert_eq!(mem::size_of::<HANDLE>(),8);
 }
 #[test]fn direct_network_connect_has_an_independent_loopback_accept_positive(){
  let listener=std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST,0)).unwrap();listener.set_nonblocking(true).unwrap();
  let std::net::SocketAddr::V4(address)=listener.local_addr().unwrap()else{unreachable!()};
  let result=connect(address).unwrap();assert!(result.connected,"{result:?}");
  let start=std::time::Instant::now();loop{match listener.accept(){Ok(_)=>break,Err(error)if error.kind()==io::ErrorKind::WouldBlock&&start.elapsed()<std::time::Duration::from_secs(2)=>std::thread::sleep(std::time::Duration::from_millis(5)),Err(error)=>panic!("independent listener did not accept native connection: {error}")}}
 }
 #[test]fn private_direct_network_worker(){
  let Ok(endpoint)=std::env::var("KELFT_NETWORK_PROBE_ENDPOINT")else{return;};
  let result=connect(endpoint.parse().unwrap()).unwrap();assert!(result.authorization_denied,"{result:?}");
  println!("native-direct-network-authorization-denied");
 }
 #[test]fn lpac_denies_direct_network_after_a_real_host_connection(){
  use crate::{windows_process::AppContainerSid,windows_snapshot::Image,windows_supervisor::{self,Limits}};use sha2::{Digest,Sha256};
  let listener=std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST,0)).unwrap();
  let std::net::SocketAddr::V4(address)=listener.local_addr().unwrap()else{unreachable!()};assert!(connect(address).unwrap().connected);
  let bytes=std::fs::read(std::env::current_exe().unwrap()).unwrap();let identity=AppContainerSid::fresh().unwrap();
  let image=Image::new(&bytes,&format!("sha256:{:x}",Sha256::digest(&bytes)),&identity).unwrap();
  let args=["--exact","windows_network_probe::tests::private_direct_network_worker","--nocapture"].map(String::from);
  let result=windows_supervisor::run(&image,&identity,&std::env::var("SystemRoot").unwrap(),&args,
   Limits{wall_ms:15000,memory_bytes:268435456,output_bytes:65536},&[("KELFT_NETWORK_PROBE_ENDPOINT".into(),address.to_string())],vec![]).unwrap();
  assert_eq!(result.exit,Some(0),"{:?}: {}{}",result.failure,String::from_utf8_lossy(&result.stdout),String::from_utf8_lossy(&result.stderr));assert!(result.failure.is_none());
  assert!(String::from_utf8_lossy(&result.stdout).contains("native-direct-network-authorization-denied"));
  assert!(connect(address).unwrap().connected);
 }
}
