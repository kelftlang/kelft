//! Filesystem broker for restricted Windows workers. Only relative names cross
//! the pipe. Root/ancestor handles deny delete sharing and all traversal rejects
//! reparse points. No project ACLs are expanded to make files accessible to LPAC.
use crate::filesystem_channel::{self,Operation,Request,HANDLE_LIMIT};
use std::{collections::BTreeMap,ffi::c_void,fs::File,io::{self,Read,Write},mem,path::Path,ptr};
use std::os::windows::{ffi::OsStrExt,io::{AsRawHandle,FromRawHandle}};
use windows_sys::Win32::{Foundation::{HANDLE,INVALID_HANDLE_VALUE},Storage::FileSystem::*};

#[repr(C)]struct Unicode {length:u16,maximum:u16,buffer:*const u16}
#[repr(C)]struct Attributes {length:u32,root:HANDLE,name:*const Unicode,flags:u32,security:*const c_void,quality:*const c_void}
#[repr(C)]struct IoStatus {status:usize,information:usize}
#[link(name="ntdll")]unsafe extern "system" {
 fn NtCreateFile(handle:*mut HANDLE,access:u32,attributes:*const Attributes,status:*mut IoStatus,size:*const i64,file_attributes:u32,sharing:u32,disposition:u32,options:u32,ea:*const c_void,ea_length:u32)->i32;
 fn RtlNtStatusToDosError(status:i32)->u32;
 fn NtSetInformationFile(file:HANDLE,status:*mut IoStatus,information:*const c_void,length:u32,class:u32)->i32;
}
fn invalid(message:&'static str)->io::Error {io::Error::new(io::ErrorKind::InvalidInput,message)}
fn denied()->io::Error {io::Error::new(io::ErrorKind::PermissionDenied,"filesystem grant denied")}
fn volume(file:&File)->io::Result<u64>{
 let mut id=FILE_ID_INFO::default();
 if unsafe{GetFileInformationByHandleEx(file.as_raw_handle(),FileIdInfo,(&mut id as *mut FILE_ID_INFO).cast(),mem::size_of_val(&id) as u32)}==0{return Err(io::Error::last_os_error());}Ok(id.VolumeSerialNumber)
}
fn same_object(a:&File,b:&File)->io::Result<bool>{let mut ids=[FILE_ID_INFO::default(),FILE_ID_INFO::default()];for(file,id)in [(a,&mut ids[0] as *mut FILE_ID_INFO),(b,&mut ids[1] as *mut FILE_ID_INFO)]{if unsafe{GetFileInformationByHandleEx(file.as_raw_handle(),FileIdInfo,id.cast(),mem::size_of::<FILE_ID_INFO>() as u32)}==0{return Err(io::Error::last_os_error());}}Ok(ids[0].VolumeSerialNumber==ids[1].VolumeSerialNumber&&ids[0].FileId.Identifier==ids[1].FileId.Identifier)}
fn check(file:&File,directory:bool,expected_volume:Option<u64>)->io::Result<()> {
 let mut attributes=FILE_ATTRIBUTE_TAG_INFO::default();
 if unsafe{GetFileInformationByHandleEx(file.as_raw_handle(),FileAttributeTagInfo,(&mut attributes as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),mem::size_of_val(&attributes) as u32)}==0{return Err(io::Error::last_os_error());}
 if unsafe{GetFileType(file.as_raw_handle())}!=FILE_TYPE_DISK || attributes.FileAttributes&FILE_ATTRIBUTE_REPARSE_POINT!=0 || (attributes.FileAttributes&FILE_ATTRIBUTE_DIRECTORY!=0)!=directory {return Err(denied());}
 if let Some(expected)=expected_volume{if volume(file)?!=expected{return Err(denied());}}Ok(())
}
fn component(name:&str)->io::Result<Vec<u16>> {
 if name.is_empty()||matches!(name,"."|"..")||name.contains(['\\','/',':','\0'])||name.ends_with(['.',' '])||name.chars().any(|c|c<' '||matches!(c,'<'|'>'|'"'|'|'|'?'|'*')) {return Err(invalid("invalid Windows broker component"));}
 let base=name.split('.').next().unwrap().to_ascii_uppercase();
 if matches!(base.as_str(),"CON"|"PRN"|"AUX"|"NUL"|"CONIN$"|"CONOUT$") || (base.starts_with("COM")||base.starts_with("LPT"))&&base.len()==4&&matches!(base.as_bytes()[3],b'1'..=b'9') {return Err(invalid("Windows device names cannot be broker paths"));}
 let wide:Vec<_>=name.encode_utf16().collect();if wide.len()>32766{return Err(invalid("Windows broker component exceeds bound"));}Ok(wide)
}
fn relative(parent:&File,name:&str,access:u32,disposition:u32,directory:bool,expected_volume:u64)->io::Result<File>{
 relative_kind(parent,name,access,disposition,Some(directory),expected_volume)
}
fn relative_kind(parent:&File,name:&str,access:u32,disposition:u32,directory:Option<bool>,expected_volume:u64)->io::Result<File>{relative_kind_open(parent,name,access,disposition,directory,expected_volume,false)}
fn relative_kind_open(parent:&File,name:&str,access:u32,disposition:u32,directory:Option<bool>,expected_volume:u64,metadata_only:bool)->io::Result<File>{
 let wide=component(name)?;let unicode=Unicode{length:(wide.len()*2) as u16,maximum:(wide.len()*2) as u16,buffer:wide.as_ptr()};
 let attributes=Attributes{length:mem::size_of::<Attributes>() as u32,root:parent.as_raw_handle(),name:&unicode,flags:0x40|if metadata_only{0}else{0x1000},security:ptr::null(),quality:ptr::null()};
 let mut status=IoStatus{status:0,information:0};let mut handle=ptr::null_mut();
 // SYNCHRONIZE, OPEN_REPARSE_POINT and synchronous I/O; never share DELETE.
 let result=unsafe{NtCreateFile(&mut handle,access|0x00100000,&attributes,&mut status,ptr::null(),FILE_ATTRIBUTE_NORMAL,if directory==Some(false)&&access&FILE_READ_DATA!=0{FILE_SHARE_READ}else{FILE_SHARE_READ|FILE_SHARE_WRITE},disposition,0x00200000|0x20|match directory{Some(true)=>1,Some(false)=>0x40,None=>0},ptr::null(),0)};
 if result<0{return Err(io::Error::from_raw_os_error(unsafe{RtlNtStatusToDosError(result)} as i32));}
 if handle.is_null()||handle==INVALID_HANDLE_VALUE{return Err(invalid("missing broker file handle"));}
 let file=unsafe{File::from_raw_handle(handle)};if metadata_only{if unsafe{GetFileType(file.as_raw_handle())}!=FILE_TYPE_DISK||volume(&file)?!=expected_volume{return Err(denied());}}else{check(&file,directory.unwrap_or(file.metadata()?.is_dir()),Some(expected_volume))?;}Ok(file)
}
struct Root {file:File,_ancestors:Vec<File>,leaf:Option<String>,pin:Option<File>,read:bool,write:bool,volume:u64}
// Windows does not apply all sharing restrictions to metadata-only file opens.
// A retained, non-inherited data-access handle participates in delete sharing;
// it is never read or exposed to a worker. ReOpenFile binds the existing object.
fn pin_object(file:&File)->io::Result<File>{if file.metadata()?.is_dir(){return file.try_clone();}let raw=unsafe{ReOpenFile(file.as_raw_handle(),FILE_READ_DATA|FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE,0)};if raw==INVALID_HANDLE_VALUE||raw.is_null(){return Err(io::Error::last_os_error());}Ok(unsafe{File::from_raw_handle(raw)})}
struct Opened {file:File,_ancestors:Vec<File>,read:bool,write:bool,transferred:u64}
pub struct Broker {roots:BTreeMap<u64,Root>,files:BTreeMap<u64,Opened>,next:u64}
impl Default for Broker {fn default()->Self{Self{roots:BTreeMap::new(),files:BTreeMap::new(),next:1<<32}}}
impl Broker {
 /// Resolve through retained, non-delete-sharing ancestors. Extended operations
 /// never authorize a path and then reopen it through an ambient host pathname.
 fn host_node(&self,token:u64,path:&str,writing:bool,access:u32)->io::Result<(File,Vec<File>)>{
  filesystem_channel::validate_relative(path)?;let root=self.roots.get(&token).ok_or_else(denied)?;if if writing{!root.write}else{!root.read}{return Err(denied());}
  if path=="."&&root.leaf.is_none(){return Ok((root.file.try_clone()?,vec![]));}
  let path=match &root.leaf{Some(leaf)=>if path=="."{leaf.clone()}else{format!("{leaf}/{path}")},None=>path.to_owned()};let mut parts=path.split('/').peekable();let mut parent=&root.file;let mut ancestors=vec![];
  while let Some(name)=parts.next(){if parts.peek().is_none(){return Ok((relative_kind_open(parent,name,access|FILE_READ_ATTRIBUTES,1,None,root.volume,access==FILE_READ_ATTRIBUTES)?,ancestors));}let next=relative(parent,name,FILE_LIST_DIRECTORY|FILE_READ_ATTRIBUTES,1,true,root.volume)?;ancestors.push(next);parent=ancestors.last().unwrap();}Err(invalid("empty extended path"))
 }
 fn host_parent(&self,token:u64,path:&str)->io::Result<(File,Vec<File>,String)>{
  filesystem_channel::validate_relative(path)?;if path=="."{return Err(denied());}let root=self.roots.get(&token).ok_or_else(denied)?;if !root.write{return Err(denied());}
  let(parent,name)=path.rsplit_once('/').unwrap_or((".",path));let(file,ancestors)=self.host_node(token,parent,true,FILE_LIST_DIRECTORY)?;if !file.metadata()?.is_dir(){return Err(io::Error::from(io::ErrorKind::NotADirectory));}component(name)?;Ok((file,ancestors,name.into()))
 }
 fn host_names(file:&File)->io::Result<Vec<String>>{
  let mut wide=vec![0u16;32768];let n=unsafe{GetFinalPathNameByHandleW(file.as_raw_handle(),wide.as_mut_ptr(),wide.len() as u32,0)};if n==0||n as usize>=wide.len(){return Err(io::Error::last_os_error());}wide.truncate(n as usize);let path=String::from_utf16(&wide).map_err(|_|invalid("unrepresentable directory path"))?;
  let mut names=vec![];let mut budget=1<<20;for entry in std::fs::read_dir(path)?{let name=entry?.file_name().into_string().map_err(|_|invalid("unrepresentable directory entry"))?;component(&name)?;if names.len()>=4096||name.len()>budget{return Err(invalid("directory entry budget"));}budget-=name.len();names.push(name);}names.sort_by(|a,b|a.as_bytes().cmp(b.as_bytes()));Ok(names)
 }
 pub fn host_list(&self,token:u64,path:&str)->io::Result<Vec<String>>{let(file,_held)=self.host_node(token,path,false,FILE_LIST_DIRECTORY)?;Self::host_names(&file)}
 pub fn host_metadata(&self,token:u64,path:&str)->io::Result<serde_json::Value>{let(file,_held)=self.host_node(token,path,false,FILE_READ_ATTRIBUTES)?;let m=file.metadata()?;Ok(serde_json::json!({"kind":if std::os::windows::fs::MetadataExt::file_attributes(&m)&FILE_ATTRIBUTE_REPARSE_POINT!=0{"link"}else if m.is_dir(){"directory"}else if m.is_file(){"file"}else{"other"},"sizeBytes":m.len().to_string()}))}
 pub fn host_temporary(&self,token:u64,path:&str,prefix:&str)->io::Result<String>{
  if prefix.is_empty()||prefix.len()>48||!prefix.bytes().all(|b|b.is_ascii_alphanumeric()||matches!(b,b'_'|b'-')){return Err(invalid("invalid temporary prefix"));}
  let(parent,_held)=self.host_node(token,path,true,FILE_LIST_DIRECTORY)?;let device=volume(&parent)?;for _ in 0..32{let mut nonce=[0;16];getrandom::fill(&mut nonce).map_err(|_|io::Error::other("temporary entropy unavailable"))?;let name=format!("{prefix}{}",crate::host_channel::hex(&nonce));match relative(&parent,&name,FILE_READ_ATTRIBUTES,2,true,device){Ok(_)=>return Ok(name),Err(e)if e.kind()==io::ErrorKind::AlreadyExists=>continue,Err(e)=>return Err(e)}}Err(io::Error::other("temporary namespace exhausted"))
 }
 pub fn host_rename(&self,source:u64,path:&str,destination:u64,target:&str)->io::Result<()> {
  if path=="."||target=="."{return Err(denied());}let(file,_source_held)=self.host_node(source,path,true,0x10000)?;let(parent,_target_held,name)=self.host_parent(destination,target)?;let name=component(&name)?;let length=(20+name.len()*2).max(24);let mut storage=vec![0usize;length.div_ceil(mem::size_of::<usize>())];let p=storage.as_mut_ptr().cast::<u8>();
  unsafe{ptr::write_unaligned(p.add(8).cast::<HANDLE>(),parent.as_raw_handle());ptr::write_unaligned(p.add(16).cast::<u32>(),(name.len()*2) as u32);ptr::copy_nonoverlapping(name.as_ptr().cast::<u8>(),p.add(20),name.len()*2);}let mut status=IoStatus{status:0,information:0};let code=unsafe{NtSetInformationFile(file.as_raw_handle(),&mut status,p.cast(),length as u32,10)};if code<0{return Err(io::Error::from_raw_os_error(unsafe{RtlNtStatusToDosError(code)} as i32));}Ok(())
 }
 pub fn host_remove(&self,token:u64,path:&str,recursive:bool)->io::Result<()> {
  if path=="."{return Err(denied());}let(file,_held)=self.host_node(token,path,true,0x10000|FILE_LIST_DIRECTORY)?;let mut entries=vec![];
  fn collect(file:File,recursive:bool,depth:usize,entries:&mut Vec<File>)->io::Result<()>{if entries.len()>=4096||depth>64{return Err(invalid("removal traversal budget"));}if file.metadata()?.is_dir()&&recursive{let device=volume(&file)?;for name in Broker::host_names(&file)?{let child=relative_kind(&file,&name,0x10000|FILE_READ_ATTRIBUTES|FILE_LIST_DIRECTORY,1,None,device)?;collect(child,true,depth+1,entries)?;}}if entries.len()>=4096{return Err(invalid("removal traversal budget"));}entries.push(file);Ok(())}
  collect(file,recursive,0,&mut entries)?;for file in entries{let mut status=IoStatus{status:0,information:0};let remove=1u8;let code=unsafe{NtSetInformationFile(file.as_raw_handle(),&mut status,(&remove as *const u8).cast(),1,13)};if code<0{return Err(io::Error::from_raw_os_error(unsafe{RtlNtStatusToDosError(code)} as i32));}}Ok(())
 }
 /// Root registration is parent-only. Returned IDs are scoped to this broker.
 pub fn add_root(&mut self,path:&Path,read:bool,write:bool)->io::Result<u64>{
  if (!read&&!write)||self.roots.len()>=HANDLE_LIMIT{return Err(invalid("invalid broker root grant"));}
  let text=path.to_str().ok_or_else(||invalid("root must be Unicode"))?;
  let text=text.strip_prefix("\\\\?\\").unwrap_or(text);let b=text.as_bytes();
  if b.len()<3||!b[0].is_ascii_alphabetic()||b[1]!=b':'||b[2]!=b'\\'||text.contains('\0'){return Err(invalid("local absolute drive root required"));}
  let drive:Vec<u16>=std::ffi::OsStr::new(&text[..3]).encode_wide().chain([0]).collect();
  let raw=unsafe{CreateFileW(drive.as_ptr(),FILE_READ_ATTRIBUTES|0x00100000,FILE_SHARE_READ|FILE_SHARE_WRITE,ptr::null(),OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,ptr::null_mut())};
  if raw==INVALID_HANDLE_VALUE||raw.is_null(){return Err(io::Error::last_os_error());}
  let mut file=unsafe{File::from_raw_handle(raw)};check(&file,true,None)?;let serial=volume(&file)?;let mut ancestors=vec![];
  let mut leaf=None;let mut pin=None;let tail=&text[3..];if !tail.is_empty(){let mut parts=tail.split('\\').peekable();while let Some(name)=parts.next(){
   if parts.peek().is_some(){let next=relative(&file,name,FILE_READ_DATA|FILE_READ_ATTRIBUTES,1,true,serial)?;ancestors.push(file);file=next;}
   else{match relative_kind(&file,name,FILE_READ_ATTRIBUTES,1,None,serial){
    Ok(next)if next.metadata()?.is_dir()=>{let pinned=relative(&file,name,FILE_READ_DATA|FILE_READ_ATTRIBUTES,1,true,serial)?;if !same_object(&next,&pinned)?{return Err(denied());}ancestors.push(file);file=pinned;},
    Ok(next)=>{leaf=Some(name.into());pin=Some(pin_object(&next)?);},
    Err(error)if write&&error.kind()==io::ErrorKind::NotFound=>{component(name)?;leaf=Some(name.into());},Err(error)=>return Err(error),
   }}
  }}
  let token=self.roots.len() as u64+1;self.roots.insert(token,Root{file,_ancestors:ancestors,leaf,pin,read,write,volume:serial});Ok(token)
 }
 fn open(&mut self,request:&Request)->io::Result<u64>{
  if self.files.len()>=HANDLE_LIMIT{return Err(invalid("broker handle budget exhausted"));}
  let root=self.roots.get_mut(&request.handle).ok_or_else(denied)?;
  let read=request.operation==Operation::OpenRead;let directory=request.operation==Operation::CreateDirectory;
  if read&&!root.read||!read&&!root.write{return Err(denied());}
  let path=match &root.leaf{Some(leaf)=>if request.path=="."{leaf.clone()}else{format!("{leaf}/{}",request.path)},None=>{if request.path=="."{return if directory{Ok(0)}else{Err(io::Error::from(io::ErrorKind::IsADirectory))};}request.path.clone()}};
  let mut parts=path.split('/').peekable();let mut parent=&root.file;let mut ancestors=Vec::new();
  while let Some(name)=parts.next(){
   if parts.peek().is_some(){let file=relative(parent,name,FILE_READ_DATA|FILE_READ_ATTRIBUTES,1,true,root.volume)?;ancestors.push(file);parent=ancestors.last().unwrap();}
   else{
    if !directory{match relative_kind(parent,name,FILE_READ_ATTRIBUTES,1,None,root.volume){Ok(metadata)if metadata.metadata()?.is_dir()=>return Err(io::Error::from(io::ErrorKind::IsADirectory)),Ok(_)=>{},Err(error)if !read&&error.kind()==io::ErrorKind::NotFound=>{},Err(error)=>return Err(error)}}
    let access=if directory{FILE_READ_ATTRIBUTES}else if read{FILE_READ_DATA|FILE_READ_ATTRIBUTES}else{FILE_WRITE_DATA|FILE_READ_ATTRIBUTES};
    let disposition=if read{1}else if request.operation==Operation::CreateNew{2}else{3};
    let file=relative(parent,name,access,disposition,directory,root.volume)?;
    if root.pin.is_none()&&root.leaf.is_some()&&request.path=="."{let pinned=if directory{relative(parent,name,FILE_READ_DATA|FILE_READ_ATTRIBUTES,1,true,root.volume)?}else{pin_object(&file)?};if !same_object(&file,&pinned)?{return Err(denied());}root.pin=Some(pinned);}
    if directory{return Ok(0);}
    if read&&file.metadata()?.len()>64<<20{return Err(invalid("broker file exceeds bound"));}
    if !read{file.set_len(0)?;}
    let token=self.next;self.next=self.next.checked_add(1).ok_or_else(||invalid("broker token exhausted"))?;
    self.files.insert(token,Opened{file,_ancestors:ancestors,read,write:!read,transferred:0});return Ok(token);
   }
  }Err(invalid("empty broker path"))
 }
 fn metadata(&self,request:&Request)->io::Result<u64>{
  let root=self.roots.get(&request.handle).ok_or_else(denied)?;
  if request.path=="."&&root.leaf.is_none(){return Ok(2);}
  let path=match &root.leaf{Some(leaf)=>if request.path=="."{leaf.clone()}else{format!("{leaf}/{}",request.path)},None=>request.path.clone()};
  let mut parts=path.split('/').peekable();let mut parent=&root.file;let mut ancestors=vec![];
  while let Some(name)=parts.next(){let last=parts.peek().is_none();let file=relative_kind(parent,name,FILE_READ_ATTRIBUTES|if last{0}else{FILE_READ_DATA},1,if last{None}else{Some(true)},root.volume)?;if last{return Ok(if file.metadata()?.is_dir(){2}else{1});}ancestors.push(file);parent=ancestors.last().unwrap();}Err(invalid("empty metadata path"))
 }
 pub fn execute(&mut self,request:&Request)->io::Result<(u64,Vec<u8>)>{
  request.validate()?;
  match request.operation{
   Operation::HostRequest|Operation::HostContinue=>Err(invalid("host service is unavailable")),
   Operation::OpenRead=>{let token=self.open(request)?;let size=self.files.get(&token).ok_or_else(denied)?.file.metadata()?.len();Ok((token,size.to_le_bytes().to_vec()))},
   Operation::OpenWrite|Operation::CreateNew|Operation::CreateDirectory=>Ok((self.open(request)?,vec![])),
   Operation::Metadata=>Ok((self.metadata(request)?,vec![])),
   Operation::Close=>{self.files.remove(&request.handle).ok_or_else(denied)?;Ok((0,vec![]))},
   Operation::Read|Operation::Write=>{
    let file=self.files.get_mut(&request.handle).ok_or_else(denied)?;
    if request.operation==Operation::Read&&!file.read||request.operation==Operation::Write&&!file.write{return Err(denied());}
    if file.transferred+request.amount as u64>64<<20{return Err(invalid("broker file transfer exceeds bound"));}
    if request.operation==Operation::Read{let mut data=vec![0;request.amount as usize];let count=file.file.read(&mut data)?;data.truncate(count);file.transferred+=count as u64;Ok((count as u64,data))}
    else{file.file.write_all(&request.data)?;file.transferred+=request.data.len() as u64;Ok((request.data.len() as u64,vec![]))}
   }
  }
 }
 pub fn serve(&mut self,input:&mut impl Read,output:&mut impl Write)->io::Result<()>{filesystem_channel::serve(input,output,|request|self.execute(request))}
}
#[cfg(test)]mod tests {
 use super::*;use crate::filesystem_channel::TRANSFER_LIMIT;
 fn temporary()->std::path::PathBuf {let mut random=[0;16];getrandom::fill(&mut random).unwrap();let name=random.iter().map(|b|format!("{b:02x}")).collect::<String>();let dir=std::env::temp_dir().join(format!("kelft-broker-{name}"));std::fs::create_dir(&dir).unwrap();dir}
 fn req(operation:Operation,handle:u64,path:&str)->Request{Request{sequence:1,operation,handle,path:path.into(),amount:0,data:vec![]}}
 #[test]fn open_descendants_pin_their_directory_chain_until_close(){
  let dir=temporary();let child=dir.join("child");std::fs::create_dir(&child).unwrap();std::fs::write(child.join("input"),b"original").unwrap();
  {let mut broker=Broker::default();let root=broker.add_root(&dir,true,false).unwrap();let(file,_)=broker.execute(&req(Operation::OpenRead,root,"child/input")).unwrap();assert!(std::fs::rename(&child,dir.join("moved")).is_err());broker.execute(&req(Operation::Close,file,"")).unwrap();std::fs::rename(&child,dir.join("moved")).unwrap();}
  std::fs::remove_dir_all(dir).unwrap();
 }
 #[test]fn exact_file_and_missing_leaf_grants_keep_root_identity_and_stable_reads(){
  let dir=temporary();let source=dir.join("input");std::fs::write(&source,[0,255,128]).unwrap();
  {let mut broker=Broker::default();let root=broker.add_root(&source,true,false).unwrap();assert_eq!(broker.execute(&req(Operation::Metadata,root,".")).unwrap().0,1);assert!(broker.execute(&req(Operation::OpenRead,root,"sibling")).is_err());let(file,size)=broker.execute(&req(Operation::OpenRead,root,".")).unwrap();assert_eq!(size,3u64.to_le_bytes());assert!(std::fs::write(&source,b"changed").is_err());broker.execute(&req(Operation::Close,file,"")).unwrap();std::fs::write(&source,[0,255,128]).unwrap();assert!(std::fs::rename(&source,dir.join("replacement")).is_err());
   let future=dir.join("new folder");let write=broker.add_root(&future,false,true).unwrap();assert!(broker.execute(&req(Operation::Metadata,write,".")).is_err());broker.execute(&req(Operation::CreateDirectory,write,".")).unwrap();assert_eq!(broker.execute(&req(Operation::Metadata,write,".")).unwrap().0,2);assert!(std::fs::rename(&future,dir.join("replacement folder")).is_err());let(file,_)=broker.execute(&req(Operation::CreateNew,write,"child")).unwrap();broker.execute(&req(Operation::Close,file,"")).unwrap();
  }std::fs::remove_dir_all(dir).unwrap();
 }
 #[test]fn native_broker_separates_read_write_and_owns_handle_lifetimes(){
  let dir=temporary();std::fs::write(dir.join("input"),b"private contents").unwrap();
  {let mut broker=Broker::default();let read=broker.add_root(&dir,true,false).unwrap();let write=broker.add_root(&dir,false,true).unwrap();
   assert!(broker.execute(&req(Operation::OpenWrite,read,"denied")).is_err());assert!(!dir.join("denied").exists());assert!(broker.execute(&req(Operation::OpenRead,write,"input")).is_err());
   let(token,_)=broker.execute(&req(Operation::OpenRead,read,"input")).unwrap();let mut request=req(Operation::Read,token,"");request.amount=TRANSFER_LIMIT as u32;
   assert_eq!(broker.execute(&request).unwrap().1,b"private contents");assert!(broker.execute(&req(Operation::Write,token,"")).is_err());broker.execute(&req(Operation::Close,token,"")).unwrap();assert!(broker.execute(&request).is_err());
   let(token,_)=broker.execute(&req(Operation::CreateNew,write,"hé 😀")).unwrap();let mut request=req(Operation::Write,token,"");request.data=vec![0,255,128];request.amount=3;broker.execute(&request).unwrap();assert_eq!(std::fs::read(dir.join("hé 😀")).unwrap(),request.data);
   assert!(broker.execute(&req(Operation::CreateNew,write,"hé 😀")).is_err());assert!(std::fs::rename(&dir,dir.with_extension("replacement")).is_err());
  }std::fs::remove_dir_all(dir).unwrap();
 }
 #[test]fn native_broker_rejects_devices_streams_and_parent_traversal(){let dir=temporary();{let mut broker=Broker::default();let root=broker.add_root(&dir,true,true).unwrap();for path in ["../escape","NUL","con.txt","LPT1","COM9.log","file:stream","file.","file ","a\\b"]{assert!(broker.execute(&req(Operation::OpenWrite,root,path)).is_err(),"{path}");}}std::fs::remove_dir_all(dir).unwrap();}
 #[test]fn native_broker_cannot_follow_a_junction_into_ungranted_files(){
  use std::os::windows::fs::OpenOptionsExt;
  let dir=temporary();let outside=temporary();let junction=dir.join("junction");std::fs::create_dir(&junction).unwrap();std::fs::write(outside.join("sentinel"),b"preserved").unwrap();
  let target=std::fs::canonicalize(&outside).unwrap();let target=target.to_str().unwrap().strip_prefix("\\\\?\\").unwrap_or(target.to_str().unwrap());
  let substitute:Vec<u16>=format!("\\??\\{target}").encode_utf16().collect();let display:Vec<u16>=target.encode_utf16().collect();
  let length=8+(substitute.len()+display.len()+2)*2;let mut bytes=Vec::new();bytes.extend(0xa0000003u32.to_le_bytes());bytes.extend((length as u16).to_le_bytes());bytes.extend(0u16.to_le_bytes());
  bytes.extend(0u16.to_le_bytes());bytes.extend((substitute.len() as u16*2).to_le_bytes());bytes.extend(((substitute.len() as u16+1)*2).to_le_bytes());bytes.extend((display.len() as u16*2).to_le_bytes());
  for word in substitute.into_iter().chain([0]).chain(display).chain([0]){bytes.extend(word.to_le_bytes());}
  {let file=std::fs::OpenOptions::new().access_mode(0x40000000).custom_flags(FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT).open(&junction).unwrap();let mut count=0;
   assert_ne!(unsafe{windows_sys::Win32::System::IO::DeviceIoControl(file.as_raw_handle(),0x000900a4,bytes.as_ptr().cast(),bytes.len() as u32,ptr::null_mut(),0,&mut count,ptr::null_mut())},0,"create junction control: {}",io::Error::last_os_error());}
  {let mut broker=Broker::default();let root=broker.add_root(&dir,true,true).unwrap();assert!(broker.add_root(&junction,true,true).is_err());
   assert!(broker.execute(&req(Operation::OpenRead,root,"junction/sentinel")).is_err());assert!(broker.execute(&req(Operation::OpenWrite,root,"junction/sentinel")).is_err());}
  assert_eq!(std::fs::read(outside.join("sentinel")).unwrap(),b"preserved");std::fs::remove_dir(&junction).unwrap();std::fs::remove_dir_all(dir).unwrap();std::fs::remove_dir_all(outside).unwrap();
 }
}
