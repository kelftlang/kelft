//! Optional, measured host-native LLD service for Linux x64 static executables.
//! No compiler/project path, response file, tool option or search path is
//! delegated to the linker. Native Microsoft linker profiles remain separate.
use crate::{cross_elf,filesystem_channel::{Operation,Request},native_target::Target,
 windows_filesystem::Broker,windows_process::AppContainerSid,windows_snapshot::Image,
 windows_supervisor::{self,Limits}};
use serde::Deserialize;
use sha2::{Digest,Sha256};
use std::{collections::HashSet,fs::{self,File},io::{self,Read},os::windows::fs::{OpenOptionsExt,MetadataExt},path::Path};
fn invalid(message:&'static str)->io::Error{io::Error::new(io::ErrorKind::InvalidInput,message)}
fn hash(bytes:&[u8])->String{format!("sha256:{:x}",Sha256::digest(bytes))}
#[derive(Deserialize)]#[serde(deny_unknown_fields)]struct Tool{path:String,sha256:String}
#[derive(Deserialize)]#[serde(deny_unknown_fields)]struct Input{name:String,path:String,sha256:String}
#[derive(Deserialize)]#[serde(deny_unknown_fields)]struct Configuration{
 schema:String,profile:String,target:String,identity:String,
 #[serde(rename="linkerProfile")]linker_profile:String,
 #[serde(rename="linkerCapabilities")]capabilities:Vec<String>,linker:Tool,libraries:Vec<Input>,
 #[serde(rename="runtimeInputs")]runtime:Vec<Input>,#[serde(rename="systemInputs")]system:Vec<Input>,
}
struct Loaded{name:String,bytes:Vec<u8>,sha256:String,_file:File}
pub struct CrossLinker{identity:String,tool:Loaded,runtime:Vec<Loaded>,_system:Vec<Loaded>,_roots:Broker}
fn load(path:&Path,name:&str,expected:Option<&str>,maximum:u64,total:&mut u64,roots:&mut Broker)->io::Result<Loaded>{
 let normalized=crate::windows_filesystem_session::normalized(path)?;let path=Path::new(&normalized);
 roots.add_root(path,true,false)?;
 let mut file=fs::OpenOptions::new().read(true).share_mode(1).custom_flags(0x00200000).open(path)?;let meta=file.metadata()?;
 *total=total.checked_add(meta.len()).ok_or_else(||invalid("cross-linker inventory overflow"))?;
 if !meta.is_file()||meta.file_attributes()&0x400!=0||meta.len()>maximum||*total>256<<20{return Err(invalid("cross-linker input exceeds profile bound"));}
 let mut bytes=vec![];Read::by_ref(&mut file).take(maximum+1).read_to_end(&mut bytes)?;
 let sha256=hash(&bytes);
 if bytes.len() as u64!=meta.len()||expected.is_some_and(|pin|pin!=sha256){return Err(invalid("pinned cross-linker input changed"));}
 Ok(Loaded{name:name.into(),bytes,sha256,_file:file})
}
fn dll(bytes:&[u8])->io::Result<()>{
 if bytes.len()<328||&bytes[..2]!=b"MZ"{return Err(invalid("cross-linker DLL header missing"));}
 let at=u32::from_le_bytes(bytes[60..64].try_into().unwrap()) as usize;
 if at<64||at>bytes.len()-264||&bytes[at..at+4]!=b"PE\0\0"||u16::from_le_bytes(bytes[at+4..at+6].try_into().unwrap())!=0x8664||u16::from_le_bytes(bytes[at+24..at+26].try_into().unwrap())!=0x20b||u16::from_le_bytes(bytes[at+22..at+24].try_into().unwrap())&0x2000==0{return Err(invalid("cross-linker DLL architecture differs"));}Ok(())
}
impl CrossLinker{
 pub fn from_package(encoded:&[u8],expected:&str,root:&Path,system:&Path)->io::Result<Self>{
  if encoded.len()>1<<20||hash(encoded)!=expected{return Err(invalid("installed cross-linker profile changed"));}
  let mut value:serde_json::Value=serde_json::from_slice(encoded)?;let c:Configuration=serde_json::from_value(value.clone())?;
  value.as_object_mut().ok_or_else(||invalid("cross-linker profile object required"))?.remove("identity");
  if Target::current()?!=Target::WindowsX64||c.schema!="kelft-cross-linker-installed/1"||c.profile!="windows-x86_64"||c.target!="linux-x86_64"||c.linker_profile!="lld-elf-static/1"||!c.capabilities.is_empty()||!c.libraries.is_empty()||c.identity!=hash(&serde_json::to_vec(&value)?)||c.runtime.len()>32||c.system.len()>64||c.linker.path!="rootfs/cross/linux-x86_64/lld.exe"{return Err(invalid("cross-linker profile identity or fixed layout differs"));}
  let mut roots=Broker::default();let mut total=0;
  let tool=load(&root.join(&c.linker.path),"image.exe",Some(&c.linker.sha256),128<<20,&mut total,&mut roots)?;
  Target::WindowsX64.validate_executable(&tool.bytes)?;
  let mut names=HashSet::new();
  let mut inputs=|rows:Vec<Input>,local:bool|->io::Result<Vec<Loaded>>{rows.into_iter().map(|input|{
   let name=&input.name;
   if name.len()>96||name!=&name.to_ascii_lowercase()||name.starts_with('.')||!name.ends_with(".dll")||!name.bytes().all(|b|b.is_ascii_alphanumeric()||matches!(b,b'_'|b'-'|b'.'))||!names.insert(name.clone()) {return Err(invalid("invalid cross-linker DLL name"));}
   let prefix=if local{"rootfs/cross/linux-x86_64/"}else{"System32/"};
   if input.path!=format!("{prefix}{name}"){return Err(invalid("cross-linker DLL escapes fixed input layout"));}
   let loaded=load(&if local{root}else{system}.join(&input.path),name,Some(&input.sha256),64<<20,&mut total,&mut roots)?;dll(&loaded.bytes)?;Ok(loaded)
  }).collect()};
  let runtime=inputs(c.runtime,true)?;let system=inputs(c.system,false)?;
  Ok(Self{identity:c.identity,tool,runtime,_system:system,_roots:roots})
 }
 /// The parent chooses a private compilation directory. The compiler has no
 /// link service; it terminates before its object is snapshotted for LLD.
 pub fn build(&self,destination:&Path,system:&str,compile:impl FnOnce(&Path)->io::Result<()>)->io::Result<serde_json::Value>{
  let mut broker=Broker::default();let output_root=broker.add_root(destination,false,true)?;
  let identity=AppContainerSid::fresh()?;
  // Tool-only bound. Compiler/program snapshots keep their 64 MiB limit.
  let mut image=Image::cross_linker(&self.tool.bytes,&self.tool.sha256,&identity)?;
  for input in &self.runtime{image.runtime_input(&input.name,&input.bytes,&input.sha256)?;}
  let work=image.work_directory()?;image.linker_scratch()?;
  compile(&work)?;
  let mut total=0;let mut retained=Broker::default();let file=work.join("target.o");
  retained.add_root(&file,true,false)?;
  let mut object=fs::OpenOptions::new().read(true).share_mode(1).custom_flags(0x00200000).open(&file)?;let meta=object.metadata()?;
  if !meta.is_file()||meta.file_attributes()&0x400!=0||meta.len()>64<<20{return Err(invalid("invalid staged cross object"));}
  let mut bytes=vec![];Read::by_ref(&mut object).take((64<<20)+1).read_to_end(&mut bytes)?;
  if bytes.len() as u64!=meta.len(){return Err(invalid("cross object changed"));}cross_elf::validate_object(&bytes)?;
  let object_hash=hash(&bytes);let input=image.runtime_input("input.o",&bytes,&object_hash)?;
  let output=work.join("output.elf");
  let mut args:Vec<String>=["-flavor","gnu","-m","elf_x86_64","-static","--entry=_start","--build-id=none","-z","noexecstack","--threads=1","--fatal-warnings","--no-mmap-output-file","-o"].map(String::from).into();
  args.push(output.to_str().ok_or_else(||invalid("Unicode private output required"))?.into());args.push(input.to_str().unwrap().into());
  let result=windows_supervisor::run(&image,&identity,system,&args,Limits{wall_ms:600000,memory_bytes:1<<30,output_bytes:1<<20},&[],vec![])?;
  if result.failure.is_some()||result.exit!=Some(0){return Err(io::Error::other(format!("pinned cross-linker failed (exit {:?}): {:?}; {}{}",result.exit,result.failure,String::from_utf8_lossy(&result.stdout),String::from_utf8_lossy(&result.stderr))));}
  // Keep the output handle and parent chain until publication completes.
  let mut output_roots=Broker::default();let linked=load(&output,"output.elf",None,64<<20,&mut total,&mut output_roots)?;
  cross_elf::validate_executable(&linked.bytes)?;
  let mut sequence=1;let mut operation=|op,handle,path:&str,data:Vec<u8>|{let request=Request{sequence,operation:op,handle,path:path.into(),amount:data.len() as u32,data};sequence+=1;broker.execute(&request)};
  let(token,_)=operation(Operation::OpenWrite,output_root,".",vec![])?;
  for chunk in linked.bytes.chunks(65536){operation(Operation::Write,token,"",chunk.to_vec())?;}operation(Operation::Close,token,"",vec![])?;
  Ok(serde_json::json!({"schema":"kelft.cross-build/1","host":"windows-x86_64","target":"linux-x86_64","linkerProfile":"lld-elf-static/1","profileIdentity":self.identity,"linkerSHA256":self.tool.sha256,"objectSHA256":object_hash,"executableSHA256":linked.sha256,"nativeCertified":false}))
 }
}
