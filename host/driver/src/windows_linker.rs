//! Compiler-only, measured Microsoft linker service. No caller-supplied flags,
//! response files, directives, SDK paths or executable tools cross this channel.
use crate::{filesystem_channel::{Operation,Request},native_artifact_channel as channel,native_target::Target,windows_filesystem::Broker,windows_filesystem_session::{self as filesystem,Grant},windows_process::AppContainerSid,windows_snapshot::Image,windows_supervisor::{self,Limits}};
use serde::Deserialize;
use sha2::{Digest,Sha256};
use std::{fs::{self,File},io::{self,Read},os::windows::fs::{OpenOptionsExt,MetadataExt},path::{Path,PathBuf},sync::atomic::{AtomicBool,Ordering}};
use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_OPEN_REPARSE_POINT,FILE_ATTRIBUTE_REPARSE_POINT};

fn invalid(message:&'static str)->io::Error{io::Error::new(io::ErrorKind::InvalidInput,message)}
fn hash(bytes:&[u8])->String{format!("sha256:{:x}",Sha256::digest(bytes))}
#[derive(Deserialize)]#[serde(deny_unknown_fields)]struct Tool{path:PathBuf,sha256:String}
#[derive(Deserialize)]#[serde(deny_unknown_fields)]struct Input{name:String,path:PathBuf,sha256:String}
#[derive(Deserialize)]#[serde(deny_unknown_fields)]struct Configuration{schema:String,profile:String,identity:String,#[serde(rename="linkerCapabilities")]capabilities:Vec<String>,linker:Tool,libraries:Vec<Input>,#[serde(rename="runtimeInputs")]runtime:Vec<Input>,#[serde(rename="systemInputs")]system:Vec<Input>,#[serde(default,rename="linkerDriver")]driver:Option<String>,#[serde(default,rename="systemInputBinding")]system_binding:Option<String>}
struct Loaded{name:String,bytes:Vec<u8>,sha256:String,_file:File}
pub struct Linker{pub identity:String,lld:bool,tool:Loaded,libraries:Vec<Loaded>,runtime:Vec<Loaded>,_system:Vec<Loaded>,_roots:Broker}

fn loaded(path:&Path,name:&str,expected:Option<&str>,roots:&mut Broker,total:&mut usize)->io::Result<Loaded>{
 loaded_input(path,name,expected,roots,total).map_err(|error|io::Error::new(error.kind(),format!("measured linker input {name}: {error}")))
}
fn loaded_input(path:&Path,name:&str,expected:Option<&str>,roots:&mut Broker,total:&mut usize)->io::Result<Loaded>{
 loaded_bounded(path,name,expected,roots,total,64<<20)
}
fn loaded_bounded(path:&Path,name:&str,expected:Option<&str>,roots:&mut Broker,total:&mut usize,maximum:u64)->io::Result<Loaded>{
 let normalized=filesystem::normalized(path)?;roots.add_root(Path::new(&normalized),true,false)?;
 let mut file=fs::OpenOptions::new().read(true).share_mode(1).custom_flags(FILE_FLAG_OPEN_REPARSE_POINT).open(&normalized)?;
 let metadata=file.metadata()?;if !metadata.is_file()||metadata.file_attributes()&FILE_ATTRIBUTE_REPARSE_POINT!=0||metadata.len()>maximum{return Err(invalid("invalid measured linker input"));}
 *total=total.checked_add(metadata.len() as usize).ok_or_else(||invalid("linker inventory overflow"))?;if *total>256<<20{return Err(invalid("linker inventory exceeds bound"));}
 let mut bytes=vec![];Read::by_ref(&mut file).take(maximum+1).read_to_end(&mut bytes)?;let sha256=hash(&bytes);if bytes.len() as u64!=metadata.len()||expected.is_some_and(|expected|sha256!=expected){return Err(invalid("measured linker input changed"));}
 Ok(Loaded{name:name.into(),bytes,sha256,_file:file})
}
// Only separately compiled development testing images may measure the current
// host's System32 bytes. Package tools, libraries and private runtime stay pinned.
fn pin_system_hashes(packaged:bool)->bool{!(packaged&&cfg!(kelft_development_windows_system_inputs))}
fn native_pe(bytes:&[u8],dll:bool)->io::Result<()>{
 if bytes.len()<64||&bytes[..2]!=b"MZ"{return Err(invalid("invalid linker PE input"));}let at=u32::from_le_bytes(bytes[60..64].try_into().unwrap()) as usize;
 let machine=if Target::current()?==Target::WindowsX64{0x8664}else{0xaa64};
 if at<64||at>bytes.len().saturating_sub(264)||&bytes[at..at+4]!=b"PE\0\0"||u16::from_le_bytes(bytes[at+4..at+6].try_into().unwrap())!=machine||u16::from_le_bytes(bytes[at+24..at+26].try_into().unwrap())!=0x20b||(u16::from_le_bytes(bytes[at+22..at+24].try_into().unwrap())&0x2000!=0)!=dll{return Err(invalid("linker PE architecture or kind differs"));}Ok(())
}
/// Confirm the effective PE loader policy, rather than trusting link options.
pub fn validate_linked_image(bytes:&[u8])->io::Result<()>{
 crate::windows_snapshot::validate(bytes)?;let pe=u32::from_le_bytes(bytes[60..64].try_into().unwrap()) as usize;let optional=pe+24;
 let word=|at|u32::from_le_bytes(bytes[at..at+4].try_into().unwrap()) as usize;
 if word(optional+108)<11{return Err(invalid("linked image has no load configuration"));}
 let rva=word(optional+192);let size=word(optional+196);if rva==0||size!=112{return Err(invalid("linked image load configuration differs"));}
 let count=u16::from_le_bytes(bytes[pe+6..pe+8].try_into().unwrap()) as usize;let table=optional+u16::from_le_bytes(bytes[pe+20..pe+22].try_into().unwrap()) as usize;
 if count==0||count>96||table>bytes.len()||count*40>bytes.len()-table{return Err(invalid("linked image section table escapes file"));}
 let mut config=None;
 for index in 0..count{let section=table+index*40;let start=word(section+12);let length=word(section+16);if rva>=start&&rva-start<=length&&size<=length-(rva-start){
  let flags=word(section+36);let offset=word(section+20).checked_add(rva-start).ok_or_else(||invalid("linked image load configuration overflow"))?;
  if config.is_some()||flags&0xe0000000!=0x40000000||offset>bytes.len()||size>bytes.len()-offset{return Err(invalid("linked image load configuration is not immutable file data"));}config=Some(offset);
 }}
 let at=config.ok_or_else(||invalid("linked image load configuration is not mapped"))?;
 if word(at)!=size||u16::from_le_bytes(bytes[at+78..at+80].try_into().unwrap())!=0x800{return Err(invalid("linked image dependency search policy differs"));}Ok(())
}

/// Accept only the five sections emitted by the private Kelft COFF writer.
/// In particular, .drectve and long section names cannot inject linker options.
pub fn validate_object(bytes:&[u8])->io::Result<()>{
 let machine=if Target::current()?==Target::WindowsX64{0x8664}else{0xaa64};
 if bytes.len()<220||bytes.len()>64<<20||u16::from_le_bytes(bytes[..2].try_into().unwrap())!=machine||u16::from_le_bytes(bytes[2..4].try_into().unwrap())!=5||bytes[16..20]!=[0;4]{return Err(invalid("invalid native Kelft COFF header"));}
 let symbols=u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;let count=u32::from_le_bytes(bytes[12..16].try_into().unwrap()) as usize;
 let strings=symbols.checked_add(count.checked_mul(18).ok_or_else(||invalid("COFF symbol overflow"))?).ok_or_else(||invalid("COFF symbol overflow"))?;
 if count==0||symbols<220||strings>bytes.len().saturating_sub(4){return Err(invalid("invalid COFF symbol table"));}let size=u32::from_le_bytes(bytes[strings..strings+4].try_into().unwrap()) as usize;if size<4||strings.checked_add(size)!=Some(bytes.len()){return Err(invalid("invalid COFF strings"));}
 for(index,name)in [b".text\0\0\0",b".rdata\0\0",b".xdata\0\0",b".pdata\0\0",b".kelft$M"].iter().enumerate(){
  let at=20+index*40;if &bytes[at..at+8]!=name.as_slice()||bytes[at+8..at+16]!=[0;8]||bytes[at+28..at+32]!=[0;4]||bytes[at+34..at+36]!=[0;2]{return Err(invalid("unsupported COFF section"));}
  let length=u32::from_le_bytes(bytes[at+16..at+20].try_into().unwrap()) as usize;let start=u32::from_le_bytes(bytes[at+20..at+24].try_into().unwrap()) as usize;
  if length!=0&&(start<220||start.checked_add(length).is_none_or(|end|end>symbols)){return Err(invalid("COFF section escapes payload"));}
  let reloc=u32::from_le_bytes(bytes[at+24..at+28].try_into().unwrap()) as usize;let mut relocations=u16::from_le_bytes(bytes[at+32..at+34].try_into().unwrap()) as usize;
  let flags=u32::from_le_bytes(bytes[at+36..at+40].try_into().unwrap());let expected=[0x60500020,0x40400040,0x40300040,0x40300040,0x40100040][index];if flags&!0x01000000!=expected{return Err(invalid("unsupported COFF section flags"));}
  if flags&0x01000000!=0{if relocations!=65535||reloc<220||reloc>symbols.saturating_sub(10){return Err(invalid("invalid COFF extended relocations"));}relocations=u32::from_le_bytes(bytes[reloc..reloc+4].try_into().unwrap()) as usize;if relocations<=65536{return Err(invalid("invalid COFF extended count"));}}
  if relocations!=0&&(reloc<220||relocations.checked_mul(10).and_then(|n|reloc.checked_add(n)).is_none_or(|end|end>symbols)){return Err(invalid("COFF relocations escape payload"));}
 }
 Ok(())
}

impl Linker{
 pub fn system_observation(&self)->serde_json::Value{
  let files:Vec<_>=self._system.iter().map(|item|serde_json::json!({"name":item.name,"sha256":item.sha256,"bytes":item.bytes.len()})).collect();
  serde_json::json!({"binding":if self.lld{"os-system32/1"}else{"package-sha256/1"},"identity":hash(&serde_json::to_vec(&files).unwrap()),"files":files})
 }
 pub fn diagnose_dependencies(&self,program:&[u8],system:&str,registry_read:bool)->io::Result<windows_supervisor::Output>{
  let identity=if registry_read{AppContainerSid::fresh_linker()}else{AppContainerSid::fresh()}?;let mut image=Image::new(program,&hash(program),&identity)?;let mut args=vec![];
  for input in &self.runtime{let path=image.support(&input.name,&input.bytes,&input.sha256)?;args.push(path.to_str().unwrap().to_string());}
  windows_supervisor::run(&image,&identity,system,&args,Limits{wall_ms:30000,memory_bytes:1<<30,output_bytes:1<<20},&[("KELFT_LINKER_LOADER_PROBE".into(),"1".into())],vec![])
 }
 pub fn from_file(path:&Path)->io::Result<Self>{
  let mut encoded=vec![];File::open(path)?.take((1<<20)+1).read_to_end(&mut encoded)?;if encoded.len()>1<<20{return Err(invalid("linker configuration exceeds bound"));}
  Self::from_value(serde_json::from_slice(&encoded)?,None)
 }
 /// Package identities use fixed relative names; relocation changes no hashes
 /// and never lets metadata supply a drive, device or external SDK path.
 pub fn from_package(encoded:&[u8],root:&Path,system:&Path)->io::Result<Self>{
  if encoded.len()>1<<20{return Err(invalid("linker configuration exceeds bound"));}Self::from_value(serde_json::from_slice(encoded)?,Some((root,system)))
 }
 fn from_value(mut value:serde_json::Value,package:Option<(&Path,&Path)>)->io::Result<Self>{
  let mut configuration:Configuration=serde_json::from_value(value.clone())?;
  value.as_object_mut().ok_or_else(||invalid("linker configuration must be an object"))?.remove("identity");
  if configuration.schema!=if package.is_some(){"kelft-windows-linker-installed/1"}else{"kelft-windows-linker-development/2"}||configuration.profile!=Target::current()?.id()||configuration.capabilities!=["registryRead"]||configuration.identity!=hash(&serde_json::to_vec(&value)?){return Err(invalid("linker configuration identity or native profile differs"));}
  let lld=configuration.driver.as_deref()==Some("lld-coff/1");
  if configuration.driver.is_some()&&!lld||lld&&(package.is_none()||configuration.system_binding.as_deref()!=Some("os-system32/1")||!configuration.runtime.is_empty())||!lld&&configuration.system_binding.is_some(){return Err(invalid("unsupported linker driver or system binding"));}
  if let Some((root,system))=package{
   let resolve=|path:&Path,expected:String,base:&Path|->io::Result<PathBuf>{if path.to_str()!=Some(expected.as_str())||path.is_absolute()||expected.contains(['\\',':','\0'])||expected.split('/').any(|part|part.is_empty()||matches!(part,"."|"..")){return Err(invalid("installed linker path differs from fixed package layout"));}Ok(base.join(path))};
   configuration.linker.path=resolve(&configuration.linker.path,"rootfs/toolchain/link.exe".into(),root)?;
   for item in configuration.libraries.iter_mut().chain(&mut configuration.runtime){item.path=resolve(&item.path,format!("rootfs/toolchain/{}",item.name.to_ascii_lowercase()),root)?;}
   for item in &mut configuration.system{item.path=resolve(&item.path,format!("System32/{}",item.name.to_ascii_lowercase()),system)?;}
  }
  if configuration.libraries.len()!=3||configuration.runtime.len()>32||configuration.system.len()>64{return Err(invalid("invalid linker inventory count"));}
  let mut roots=Broker::default();let mut total=0;let tool=loaded_bounded(&configuration.linker.path,"image.exe",Some(&configuration.linker.sha256),&mut roots,&mut total,if lld{128<<20}else{64<<20})?;native_pe(&tool.bytes,false)?;if !lld{crate::windows_snapshot::validate(&tool.bytes)?;}
  let mut names=std::collections::HashSet::new();names.insert("image.exe".to_string());names.insert("work".to_string());names.insert("input.obj".to_string());
  let mut load_inputs=|inputs:Vec<Input>,library:bool,pinned:bool|->io::Result<Vec<Loaded>>{inputs.into_iter().map(|item|{
   let name=item.name.to_ascii_lowercase();if name.len()>96||!name.bytes().all(|c|c.is_ascii_alphanumeric()||matches!(c,b'.'|b'_'|b'-'))||!names.insert(name.clone())||if library{!matches!(name.as_str(),"kernel32.lib"|"shell32.lib"|"ntdll.lib")}else{!name.ends_with(".dll")}{return Err(invalid("invalid or duplicate linker inventory name"));}
   let input=loaded(&item.path,&name,pinned.then_some(item.sha256.as_str()),&mut roots,&mut total)?;if library{if !input.bytes.starts_with(b"!<arch>\n"){return Err(invalid("invalid SDK import library"));}}else{native_pe(&input.bytes,true)?;}Ok(input)
  }).collect()};
  let libraries=load_inputs(configuration.libraries,true,true)?;let runtime=load_inputs(configuration.runtime,false,true)?;let system=load_inputs(configuration.system,false,!lld&&pin_system_hashes(package.is_some()))?;
  Ok(Self{identity:configuration.identity,lld,tool,libraries,runtime,_system:system,_roots:roots})
 }
 pub fn execute(&self,request:&channel::Request,system:&str,cancel:&AtomicBool,authority:&[Grant],protected:&[PathBuf])->io::Result<channel::Response>{
  let rejected=|status|Ok(channel::Response{status,stdout:vec![],stderr:vec![]});
  if request.target!=format!("linker-{}-v1",Target::current()?.id()){return rejected(-1);}
  if request.args.len()!=2||request.args[1]!=self.identity||request.read.len()!=0||request.write.len()!=1||request.write[0]!=request.args[0]{return rejected(-2);}
  let grants=match filesystem::delegated(&[],&request.write,authority){Ok(value)=>value,Err(_)=>return rejected(-2)};let destination=&grants[0].path;
  for path in protected{if filesystem::within(destination,path)?||filesystem::within(path,destination)?{return rejected(-2);}}
  if validate_object(&request.image).is_err(){return rejected(-4);}
  // Retain the destination's parent chain before invoking a tool. Only the
  // parent writes the final bytes; the linker has no project filesystem grant.
  let mut broker=Broker::default();let output_root=broker.add_root(destination,false,true)?;
  let identity=if self.lld{AppContainerSid::fresh()?}else{AppContainerSid::fresh_linker()?};let mut image=if self.lld{Image::cross_linker(&self.tool.bytes,&self.tool.sha256,&identity)?}else{Image::new(&self.tool.bytes,&self.tool.sha256,&identity)?};
  let object=image.support("input.obj",&request.image,&hash(&request.image))?;let mut libraries=vec![];
  for input in self.libraries.iter().chain(&self.runtime){let path=image.support(&input.name,&input.bytes,&input.sha256)?;if input.name.ends_with(".lib"){libraries.push(path);}}
  let output=image.work_directory()?.join("output.exe");image.linker_scratch()?;let machine=if Target::current()?==Target::WindowsX64{"X64"}else{"ARM64"};
  let mut args:Vec<String>=["/NOLOGO","/SUBSYSTEM:CONSOLE","/ENTRY:k_start","/NODEFAULTLIB","/Brepro","/INCREMENTAL:NO","/DEBUG:NONE","/PDB:NONE","/MANIFEST:NO","/NOIMPLIB","/NOEXP","/NXCOMPAT","/DYNAMICBASE","/DEPENDENTLOADFLAG:0x800","/STACK:16777216,65536","/ERRORREPORT:NONE"].map(String::from).into();
  if self.lld{args.retain(|arg|!matches!(arg.as_str(),"/NOEXP"|"/ERRORREPORT:NONE"));args.splice(0..0,["-flavor".into(),"link".into(),"/threads:1".into()]);}
  args.push(format!("/MACHINE:{machine}"));args.push(format!("/OUT:{}",output.to_str().ok_or_else(||invalid("non-Unicode private output"))?));args.push(object.to_str().unwrap().into());args.extend(libraries.iter().map(|p|p.to_str().unwrap().to_string()));
  let result=windows_supervisor::run_cancellable(&image,&identity,system,&args,Limits{wall_ms:600000,memory_bytes:1<<30,output_bytes:1<<20},&[],vec![],Some(cancel))?;
  if let Some(failure)=result.failure{return Err(io::Error::other(format!("trusted linker {}: {failure}; {}{}",self.tool.sha256,String::from_utf8_lossy(&result.stdout),String::from_utf8_lossy(&result.stderr))));}if cancel.load(Ordering::Acquire){return rejected(-3);}let status=result.exit.ok_or_else(||invalid("linker exit missing"))? as i32;
  if status!=0{return Ok(channel::Response{status,stdout:result.stdout,stderr:result.stderr});}
  let mut file=fs::OpenOptions::new().read(true).share_mode(1).custom_flags(FILE_FLAG_OPEN_REPARSE_POINT).open(&output)?;let metadata=file.metadata()?;if !metadata.is_file()||metadata.file_attributes()&FILE_ATTRIBUTE_REPARSE_POINT!=0||metadata.len()>64<<20{return Err(invalid("invalid linked output"));}
  let mut bytes=vec![];Read::by_ref(&mut file).take((64<<20)+1).read_to_end(&mut bytes)?;validate_linked_image(&bytes)?;
  let mut sequence=1;let mut operation=|op,handle,path:&str,data:Vec<u8>|{let request=Request{sequence,operation:op,handle,path:path.into(),amount:data.len() as u32,data};sequence+=1;broker.execute(&request)};
  let(token,_)=operation(Operation::OpenWrite,output_root,".",vec![])?;for chunk in bytes.chunks(65536){operation(Operation::Write,token,"",chunk.to_vec())?;}operation(Operation::Close,token,"",vec![])?;
  Ok(channel::Response{status:0,stdout:result.stdout,stderr:result.stderr})
 }
}

#[cfg(test)]mod tests{
 use super::*;
 #[test]fn host_system_binding_is_compile_time_only_and_package_only(){
  assert!(pin_system_hashes(false));assert_eq!(pin_system_hashes(true),!cfg!(kelft_development_windows_system_inputs));
 }
 #[test]fn measured_inputs_retain_locks_hashes_and_allocation_bounds(){
  let directory=std::env::temp_dir().join(format!("kelft-linker-input-{}",std::process::id()));fs::create_dir(&directory).unwrap();
  let file=directory.join("input.dll");fs::write(&file,b"host-observation").unwrap();
  {
   let mut roots=Broker::default();let mut total=0;
   assert!(loaded(&file,"input.dll",Some("sha256:changed"),&mut roots,&mut total).is_err());
  }
  {
   let mut roots=Broker::default();let mut total=0;let observed=loaded(&file,"input.dll",None,&mut roots,&mut total).unwrap();
   assert_eq!(observed.sha256,hash(b"host-observation"));assert_eq!(total,16);
   assert!(fs::OpenOptions::new().write(true).open(&file).is_err(),"retained input handle must deny writes");
  }
  {
   let mut roots=Broker::default();let mut total=256<<20;assert!(loaded(&file,"input.dll",None,&mut roots,&mut total).is_err());
  }
  fs::OpenOptions::new().write(true).open(&file).unwrap().set_len((64<<20)+1).unwrap();
  {let mut roots=Broker::default();let mut total=0;assert!(loaded(&file,"input.dll",None,&mut roots,&mut total).is_err());}
  fs::remove_file(&file).unwrap();fs::remove_dir(&directory).unwrap();
 }
 #[test]fn linked_images_require_an_immutable_bounded_system32_load_configuration(){
  let mut image=vec![0u8;1024];image[..2].copy_from_slice(b"MZ");image[60..64].copy_from_slice(&64u32.to_le_bytes());image[64..68].copy_from_slice(b"PE\0\0");image[68..70].copy_from_slice(&(if Target::current().unwrap()==Target::WindowsX64{0x8664u16}else{0xaa64}).to_le_bytes());image[70..72].copy_from_slice(&1u16.to_le_bytes());image[84..86].copy_from_slice(&240u16.to_le_bytes());image[86..88].copy_from_slice(&2u16.to_le_bytes());image[88..90].copy_from_slice(&0x20bu16.to_le_bytes());image[160..168].copy_from_slice(&1048576u64.to_le_bytes());image[168..176].copy_from_slice(&65536u64.to_le_bytes());image[196..200].copy_from_slice(&16u32.to_le_bytes());image[280..284].copy_from_slice(&0x1000u32.to_le_bytes());image[284..288].copy_from_slice(&112u32.to_le_bytes());image[340..344].copy_from_slice(&0x1000u32.to_le_bytes());image[344..348].copy_from_slice(&112u32.to_le_bytes());image[348..352].copy_from_slice(&512u32.to_le_bytes());image[364..368].copy_from_slice(&0x40000040u32.to_le_bytes());image[512..516].copy_from_slice(&112u32.to_le_bytes());image[590..592].copy_from_slice(&0x800u16.to_le_bytes());validate_linked_image(&image).unwrap();
  for(at,value)in [(196,10u32),(280,0),(280,u32::MAX),(284,80),(340,0x1001),(344,111),(348,u32::MAX),(364,0xc0000040),(364,0x60000040),(512,80),(588,0)]{let mut changed=image.clone();changed[at..at+4].copy_from_slice(&value.to_le_bytes());assert!(validate_linked_image(&changed).is_err(),"accepted altered PE field at {at}");}
  for length in [0,63,327,367,511,623]{assert!(validate_linked_image(&image[..length]).is_err());}
 }
 #[test]fn unsupported_coff_headers_and_directive_sections_fail_before_linking(){
  for n in 0..220{assert!(validate_object(&vec![0;n]).is_err());}
  let mut bytes=vec![0;242];bytes[..2].copy_from_slice(&(if Target::current().unwrap()==Target::WindowsX64{0x8664u16}else{0xaa64}).to_le_bytes());bytes[2..4].copy_from_slice(&5u16.to_le_bytes());bytes[8..12].copy_from_slice(&220u32.to_le_bytes());bytes[12..16].copy_from_slice(&1u32.to_le_bytes());bytes[238..242].copy_from_slice(&4u32.to_le_bytes());
  for(index,name)in [b".text\0\0\0",b".rdata\0\0",b".xdata\0\0",b".pdata\0\0",b".kelft$M"].iter().enumerate(){let at=20+index*40;bytes[at..at+8].copy_from_slice(name.as_slice());let flags:u32=[0x60500020,0x40400040,0x40300040,0x40300040,0x40100040][index];bytes[at+36..at+40].copy_from_slice(&flags.to_le_bytes());}
  validate_object(&bytes).unwrap();bytes[20..28].copy_from_slice(b".drectve");assert!(validate_object(&bytes).is_err());
 }
}
