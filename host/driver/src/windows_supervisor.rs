//! Native Windows artifact supervision. The image must already be authenticated
//! and locked; capture, inherited handles and job lifetime stay parent-owned.
use crate::{windows_process::{self,AppContainerSid,Spawn},windows_snapshot::Image};
use std::{fs::File,io::{self,Read},os::windows::io::{AsRawHandle,FromRawHandle},ptr,sync::{Arc,atomic::{AtomicBool,AtomicUsize,Ordering}},thread,time::Duration};
use windows_sys::Win32::{Foundation::{HANDLE,DUPLICATE_SAME_ACCESS,DuplicateHandle},Storage::FileSystem::*,System::{Pipes::CreatePipe,Threading::GetCurrentProcess}};
#[derive(Clone,Copy)]pub struct Limits{pub wall_ms:u32,pub memory_bytes:usize,pub output_bytes:usize}
pub struct Output{pub exit:Option<u32>,pub stdout:Vec<u8>,pub stderr:Vec<u8>,pub failure:Option<String>,pub usage:windows_process::Usage}
fn invalid(message:&'static str)->io::Error{io::Error::new(io::ErrorKind::InvalidInput,message)}
fn quote(argument:&str)->io::Result<String>{
 if argument.contains('\0')||argument.len()>4095{return Err(invalid("invalid native argument"));}
 if !argument.is_empty()&&!argument.contains([' ','\t','"']){return Ok(argument.into());}
 let mut result=String::from("\"");let mut slashes=0;
 for c in argument.chars(){if c=='\\'{slashes+=1;continue;}if c=='"'{result.push_str(&"\\".repeat(slashes*2+1));}else{result.push_str(&"\\".repeat(slashes));}slashes=0;result.push(c);}
 result.push_str(&"\\".repeat(slashes*2));result.push('"');Ok(result)
}
pub fn command_line(image:&str,args:&[String])->io::Result<String>{
 if args.len()>4096||args.iter().map(String::len).sum::<usize>()>1<<20{return Err(invalid("native argument storage exceeds bound"));}
 // The image path has the Windows path bound, rather than the per-argument bound.
 if image.contains(['\0','"']){return Err(invalid("invalid image path"));}let mut result=format!("\"{image}\"");
 for argument in args{result.push(' ');result.push_str(&quote(argument)?);}
 if result.encode_utf16().count()>=32767{return Err(invalid("Windows command line exceeds bound"));}Ok(result)
}
pub(crate) fn pipe()->io::Result<(File,File)>{let(mut input,mut output)=(ptr::null_mut(),ptr::null_mut());if unsafe{CreatePipe(&mut input,&mut output,ptr::null(),4096)}==0{return Err(io::Error::last_os_error());}Ok(unsafe{(File::from_raw_handle(input),File::from_raw_handle(output))})}
fn inherited(file:&File)->io::Result<File>{let mut output=ptr::null_mut();if unsafe{DuplicateHandle(GetCurrentProcess(),file.as_raw_handle(),GetCurrentProcess(),&mut output,0,1,DUPLICATE_SAME_ACCESS)}==0{return Err(io::Error::last_os_error());}Ok(unsafe{File::from_raw_handle(output)})}
fn capture(mut pipe:File,maximum:usize,total:Arc<AtomicUsize>,failed:Arc<AtomicBool>)->io::Result<thread::JoinHandle<io::Result<Vec<u8>>>>{
 thread::Builder::new().name("kelft-native-capture".into()).spawn(move||{let mut output=vec![];let mut buffer=[0u8;4096];loop{
  let count=match pipe.read(&mut buffer){Ok(0)=>break,Ok(n)=>n,Err(error)if error.kind()==io::ErrorKind::Interrupted=>continue,Err(error)=>{failed.store(true,Ordering::Release);return Err(error);}};
  let before=total.fetch_add(count,Ordering::AcqRel);if before>maximum||count>maximum-before{failed.store(true,Ordering::Release);}if before<maximum{output.extend_from_slice(&buffer[..count.min(maximum-before)]);}
 }Ok(output)})
}
pub fn run(image:&Image,identity:&AppContainerSid,system_root:&str,args:&[String],limits:Limits,environment:&[(String,String)],controls:Vec<(String,File)>)->io::Result<Output>{
 run_cancellable(image,identity,system_root,args,limits,environment,controls,None)
}
pub fn run_cancellable(image:&Image,identity:&AppContainerSid,system_root:&str,args:&[String],limits:Limits,environment:&[(String,String)],controls:Vec<(String,File)>,cancel:Option<&AtomicBool>)->io::Result<Output>{
 run_inner(image,identity,system_root,args,limits,environment,controls,cancel,None,None,None,None)
}
pub fn run_with_input(image:&Image,identity:&AppContainerSid,system_root:&str,args:&[String],limits:Limits,environment:&[(String,String)],controls:Vec<(String,File)>,input:Vec<u8>,directory:&str)->io::Result<Output>{if input.len()>65536{return Err(invalid("native stdin bound"));}run_inner(image,identity,system_root,args,limits,environment,controls,None,None,Some(input),None,Some(directory))}
pub fn run_engine(image:&Image,identity:&AppContainerSid,system_root:&str,args:&[String],limits:Limits,environment:&[(String,String)],broker:crate::windows_filesystem::Broker)->io::Result<Output>{if !image.is_runtime(){return Err(invalid("engine broker requires an explicit runtime snapshot"));}run_inner(image,identity,system_root,args,limits,environment,vec![],None,Some(broker),None,None,None)}
/// Only windows_host's attested installed-command route selects this role.
#[cfg(feature="installed-native")]
pub(crate) fn run_installed(image:&Image,identity:&AppContainerSid,system_root:&str,executable:&str,cwd:&str,args:&[String],limits:Limits,environment:&[(String,String)],input:Vec<u8>)->io::Result<Output>{run_inner(image,identity,system_root,args,limits,environment,vec![],None,None,Some(input),Some((executable,cwd)),None)}
fn run_inner(image:&Image,identity:&AppContainerSid,system_root:&str,args:&[String],limits:Limits,environment:&[(String,String)],controls:Vec<(String,File)>,cancel:Option<&AtomicBool>,engine:Option<crate::windows_filesystem::Broker>,stdin_bytes:Option<Vec<u8>>,installed:Option<(&str,&str)>,working_directory:Option<&str>)->io::Result<Output>{
 if limits.wall_ms==0||limits.wall_ms>600000||!(16777216..=1073741824).contains(&limits.memory_bytes)||limits.output_bytes>16<<20||controls.len()>4{return Err(invalid("native supervisor limits"));}
 let image_path=installed.map(|v|v.0).unwrap_or(image.path().to_str().ok_or_else(||invalid("native image path is not Unicode"))?);let directory=working_directory.or(installed.map(|v|v.1)).unwrap_or(image.directory().to_str().ok_or_else(||invalid("native directory is not Unicode"))?);
 let scratch=image.scratch_directory().to_str().ok_or_else(||invalid("native scratch is not Unicode"))?;
 let line=command_line(image_path,args)?;let mut block=windows_process::environment(system_root,scratch)?;block.pop();let mut names=std::collections::HashSet::new();
 let handles=controls.iter().map(|(_,file)|inherited(file)).collect::<io::Result<Vec<_>>>()?;
 let mut entries=environment.to_vec();for((name,_),handle)in controls.iter().zip(&handles){if !name.starts_with("KELFT_"){return Err(invalid("private control handle name required"));}entries.push((name.clone(),(handle.as_raw_handle() as usize).to_string()));}
 for(name,value)in &entries{let key=name.to_ascii_uppercase();if name.is_empty()||name.contains(['=','\0'])||value.contains('\0')||matches!(key.as_str(),"LOCALAPPDATA"|"SYSTEMROOT"|"SYSTEMDRIVE"|"WINDIR"|"TEMP"|"TMP")||!names.insert(key){return Err(invalid("invalid or duplicate native environment entry"));}block.extend(format!("{name}={value}").encode_utf16());block.push(0);}block.push(0);
 let null:Vec<u16>="NUL".encode_utf16().chain([0]).collect();let raw=unsafe{CreateFileW(null.as_ptr(),FILE_GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,ptr::null(),OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,ptr::null_mut())};if raw.is_null()||raw==windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE{return Err(io::Error::last_os_error());}let input=unsafe{File::from_raw_handle(raw)};let(input,responses)=if engine.is_some(){drop(input);let(read,write)=pipe()?;(read,Some(write))}else{(input,None)};
 let(input,input_writer)=if stdin_bytes.is_some(){drop(input);let(read,write)=pipe()?;(read,Some(write))}else{(input,None)};
 let(stdout,output)=pipe()?;let(stderr,error)=pipe()?;let raw_handles:Vec<HANDLE>=handles.iter().map(AsRawHandle::as_raw_handle).collect();
 let spawn=Spawn{image:image_path,command_line:&line,directory,environment:&block,input:input.as_raw_handle(),output:output.as_raw_handle(),error:error.as_raw_handle(),controls:&raw_handles,identity,memory_bytes:limits.memory_bytes,timeout_ms:limits.wall_ms};
 let paused=unsafe{if installed.is_some(){spawn.start_installed()}else{spawn.start()}}?;
 // Consume and close every parent copy of a child control end before waiting;
 // otherwise a truncated worker request could leave its broker blocked forever.
 drop((input,output,error,handles,controls));let total=Arc::new(AtomicUsize::new(0));let failed=Arc::new(AtomicBool::new(false));
 let out=capture(stdout,limits.output_bytes,total.clone(),failed.clone())?;let err=if let Some(mut broker)=engine{let mut input=stderr;let mut output=responses.ok_or_else(||invalid("engine response pipe missing"))?;let failed=failed.clone();thread::Builder::new().name("kelft-engine-broker".into()).spawn(move||crate::engine_channel::serve(&mut input,&mut output,limits.output_bytes,total,failed,|request|broker.execute(request)))?}else{capture(stderr,limits.output_bytes,total,failed.clone())?};
 let writer=match(input_writer,stdin_bytes){(Some(mut pipe),Some(bytes))=>Some(thread::Builder::new().name("kelft-native-input".into()).spawn(move||{use std::io::Write;match pipe.write_all(&bytes){Ok(())=>Ok(()),Err(e)if e.kind()==io::ErrorKind::BrokenPipe=>Ok(()),Err(e)=>Err(e)}})?),_=>None};
 let mut worker=paused.resume()?;let(mut exit,mut failure)=(None,None);
 loop{if cancel.is_some_and(|flag|flag.load(Ordering::Acquire)){worker.terminate()?;failure=Some("native worker cancelled by parent".into());break;}
  if failed.load(Ordering::Acquire){worker.terminate()?;failure=Some("native output limit or capture failure".into());break;}
  match worker.try_exit(){Ok(Some(code))=>{if code>255{failure=Some(format!("native worker abnormal exit {code:#010x}"));}else{exit=Some(code);}break;},Ok(None)=>thread::sleep(Duration::from_millis(5)),Err(error)=>{worker.terminate()?;failure=Some(error.to_string());break;}}
 }let usage=worker.usage();drop(worker);if let Some(writer)=writer{writer.join().map_err(|_|io::Error::other("native input writer panicked"))??;}
 let stdout=out.join().map_err(|_|io::Error::other("native stdout capture panicked"))??;let stderr=err.join().map_err(|_|io::Error::other("native stderr capture panicked"))??;
 if failed.load(Ordering::Acquire){failure=Some("native output limit or capture failure".into());exit=None;}Ok(Output{exit,stdout,stderr,failure,usage:usage?})
}
#[cfg(test)]mod tests {
 use super::*;use sha2::{Digest,Sha256};
 #[test]fn windows_quoting_preserves_empty_quotes_unicode_and_trailing_backslashes(){assert_eq!(quote("").unwrap(),"\"\"");assert_eq!(quote("a\\").unwrap(),"a\\");assert_eq!(quote("a b\\").unwrap(),"\"a b\\\\\"");assert_eq!(quote("hé\"x").unwrap(),"\"hé\\\"x\"");assert!(quote("bad\0argument").is_err());assert!(command_line("C:\\program.exe",&vec!["x".repeat(4095);9]).is_err());}
 #[test]fn restricted_snapshots_execute_without_ambient_environment_and_enforce_bounds(){
  let system=std::env::var("SystemRoot").unwrap();let bytes=std::fs::read(std::path::Path::new(&system).join("System32/cmd.exe")).unwrap();let hash=format!("sha256:{:x}",Sha256::digest(&bytes));let identity=AppContainerSid::fresh().unwrap();let image=Image::new(&bytes,&hash,&identity).unwrap();let limits=Limits{wall_ms:10000,memory_bytes:268435456,output_bytes:65536};
  let args=["/d","/q","/c","if defined KELFT_NATIVE_PROBE_AMBIENT (exit /b 93) else (exit /b 42)"].map(String::from);let result=run(&image,&identity,&system,&args,limits,&[],vec![]).unwrap();assert_eq!(result.exit,Some(42),"{:?}: {}{}",result.failure,String::from_utf8_lossy(&result.stdout),String::from_utf8_lossy(&result.stderr));assert!(result.failure.is_none());assert!(result.usage.peak_process_memory_bytes>0&&result.usage.peak_process_memory_bytes<=limits.memory_bytes);assert!(result.usage.peak_job_memory_bytes>0&&result.usage.peak_job_memory_bytes<=limits.memory_bytes);assert_eq!(result.usage.process_commit_limit_bytes,limits.memory_bytes);assert_eq!(result.usage.job_commit_limit_bytes,limits.memory_bytes);assert!(result.usage.elapsed_ms<limits.wall_ms as u64+5000);
  let args=["/d","/q","/c","for /l %i in (1,1,2147483647) do @echo flood"].map(String::from);let result=run(&image,&identity,&system,&args,Limits{output_bytes:4096,..limits},&[],vec![]).unwrap();assert!(result.failure.is_some());assert!(result.stdout.len()+result.stderr.len()<=4096);
  let args=["/d","/q","/c","for /l %i in (1,1,2147483647) do @rem deadline"].map(String::from);let result=run(&image,&identity,&system,&args,Limits{wall_ms:100,..limits},&[],vec![]).unwrap();assert!(result.failure.is_some());assert!(result.exit.is_none());
 }
 #[test]fn private_filesystem_worker(){
  if std::env::var("KELFT_FS_PROBE").as_deref()!=Ok("1"){return;}
  use crate::filesystem_channel::{self as rpc,Operation,Request};
  let handle=|name:&str|std::env::var(name).unwrap().parse::<usize>().unwrap() as HANDLE;
  let mut output=unsafe{File::from_raw_handle(handle("KELFT_FS_REQUEST"))};let mut input=unsafe{File::from_raw_handle(handle("KELFT_FS_RESPONSE"))};
  let mut request=Request{sequence:1,operation:Operation::OpenRead,handle:1,path:"input".into(),amount:0,data:vec![]};rpc::write_request(&mut output,&request).unwrap();let opened=rpc::read_response(&mut input,1).unwrap();assert_eq!(opened.status,0);
  request=Request{sequence:2,operation:Operation::Read,handle:opened.value,path:String::new(),amount:64,data:vec![]};rpc::write_request(&mut output,&request).unwrap();assert_eq!(rpc::read_response(&mut input,2).unwrap().data,vec![0,255,128]);
  request=Request{sequence:3,operation:Operation::Close,handle:opened.value,path:String::new(),amount:0,data:vec![]};rpc::write_request(&mut output,&request).unwrap();assert_eq!(rpc::read_response(&mut input,3).unwrap().status,0);
  request=Request{sequence:4,operation:Operation::CreateNew,handle:1,path:"denied".into(),amount:0,data:vec![]};rpc::write_request(&mut output,&request).unwrap();assert_eq!(rpc::read_response(&mut input,4).unwrap().status,-1);
  assert!(std::fs::read(std::env::var("KELFT_FS_OUTSIDE").unwrap()).is_err());
  println!("bounded-filesystem-worker-ok");
 }
 #[test]fn native_worker_uses_only_its_broker_and_cannot_open_host_files(){
  let system=std::env::var("SystemRoot").unwrap();let bytes=std::fs::read(std::env::current_exe().unwrap()).unwrap();let digest=format!("sha256:{:x}",Sha256::digest(&bytes));let identity=AppContainerSid::fresh().unwrap();let image=Image::new(&bytes,&digest,&identity).unwrap();
  let root=image.directory().with_extension("broker-data");std::fs::create_dir(&root).unwrap();std::fs::write(root.join("input"),[0,255,128]).unwrap();let mut broker=crate::windows_filesystem::Broker::default();assert_eq!(broker.add_root(&root,true,false).unwrap(),1);
  let(mut requests,child_write)=pipe().unwrap();let(child_read,mut responses)=pipe().unwrap();let service=thread::spawn(move||broker.serve(&mut requests,&mut responses));
  let env=vec![("KELFT_FS_PROBE".into(),"1".into()),("KELFT_FS_OUTSIDE".into(),root.join("input").to_str().unwrap().into())];
  let args=["--exact","windows_supervisor::tests::private_filesystem_worker","--nocapture"].map(String::from);
  let result=run(&image,&identity,&system,&args,Limits{wall_ms:10000,memory_bytes:268435456,output_bytes:65536},&env,vec![("KELFT_FS_REQUEST".into(),child_write),("KELFT_FS_RESPONSE".into(),child_read)]).unwrap();
  service.join().unwrap().unwrap();assert_eq!(result.exit,Some(0),"{:?}: {}{}",result.failure,String::from_utf8_lossy(&result.stdout),String::from_utf8_lossy(&result.stderr));assert!(String::from_utf8_lossy(&result.stdout).contains("bounded-filesystem-worker-ok"));assert!(!root.join("denied").exists());std::fs::remove_dir_all(root).unwrap();
 }
}
