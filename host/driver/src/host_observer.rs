//! Development transport recorder. Decisions and assertions belong to callers.
#[cfg(target_os="windows")]
fn main()->Result<(),Box<dyn std::error::Error>>{
 use kelft_wasi::{host_channel::Policy,windows_host::Host,windows_filesystem_session::{Grant,MappedGrant}};
 let args=std::env::args().skip(1).collect::<Vec<_>>();
 if args.first().is_some_and(|a|a=="--lifetime-worker"){return lifetime_worker(&args[1..]);}
 if args.first().is_some_and(|a|a=="--lifetime-observations"){return lifetime_observations(&args[1..]);}
 if args.len()!=1{return Err("expected observation input".into());}
 let file=std::fs::File::open(&args[0])?;use std::io::Read;let mut raw=vec![];file.take(4*1024*1024+1).read_to_end(&mut raw)?;if raw.len()>4*1024*1024{return Err("observation bound".into());}
 let input:serde_json::Value=serde_json::from_slice(&raw)?;let policy:Policy=serde_json::from_value(input["policy"].clone())?;
 let root=input["root"].as_str().ok_or("root")?;let mappings=vec![MappedGrant{guest:"/project".into(),grant:Grant{path:root.into(),read:true,write:false}}];
 let mut host=Host::new(policy.clone(),mappings,"/project".into(),std::env::var("SystemRoot")?,60000)?;
 let mut observations=vec![];let mut replacement=None;for request in input["requests"].as_array().filter(|r|r.len()<=32).ok_or("requests")?{
  let racing=if request["args"][0]=="wait"{let path=std::path::PathBuf::from(request["executable"].as_str().ok_or("image")?);Some(std::thread::spawn(move||{std::thread::sleep(std::time::Duration::from_millis(200));for _ in 0..200{match std::fs::OpenOptions::new().write(true).open(&path){Err(e)if e.raw_os_error()==Some(32)=>{let rename=std::fs::rename(&path,path.with_extension("moved"));return serde_json::json!({"writeBlocked":true,"renameBlocked":rename.is_err()});},Ok(file)=>drop(file),Err(_)=>{}}std::thread::sleep(std::time::Duration::from_millis(5));}serde_json::json!({"writeBlocked":false,"renameBlocked":false})}))}else{None};
  let envelope=serde_json::json!({"schema":"kelft.host-request/1","kind":"process","maximum":policy,"request":request});
  let response:serde_json::Value=serde_json::from_slice(&host.dispatch(&envelope.to_string())?)?;
  if let Some(racing)=racing{replacement=Some(racing.join().map_err(|_|"replacement observer panicked")?);}
  observations.push(serde_json::json!({"request":request,"response":response,"limits":{"stdout_bytes":request["limits"]["stdoutBytes"],"stderr_bytes":request["limits"]["stderrBytes"]}}));
 }
 println!("{}",serde_json::json!({"observations":observations,"replacement":replacement}));Ok(())
}
#[cfg(target_os="windows")]
fn lifetime_worker(args:&[String])->Result<(),Box<dyn std::error::Error>>{
 use kelft_wasi::{windows_process::{AppContainerSid,Spawn,environment},windows_snapshot::Image,windows_supervisor::command_line};
 use std::{io::Write,os::windows::io::{AsRawHandle,FromRawHandle}};
 if args.len()!=2||!matches!(args[1].as_str(),"paused"|"running"){return Err("lifetime worker inputs".into());}
 let bytes=std::fs::read(&args[0])?;use sha2::{Digest,Sha256};let hash=format!("sha256:{:x}",Sha256::digest(&bytes));let identity=AppContainerSid::fresh()?;let image=Image::new(&bytes,&hash,&identity)?;
 let path=image.path().to_str().ok_or("image path")?;let directory=image.directory().to_str().ok_or("image directory")?;let line=command_line(path,&["wait".into()])?;let env=environment(&std::env::var("SystemRoot")?,directory)?;
 let input=std::fs::File::open("NUL")?;let(mut read,mut write)=(std::ptr::null_mut(),std::ptr::null_mut());if unsafe{windows_sys::Win32::System::Pipes::CreatePipe(&mut read,&mut write,std::ptr::null(),4096)}==0{return Err(std::io::Error::last_os_error().into());}let _read=unsafe{std::fs::File::from_raw_handle(read)};let output=unsafe{std::fs::File::from_raw_handle(write)};
 let paused=unsafe{Spawn{image:path,command_line:&line,directory,environment:&env,input:input.as_raw_handle(),output:output.as_raw_handle(),error:output.as_raw_handle(),controls:&[],identity:&identity,memory_bytes:268435456,timeout_ms:30000}.start()}?;
 // A suspended worker also has its job assigned atomically at creation.
 let ready=|pid|->Result<(),Box<dyn std::error::Error>>{println!("{}",serde_json::json!({"pid":pid,"profile":identity.moniker()?,"directory":directory}));std::io::stdout().flush()?;Ok(())};
 if args[1]=="running"{let worker=paused.resume()?;ready(worker.process_id())?;std::thread::sleep(std::time::Duration::from_secs(30));drop(worker);}else{
  // The process identifier can be read from the owned process handle before resume.
  // Keep it paused by using the creation receipt from the OS below.
  let pid=paused.process_id();ready(pid)?;std::thread::sleep(std::time::Duration::from_secs(30));drop(paused);
 }Ok(())
}
#[cfg(target_os="windows")]
fn lifetime_observations(args:&[String])->Result<(),Box<dyn std::error::Error>>{
 use std::{io::{BufRead,BufReader},process::{Command,Stdio},path::PathBuf};
 use windows_sys::Win32::{Foundation::CloseHandle,System::Threading::{OpenProcess,WaitForSingleObject}};
 if args.len()!=1{return Err("expected lifetime probe".into());}let mut results=vec![];
 for phase in ["paused","running"]{
  let mut owner=Command::new(std::env::current_exe()?).args(["--lifetime-worker",&args[0],phase]).stdout(Stdio::piped()).stderr(Stdio::inherit()).spawn()?;
  let mut line=String::new();BufReader::new(owner.stdout.take().ok_or("owner output")?).read_line(&mut line)?;let value:serde_json::Value=serde_json::from_str(&line)?;let pid=value["pid"].as_u64().ok_or("child pid")? as u32;
  let handle=unsafe{OpenProcess(0x00100000|0x1000,0,pid)};if handle.is_null(){owner.kill()?;owner.wait()?;return Err("child observation handle".into());}
  let before=unsafe{WaitForSingleObject(handle,0)};owner.kill()?;owner.wait()?;let after=unsafe{WaitForSingleObject(handle,5000)};unsafe{CloseHandle(handle)};
  let profile=value["profile"].as_str().filter(|s|s.starts_with("kelft-")&&s.len()==62&&s[6..].bytes().all(|b|b.is_ascii_hexdigit())).ok_or("private profile receipt")?;let name=profile.encode_utf16().chain([0]).collect::<Vec<_>>();let cleanup=unsafe{windows_sys::Win32::Security::Isolation::DeleteAppContainerProfile(name.as_ptr())};
  let directory=PathBuf::from(value["directory"].as_str().ok_or("snapshot receipt")?);let temporary=kelft_wasi::windows_snapshot::temporary_directory()?;
  if directory.parent()!=Some(temporary.as_path())||!directory.file_name().and_then(|s|s.to_str()).is_some_and(|s|s.starts_with("kelft-image-")&&s.len()==60&&s[12..].bytes().all(|b|b.is_ascii_hexdigit()))||std::fs::symlink_metadata(&directory)?.file_type().is_symlink(){return Err("private snapshot cleanup target".into());}
  std::fs::remove_file(directory.join("image.exe"))?;std::fs::remove_dir(directory)?;
  results.push(serde_json::json!({"phase":phase,"aliveBefore":before==258,"exitedAfterOwnerDeath":after==0,"profileRemoved":cleanup==0}));
 }println!("{}",serde_json::to_string(&results)?);Ok(())
}
#[cfg(not(target_os="windows"))]
fn main(){eprintln!("unsupported development observation host");std::process::exit(2);}
