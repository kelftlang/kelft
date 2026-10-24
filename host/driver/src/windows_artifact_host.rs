//! Windows test entry for the native compiler artifact channel.
//! This entry does not establish installed target support or certification.
#[cfg(target_os="windows")]
fn main(){
 use kelft_wasi::{windows_artifact,windows_supervisor::Limits};
 use std::{io::Write,fs};
 use std::os::windows::fs::OpenOptionsExt;
 use sha2::{Digest,Sha256};
 let result=(||->Result<u32,Box<dyn std::error::Error>>{
  let args:Vec<_>=std::env::args().skip(1).collect();
  if args.len()<4||!matches!(args[0].as_str(),"--compiler"|"--candidate")||args[2]!="--sha256"{return Err("expected --compiler/--candidate IMAGE --sha256 HASH [--filesystem-policy FILE] [--linker-policy FILE] [--result-file FILE] [-- ARGS]".into());}
  let candidate=args[0]=="--candidate";let mut at=4;let(mut policy,mut linker_policy,mut result_path)=(None,None,None);
  while let Some(flag)=args.get(at){if flag=="--"{break;}let value=args.get(at+1).ok_or("missing Windows role option value")?;match flag.as_str(){"--filesystem-policy" if policy.is_none()=>policy=Some(value),"--linker-policy" if linker_policy.is_none()=>linker_policy=Some(value),"--result-file" if result_path.is_none()=>result_path=Some(value),_=>return Err("unknown or duplicate Windows role option".into())}at+=2;}
  if candidate&&(policy.is_some()||linker_policy.is_some()){return Err("standalone candidate cannot receive compiler or linker authority".into());}
  let mut record=result_path.map(|path|fs::OpenOptions::new().write(true).create_new(true).share_mode(1).open(path)).transpose()?;
  let arguments=args.get(at+1..).unwrap_or(&[]);let linker=linker_policy.map(|path|kelft_wasi::windows_linker::Linker::from_file(std::path::Path::new(path))).transpose()?;if linker.is_some()&&policy.is_none(){return Err("linker requires explicit compiler filesystem authority".into());}
  let file=fs::File::open(&args[1])?;if file.metadata()?.len()>64<<20{return Err("compiler image exceeds bound".into());}
  let mut bytes=vec![];use std::io::Read;file.take((64<<20)+1).read_to_end(&mut bytes)?;
  let system=std::env::var("SystemRoot")?;
  let limits=Limits{wall_ms:600000,memory_bytes:1<<30,output_bytes:16<<20};
  let output=if candidate{windows_artifact::run_candidate(&bytes,&args[3],&system,arguments,Limits{wall_ms:10000,..limits})}else if let Some(path)=policy{
   #[derive(serde::Deserialize)]#[serde(deny_unknown_fields)]struct Policy{schema:String,cwd:String,read:Vec<String>,write:Vec<String>,#[serde(default,rename="programRead")]program_read:Vec<String>,#[serde(default,rename="programWrite")]program_write:Vec<String>}
   let file=fs::File::open(path)?;if file.metadata()?.len()>1<<20{return Err("filesystem policy exceeds bound".into());}let policy:Policy=serde_json::from_reader(file)?;if policy.schema!="kelft-windows-filesystem-development/1"||policy.read.len()+policy.write.len()>128||policy.program_read.len()+policy.program_write.len()>128{return Err("invalid Windows filesystem policy".into());}
   use kelft_wasi::windows_filesystem_session::Grant;let grants:Vec<_>=policy.read.iter().map(|p|Grant{path:p.into(),read:true,write:false}).chain(policy.write.iter().map(|p|Grant{path:p.into(),read:false,write:true})).collect();
   let program_grants:Vec<_>=policy.program_read.iter().map(|p|Grant{path:p.into(),read:true,write:false}).chain(policy.program_write.iter().map(|p|Grant{path:p.into(),read:false,write:true})).collect();
   windows_artifact::run_compiler_with_services(&bytes,&args[3],&system,arguments,limits,limits,&grants,&program_grants,std::path::Path::new(&policy.cwd),linker)
  }else{windows_artifact::run_compiler(&bytes,&args[3],&system,arguments,limits,limits)};
  let output=match output{Ok(output)=>output,Err(error)=>{if let Some(file)=record.as_mut(){serde_json::to_writer(&mut *file,&serde_json::json!({"schema":"kelft-windows-worker-result-development/1","role":if candidate{"candidate"}else{"compiler"},"imageHash":args[3],"error":error.to_string(),"usage":null}))?;file.sync_all()?;}return Err(error.into());}};
  if let Some(file)=record.as_mut(){serde_json::to_writer(&mut *file,&serde_json::json!({"schema":"kelft-windows-worker-result-development/1","role":if candidate{"candidate"}else{"compiler"},"imageHash":args[3],"exit":output.exit,"failure":output.failure,"usage":output.usage,"stdoutHash":format!("sha256:{:x}",Sha256::digest(&output.stdout)),"stderrHash":format!("sha256:{:x}",Sha256::digest(&output.stderr))}))?;file.sync_all()?;}
  std::io::stdout().write_all(&output.stdout)?;std::io::stderr().write_all(&output.stderr)?;
  if let Some(failure)=output.failure{return Err(failure.into());}Ok(output.exit.ok_or("compiler exit missing")?)
 })();match result{Ok(code)=>std::process::exit(code as i32),Err(error)=>{eprintln!("error[K0600]: {error}");std::process::exit(125);}}
}
#[cfg(not(target_os="windows"))]
fn main(){eprintln!("Windows native execution required");std::process::exit(125);}
