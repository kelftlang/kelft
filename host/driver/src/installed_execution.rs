//! Fixed native compiler/candidate routes. Guest paths and trusted metadata never
//! come from an artifact's environment or process arguments.
use crate::protocol::{self,ExecutionResult,WorkerRequest};
use serde_json::json;
use std::{fs,path::Path};
type Error=Box<dyn std::error::Error>;
fn mount<'a>(request:&'a WorkerRequest,guest:&str)->Result<&'a Path,Error>{
 let rows:Vec<_>=request.mounts.iter().filter(|m|m.guest==guest).collect();
 if rows.len()!=1{return Err(format!("missing or duplicate trusted mount {guest}").into());}Ok(&rows[0].host)
}
pub fn execute(request:&WorkerRequest)->Result<ExecutionResult,Error>{
 request.limits.validate()?;
 if request.schema_version!="0.1"||protocol::hash(&fs::read(&request.module)?)!=request.artifact_hash{return Err("native request integrity mismatch".into());}
 let(_,compiler)=crate::installed_paths()?;
 let is_compiler=fs::canonicalize(&request.module)?==fs::canonicalize(compiler)?;
 #[cfg(target_os="linux")]
 if !is_compiler {return crate::installed_linux_host::execute(request);}
 let mut boundary=crate::boundary_command()?;let command=&mut boundary.command;command.env_clear();
 #[cfg(target_os="linux")] {
  use std::os::unix::process::CommandExt;
  let parent=std::process::id() as i32;
  unsafe {command.pre_exec(move||{
   unsafe extern "C" {fn prctl(option:i32,...)->i32;fn getppid()->i32;}
   if prctl(1,9,0,0,0)!=0||getppid()!=parent{return Err(std::io::Error::other("native boundary parent changed"));}Ok(())
  });}
 }
 let mut result_directory=None;
 if is_compiler{
  if request.args.len()!=3||request.args[0]!="protocol"||!matches!(request.args[1].as_str(),"prepare"|"finalize")||request.args[2]!="/control/request.json"{return Err("installed compiler requires fixed protocol arguments".into());}
  let (project,control,output,fixtures)=(mount(request,"/project")?,mount(request,"/control")?,mount(request,"/output")?,mount(request,"/fixtures")?);
  // Keep the ledger mount beneath the compiler's fixed /out write authority.
  fs::create_dir_all(output.join("ledger"))?;
  command.arg("protocol").arg(&request.args[1]).arg(control.join("request.json"))
   .arg("--project-root").arg(project).arg("--output-root").arg(output)
   .arg("--control-root").arg(control).arg("--fixtures-root").arg(fixtures);
  if let Some(ledger)=request.mounts.iter().find(|m|m.guest=="/ledger") {command.arg("--ledger-root").arg(&ledger.host);}
 }else{
  let mut nonce=[0u8;24];getrandom::fill(&mut nonce).map_err(|_|"candidate entropy unavailable")?;
  let directory=crate::native::private_temp_dir()?.join(format!("kelft-native-result-{}",protocol::hex(&nonce)));fs::create_dir(&directory)?;
  let result=directory.join("result.json");
  // Recover the project from fixed /project guest paths; no private session mounts enter this route.
  let root=crate::execution::PROJECT_ROOT.get().ok_or("candidate project authority missing")?;
  let mut reads=vec![];let mut writes=vec![];
  command.arg("candidate-run").arg(&request.module).arg("--project-root").arg(root)
   .arg("--artifact-hash").arg(&request.artifact_hash).arg("--result").arg(&result)
   .arg("--timeout-ms").arg(request.limits.timeout_ms.to_string())
   .arg("--memory-bytes").arg(request.limits.memory_bytes.to_string())
   .arg("--stdout-bytes").arg(request.limits.stdout_bytes.to_string())
   .arg("--stderr-bytes").arg(request.limits.stderr_bytes.to_string());
  #[cfg(target_os="macos")]
  command.arg("--coordinator-sha256").arg(protocol::hash(&fs::read(std::env::current_exe()?)?));
  for item in &request.mounts{
   let host=fs::canonicalize(&item.host)?;
   if fs::canonicalize(crate::native::private_temp_dir()?)?.starts_with(&host)||cfg!(target_os="linux")&&std::path::Path::new("/tmp").starts_with(&host){return Err("candidate grant overlaps private temporary state".into());}
   let expected=crate::native_target::guest_path(root,&host)?;
   if item.guest!=expected{return Err("candidate guest authority differs".into());}
   if item.read{command.arg("--read").arg(&host);reads.push(expected.clone());}
   if item.write{command.arg("--write").arg(&host);writes.push(expected);}
  }
  let mut policy=json!({"execute":false,"read":reads,"write":writes});if request.configuration.starts_with('{'){let requested:kelft_wasi::host_channel::Policy=serde_json::from_str(&request.configuration)?;if !requested.validate()||requested.read!=reads||requested.write!=writes||requested.execute{return Err("candidate process policy differs from mounted authority".into());}policy["process"]=serde_json::to_value(requested.process)?;}
  command.arg("--policy").arg(serde_json::to_string(&policy)?).arg("--").args(&request.args);
  result_directory=Some((directory,result));
 }
 #[cfg(any(target_os="macos",target_os="windows"))]
 let output=boundary.run(&request.limits);
 #[cfg(not(any(target_os="macos",target_os="windows")))]
 let output=crate::native::run(command,&request.limits);
 let boundary_result=match &result_directory{Some((_,file))=>fs::read(file).and_then(|b|serde_json::from_slice::<serde_json::Value>(&b).map_err(std::io::Error::other)).map(Some),None=>Ok(None)};
 if let Some((directory,_))=&result_directory{fs::remove_dir_all(directory)?;}
 let output=output?;
 let mut failure=output.failure;
 let boundary_result=boundary_result.map_err(|error|format!("native candidate result unavailable: {error}; boundary exit {:?}; supervision {:?}; stderr {}",output.exit,failure,String::from_utf8_lossy(&output.stderr[..output.stderr.len().min(4096)])))?;
 if let Some(result)=boundary_result{if result["exit"].as_i64()!=output.exit.map(i64::from){return Err("native candidate result differs".into());}if result["boundaryFailure"].as_i64()!=Some(0){failure=Some("native candidate resource or supervision boundary".into());}}
 if protocol::hash(&fs::read(&request.module)?)!=request.artifact_hash{return Err("native artifact changed during execution".into());}
 let status=if failure.is_some(){"resource-error"}else{"exited"};
 Ok(ExecutionResult{status:status.into(),artifact_hash:request.artifact_hash.clone(),exit:if failure.is_none(){output.exit}else{None},stdout_hex:protocol::hex(&output.stdout),stderr_hex:protocol::hex(&output.stderr),trap:None,error:failure})
}
pub(crate) static PROJECT_ROOT:std::sync::OnceLock<std::path::PathBuf>=std::sync::OnceLock::new();
