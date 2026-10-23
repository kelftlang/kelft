//! Mechanisms for Kelft-owned test plans. Compilation and each case reuse the
//! installed boundary; discovery semantics and verdicts belong to Kelft.
use crate::{native, native_target::{self,Target}, protocol::{self, Limits, Mount, WorkerRequest}};
use serde_json::{Value, json};
use std::{collections::BTreeMap, fs, io::{Read, Write}, path::{Path, PathBuf}};
type Error = Box<dyn std::error::Error>;
const SOURCE_LIMIT: usize = 8 << 20;
#[cfg(kelft_testing)]
const POLICY:&[u8]=include_bytes!(env!("KELFT_TESTING_POLICY"));
#[cfg(not(kelft_testing))]
const POLICY:&[u8]=&[];
pub fn enabled()->bool{!POLICY.is_empty()||crate::installed_rebuild::has_policy("testing")}
fn limits(compile: bool) -> Limits {Limits {timeout_ms:if compile {600000}else{30000},memory_bytes:1<<30,stdout_bytes:4<<20,stderr_bytes:1<<20}}
fn path_text(path:&Path)->Result<String,Error>{Ok(path.to_str().ok_or("test path must be Unicode")?.into())}
fn read(path:&Path,limit:usize)->Result<Vec<u8>,Error>{
 let metadata=fs::symlink_metadata(path)?;
 if !metadata.is_file()||metadata.len()>limit as u64{return Err("test input must be a bounded regular file".into());}
 #[cfg(windows)] {use std::os::windows::fs::MetadataExt;if metadata.file_attributes()&0x400!=0{return Err("test input cannot be a reparse point".into());}}
 let mut bytes=vec![];fs::File::open(path)?.take(limit as u64+1).read_to_end(&mut bytes)?;if bytes.len()>limit{return Err("test input exceeds bound".into());}Ok(bytes)
}
fn contained(root:&Path,path:&Path)->Result<PathBuf,Error>{let full=fs::canonicalize(path)?;if !full.starts_with(root){return Err("test path escapes project root".into());}Ok(full)}
fn sources(root:&Path,path:&Path,out:&mut BTreeMap<String,String>,budget:&mut usize,depth:usize)->Result<(),Error>{
 if depth>64||out.len()>=1024{return Err("test discovery bound".into());}let metadata=fs::symlink_metadata(path)?;
 #[cfg(windows)] {use std::os::windows::fs::MetadataExt;if metadata.file_attributes()&0x400!=0{return Err("test discovery cannot follow reparse points".into());}}
 if metadata.file_type().is_symlink(){return Err("test discovery cannot follow symbolic links".into());}let full=contained(root,path)?;
 if metadata.is_dir(){
  let mut children=fs::read_dir(&full)?.map(|e|e.map(|e|e.path())).collect::<Result<Vec<_>,_>>()?;children.sort();if children.len()>4096{return Err("test directory entry limit".into());}
  for child in children {if child.file_name().and_then(|n|n.to_str()).is_some_and(|n|n.starts_with(".kelft-test-")){continue;}sources(root,&child,out,budget,depth+1)?;}
 }else if metadata.is_file()&&full.file_name().and_then(|n|n.to_str()).is_some_and(|n|n.ends_with(".test.kelft")){
  let bytes=read(&full,(*budget).min(SOURCE_LIMIT))?;*budget=budget.checked_sub(bytes.len()).ok_or("test source budget")?;
  let file=native_target::guest_path(root,&full)?;out.insert(file.trim_start_matches("/project/").into(),String::from_utf8(bytes)?);
 }Ok(())
}
struct Scratch {root:PathBuf,path:PathBuf}
impl Drop for Scratch {fn drop(&mut self){
 if self.path.parent()==Some(self.root.as_path())&&self.path.file_name().and_then(|n|n.to_str()).is_some_and(|n|n.starts_with(".kelft-test-"))&&fs::canonicalize(&self.path).is_ok_and(|p|p==self.path){let _=fs::remove_dir_all(&self.path);}
}}
fn scratch(root:&Path)->Result<Scratch,Error>{
 let mut nonce=[0;16];getrandom::fill(&mut nonce).map_err(|_|"test entropy unavailable")?;let path=root.join(format!(".kelft-test-{}",protocol::hex(&nonce)));
 #[cfg(unix)] {use std::os::unix::fs::DirBuilderExt;fs::DirBuilder::new().mode(0o700).create(&path)?;}
 #[cfg(windows)] fs::create_dir(&path)?;
 Ok(Scratch {root:root.into(),path})
}
fn boundary(arguments:Vec<String>,compile:bool)->Result<native::Output,Error>{
 let mut command=crate::boundary_command()?;command.command.args(arguments).env_clear();
 #[cfg(target_os="linux")] let result=native::run(&mut command.command,&limits(compile));
 #[cfg(any(target_os="windows",target_os="macos"))] let result=command.run(&limits(compile));
 result
}
fn plan(root:&Path,scratch:&Scratch,request:&Value)->Result<Value,Error>{
 let file=scratch.path.join("request.json");let bytes=serde_json::to_vec(request)?;if bytes.len()>16<<20{return Err("test request limit".into());}fs::write(&file,bytes)?;
 let image=scratch.path.join(format!("test-policy{}",Target::current()?.executable_suffix()));
 let policy=crate::installed_rebuild::load_policy("testing",POLICY)?;
 if !image.exists(){fs::write(&image,&policy)?;#[cfg(unix)] {use std::os::unix::fs::PermissionsExt;fs::set_permissions(&image,fs::Permissions::from_mode(0o700))?;}}
 let work=WorkerRequest{schema_version:"0.1".into(),module:image,artifact_hash:protocol::hash(&policy),args:vec!["test-plan".into(),native_target::guest_path(root,&file)?],mounts:vec![Mount{host:scratch.path.clone(),guest:native_target::guest_path(root,&scratch.path)?,read:true,write:false}],configuration:String::new(),limits:limits(true)};
 let output=crate::execution::execute(&work)?;
 if output.exit!=Some(0)||output.status!="exited"{return Err(format!("test planning failed: {}",String::from_utf8_lossy(&protocol::unhex(&output.stderr_hex)?)).into());}
 let result:Value=serde_json::from_slice(&protocol::unhex(&output.stdout_hex)?)?;if result["schema"]!="kelft.test-action/1"{return Err("invalid test action contract".into());}Ok(result)
}
fn present(mut report:Value,args:&[String],code:i32)->Result<i32,Error>{
 if report["target"].is_null(){report["target"]=json!(Target::current()?.id());}
 if args.iter().any(|a|a=="--json"){println!("{report}");}
 else if report["status"]=="listed"{for id in report["cases"].as_array().ok_or("test listing missing")?{println!("{}",id.as_str().ok_or("test id missing")?);}}
 else {
  if let Some(cases)=report["cases"].as_array(){for case in cases {
   println!("{} {}",case["status"].as_str().unwrap_or("failed"),case["id"].as_str().unwrap_or("unknown"));
   if case["status"]!="passed"{eprintln!("  {}",case["reason"].as_str().unwrap_or("test failed"));
    if let Some(failures)=case["execution"]["completion"]["failures"].as_array(){for message in failures{eprintln!("  {}",message.as_str().unwrap_or("assertion failed"));}}
    for observation in [&case["build"],&case["execution"]]{if let Some(hex)=observation["stderrHex"].as_str(){if let Ok(bytes)=protocol::unhex(hex){std::io::stderr().write_all(&bytes)?;}}}
   }
  }}
  if let Some(error)=report["error"].as_object(){eprintln!("error[{}]: {}",error.get("code").and_then(Value::as_str).unwrap_or("TEST_HOST"),error.get("message").and_then(Value::as_str).unwrap_or("test operation failed"));}
  println!("{} passed; {} failed",report["totals"]["passed"].as_u64().unwrap_or(0),report["totals"]["failed"].as_u64().unwrap_or(0));
 }Ok(code)
}
fn run(args:&[String])->Result<i32,Error>{
 if !enabled(){return Err("native Kelft test policy is unavailable; rebuild the installation with KELFT_TESTING_POLICY".into());}
 crate::installed_paths()?;let cwd=fs::canonicalize(std::env::current_dir()?)?;
 let selected=args.windows(2).find(|a|a[0]=="--project-root").map(|a|a[1].as_str());let root=fs::canonicalize(selected.map_or_else(||cwd.clone(),|p|cwd.join(p)))?;
 if !root.is_dir()||root.parent().is_none(){return Err("invalid test project root".into());}
 crate::execution::PROJECT_ROOT.get_or_init(||root.clone());
 let scratch=scratch(&root)?;let target=Target::current()?;let mut request=json!({"schema":"kelft.test-request/1","arguments":args,"target":target.id(),"builds":{},"executions":{}});
 let mut binaries=BTreeMap::<String,PathBuf>::new();let mut observed=BTreeMap::<String,String>::new();let mut grants=vec![];let maximum_file=scratch.path.join("maximum.json");let mut case_timeout=30000;let mut process_grants=json!([]);
 for _ in 0..8200 {
  let action=plan(&root,&scratch,&request)?;
  match action["operation"].as_str().ok_or("test operation required")? {
   "discover"=>{
    if request.get("sources").is_some(){return Err("repeated test discovery".into());}let path=action["path"].as_str().ok_or("test discovery path required")?;
    case_timeout=action["timeoutMs"].as_u64().filter(|n|*n>0&&*n<=600000).ok_or("invalid test timeout")?;
    if action["corpus"]==true {
     let file=contained(&root,&cwd.join(path))?;observed.insert(path.into(),String::from_utf8(read(&file,SOURCE_LIMIT)?)?);
     request["expectations"]=serde_json::from_slice(&read(&contained(&root,&root.join("tests/native-conformance.json"))?,1<<20)?)?;
    }else{let mut budget=SOURCE_LIMIT;sources(&root,&cwd.join(path),&mut observed,&mut budget,0)?;}
    request["sources"]=serde_json::to_value(&observed)?;
    let policy=action["policy"].as_str().ok_or("test policy path missing")?;
    let permissions=if policy.is_empty(){json!({"read":[],"write":[]})}else{serde_json::from_slice::<Value>(&read(&contained(&root,&cwd.join(policy))?,1<<20)?)?};
    let fields=permissions.as_object().ok_or("test capability object required")?;
    if fields.keys().any(|k|!matches!(k.as_str(),"read"|"write"|"execute"|"process"))||fields.get("execute").is_some_and(|v|v!=&json!(false)){return Err("unsupported test capability".into());}
    process_grants=fields.get("process").cloned().unwrap_or_else(||json!([]));
    let (mounts,_)=crate::orchestration::permissions(&root,&permissions)?;
    let mut maximum=json!({"read":mounts.iter().filter(|m|m.read).map(|m|m.guest.clone()).collect::<Vec<_>>(),"write":mounts.iter().filter(|m|m.write).map(|m|m.guest.clone()).collect::<Vec<_>>(),"execute":false});if fields.contains_key("process"){maximum["process"]=process_grants.clone();let parsed:kelft_wasi::host_channel::Policy=serde_json::from_value(maximum.clone())?;if !parsed.validate(){return Err("invalid process capability policy".into());}}grants=mounts;
    for key in ["read","write"]{maximum[key].as_array_mut().ok_or("test maximum roots")?.push(json!(native_target::guest_path(&root,&scratch.path)?));}fs::write(&maximum_file,serde_json::to_vec(&maximum)?)?;
   },
   "build"=>{
    let file=action["file"].as_str().ok_or("test suite file required")?;if binaries.contains_key(file){return Err("repeated test build".into());}
    let index=binaries.len();let output=scratch.path.join(format!("suite-{index}{}",target.executable_suffix()));
    let source=if action["entry"]==true {
     let source=contained(&root,&root.join(file))?;read(&source,SOURCE_LIMIT)?;source
    }else{
     let expected=observed.get(file).ok_or("test suite was not observed")?;if read(&root.join(file),SOURCE_LIMIT)?!=expected.as_bytes(){return Err("test source changed during discovery".into());}
     let source=scratch.path.join(format!("suite-{index}.kelft"));fs::write(&source,action["source"].as_str().ok_or("test wrapper source missing")?)?;source
    };
    let arguments=vec!["build".into(),path_text(&source)?,"--project-root".into(),path_text(&root)?,"-o".into(),path_text(&output)?,"--capabilities".into(),path_text(&maximum_file)?];
    let mut build=crate::installed_request::parse(&arguments,target,&cwd)?;build.prepare_paths(&cwd)?;let result={let _lock=crate::installed_targets::build_lock()?;boundary(build.boundary_args(target)?,true)?};
    request["builds"][file]=json!({"status":if result.exit==Some(0)&&result.failure.is_none(){"success"}else{"failed"},"exit":result.exit,"stdoutHex":protocol::hex(&result.stdout),"stderrHex":protocol::hex(&result.stderr),"error":result.failure});binaries.insert(file.into(),output);
   },
   "run"=>{
    let id=action["id"].as_str().ok_or("test id required")?;if request["executions"].get(id).is_some(){return Err("repeated test execution".into());}
    let image=binaries.get(action["file"].as_str().ok_or("test file required")?).ok_or("test image missing")?;let directory=scratch.path.join(format!("case-{}",request["executions"].as_object().ok_or("execution observations")?.len()));fs::create_dir(&directory)?;let record=directory.join("result.json");
    let mut mounts=grants.clone();
    mounts.push(Mount{host:directory.clone(),guest:native_target::guest_path(&root,&directory)?,read:true,write:true});crate::execution::PROJECT_ROOT.get_or_init(||root.clone());
    let arguments=if action["corpus"]==true{vec![]}else{vec![id.into(),native_target::guest_path(&root,&record)?]};
    let mut case_limits=limits(false);case_limits.timeout_ms=case_timeout;
    let configuration=if process_grants==json!([]){String::new()}else{serde_json::to_string(&json!({"read":mounts.iter().filter(|m|m.read).map(|m|m.guest.clone()).collect::<Vec<_>>(),"write":mounts.iter().filter(|m|m.write).map(|m|m.guest.clone()).collect::<Vec<_>>(),"execute":false,"process":process_grants}))?};
    let work=WorkerRequest{schema_version:"0.1".into(),module:image.clone(),artifact_hash:protocol::hash(&read(image,268435456)?),args:arguments,mounts,configuration,limits:case_limits};
    let result=crate::execution::execute(&work);let completion=if record.exists(){read(&record,1<<20).ok().and_then(|b|serde_json::from_slice::<Value>(&b).ok()).unwrap_or(Value::Null)}else{Value::Null};
    let mut result=match result{Ok(result)=>serde_json::to_value(result)?,Err(error)=>json!({"status":"host-error","error":error.to_string()})};result["completion"]=completion;request["executions"][id]=result;
   },
   "complete"=>return present(action["report"].clone(),args,action["exit"].as_i64().filter(|c|[0,1,64].contains(c)).ok_or("test exit contract")? as i32),
   _=>return Err("unknown test host operation".into()),
  }
 }Err("test plan step limit".into())
}
pub fn dispatch(args:&[String])->Result<i32,Error>{match run(args){Ok(code)=>Ok(code),Err(error)=>present(json!({"schema":"kelft.test-report/1","status":"failure","cases":[],"totals":{"passed":0,"failed":0},"error":{"code":"TEST_HOST","message":error.to_string()}}),args,1)}}
