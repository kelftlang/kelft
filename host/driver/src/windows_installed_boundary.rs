//! Installed Windows boundary. Package inputs are compiled-in hash pins; only
//! fixed compiler/linker/candidate routes and explicitly pinned optional profiles
//! cross into separate LPAC identities.
#[cfg(target_os="windows")]
mod platform {
 include!(env!("KELFT_NATIVE_PINS"));
 use kelft_wasi::{native_target::{self,Target},native_resources::Contract,windows_artifact,windows_filesystem::Broker,windows_filesystem_session::{self as session,Grant,MappedGrant},windows_linker::Linker,windows_process::AppContainerSid,windows_snapshot::Image,windows_supervisor::{Limits,Output}};
 use sha2::{Digest,Sha256};
 use std::{fs,io::{self,Read,Write},os::windows::fs::{OpenOptionsExt,MetadataExt},path::{Path,PathBuf}};
 type Error=Box<dyn std::error::Error>;
 fn hash(bytes:&[u8])->String{format!("sha256:{:x}",Sha256::digest(bytes))}
 fn read(path:&Path,maximum:u64)->Result<(fs::File,Vec<u8>),Error>{let mut file=fs::OpenOptions::new().read(true).share_mode(1).custom_flags(0x00200000).open(path)?;let metadata=file.metadata()?;if !metadata.is_file()||metadata.file_attributes()&0x400!=0||metadata.len()>maximum{return Err("invalid installed input".into());}let mut bytes=vec![];Read::by_ref(&mut file).take(maximum+1).read_to_end(&mut bytes)?;if bytes.len() as u64!=metadata.len(){return Err("installed input changed".into());}Ok((file,bytes))}
 fn mapped(host:PathBuf,guest:&str,read:bool,write:bool)->MappedGrant{MappedGrant{guest:guest.into(),grant:Grant{path:host,read,write}}}
 fn host_file(root:&Path,text:&str)->Result<(PathBuf,String),Error>{let source=Path::new(text);let file=fs::canonicalize(if source.is_absolute(){source.to_path_buf()}else{root.join(source)})?;let guest=native_target::guest_path(root,&file)?;Ok((file,guest))}
 fn grant_safe(root:&Path,path:&Path,write:bool)->Result<(),Error>{let temporary=fs::canonicalize(kelft_wasi::windows_snapshot::temporary_directory()?)?;if session::within(&temporary,path)?||session::within(root,path)?||write&&session::within(path,root)?||kelft_wasi::windows_snapshot::cross_linker_storage_overlap(path)?{return Err("grant overlaps private or installed state".into());}Ok(())}
 struct Flags{values:std::collections::BTreeMap<String,String>,reads:Vec<String>,writes:Vec<String>,tail:Vec<String>}
 impl Flags{
  fn parse(args:&[String],allowed:&[&str],grants:bool)->Result<Self,Error>{let mut result=Self{values:Default::default(),reads:vec![],writes:vec![],tail:vec![]};let mut at=0;while at<args.len(){let key=&args[at];if key=="--"{if !grants{return Err("unexpected argument tail".into());}result.tail=args[at+1..].to_vec();break;}let value=args.get(at+1).ok_or("missing installed option value")?;if grants&&matches!(key.as_str(),"--read"|"--write"){if key=="--read"{result.reads.push(value.clone());}else{result.writes.push(value.clone());}}else if !allowed.contains(&key.as_str())||result.values.insert(key.clone(),value.clone()).is_some(){return Err("unknown or duplicate installed option".into());}at+=2;}if result.reads.len()+result.writes.len()>128{return Err("candidate grant count".into());}Ok(result)}
  fn need(&self,key:&str)->Result<&str,Error>{self.values.get(key).map(String::as_str).ok_or_else(||format!("missing {key}").into())}
 }
 fn publish_result(path:&Path,exit:u32,failure:bool,output:&Output)->Result<(),Error>{let mut roots=Broker::default();roots.add_root(path,false,true)?;let mut file=fs::OpenOptions::new().write(true).create_new(true).share_mode(1).open(path)?;serde_json::to_writer(&mut file,&serde_json::json!({"exit":exit,"boundaryFailure":if failure{1}else{0},"usage":output.usage,"resourceContract":Contract::for_role(Target::current()?,"candidate")?}))?;file.sync_all()?;Ok(())}
 pub fn dispatch()->Result<u32,Error>{
  let mut args:Vec<String>=std::env::args().skip(1).collect();if args.len()<3||args[0]!="--installed-root"{return Err("installed root and command required".into());}
  let coordinator_hash=if args.get(2).is_some_and(|a|a=="--coordinator-sha256"){let value=args.get(3).ok_or("coordinator identity missing")?.clone();args.drain(2..4);Some(value)}else{None};
  if args.get(2).is_some_and(|arg|arg=="--coordinator-lifeline"){args.remove(2);kelft_wasi::windows_lifeline::watch_stdin()?;}if args.len()<3{return Err("installed boundary command missing".into());}
  let root=fs::canonicalize(&args[1])?;let executable=fs::canonicalize(std::env::current_exe()?)?;if executable.parent().and_then(Path::parent)!=Some(root.as_path()){return Err("installed boundary root differs".into());}
  #[cfg(kelft_target_components)]let _installation_lock=kelft_wasi::component_store::lock(&root,false)?;
  let mut retained=Broker::default();retained.add_root(&root,true,false)?;
  let(compiler,configuration)=(root.join("rootfs/compiler.exe"),root.join("rootfs/control/toolchain.json"));
  let(_compiler_file,compiler_bytes)=read(&compiler,64<<20)?;if !cfg!(kelft_rebuild)&&hash(&compiler_bytes)!=COMPILER_SHA256{return Err("installed compiler changed".into());}Target::current()?.validate_executable(&compiler_bytes)?;
  let compiler_hash=hash(&compiler_bytes);
  let(_configuration_file,configuration_bytes)=read(&configuration,1<<20)?;if hash(&configuration_bytes)!=WINDOWS_LINKER_POLICY_SHA256{return Err("installed linker policy changed".into());}
  let mut windows=[0u16;32768];let size=unsafe{windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW(windows.as_mut_ptr(),windows.len() as u32)} as usize;if size==0||size>=windows.len(){return Err("system Windows directory unavailable".into());}let system=String::from_utf16(&windows[..size])?;let contract=Contract::for_role(Target::current()?,"compiler")?;let limits=Limits{wall_ms:contract.compiler.wall_ms.try_into()?,memory_bytes:contract.memory.ceiling_bytes.try_into()?,output_bytes:16<<20};let command=args[2].as_str();
  if command=="engine-run"{
   let engine=args.get(3).ok_or("explicit engine required")?;if !matches!(engine.as_str(),"javascript"|"wasm"){return Err("optional engine profile unavailable".into());}
   let module=args.get(4).ok_or("engine module missing")?;let flags=Flags::parse(&args[5..],&["--project-root","--policy"],true)?;
   let project=fs::canonicalize(flags.need("--project-root")?)?;if !project.is_dir()||project.parent().is_none(){return Err("engine project root differs".into());}grant_safe(&root,&project,false)?;
   let mut mappings=std::collections::BTreeMap::<String,MappedGrant>::new();let(mut actual_read,mut actual_write)=(std::collections::BTreeSet::new(),std::collections::BTreeSet::new());
   for(paths,writing)in [(&flags.reads,false),(&flags.writes,true)]{for path in paths{let host=fs::canonicalize(path)?;grant_safe(&root,&host,writing)?;if !host.is_dir(){return Err("engine grants require directories".into());}let guest=native_target::guest_path(&project,&host)?;session::guest_name(&guest)?;if writing{actual_write.insert(guest.clone());}else{actual_read.insert(guest.clone());}let entry=mappings.entry(guest.clone()).or_insert_with(||mapped(host,&guest,false,false));entry.grant.read|=!writing;entry.grant.write|=writing;}}
   let policy=if let Some(file)=flags.values.get("--policy"){let(file,_)=host_file(&project,file)?;let(_held,bytes)=read(&file,1<<20)?;serde_json::from_slice::<serde_json::Value>(&bytes)?}else{serde_json::json!({"read":[],"write":[]})};
   let fields=policy.as_object().ok_or("engine policy object required")?;if fields.keys().any(|name|!matches!(name.as_str(),"read"|"write"|"execute"))||fields.get("execute").is_some_and(|v|v!=&serde_json::json!(false)){return Err("engine policy cannot delegate execution".into());}
   for(name,actual)in [("read",actual_read),("write",actual_write)]{let rows=policy[name].as_array().ok_or("engine policy roots required")?;if rows.len()>128{return Err("engine root budget".into());}let mut expected=std::collections::BTreeSet::new();for row in rows{let text=row.as_str().ok_or("engine root string required")?;let host=fs::canonicalize(project.join(text))?;expected.insert(native_target::guest_path(&project,&host)?);}if actual!=expected{return Err("engine grants differ from policy".into());}}
   let expected=option_env!("KELFT_OPTIONAL_ENGINE_PROFILES_SHA256").ok_or("optional engines were not included in this package")?;let(_manifest_file,manifest)=read(&root.join("rootfs/control/engine-profiles.json"),1<<20)?;let profiles=kelft_wasi::engine_profiles::authenticate(&manifest,expected,Target::current()?)?;
   let runtime_input=if engine=="javascript"{&profiles.javascript.as_ref().ok_or("JavaScript profile unavailable")?.runtime}else{&profiles.wasm.as_ref().ok_or("Wasm profile unavailable")?.runtime};
   let(_runtime_file,runtime)=read(&root.join(&runtime_input.path),256<<20)?;if hash(&runtime)!=runtime_input.sha256{return Err("installed engine runtime changed".into());}
   let(file,_)=host_file(&project,module)?;let(_program_file,program)=read(&file,64<<20)?;
   let mappings=mappings.into_values().collect::<Vec<_>>();let output=if engine=="javascript"{let profile=profiles.javascript.as_ref().unwrap();let(_adapter_file,adapter)=read(&root.join(&profile.adapter.path),1<<20)?;if hash(&adapter)!=profile.adapter.sha256{return Err("installed engine adapter changed".into());}kelft_wasi::windows_engine::javascript(&runtime,&runtime_input.sha256,&adapter,&profile.adapter.sha256,&program,&flags.tail,&mappings,&system,limits)?}else{kelft_wasi::windows_engine::wasm(&runtime,&runtime_input.sha256,&program,&flags.tail,&mappings,&system,limits)?};
   io::stdout().write_all(&output.stdout)?;io::stderr().write_all(&output.stderr)?;if let Some(error)=output.failure{return Err(error.into());}return output.exit.ok_or("engine exit missing".into());
  }
  if command=="candidate-run"{
   let module=args.get(3).ok_or("candidate image missing")?;let flags=Flags::parse(&args[4..],&["--project-root","--artifact-hash","--result","--timeout-ms","--memory-bytes","--stdout-bytes","--stderr-bytes","--policy"],true)?;
   let project=fs::canonicalize(flags.need("--project-root")?)?;if !project.is_dir()||project.parent().is_none(){return Err("candidate project root differs".into());}
   let mut mappings=std::collections::BTreeMap::<String,MappedGrant>::new();let(mut reads,mut writes)=(vec![],vec![]);
   for(paths,writing)in [(&flags.reads,false),(&flags.writes,true)]{for path in paths{let host=fs::canonicalize(path)?;grant_safe(&root,&host,writing)?;let guest=native_target::guest_path(&project,&host)?;if writing{writes.push(guest.clone());}else{reads.push(guest.clone());}let entry=mappings.entry(guest.clone()).or_insert_with(||mapped(host,&guest,false,false));if writing{entry.grant.write=true;}else{entry.grant.read=true;}}}
   let policy:kelft_wasi::host_channel::Policy=serde_json::from_str(flags.need("--policy")?)?;if !policy.validate()||policy.read!=reads||policy.write!=writes||policy.execute{return Err("candidate policy differs from explicit mappings".into());}
   let wall:u32=flags.need("--timeout-ms")?.parse()?;let memory:usize=flags.need("--memory-bytes")?.parse()?;let stdout:usize=flags.need("--stdout-bytes")?.parse()?;let stderr:usize=flags.need("--stderr-bytes")?.parse()?;if stdout>64<<20||stderr>64<<20{return Err("candidate output limit differs".into());}
   let(_file,bytes)=read(Path::new(module),64<<20)?;let expected=flags.need("--artifact-hash")?;if hash(&bytes)!=expected{return Err("candidate image changed".into());}let identity=AppContainerSid::fresh()?;let image=Image::new(&bytes,expected,&identity)?;
   #[cfg(kelft_target_components)]drop(_installation_lock);
   let installed=coordinator_hash.as_ref().map(|sha|kelft_wasi::windows_host::Installed{root:root.clone(),coordinator_sha256:sha.clone()});
   let output=session::run_mapped_policy(&image,&identity,&system,&flags.tail,Limits{wall_ms:wall,memory_bytes:memory,output_bytes:stdout.checked_add(stderr).ok_or("capture overflow")?.min(16<<20)},&mappings.into_values().collect::<Vec<_>>(),"/project",&[],vec![],None,Some(policy),installed)?;
   let failed=output.failure.is_some()||output.stdout.len()>stdout||output.stderr.len()>stderr;let exit=if failed{125}else{output.exit.ok_or("candidate exit missing")?};publish_result(Path::new(flags.need("--result")?),exit,failed,&output)?;
   io::stdout().write_all(&output.stdout[..output.stdout.len().min(stdout)])?;io::stderr().write_all(&output.stderr[..output.stderr.len().min(stderr)])?;return Ok(exit);
  }
  if command=="cross-build" {
   let _component_lock=kelft_wasi::component_store::activation(&root,"linux-x86_64")?;
   let expected=option_env!("KELFT_WINDOWS_LINUX_CROSS_SHA256").ok_or("offline cross-linker profile was not included in this package")?;
   let flags=Flags::parse(&args[4..],&["--project-root","-o","--artifact-target","--capabilities","--intent","--bindings"],false)?;
   if Target::current()?!=Target::WindowsX64||flags.need("--artifact-target")?!="linux-x86_64"{return Err("unsupported cross-link artifact target".into());}
   let project=fs::canonicalize(flags.need("--project-root")?)?;if !project.is_dir()||project.parent().is_none(){return Err("invalid cross-build project root".into());}grant_safe(&root,&project,false)?;
   let(entry_host,entry)=host_file(&project,args.get(3).ok_or("cross-build entry required")?)?;
   let requested=std::path::absolute(flags.need("-o")?)?;let parent=fs::canonicalize(requested.parent().ok_or("output parent required")?)?;grant_safe(&root,&parent,true)?;
   let name=requested.file_name().ok_or("output name required")?.to_str().ok_or("Unicode output name required")?;session::guest_name(&format!("/out/{name}"))?;
   let destination=parent.join(name);
   if destination.extension().and_then(|v|v.to_str()).is_some_and(|v|v.eq_ignore_ascii_case("kelft"))||destination.exists()&&fs::canonicalize(&destination)?==entry_host{return Err("output overlaps compiler source".into());}
   let mut worker=vec!["cross-object".into(),entry,"--project-root".into(),"/project".into(),"--artifact-target".into(),"linux-x86_64".into(),"-o".into(),"/out/target.o".into()];
   for flag in ["--capabilities","--intent","--bindings"]{if let Some(path)=flags.values.get(flag){let(host,guest)=host_file(&project,path)?;if destination.exists()&&fs::canonicalize(&destination)?==host{return Err("output overlaps compiler input".into());}worker.extend([flag.into(),guest]);}}
   let(_profile_file,profile)=read(&root.join("rootfs/control/cross-linux-x86_64.json"),1<<20)?;
   let linker=kelft_wasi::windows_cross_linker::CrossLinker::from_package(&profile,expected,&root,Path::new(&system))?;
   let mut usage=None;
   let mut report=linker.build(&destination,&system,|private|{
    let grants=[mapped(project.clone(),"/project",true,false),mapped(private.to_path_buf(),"/out",true,true)];
    let output=windows_artifact::run_compiler_mapped(&compiler_bytes,&compiler_hash,&system,&worker,limits,limits,&grants,&[],"/project",None)?;
    if output.failure.is_some()||output.exit!=Some(0){return Err(io::Error::other(format!("cross-object compiler failed: {:?}; {}{}",output.failure,String::from_utf8_lossy(&output.stdout),String::from_utf8_lossy(&output.stderr))));}
    usage=Some(serde_json::to_value(output.usage)?);Ok(())
   })?;
   report["workerUsage"]=usage.unwrap_or_default();report["resourceContract"]=serde_json::to_value(contract)?;
   serde_json::to_writer(io::stdout(),&report)?;writeln!(io::stdout())?;return Ok(0);
  }
  if matches!(command,"check"|"tokens"|"ast"|"ir"|"native-object"|"cross-object") {
   let entry_arg=args.get(3).ok_or("compiler source required")?;let cross=command=="cross-object";let object=command=="native-object"||cross;
   let allowed:&[&str]=if cross{&["--project-root","-o","--artifact-target","--capabilities","--intent","--bindings"]}else if object{&["--project-root","-o","--capabilities","--intent","--bindings"]}else{&["--project-root","--capabilities","--intent","--bindings"]};
   let flags=Flags::parse(&args[4..],allowed,false)?;let project=fs::canonicalize(flags.need("--project-root")?)?;
   if cross&&(Target::current()?!=Target::WindowsX64||flags.need("--artifact-target")?!="linux-x86_64"){return Err("unsupported cross-object artifact target".into());}
   if !project.is_dir()||project.parent().is_none(){return Err("invalid compiler project root".into());}grant_safe(&root,&project,false)?;
   let(entry_host,entry)=host_file(&project,entry_arg)?;let mut grants=vec![mapped(project.clone(),"/project",true,false)];
   let mut worker=vec![command.into(),entry,"--project-root".into(),"/project".into()];
   if cross {worker.extend(["--artifact-target".into(),"linux-x86_64".into()]);}
   if object {
    let requested=std::path::absolute(flags.need("-o")?)?;let parent=fs::canonicalize(requested.parent().ok_or("output parent required")?)?;grant_safe(&root,&parent,true)?;
    let name=requested.file_name().ok_or("output name required")?.to_str().ok_or("Unicode output name required")?;session::guest_name(&format!("/out/{name}"))?;
    if requested.exists()&&fs::canonicalize(&requested)?==entry_host{return Err("output overlaps compiler source".into());}
    grants.push(mapped(parent,"/out",true,true));worker.extend(["-o".into(),format!("/out/{name}")]);
   }
   for flag in ["--capabilities","--intent","--bindings"]{if let Some(path)=flags.values.get(flag){let(host,guest)=host_file(&project,path)?;if object&&fs::canonicalize(flags.need("-o")?).is_ok_and(|output|output==host){return Err("output overlaps compiler input".into());}worker.extend([flag.into(),guest]);}}
   let output=windows_artifact::run_compiler_mapped(&compiler_bytes,&compiler_hash,&system,&worker,limits,limits,&grants,&[],"/project",None)?;
   if let Some(error)=output.failure{return Err(error.into());}io::stdout().write_all(&output.stdout)?;io::stderr().write_all(&output.stderr)?;return Ok(output.exit.ok_or("compiler exit missing")?);
  }
  if !matches!(command,"native-build"|"protocol"){return Err("expected native-build, protocol or candidate-run; optional engines require a separate prepared profile".into());}
  let linker=Linker::from_package(&configuration_bytes,&root,Path::new(&system))?;
  let system_observation=linker.system_observation();
  let first=if command=="protocol"{5}else{4};if args.len()<first{return Err("installed compiler arguments missing".into());}
  let allowed:&[&str]=if command=="protocol"{&["--project-root","--output-root","--control-root","--fixtures-root","--ledger-root"]}else{&["--project-root","-o","--capabilities","--intent","--bindings","--object-output"]};let flags=Flags::parse(&args[first..],allowed,false)?;
  let project=fs::canonicalize(flags.need("--project-root")?)?;if !project.is_dir()||project.parent().is_none(){return Err("compiler project root differs".into());}grant_safe(&root,&project,false)?;
  let mut grants=vec![mapped(project.clone(),"/project",true,false),mapped(configuration.clone(),"/control/toolchain.json",true,false)];let mut worker;
  if command=="protocol"{
   if !matches!(args[3].as_str(),"prepare"|"finalize"){return Err("unknown protocol phase".into());}
   let control=fs::canonicalize(flags.need("--control-root")?)?;if fs::canonicalize(&args[4])?!=control.join("request.json"){return Err("trusted request path differs".into());}
   let output=fs::canonicalize(flags.need("--output-root")?)?;grant_safe(&root,&output,true)?;
   grants.push(mapped(output,"/out",true,true));grants.push(mapped(control,"/control",true,false));grants.push(mapped(fs::canonicalize(flags.need("--fixtures-root")?)?,"/fixtures",true,false));
   if let Some(path)=flags.values.get("--ledger-root"){let host=fs::canonicalize(path)?;grant_safe(&root,&host,true)?;grants.push(mapped(host,"/out/ledger",true,true));}
   worker=vec!["protocol".into(),args[3].clone(),"/control/request.json".into()];
  }else{
   let(_,entry)=host_file(&project,&args[3])?;let requested=std::path::absolute(flags.need("-o")?)?;let parent=fs::canonicalize(requested.parent().ok_or("output parent required")?)?;grant_safe(&root,&parent,true)?;let name=requested.file_name().ok_or("output name required")?.to_str().ok_or("Unicode output name required")?;session::guest_name(&format!("/out/{name}"))?;
   grants.push(mapped(parent.clone(),"/out",true,true));worker=vec!["native-build".into(),entry,"--project-root".into(),"/project".into(),"--toolchain".into(),"/control/toolchain.json".into(),"-o".into(),format!("/out/{name}")];
   if let Some(path)=flags.values.get("--object-output"){let object=std::path::absolute(path)?;if fs::canonicalize(object.parent().ok_or("object parent required")?)?!=parent||object.file_name()==requested.file_name(){return Err("object output must be distinct in the same authorized output directory".into());}let object_name=object.file_name().ok_or("object name required")?.to_str().ok_or("Unicode object name required")?;session::guest_name(&format!("/out/{object_name}"))?;worker.extend(["--object-output".into(),format!("/out/{object_name}")]);}
   for flag in ["--capabilities","--intent","--bindings"]{if let Some(path)=flags.values.get(flag){let(_,guest)=host_file(&project,path)?;worker.extend([flag.into(),guest]);}}
  }
  let output=windows_artifact::run_compiler_mapped(&compiler_bytes,&compiler_hash,&system,&worker,limits,limits,&grants,&[],"/project",Some(linker))?;
  if output.failure.is_some()||output.exit!=Some(0)&&!(command=="protocol"&&matches!(output.exit,Some(1|2))&&output.stderr.is_empty()){eprintln!("native worker usage: {}",serde_json::to_string(&output.usage)?);}
  if let Some(error)=output.failure{return Err(error.into());}
  if command=="native-build"&&output.exit==Some(0){let mut report:serde_json::Value=serde_json::from_slice(&output.stdout)?;report.as_object_mut().ok_or("compiler report object required")?.insert("workerUsage".into(),serde_json::to_value(&output.usage)?);report.as_object_mut().unwrap().insert("resourceContract".into(),serde_json::to_value(&contract)?);report.as_object_mut().unwrap().insert("hostSystemInputs".into(),system_observation);serde_json::to_writer(io::stdout(),&report)?;writeln!(io::stdout())?;}else{io::stdout().write_all(&output.stdout)?;}
  io::stderr().write_all(&output.stderr)?;Ok(output.exit.ok_or("compiler exit missing")?)
 }
}
#[cfg(target_os="windows")]
fn main(){match platform::dispatch(){Ok(code)=>std::process::exit(code as i32),Err(error)=>{eprintln!("error[K0600]: {error}");std::process::exit(125);}}}
#[cfg(not(target_os="windows"))]
fn main(){eprintln!("native Windows host required");std::process::exit(125);}
