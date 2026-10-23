//! Native development controls for the trusted linker, independent of a Kelft
//! compiler image. This cannot satisfy the generated-compiler execution gate.
#[cfg(target_os="windows")]
fn main(){
 use kelft_wasi::{native_artifact_channel::Request,native_target::Target,windows_filesystem_session::Grant,windows_linker::Linker};
 use std::{fs,io::Read,path::PathBuf,sync::atomic::AtomicBool};
 if std::env::var("KELFT_LINKER_LOADER_PROBE").as_deref()==Ok("1"){
  use std::os::windows::ffi::OsStrExt;
  #[link(name="kernel32")]unsafe extern "system"{fn LoadLibraryExW(file:*const u16,reserved:*mut std::ffi::c_void,flags:u32)->*mut std::ffi::c_void;fn FreeLibrary(module:*mut std::ffi::c_void)->i32;fn CreateFileMappingW(file:*mut std::ffi::c_void,security:*const std::ffi::c_void,protect:u32,high:u32,low:u32,name:*const u16)->*mut std::ffi::c_void;fn CloseHandle(handle:*mut std::ffi::c_void)->i32;}
  #[link(name="ntdll")]unsafe extern "system"{fn RtlGetLastNtStatus()->i32;}
  #[repr(C)]struct ActCtx{size:u32,flags:u32,source:*const u16,architecture:u16,language:u16,directory:*const u16,resource:*const u16,application:*const u16,module:*mut std::ffi::c_void}
  #[link(name="kernel32")]unsafe extern "system"{fn CreateActCtxW(context:*const ActCtx)->*mut std::ffi::c_void;fn ReleaseActCtx(context:*mut std::ffi::c_void);}
  let mut failed=false;
  for path in std::env::args().skip(1){
   use std::os::windows::{fs::OpenOptionsExt,io::AsRawHandle};
   let readable=fs::read(&path).is_ok();let executable=fs::OpenOptions::new().access_mode(0x1200a9).share_mode(1).open(&path);
   let section=executable.as_ref().map_err(|e|e.to_string()).and_then(|file|{let handle=unsafe{CreateFileMappingW(file.as_raw_handle(),std::ptr::null(),0x01000002,0,0,std::ptr::null())};if handle.is_null(){Err(std::io::Error::last_os_error().to_string())}else{unsafe{CloseHandle(handle)};Ok(())}});
   let name:Vec<u16>=std::ffi::OsStr::new(&path).encode_wide().chain([0]).collect();
   let context=ActCtx{size:std::mem::size_of::<ActCtx>() as u32,flags:8,source:name.as_ptr(),architecture:0,language:0,directory:std::ptr::null(),resource:2usize as *const u16,application:std::ptr::null(),module:std::ptr::null_mut()};
   let activation=unsafe{CreateActCtxW(&context)};let activation_error=if activation as isize == -1{Some(std::io::Error::last_os_error().to_string())}else{unsafe{ReleaseActCtx(activation)};None};
   // Diagnostic mapping only: never call exports or retain this uninitialized
   // module across the real load, which must resolve imports and run startup.
   let unresolved=unsafe{LoadLibraryExW(name.as_ptr(),std::ptr::null_mut(),1)};
   let unresolved_error=if unresolved.is_null(){Some(std::io::Error::last_os_error().to_string())}else{unsafe{FreeLibrary(unresolved)};None};
   let module=unsafe{LoadLibraryExW(name.as_ptr(),std::ptr::null_mut(),0x1100)};let status=unsafe{RtlGetLastNtStatus()};let error=if module.is_null(){failed=true;Some(std::io::Error::last_os_error().to_string())}else{unsafe{FreeLibrary(module)};None};println!("{}",serde_json::json!({"path":path,"readable":readable,"executableOpen":executable.is_ok(),"imageSection":section.is_ok(),"imageSectionError":section.err(),"activationContext":activation as isize != -1,"activationContextError":activation_error,"unresolvedMapping":!unresolved.is_null(),"unresolvedMappingError":unresolved_error,"loaded":!module.is_null(),"ntStatus":if module.is_null(){Some(format!("0x{:08x}",status as u32))}else{None},"error":error}));
  }std::process::exit(if failed{1}else{0});
 }
 let result=(||->Result<(),Box<dyn std::error::Error>>{
  let args:Vec<_>=std::env::args().skip(1).collect();if args.len()==2&&matches!(args[1].as_str(),"--diagnose-loader"|"--diagnose-loader-no-registry"){let linker=Linker::from_file(std::path::Path::new(&args[0]))?;let result=linker.diagnose_dependencies(&fs::read(std::env::current_exe()?)?,&std::env::var("SystemRoot")?,args[1]=="--diagnose-loader")?;print!("{}",String::from_utf8_lossy(&result.stdout));eprint!("{}",String::from_utf8_lossy(&result.stderr));if let Some(failure)=result.failure{return Err(failure.into());}if result.exit!=Some(0){return Err("loader probe failed".into());}return Ok(());}if args.len()!=3{return Err("expected POLICY OBJECT OUTPUT-DIRECTORY".into());}
  let linker=Linker::from_file(std::path::Path::new(&args[0]))?;let mut object=vec![];fs::File::open(&args[1])?.take((64<<20)+1).read_to_end(&mut object)?;
  let directory=PathBuf::from(&args[2]);let destination=directory.join("probe.exe");let unauthorized=directory.parent().ok_or("probe output requires parent")?.join("unauthorized.exe");if unauthorized.exists(){return Err("unauthorized-output control path already exists".into());}let output=destination.to_str().ok_or("Unicode destination required")?;let system=std::env::var("SystemRoot")?;let cancel=AtomicBool::new(false);
  let authority=[Grant{path:directory.clone(),read:false,write:true}];let base=Request{target:format!("linker-{}-v1",Target::current()?.id()),args:vec![output.into(),linker.identity.clone()],read:vec![],write:vec![output.into()],image:object};
  let mut checks=vec![];let mut first=None;
  for mode in ["valid","repeat","object","directives","identity","authority","target"]{
   let mut request=Request{target:base.target.clone(),args:base.args.clone(),read:base.read.clone(),write:base.write.clone(),image:base.image.clone()};
   let expected=match mode{
    "object"=>{request.image.clear();-4},
    "directives"=>{if request.image.len()<28{return Err("COFF fixture too short".into());}request.image[20..28].copy_from_slice(b".drectve");-4},
    "identity"=>{request.args[1]="wrong".into();-2},
    "authority"=>{request.args[0]=unauthorized.to_str().ok_or("Unicode path required")?.into();request.write[0]=request.args[0].clone();-2},
    "target"=>{request.target="linker-other-v1".into();-1},_=>0};
   let response=linker.execute(&request,&system,&cancel,&authority,&[])?;
   if response.status!=expected||!response.stdout.is_empty()||!response.stderr.is_empty(){return Err(format!("{mode}: status {} expected {expected}; {}{}",response.status,String::from_utf8_lossy(&response.stdout),String::from_utf8_lossy(&response.stderr)).into());}
   if mode=="valid"{first=Some(fs::read(&destination)?);}if mode=="repeat"&&first.as_ref()!=Some(&fs::read(&destination)?){return Err("private linker snapshots produced different executable bytes".into());}
   if unauthorized.exists(){return Err("linker created an unauthorized output".into());}checks.push(serde_json::json!({"name":mode,"passed":true}));
  }
  println!("{}",serde_json::json!({"state":"passed","checks":checks,"nativeWindowsHostExecution":true,"nativeGeneratedKelftExecution":false,"productionClosureVerified":false,"releaseEligible":false}));Ok(())
 })();if let Err(error)=result{eprintln!("error[K0600]: {error}");std::process::exit(125);}
}
#[cfg(not(target_os="windows"))]
fn main(){eprintln!("native Windows execution required");std::process::exit(125);}
