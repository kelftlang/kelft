//! Optional runtime startup diagnostics; no installed engine is enabled here.
#[cfg(target_os="windows")]
fn run()->Result<(),Box<dyn std::error::Error>>{
 use kelft_wasi::{windows_process::AppContainerSid,windows_snapshot::Image,windows_supervisor::{self,Limits},native_target::Target};
 use std::{fs,io::Read};use sha2::{Digest,Sha256};
 let args=std::env::args().skip(1).collect::<Vec<_>>();let wasm=args.len()==5&&args[0]=="--wasm-broker";let broker_mode=wasm||args.len()==6&&args[0]=="--broker";if !broker_mode&&(args.len()!=3||args[0]!="--node"){return Err("expected --node IMAGE SHA256, --broker IMAGE SHA256 WRAPPER PROGRAM PROJECT, or --wasm-broker IMAGE SHA256 PROGRAM PROJECT".into());}
 let mut file=fs::File::open(&args[1])?;if !file.metadata()?.is_file()||file.metadata()?.len()>256<<20{return Err("bounded native engine input required".into());}let mut bytes=vec![];Read::by_ref(&mut file).take((256<<20)+1).read_to_end(&mut bytes)?;let expected=format!("sha256:{:x}",Sha256::digest(&bytes));if expected!=args[2]{return Err("native engine input hash differs".into());}
 let system=std::env::var("SystemRoot")?;let mut observations=vec![];
 if broker_mode{
  let project=fs::canonicalize(&args[if wasm{4}else{5}])?;let program=fs::read(&args[if wasm{3}else{4}])?;
  let grants=vec![kelft_wasi::windows_filesystem_session::MappedGrant{guest:"/project/data".into(),grant:kelft_wasi::windows_filesystem_session::Grant{path:project.join("data"),read:true,write:false}},kelft_wasi::windows_filesystem_session::MappedGrant{guest:"/project/writable".into(),grant:kelft_wasi::windows_filesystem_session::Grant{path:project.join("writable"),read:false,write:true}}];
  let arguments=["h\u{e9} \u{1f600}","quoted\" tail\\",""] .map(String::from);
  let limits=Limits{wall_ms:15000,memory_bytes:1<<30,output_bytes:65536};let result=if wasm{kelft_wasi::windows_engine::wasm(&bytes,&expected,&program,&arguments,&grants,&system,limits)?}else{let adapter=fs::read(&args[3])?;let hash=format!("sha256:{:x}",Sha256::digest(&adapter));kelft_wasi::windows_engine::javascript(&bytes,&expected,&adapter,&hash,&program,&arguments,&grants,&system,limits)?};
  println!("{}",serde_json::json!({"schema":"kelft-native-engine-broker-development/1","profile":Target::current()?.id(),"imageSHA256":expected,"exit":result.exit,"stdout":String::from_utf8_lossy(&result.stdout),"stderr":String::from_utf8_lossy(&result.stderr),"failure":result.failure,"usage":result.usage,"registryRead":true,"filesystemBrokerIntegrated":true,"compilerOrProgramImageCapChanged":false,"installedEngineProfileVerified":false,"certified":false,"releaseEligible":false}));return Ok(());
 }
 for registry_read in [false,true]{let identity=if registry_read{AppContainerSid::fresh_engine()?}else{AppContainerSid::fresh()?};let image=Image::runtime(&bytes,&expected,&identity)?;
 for arguments in [vec!["--version".to_owned()],vec!["--jitless".into(),"--max-old-space-size=256".into(),"--eval".into(),"process.stdout.write('native-engine-started\\n')".into()]]{
  let result=windows_supervisor::run(&image,&identity,&system,&arguments,Limits{wall_ms:15000,memory_bytes:1<<30,output_bytes:65536},&[],vec![])?;
  observations.push(serde_json::json!({"registryRead":registry_read,"args":arguments,"exit":result.exit,"stdout":String::from_utf8_lossy(&result.stdout),"stderr":String::from_utf8_lossy(&result.stderr),"failure":result.failure,"usage":result.usage}));
 }
 }
 println!("{}",serde_json::json!({"schema":"kelft-native-engine-startup-development/1","profile":Target::current()?.id(),"imageSHA256":expected,"observations":observations,"compilerOrProgramImageCapChanged":false,"filesystemBrokerIntegrated":false,"installedEngineProfileVerified":false,"certified":false,"releaseEligible":false}));Ok(())
}
#[cfg(target_os="windows")]
fn main(){if let Err(error)=run(){eprintln!("error[K0600]: {error}");std::process::exit(125);}}
#[cfg(not(target_os="windows"))]
fn main(){eprintln!("native Windows host required");std::process::exit(125);}
