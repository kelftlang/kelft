//! Private native execution adapter. Public targets remain certification-gated.
#[cfg(target_os="macos")]
fn run()->Result<(),Box<dyn std::error::Error>>{
 use kelft_wasi::{macos_snapshot::Image,macos_supervisor::{self,Host,Limits},macos_seatbelt::Role,macos_filesystem_session::{self as filesystem,Grant}};
 use std::{fs,io::Read,path::Path};use sha2::{Digest,Sha256};
 let args=std::env::args().skip(1).collect::<Vec<_>>();if macos_supervisor::helper(&args)?.is_some(){return Ok(());}
 let linker_control=args.first().is_some_and(|value|value=="--linker-control");let services=args.first().is_some_and(|value|value=="--compiler-services");let compiler=services||args.first().is_some_and(|value|value=="--compiler");let guest=args.first().is_some_and(|value|value=="--guest");let mapped=compiler||guest;
 let separator=if linker_control{8}else if services{7}else if mapped{5}else{4};
 if args.len()<=separator||!matches!(args[0].as_str(),"--run"|"--guest"|"--compiler"|"--compiler-services"|"--linker-control")||args[separator]!="--"{return Err("expected --run IMAGE SHA256 WALL_MS -- ARGS, --compiler|--guest IMAGE SHA256 WALL_MS PROJECT|- -- ARGS, or --compiler-services IMAGE SHA256 WALL_MS PROJECT OUT LINKER_CONFIG -- ARGS".into());}
 let read=|path:&Path|->Result<Vec<u8>,Box<dyn std::error::Error>>{let mut file=fs::File::open(path)?;if !file.metadata()?.is_file()||file.metadata()?.len()>64<<20{return Err("bounded native image required".into());}let mut bytes=vec![];Read::by_ref(&mut file).take((64<<20)+1).read_to_end(&mut bytes)?;Ok(bytes)};
 let base=fs::canonicalize(std::env::temp_dir())?;let helper=read(&std::env::current_exe()?)?;let helper_hash=format!("sha256:{:x}",Sha256::digest(&helper));let host=Host::new(&helper,&helper_hash,&base)?;
 let image=Image::new(&read(Path::new(&args[1]))?,&args[2],&base)?;
 let limits=Limits{wall_ms:args[3].parse()?,output_bytes:65536};let arguments=&args[separator+1..];
 let mut grants=vec![];if mapped&&args[4]!="-"{let project=fs::canonicalize(&args[4])?;if !project.is_dir(){return Err("project directory required".into());}grants.push(Grant{guest:"/project".into(),path:project,read:true,write:false});}
 let linker=if services{let out=fs::canonicalize(&args[5])?;if !out.is_dir(){return Err("output directory required".into());}grants.push(Grant{guest:"/out".into(),path:out,read:true,write:true});Some(kelft_wasi::macos_linker::Linker::from_file(Path::new(&args[6]))?)}else{None};
 let output=if linker_control{let paths=macos_supervisor::LinkerPaths{sdk:fs::canonicalize(&args[4])?,tools:fs::canonicalize(&args[5])?,object:fs::canonicalize(&args[6])?,output:fs::canonicalize(&args[7])?};host.run(&image,Role::Linker,arguments,&[],&[],Some(paths),limits,None)?}else if compiler{kelft_wasi::macos_artifact::run_compiler_with_linker(&host,&image,&base,arguments,limits,Limits{wall_ms:5000,output_bytes:65536},&grants,&[],"/project",&[],linker.as_ref())?}
  else if guest{filesystem::run(&host,&image,Role::Candidate,arguments,limits,&grants,"/project",&[],&[],None,&[],std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)))?}
  else{host.run(&image,Role::Candidate,arguments,&[],&[],None,limits,None)?};
 let hex=|bytes:&[u8]|bytes.iter().map(|b|format!("{b:02x}")).collect::<String>();
 println!("{}",serde_json::json!({"schema":"kelft-macos-native-execution-development/1","state":"observed","imageSHA256":image.sha256(),"helperSHA256":helper_hash,"role":if compiler{"compiler"}else if linker_control{"linker"}else{"candidate"},"exit":output.exit,"stdoutHex":hex(&output.stdout),"stderrHex":hex(&output.stderr),"failure":output.failure,"elapsedMs":output.elapsed_ms,"usage":output.usage,"authenticatedSnapshotVerified":true,"filesystemBrokerIntegrated":mapped,"artifactServiceIntegrated":compiler,"programFilesystemGrants":0,"linkerServiceIntegrated":services,"certified":false,"releaseEligible":false}));Ok(())
}
#[cfg(target_os="macos")]
fn main(){if let Err(error)=run(){eprintln!("error[K0600]: {error}");std::process::exit(125);}}
#[cfg(not(target_os="macos"))]
fn main(){eprintln!("native macOS host required");std::process::exit(125);}
