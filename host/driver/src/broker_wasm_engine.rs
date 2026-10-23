//! Separate Wasmtime runtime. Installed coordinators never link this engine.
use kelft_wasi::broker_wasi::{self,Client,Root};use std::{fs,io::{self,Read},process};use sha2::{Digest,Sha256};
fn run()->Result<i32,Box<dyn std::error::Error>>{
 let args=std::env::args().skip(1).collect::<Vec<_>>();if args==["--version"]{println!("kelft-wasmtime 49.0.3; broker-wasi 1");return Ok(0);}if args.len()<3||args[2]!="--"{return Err("expected immutable module SHA256 -- ARGS".into());}
 if std::env::var("KELFT_ENGINE_PROFILE").as_deref()!=Ok("wasm-kfs/1"){return Err("explicit Wasm filesystem profile required".into());}
 let mut file=fs::File::open(&args[0])?;if !file.metadata()?.is_file()||file.metadata()?.len()>64<<20{return Err("bounded immutable module required".into());}let mut bytes=vec![];Read::by_ref(&mut file).take((64<<20)+1).read_to_end(&mut bytes)?;if format!("sha256:{:x}",Sha256::digest(&bytes))!=args[1]{return Err("Wasm module changed".into());}
 let roots:Vec<Root>=serde_json::from_str(&std::env::var("KELFT_FS_ROOTS")?)?;
 #[cfg(unix)]let client=if std::env::var("KELFT_FS_REQUEST").as_deref()==Ok("3")&&std::env::var("KELFT_FS_RESPONSE").as_deref()==Ok("3"){use std::os::fd::FromRawFd;let socket=unsafe{std::os::unix::net::UnixStream::from_raw_fd(3)};Client::new(socket.try_clone()?,socket)}else{Client::new(io::stdin(),io::stderr())};
 #[cfg(not(unix))]let client=Client::new(io::stdin(),io::stderr());
 let mut diagnostic=client.clone();match broker_wasi::execute(&bytes,&args[3..],roots,client){Ok(exit)=>Ok(exit),Err(error)=>{let text=format!("error[K0600]: {error:#}\n");diagnostic.stderr(&text.as_bytes()[..text.len().min(65536)])?;Ok(125)}}
}
fn main(){match run(){Ok(code)=>process::exit(code),Err(error)=>{eprintln!("error[K0600]: {error}");process::exit(125);}}}
