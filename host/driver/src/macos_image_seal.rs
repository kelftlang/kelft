//! Maintainer format check. No Mach-O code is loaded or executed on this host.
use std::{fs,io::{Read,Write},path::Path};
use kelft_wasi::{macos_linked_image,native_target::Target};
fn run()->Result<(),Box<dyn std::error::Error>>{
 let args:Vec<_>=std::env::args_os().skip(1).collect();if args.len()!=2{return Err("usage: kelft-macos-image-seal INPUT OUTPUT".into());}
 let input=Path::new(&args[0]);let metadata=fs::symlink_metadata(input)?;if !metadata.is_file()||metadata.len()>64<<20{return Err("bounded regular image required".into());}
 let mut bytes=vec![];fs::File::open(input)?.take((64<<20)+1).read_to_end(&mut bytes)?;
 let target=match bytes.get(4..8){Some([7,0,0,1])=>Target::MacosX64,Some([12,0,0,1])=>Target::MacosArm64,_=>return Err("native macOS image required".into())};
 macos_linked_image::seal_stack(&mut bytes,target)?;let mut output=fs::OpenOptions::new().write(true).create_new(true).open(&args[1])?;output.write_all(&bytes)?;output.sync_all()?;Ok(())
}
fn main(){if let Err(error)=run(){eprintln!("{error}");std::process::exit(1);}}
