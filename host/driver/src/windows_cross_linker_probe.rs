//! Development probe for the isolated cross linker, without rebuilding a
//! compiler package. This binary is never part of an installed distribution.
#[cfg(target_os="windows")]
fn main()->Result<(),Box<dyn std::error::Error>>{
 use std::{fs,io::Read,path::Path};use sha2::{Digest,Sha256};
 let args:Vec<String>=std::env::args().skip(1).collect();
 if args.len()!=3{return Err("expected PACKAGE_ROOT OBJECT OUTPUT".into());}
 let root=fs::canonicalize(&args[0])?;
 let mut encoded=vec![];fs::File::open(root.join("rootfs/control/cross-linux-x86_64.json"))?.take((1<<20)+1).read_to_end(&mut encoded)?;
 let expected=format!("sha256:{:x}",Sha256::digest(&encoded));
 let mut windows=[0u16;32768];let size=unsafe{windows_sys::Win32::System::SystemInformation::GetSystemWindowsDirectoryW(windows.as_mut_ptr(),windows.len() as u32)} as usize;
 if size==0||size>=windows.len(){return Err("Windows directory unavailable".into());}let system=String::from_utf16(&windows[..size])?;
 let linker=kelft_wasi::windows_cross_linker::CrossLinker::from_package(&encoded,&expected,&root,Path::new(&system))?;
 let mut object=vec![];fs::File::open(&args[1])?.take((64<<20)+1).read_to_end(&mut object)?;
 kelft_wasi::cross_elf::validate_object(&object)?;
 let output=std::path::absolute(&args[2])?;
 let report=linker.build(&output,&system,|private|fs::write(private.join("target.o"),&object))?;
 println!("{report}");Ok(())
}
#[cfg(not(target_os="windows"))]
fn main(){eprintln!("Windows native host required");std::process::exit(125);}
