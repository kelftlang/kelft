//! Data-only OS probe for Kelft-authored host assertions. No test verdicts.
use std::io::{Read,Write};
#[cfg(not(target_os="macos"))]
fn working_directory()->std::io::Result<String>{
 std::env::current_dir()?.into_os_string().into_string().map_err(|_|std::io::Error::new(std::io::ErrorKind::InvalidData,"working directory is not UTF-8"))
}
#[cfg(target_os="macos")]
fn working_directory()->std::io::Result<String>{
 // Observe the directory through metadata; getcwd opens it for reading.
 let invalid=||std::io::Error::new(std::io::ErrorKind::InvalidData,"invalid working-directory metadata");
 let mut attributes:libc::attrlist=unsafe{std::mem::zeroed()};attributes.bitmapcount=libc::ATTR_BIT_MAP_COUNT as u16;attributes.commonattr=libc::ATTR_CMN_FULLPATH;
 let mut bytes=[0u8;4096];
 if unsafe{libc::getattrlist(c".".as_ptr(),(&mut attributes as *mut libc::attrlist).cast(),bytes.as_mut_ptr().cast(),bytes.len(),0)}!=0{return Err(std::io::Error::last_os_error());}
 let total=u32::from_ne_bytes(bytes[..4].try_into().unwrap()) as usize;
 let offset=i32::from_ne_bytes(bytes[4..8].try_into().unwrap());let length=u32::from_ne_bytes(bytes[8..12].try_into().unwrap()) as usize;
 let start=4usize.checked_add_signed(offset as isize).ok_or_else(invalid)?;let end=start.checked_add(length).ok_or_else(invalid)?;
 if total>bytes.len()||start<12||end>total{return Err(invalid());}
 let value=std::ffi::CStr::from_bytes_with_nul(&bytes[start..end]).map_err(|_|invalid())?;
 Ok(value.to_str().map_err(|_|invalid())?.to_owned())
}
fn main(){
 let arguments=std::env::args().skip(1).collect::<Vec<_>>();let mode=arguments.first().map(String::as_str).unwrap_or("");
 match mode{
  "arguments"=>println!("{}",serde_json::json!({"cwd":working_directory().unwrap().replace('\\',"/"),"args":&arguments[1..],"mode":std::env::var("MODE").ok(),"ambient":std::env::var("KELFT_TEST_SECRET").ok()})),
  "duplex"=>{std::io::stdout().write_all(&[42;65536]).unwrap();std::io::stdout().flush().unwrap();let mut input=vec![];std::io::stdin().take(65537).read_to_end(&mut input).unwrap();std::io::stdout().write_all(&input).unwrap();},
  "binary"=>{let mut input=vec![];std::io::stdin().take(65537).read_to_end(&mut input).unwrap();std::io::stdout().write_all(&input).unwrap();std::io::stderr().write_all(&[255,0,128]).unwrap();std::process::exit(7);},
  "wait"=>{println!("started");std::io::stdout().flush().unwrap();loop{std::thread::sleep(std::time::Duration::from_millis(20));}},
  "identity"=>{println!("snapshot-started");std::io::stdout().flush().unwrap();std::thread::sleep(std::time::Duration::from_secs(2));println!("snapshot-original");},
  "memory"=>{println!("started");std::io::stdout().flush().unwrap();
   #[cfg(unix)]loop{let address=unsafe{libc::mmap(std::ptr::null_mut(),256<<20,libc::PROT_NONE,libc::MAP_PRIVATE|libc::MAP_ANON,-1,0)};if address==libc::MAP_FAILED{eprintln!("memory allocation reservation failed");std::process::abort();}}
   #[cfg(not(unix))]{let mut held=Vec::new();loop{held.push(vec![42u8;8<<20]);std::hint::black_box(&held);}}
  },
  "flood"=>{let mut output=std::io::stdout();let bytes=[b'x';4096];loop{if output.write_all(&bytes).is_err(){break;}}},
  "spawn"=>{let child=std::process::Command::new(std::env::current_exe().unwrap()).arg("wait").spawn();println!("{}",serde_json::json!({"spawned":child.is_ok()}));if let Ok(mut child)=child{let _=child.kill();let _=child.wait();}},
  _=>std::process::exit(64)
 }
}
