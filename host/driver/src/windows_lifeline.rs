//! A private coordinator-owned pipe ties a trusted service to its controller.
//! It carries no requests, credentials or candidate input.
use std::{fs::File,io::{self,Read},os::windows::io::{AsRawHandle,FromRawHandle},ptr};
use windows_sys::Win32::{Foundation::{DuplicateHandle,DUPLICATE_SAME_ACCESS,INVALID_HANDLE_VALUE},Storage::FileSystem::{GetFileType,FILE_TYPE_PIPE},System::{Pipes::CreatePipe,Threading::{GetCurrentProcess,TerminateProcess}}};
pub fn pair()->io::Result<(File,File)>{
 let(mut read,mut write)=(ptr::null_mut(),ptr::null_mut());
 if unsafe{CreatePipe(&mut read,&mut write,ptr::null(),4096)}==0{return Err(io::Error::last_os_error());}
 Ok(unsafe{(File::from_raw_handle(read),File::from_raw_handle(write))})
}
pub fn watch_stdin()->io::Result<()>{
 let input=std::io::stdin().as_raw_handle();
 if input.is_null()||input==INVALID_HANDLE_VALUE||unsafe{GetFileType(input)}!=FILE_TYPE_PIPE{return Err(io::Error::other("private coordinator pipe required"));}
 let mut raw=ptr::null_mut();if unsafe{DuplicateHandle(GetCurrentProcess(),input,GetCurrentProcess(),&mut raw,0,0,DUPLICATE_SAME_ACCESS)}==0{return Err(io::Error::last_os_error());}
 let mut file=unsafe{File::from_raw_handle(raw)};
 std::thread::Builder::new().name("kelft-coordinator-lifetime".into()).spawn(move||{
  // EOF, an I/O failure or any unexpected byte closes this service and every
  // kill-on-close job it owns. No pipe end is delegated to a restricted worker.
  let mut byte=[0u8;1];loop{match file.read(&mut byte){Err(error)if error.kind()==io::ErrorKind::Interrupted=>continue,_=>break}}
  unsafe{TerminateProcess(GetCurrentProcess(),125);}
 })?;Ok(())
}
#[cfg(test)]mod tests{
 use super::*;use std::{io::{BufRead,BufReader,Write},process::{Command,Stdio},sync::mpsc,time::Duration};
 #[test]fn lifeline_worker(){if std::env::var("KELFT_LIFELINE_TEST").as_deref()!=Ok("1"){return;}watch_stdin().unwrap();println!("lifeline-ready");std::io::stdout().flush().unwrap();loop{std::thread::sleep(Duration::from_millis(10));}}
 #[test]fn coordinator_pipe_lifetime_and_unexpected_data_terminate_the_owned_process(){
  for unexpected in [false,true]{let(read,mut write)=pair().unwrap();let mut child=Command::new(std::env::current_exe().unwrap()).args(["--exact","windows_lifeline::tests::lifeline_worker","--nocapture"]).env("KELFT_LIFELINE_TEST","1").stdin(Stdio::from(read)).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().unwrap();
   let output=child.stdout.take().unwrap();let(tx,rx)=mpsc::channel();let reader=std::thread::spawn(move||{for line in BufReader::new(output).lines(){if line.is_ok_and(|s|s=="lifeline-ready"){let _=tx.send(());break;}}});
   let ready=rx.recv_timeout(Duration::from_secs(10));if ready.is_err(){let _=child.kill();let _=child.wait();}ready.unwrap();reader.join().unwrap();assert!(child.try_wait().unwrap().is_none());
   if unexpected{write.write_all(b"unexpected").unwrap();}else{drop(write);}
   let deadline=std::time::Instant::now()+Duration::from_secs(5);loop{if let Some(exit)=child.try_wait().unwrap(){assert_eq!(exit.code(),Some(125));break;}if std::time::Instant::now()>deadline{let _=child.kill();let _=child.wait();panic!("trusted service survived its coordinator lifeline");}std::thread::sleep(Duration::from_millis(5));}
  }
 }
}
