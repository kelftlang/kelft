//! Authenticated process-lifetime handoff. Kernel sender credentials bind the
//! peer; a stable process identity survives exec and generation-checked signals
//! never target a recycled PID. Only trusted owners receive lifetime tokens.
use mach2::{bootstrap,kern_return::KERN_SUCCESS,mach_port,message::*,port::*,traps::mach_task_self};
use std::{cell::Cell,ffi::CString,io,mem,os::fd::{AsRawFd,FromRawFd,OwnedFd},time::{Duration,Instant}};
const MESSAGE_ID:i32=0x4b545332;
const HANDOFF_BYTES:u32=40;
const TIMEOUT_MS:u32=5000;
#[repr(C)]#[derive(Default)]struct Handoff{header:mach_msg_header_t,pid:u32,generation:u32,unique:u64,trailer:mach_msg_audit_trailer_t}
#[repr(C)]#[derive(Default)]struct Identity{uuid:[u8;16],unique:u64,parent:u64,generation:i32,original_parent_generation:i32,reserved:[u64;2]}
#[link(name="proc")]unsafe extern "C"{
 fn proc_pidinfo(pid:i32,flavor:i32,arg:u64,buffer:*mut libc::c_void,size:i32)->i32;
 fn proc_signal_with_audittoken(token:*const u32,signal:i32)->i32;
}
fn identity(pid:u32)->io::Result<Identity>{
 if pid==0||pid>i32::MAX as u32{return Err(invalid("valid process identity required"));}let mut value=Identity::default();
 let size=mem::size_of::<Identity>() as i32;let count=unsafe{proc_pidinfo(pid as i32,17,0,(&mut value as *mut Identity).cast(),size)};
 if count!=size{return Err(io::Error::last_os_error());}if value.unique==0{return Err(invalid("kernel process identity missing"));}Ok(value)
}
fn check(code:i32,operation:&str)->io::Result<()>{if code==KERN_SUCCESS{Ok(())}else{Err(io::Error::other(format!("{operation}: Mach status {code:#x}")))}}
fn invalid(message:&str)->io::Error{io::Error::new(io::ErrorKind::InvalidData,message)}
fn service_name(name:&str)->io::Result<CString>{
 if !name.starts_with("kelft-life-")||name.len()!=75||!name[11..].bytes().all(|b|b.is_ascii_hexdigit()){return Err(invalid("private lifetime endpoint required"));}
 CString::new(name).map_err(|_|invalid("invalid lifetime endpoint"))
}
/// An unguessable endpoint does not itself confer authority. Every receipt
/// requires a kernel-authenticated peer and an independently expected worker.
pub struct Endpoint{port:mach_port_t,name:CString,registered:bool}
impl Endpoint{
 pub fn new()->io::Result<Self>{
  let mut entropy=[0;32];getrandom::fill(&mut entropy).map_err(|error|io::Error::other(error.to_string()))?;
  let name=service_name(&format!("kelft-life-{}",entropy.iter().map(|b|format!("{b:02x}")).collect::<String>()))?;let mut port=MACH_PORT_NULL;
  unsafe{check(mach_port::mach_port_allocate(mach_task_self(),MACH_PORT_RIGHT_RECEIVE,&mut port),"allocate lifetime endpoint")?;}
  let mut endpoint=Self{port,name,registered:false};unsafe{
   check(mach_port::mach_port_insert_right(mach_task_self(),port,port,MACH_MSG_TYPE_MAKE_SEND),"make lifetime endpoint send right")?;
   check(bootstrap::bootstrap_register(bootstrap::bootstrap_port,endpoint.name.as_ptr().cast_mut(),port),"register lifetime endpoint")?;
  }endpoint.registered=true;Ok(endpoint)
 }
 pub fn name(&self)->&str{self.name.to_str().expect("ASCII lifetime endpoint")}
 pub fn receive(&self,sender_pid:u32,task_pid:u32)->io::Result<Task>{
  if sender_pid==0||task_pid==0||task_pid==std::process::id(){return Err(invalid("independent process identities required"));}
  let mut message=Handoff::default();let options=MACH_RCV_MSG|MACH_RCV_TIMEOUT|(MACH_RCV_TRAILER_AUDIT<<24) as i32;
  unsafe{check(mach_msg(&mut message.header,options,0,mem::size_of::<Handoff>() as u32,self.port,TIMEOUT_MS,MACH_PORT_NULL),"receive lifetime handoff")?;}
  let valid=message.header.msgh_id==MESSAGE_ID&&message.header.msgh_size==HANDOFF_BYTES
   &&message.header.msgh_bits&MACH_MSGH_BITS_COMPLEX==0&&message.header.msgh_remote_port==MACH_PORT_NULL&&message.header.msgh_voucher_port==MACH_PORT_NULL
   &&message.trailer.msgh_trailer_type==MACH_MSG_TRAILER_FORMAT_0&&message.trailer.msgh_trailer_size>=mem::size_of::<mach_msg_audit_trailer_t>() as u32
   &&message.trailer.msgh_audit.val[5]==sender_pid&&message.pid==task_pid&&message.unique!=0;
  if !valid{unsafe{mach_msg_destroy(&mut message.header);}return Err(invalid("lifetime handoff or kernel sender identity differs"));}
  if identity(task_pid)?.unique!=message.unique{return Err(invalid("handed-off process lifetime differs"));}
  let exit=ProcessExit::new(task_pid)?;
  // Register while the sender owns its child, then recheck the kernel identity
  // so an exit/reuse race cannot associate this filter with another process.
  if identity(task_pid)?.unique!=message.unique{return Err(invalid("process lifetime changed during observation setup"));}
  Ok(Task{pid:task_pid,unique:message.unique,exit})
 }
}
impl Drop for Endpoint{fn drop(&mut self){unsafe{if self.registered{bootstrap::bootstrap_register(bootstrap::bootstrap_port,self.name.as_ptr().cast_mut(),MACH_PORT_NULL);}mach_port::mach_port_destroy(mach_task_self(),self.port);}}}
struct ProcessExit { queue: OwnedFd, pid: u32, observed: Cell<bool> }
impl ProcessExit {
    fn new(pid: u32) -> io::Result<Self> {
        let fd = unsafe { libc::kqueue() };
        if fd < 0 { return Err(io::Error::last_os_error()); }
        let queue = unsafe { OwnedFd::from_raw_fd(fd) };
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 { return Err(io::Error::last_os_error()); }
        let event = libc::kevent { ident: pid as usize, filter: libc::EVFILT_PROC,
            flags: libc::EV_ADD | libc::EV_ENABLE | libc::EV_ONESHOT,
            fflags: libc::NOTE_EXIT, data: 0, udata: std::ptr::null_mut() };
        if unsafe { libc::kevent(fd, &event, 1, std::ptr::null_mut(), 0, std::ptr::null()) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { queue, pid, observed: Cell::new(false) })
    }
    fn exited(&self) -> io::Result<bool> {
        if self.observed.get() { return Ok(true); }
        let mut event = unsafe { mem::zeroed::<libc::kevent>() };
        let timeout = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        let count = unsafe { libc::kevent(self.queue.as_raw_fd(), std::ptr::null(), 0, &mut event, 1, &timeout) };
        if count < 0 { return Err(io::Error::last_os_error()); }
        if count == 0 { return Ok(false); }
        if event.ident != self.pid as usize || event.filter != libc::EVFILT_PROC
            || event.flags & libc::EV_ERROR != 0 || event.fflags & libc::NOTE_EXIT == 0 {
            return Err(invalid("kernel worker exit observation differs"));
        }
        self.observed.set(true);
        Ok(true)
    }
}

/// A token is accepted only after sender and lifetime authentication. No raw
/// PID termination fallback exists for a process that this owner did not spawn.
pub struct Task{pid:u32,unique:u64,exit:ProcessExit}
impl Task{
 pub fn export(&self,endpoint:&str)->io::Result<()>{let current=identity(self.pid)?;if current.unique!=self.unique{return Err(invalid("process lifetime changed before relay"));}send(endpoint,self.pid,&current)}
 pub fn current_generation(&self)->io::Result<u32>{let current=identity(self.pid)?;if current.unique!=self.unique{return Err(invalid("process lifetime differs"));}Ok(current.generation as u32)}
 pub fn terminate(&self)->io::Result<()>{
  let start=Instant::now();loop{
   if self.dead()?{return Ok(());}let current=match identity(self.pid){Ok(value)=>value,Err(error)=>{if self.dead()?{return Ok(());}if error.raw_os_error()==Some(libc::ESRCH)&&start.elapsed()<Duration::from_secs(2){std::thread::yield_now();continue;}return Err(error);}};
   if current.unique!=self.unique{if self.dead()?{return Ok(());}return Err(invalid("refusing to signal a replaced process lifetime"));}
   let mut token=[0u32;8];token[5]=self.pid;token[7]=current.generation as u32;
   let result=unsafe{proc_signal_with_audittoken(token.as_ptr(),libc::SIGKILL)};
   if result==0{return Ok(());}if self.dead()?{return Ok(());}
   if result!=libc::ESRCH{return Err(io::Error::from_raw_os_error(result));}
   // Exec may advance the generation between lookup and signal delivery. Each
   // retry checks the same stable lifetime and the kernel checks that exact
   // new generation atomically. PID reuse never becomes a successful signal.
   if start.elapsed()>=Duration::from_secs(2){return Err(io::Error::new(io::ErrorKind::TimedOut,"process generation kept changing during termination"));}
   std::thread::yield_now();
  }
 }
 pub fn dead(&self)->io::Result<bool>{self.exit.exited()}
 pub fn wait_dead(&self,timeout:Duration)->io::Result<()>{let start=Instant::now();while !self.dead()?{if start.elapsed()>=timeout{return Err(io::Error::new(io::ErrorKind::TimedOut,"authenticated process survived its supervisor"));}std::thread::sleep(Duration::from_millis(5));}Ok(())}
}
impl Drop for Task{fn drop(&mut self){let _=self.terminate();}}
pub fn export_self(endpoint:&str)->io::Result<()>{let pid=std::process::id();send(endpoint,pid,&identity(pid)?)}
fn send(endpoint:&str,pid:u32,identity:&Identity)->io::Result<()>{
 let name=service_name(endpoint)?;let mut destination=MACH_PORT_NULL;
 unsafe{check(bootstrap::bootstrap_look_up(bootstrap::bootstrap_port,name.as_ptr(),&mut destination),"look up private lifetime endpoint")?;}
 let mut message=Handoff::default();message.header.msgh_bits=MACH_MSG_TYPE_COPY_SEND;message.header.msgh_size=HANDOFF_BYTES;message.header.msgh_remote_port=destination;message.header.msgh_id=MESSAGE_ID;
 message.pid=pid;message.generation=identity.generation as u32;message.unique=identity.unique;
 let result=unsafe{mach_msg(&mut message.header,MACH_SEND_MSG|MACH_SEND_TIMEOUT,HANDOFF_BYTES,0,MACH_PORT_NULL,TIMEOUT_MS,MACH_PORT_NULL)};
 unsafe{mach_port::mach_port_deallocate(mach_task_self(),destination);}check(result,"send private lifetime token")
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stale_generations_and_wrong_lifetimes_cannot_signal_a_live_child() {
        let mut descriptors=[-1;2];assert_eq!(unsafe{libc::pipe(descriptors.as_mut_ptr())},0);
        let input=unsafe{OwnedFd::from_raw_fd(descriptors[0])};let keepalive=unsafe{OwnedFd::from_raw_fd(descriptors[1])};
        let pid=unsafe{libc::fork()};assert!(pid>=0);
        if pid==0{unsafe{libc::close(keepalive.as_raw_fd());let mut byte=0u8;libc::read(input.as_raw_fd(),(&mut byte as *mut u8).cast(),1);libc::_exit(0);}}
        struct Child(i32);impl Drop for Child{fn drop(&mut self){if self.0>0{unsafe{libc::kill(self.0,libc::SIGKILL);libc::waitpid(self.0,std::ptr::null_mut(),0);}}}}
        let mut child=Child(pid);drop(input);let current=identity(pid as u32).unwrap();let exit=ProcessExit::new(pid as u32).unwrap();assert!(!exit.exited().unwrap());
        let mut stale=[0u32;8];stale[5]=pid as u32;stale[7]=(current.generation as u32).wrapping_add(1);
        assert_eq!(unsafe{proc_signal_with_audittoken(stale.as_ptr(),libc::SIGKILL)},libc::ESRCH);assert!(!exit.exited().unwrap());
        let wrong=Task{pid:pid as u32,unique:current.unique^u64::MAX,exit:ProcessExit::new(pid as u32).unwrap()};assert!(wrong.terminate().is_err());drop(wrong);assert!(!exit.exited().unwrap());
        let valid=Task{pid:pid as u32,unique:current.unique,exit};valid.terminate().unwrap();valid.wait_dead(Duration::from_secs(2)).unwrap();let mut status=0;assert_eq!(unsafe{libc::waitpid(pid,&mut status,0)},pid);child.0=0;assert!(libc::WIFSIGNALED(status));assert_eq!(libc::WTERMSIG(status),libc::SIGKILL);drop(keepalive);
    }
    #[test]
    fn process_exit_requires_a_kernel_event_after_a_live_positive() {
        use std::io::Write;
        let mut descriptors = [-1; 2];
        assert_eq!(unsafe { libc::pipe(descriptors.as_mut_ptr()) }, 0);
        let input = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
        let output = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            // This child touches no inherited Rust/runtime state after fork.
            unsafe {
                libc::close(output.as_raw_fd());
                let mut byte = 0u8;
                let read = libc::read(input.as_raw_fd(), (&mut byte as *mut u8).cast(), 1);
                libc::_exit(if read == 1 {0} else {125});
            }
        }
        struct Child(i32);
        impl Drop for Child {
            fn drop(&mut self) {
                if self.0 > 0 { unsafe { libc::kill(self.0, libc::SIGKILL); libc::waitpid(self.0, std::ptr::null_mut(), 0); } }
            }
        }
        let mut child = Child(pid);
        drop(input);
        let exit = ProcessExit::new(pid as u32).unwrap();
        assert!(!exit.exited().unwrap());
        std::fs::File::from(output).write_all(&[1]).unwrap();
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        child.0 = 0;
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
        assert!(exit.exited().unwrap());
        assert!(exit.exited().unwrap());
    }
    #[test]
    fn handoff_layout_and_endpoint_names_are_bounded() {
        assert_eq!(mem::size_of::<mach_msg_header_t>(), 24);
        assert_eq!(mem::offset_of!(Handoff, trailer), HANDOFF_BYTES as usize);
        assert_eq!(mem::size_of::<Handoff>(), 96);
        assert_eq!(mem::size_of::<Identity>(),56);
        assert_eq!(mem::offset_of!(Identity,unique),16);
        assert_eq!(mem::offset_of!(Identity,generation),32);
        assert_eq!(mem::size_of::<libc::kevent>(), 32);
        assert_eq!(mem::offset_of!(libc::kevent, fflags), 12);
        assert_eq!(mem::offset_of!(libc::kevent, data), 16);
        assert!(service_name(&format!("kelft-life-{}", "a".repeat(64))).is_ok());
        for bad in ["", "other", &format!("kelft-life-{}", "x".repeat(64))] { assert!(service_name(bad).is_err()); }
    }
}
