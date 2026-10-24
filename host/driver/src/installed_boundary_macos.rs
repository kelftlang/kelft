//! Authenticate the installed boundary before launching its dedicated service.
use std::{fs,io::Read,os::unix::fs::OpenOptionsExt,process::Command};
use kelft_wasi::{macos_snapshot::Image,unix_filesystem::Broker};
type Error=Box<dyn std::error::Error>;
pub(crate) struct BoundaryCommand{pub command:Command,_image:Image,_root:Broker}
impl BoundaryCommand{pub fn run(&mut self,limits:&crate::protocol::Limits)->Result<crate::native::Output,Error>{crate::native::run(&mut self.command,limits)}}
pub(crate) fn boundary_command()->Result<BoundaryCommand,Error>{
 let(boundary,_)=crate::installed_paths()?;let root=boundary.parent().and_then(std::path::Path::parent).ok_or("installed root missing")?;let mut retained=Broker::default();retained.add_root(root,true,false)?;
 let mut file=fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW|libc::O_CLOEXEC|libc::O_NONBLOCK).open(&boundary)?;if !file.metadata()?.is_file()||file.metadata()?.len()>64<<20{return Err("invalid installed boundary image".into());}let mut bytes=vec![];Read::by_ref(&mut file).take((64<<20)+1).read_to_end(&mut bytes)?;
 let image=Image::new(&bytes,crate::BOUNDARY_SHA256,&fs::canonicalize(crate::native::private_temp_dir()?)?)?;let mut command=Command::new(image.path());command.arg("--installed-root").arg(root).arg("--snapshot-boundary");Ok(BoundaryCommand{command,_image:image,_root:retained})
}
