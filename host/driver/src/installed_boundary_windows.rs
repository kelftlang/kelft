//! Windows supervisor handoff. Retained non-delete-sharing ancestor handles and
//! read-only image handles close package path/content substitution races.
use std::{fs,io::Read,os::windows::fs::{OpenOptionsExt,MetadataExt},process::Command};
use kelft_wasi::windows_filesystem::Broker;
type Error=Box<dyn std::error::Error>;
pub(crate) struct BoundaryCommand {pub command:Command,_images:Vec<fs::File>,_roots:Broker,_lifeline:fs::File}
impl BoundaryCommand{pub fn run(&mut self,limits:&crate::protocol::Limits)->Result<crate::native::Output,Error>{crate::native::run_with_stdin(&mut self.command,limits)}}
pub(crate) fn boundary_command()->Result<BoundaryCommand,Error>{
 let(boundary,compiler)=crate::installed_paths()?;
 let root=boundary.parent().and_then(std::path::Path::parent).ok_or("installed root missing")?;
 let mut roots=Broker::default();roots.add_root(root,true,false)?;
 let mut images=vec![];
 let compiler_hash=crate::compiler_sha256()?;
 for (path,expected) in [(&boundary,crate::BOUNDARY_SHA256),(&compiler,compiler_hash.as_str())]{
  let mut file=fs::OpenOptions::new().read(true).share_mode(1).custom_flags(0x00200000).open(path)?;
  let metadata=file.metadata()?;if !metadata.is_file()||metadata.file_attributes()&0x400!=0||metadata.len()>67_108_864{return Err("invalid installed image".into());}
  let mut bytes=vec![];Read::by_ref(&mut file).take(67_108_865).read_to_end(&mut bytes)?;
  if crate::protocol::hash(&bytes)!=expected{return Err("installed image changed".into());}
  crate::native_target::Target::current()?.validate_executable(&bytes)?;images.push(file);
 }
 let(input,lifeline)=kelft_wasi::windows_lifeline::pair()?;
 let mut coordinator=fs::OpenOptions::new().read(true).share_mode(1).custom_flags(0x00200000).open(std::env::current_exe()?)?;
 let metadata=coordinator.metadata()?;if !metadata.is_file()||metadata.file_attributes()&0x400!=0||metadata.len()>67_108_864{return Err("invalid installed coordinator".into());}
 let mut bytes=vec![];Read::by_ref(&mut coordinator).take(67_108_865).read_to_end(&mut bytes)?;let coordinator_hash=crate::protocol::hash(&bytes);images.push(coordinator);
 let mut command=Command::new(&boundary);command.arg("--installed-root").arg(root).arg("--coordinator-sha256").arg(coordinator_hash).arg("--coordinator-lifeline").stdin(std::process::Stdio::from(input));
 Ok(BoundaryCommand{command,_images:images,_roots:roots,_lifeline:lifeline})
}
