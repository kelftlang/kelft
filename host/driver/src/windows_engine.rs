//! Explicit JavaScript execution uses a fresh LPAC identity and KFS1 only.
use crate::{windows_process::AppContainerSid,windows_snapshot::Image,windows_supervisor::{self,Limits,Output},windows_filesystem::Broker,windows_filesystem_session::{MappedGrant,guest_name}};
use sha2::{Digest,Sha256};use std::io;
fn authority(grants:&[MappedGrant],profile:&str)->io::Result<(Broker,Vec<(String,String)>)>{
 if grants.len()>128{return Err(io::Error::other("engine filesystem root budget"));}let mut broker=Broker::default();let mut roots=vec![];let(mut reads,mut writes)=(vec![],vec![]);let mut seen=std::collections::HashSet::new();
 for mapping in grants{guest_name(&mapping.guest)?;if !seen.insert(&mapping.guest){return Err(io::Error::other("duplicate engine filesystem mapping"));}let grant=&mapping.grant;let token=broker.add_root(&grant.path,grant.read,grant.write)?;if grant.read{reads.push(&mapping.guest);}if grant.write{writes.push(&mapping.guest);}roots.push(serde_json::json!({"guest":mapping.guest,"handle":token.to_string(),"read":grant.read,"write":grant.write}));}
 Ok((broker,vec![("KELFT_ENGINE_PROFILE".into(),profile.into()),("KELFT_FS_ROOTS".into(),serde_json::to_string(&roots)?),("KELFT_FS_CWD".into(),"/project".into()),("KELFT_CAPABILITIES".into(),serde_json::json!({"execute":false,"read":reads,"write":writes}).to_string())]))
}
pub fn javascript(runtime:&[u8],runtime_hash:&str,adapter:&[u8],adapter_hash:&str,program:&[u8],args:&[String],grants:&[MappedGrant],system:&str,limits:Limits)->io::Result<Output>{
 if grants.len()>128{return Err(io::Error::other("engine filesystem root budget"));}
 let identity=AppContainerSid::fresh_engine()?;let mut image=Image::runtime(runtime,runtime_hash,&identity)?;
 let control=image.runtime_input("control.mjs",adapter,adapter_hash)?;let program_hash=format!("sha256:{:x}",Sha256::digest(program));
 let program=image.runtime_input("program.mjs",program,&program_hash)?;let(broker,environment)=authority(grants,"javascript-kfs/1")?;
 let mut arguments=vec!["--jitless".into(),"--max-old-space-size=256".into(),"--input-type=module".into(),"--eval".into(),"import fs from 'node:fs';const control=process.argv[1],program=process.argv[2];process.argv=[process.argv[0],program,...process.argv.slice(3)];await import('data:text/javascript;base64,'+fs.readFileSync(control).toString('base64'));await import('data:text/javascript;base64,'+fs.readFileSync(program).toString('base64'));".into(),control.to_str().ok_or_else(||io::Error::other("Unicode adapter path required"))?.into(),program.to_str().ok_or_else(||io::Error::other("Unicode module path required"))?.into()];arguments.extend_from_slice(args);
 windows_supervisor::run_engine(&image,&identity,system,&arguments,limits,&environment,broker)
}
pub fn wasm(runtime:&[u8],runtime_hash:&str,program:&[u8],args:&[String],grants:&[MappedGrant],system:&str,limits:Limits)->io::Result<Output>{
 let identity=AppContainerSid::fresh_engine()?;let mut image=Image::runtime(runtime,runtime_hash,&identity)?;let digest=format!("sha256:{:x}",Sha256::digest(program));let module=image.runtime_input("program.wasm",program,&digest)?;let(broker,environment)=authority(grants,"wasm-kfs/1")?;
 let mut arguments=vec![module.to_str().ok_or_else(||io::Error::other("Unicode module path required"))?.into(),digest,"--".into()];arguments.extend_from_slice(args);windows_supervisor::run_engine(&image,&identity,system,&arguments,limits,&environment,broker)
}
