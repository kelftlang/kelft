//! Installed optional inputs are authenticated by the compiled boundary pin.
use crate::native_target::Target;use serde::Deserialize;use sha2::{Digest,Sha256};use std::io;
#[derive(Deserialize,Debug)]#[serde(deny_unknown_fields)]pub struct Input{pub path:String,pub sha256:String}
#[derive(Deserialize,Debug)]#[serde(deny_unknown_fields)]pub struct Javascript{pub runtime:Input,pub adapter:Input,pub version:String}
#[derive(Deserialize,Debug)]#[serde(deny_unknown_fields)]pub struct Wasm{pub runtime:Input,pub version:String}
#[derive(Deserialize,Debug)]#[serde(deny_unknown_fields)]pub struct Profiles{pub schema:String,pub profile:String,pub javascript:Option<Javascript>,pub wasm:Option<Wasm>}
fn invalid()->io::Error{io::Error::other("installed optional-engine profile differs")}
pub fn authenticate(bytes:&[u8],expected:&str,target:Target)->io::Result<Profiles>{
 if bytes.len()>1<<20||format!("sha256:{:x}",Sha256::digest(bytes))!=expected{return Err(invalid());}
 let profiles:Profiles=serde_json::from_slice(bytes).map_err(|_|invalid())?;
 if profiles.schema!="kelft-installed-engine-profiles/1"||profiles.profile!=target.id(){return Err(invalid());}
 if profiles.javascript.is_none()&&profiles.wasm.is_none(){return Err(invalid());}let mut inputs=vec![];
 if let Some(js)=&profiles.javascript{if js.runtime.path!=format!("rootfs/engines/javascript/node{}",target.executable_suffix())||js.adapter.path!="rootfs/engines/javascript/filesystem.mjs"||js.version!="v24.22.0"{return Err(invalid());}inputs.extend([&js.runtime,&js.adapter]);}
 if let Some(wasm)=&profiles.wasm{if wasm.runtime.path!=format!("rootfs/engines/wasm/runtime{}",target.executable_suffix())||wasm.version!="wasmtime-49.0.3"{return Err(invalid());}inputs.push(&wasm.runtime);}
 for input in inputs{if input.sha256.len()!=71||!input.sha256.starts_with("sha256:")||!input.sha256[7..].bytes().all(|c|c.is_ascii_hexdigit()&&!c.is_ascii_uppercase()){return Err(invalid());}}
 Ok(profiles)
}
#[cfg(test)]mod tests{
 use super::*;
 #[test]fn authenticated_profiles_reject_cross_architecture_unknown_fields_and_nonfixed_paths(){
  let original=serde_json::json!({"schema":"kelft-installed-engine-profiles/1","profile":"windows-x86_64","javascript":{"runtime":{"path":"rootfs/engines/javascript/node.exe","sha256":format!("sha256:{}","a".repeat(64))},"adapter":{"path":"rootfs/engines/javascript/filesystem.mjs","sha256":format!("sha256:{}","b".repeat(64))},"version":"v24.22.0"}});
  let verify=|v:&serde_json::Value,target|{let bytes=serde_json::to_vec(v).unwrap();authenticate(&bytes,&format!("sha256:{:x}",Sha256::digest(&bytes)),target)};
  verify(&original,Target::WindowsX64).unwrap();assert!(verify(&original,Target::WindowsArm64).is_err());
  for path in ["../node.exe","C:\\node.exe","rootfs/engines/javascript/other.exe"]{let mut value=original.clone();value["javascript"]["runtime"]["path"]=path.into();assert!(verify(&value,Target::WindowsX64).is_err());}
  let mut value=original.clone();value["javascript"]["flags"]=serde_json::json!(["--inspect"]);assert!(verify(&value,Target::WindowsX64).is_err());
  assert!(authenticate(&serde_json::to_vec(&original).unwrap(),&format!("sha256:{}","0".repeat(64)),Target::WindowsX64).is_err());
 }
}
