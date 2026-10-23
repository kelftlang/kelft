//! Versioned host envelopes and boundary validation. This is the OS enforcement
//! layer; compiler/stdlib capability decisions have independent Kelft/TS modules.
use serde::{Deserialize,Serialize};
use serde_json::{Value,json};
use std::collections::{BTreeMap,BTreeSet};
#[derive(Clone,Debug,Deserialize,Serialize)]
#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct Limits {pub timeout_ms:u32,pub memory_bytes:usize,pub stdout_bytes:usize,pub stderr_bytes:usize}
impl Limits {pub fn valid(&self)->bool{self.timeout_ms>0&&self.timeout_ms<=600000&&self.memory_bytes>0&&self.memory_bytes<=549755813888&&self.stdout_bytes<=16<<20&&self.stderr_bytes<=16<<20}}
#[derive(Clone,Debug,Deserialize,Serialize)]#[serde(deny_unknown_fields)]
pub struct Grant {pub executable:String,pub sha256:String,pub cwd:Vec<String>,pub environment:BTreeMap<String,String>,pub read:Vec<String>,pub write:Vec<String>,pub limits:Limits,#[serde(default="native_profile")]pub profile:String}
fn native_profile()->String{"native".into()}
#[derive(Clone,Debug,Deserialize,Serialize)]#[serde(deny_unknown_fields)]
pub struct Policy {pub read:Vec<String>,pub write:Vec<String>,#[serde(default)]pub execute:bool,#[serde(default)]pub process:Vec<Grant>}
#[derive(Clone,Debug,Deserialize,Serialize)]#[serde(rename_all="camelCase",deny_unknown_fields)]
pub struct Process {pub schema:String,pub executable:String,pub sha256:String,pub args:Vec<String>,pub cwd:String,pub environment:BTreeMap<String,String>,pub stdin_hex:String,pub read:Vec<String>,pub write:Vec<String>,pub limits:Limits}
#[derive(Deserialize)]#[serde(deny_unknown_fields)]
pub struct Envelope {pub schema:String,pub kind:String,pub maximum:Policy,pub request:Value}
#[derive(Clone,Deserialize)]#[serde(deny_unknown_fields)]
pub struct Filesystem {pub schema:String,pub operation:String,pub path:String,#[serde(default)]pub destination:Option<String>,#[serde(default)]pub prefix:Option<String>,#[serde(default)]pub recursive:Option<bool>}
pub fn normal(path:&str)->bool {let bytes=path.as_bytes();let start=if path.starts_with('/'){1}else if bytes.len()>=3&&bytes[0].is_ascii_alphabetic()&&bytes[1]==b':'&&bytes[2]==b'/'{3}else{return false};path.len()<=4095&&!path.contains(['\\','\0'])&&(path.len()==start||path[start..].split('/').all(|c|!c.is_empty()&&!matches!(c,"."|"..")&&!c.contains(':')))}
pub fn within(path:&str,root:&str)->bool {path==root||path.strip_prefix(root).is_some_and(|tail|root.ends_with('/')||tail.starts_with('/'))}
fn paths(paths:&[String])->bool {paths.len()<=128&&paths.iter().all(|p|normal(p))}
fn subset(paths:&[String],roots:&[String])->bool{paths.iter().all(|p|roots.iter().any(|r|within(p,r)))}
fn hash(hash:&str)->bool{hash.len()==71&&hash.starts_with("sha256:")&&hash[7..].bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))}
pub(crate) fn environment(environment:&BTreeMap<String,String>)->bool{environment.len()<=32&&environment.keys().map(|k|k.to_ascii_uppercase()).collect::<BTreeSet<_>>().len()==environment.len()&&environment.iter().all(|(k,v)|{let key=k.to_ascii_uppercase();!k.is_empty()&&k.bytes().enumerate().all(|(i,b)|b.is_ascii_alphabetic()||b==b'_'||i>0&&b.is_ascii_digit())&&!key.starts_with("KELFT_")&&!matches!(key.as_str(),"LOCALAPPDATA"|"SYSTEMROOT"|"SYSTEMDRIVE"|"WINDIR"|"TEMP"|"TMP"|"NODE_OPTIONS"|"NODE_PATH"|"LD_PRELOAD"|"LD_LIBRARY_PATH"|"DYLD_INSERT_LIBRARIES"|"DYLD_LIBRARY_PATH")&&!v.contains('\0')&&v.len()<=4096})}
impl Policy {
 pub fn validate(&self)->bool {if !paths(&self.read)||!paths(&self.write)||self.process.len()>32{return false;}let mut seen=BTreeSet::new();self.process.iter().all(|g|normal(&g.executable)&&hash(&g.sha256)&&seen.insert(&g.executable)&&paths(&g.cwd)&&paths(&g.read)&&paths(&g.write)&&environment(&g.environment)&&g.limits.valid()&&matches!(g.profile.as_str(),"native"|"installed-kelft")&&subset(&g.read,&self.read)&&subset(&g.write,&self.write))}
 pub fn grant<'a>(&'a self,r:&Process)->Option<&'a Grant>{self.process.iter().find(|g|g.executable==r.executable&&g.sha256==r.sha256&&g.cwd.iter().any(|p|within(&r.cwd,p))&&r.environment.iter().all(|(k,v)|g.environment.get(k)==Some(v))&&subset(&r.read,&g.read)&&subset(&r.write,&g.write)&&subset(&r.read,&self.read)&&subset(&r.write,&self.write)&&r.limits.timeout_ms<=g.limits.timeout_ms&&r.limits.memory_bytes<=g.limits.memory_bytes&&r.limits.stdout_bytes<=g.limits.stdout_bytes&&r.limits.stderr_bytes<=g.limits.stderr_bytes)}
}
impl Process {pub fn validate(&self)->bool{self.schema=="kelft.process-request/1"&&normal(&self.executable)&&hash(&self.sha256)&&normal(&self.cwd)&&environment(&self.environment)&&paths(&self.read)&&paths(&self.write)&&self.limits.valid()&&self.args.len()<=256&&self.args.iter().all(|s|s.len()<=32768&&!s.contains('\0'))&&self.args.iter().map(String::len).sum::<usize>()<=65536&&self.stdin_hex.len()<=131072&&self.stdin_hex.len()%2==0&&self.stdin_hex.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))}}
pub fn authorize<'a>(maximum:&'a Policy,caller:&'a Policy,request:&Process)->Result<&'a Grant,&'static str>{if !maximum.validate()||!caller.validate(){return Err("INVALID_POLICY");}if !request.validate(){return Err("INVALID_REQUEST");}let max=maximum.grant(request).ok_or("PROCESS_DENIED")?;let grant=caller.grant(request).ok_or("PROCESS_DENIED")?;if max.profile!=grant.profile{return Err("PROCESS_DENIED");}Ok(grant)}
pub fn filesystem_error(error:&str)->Value{json!({"schema":"kelft.filesystem-result/1","error":error,"value":null})}
pub fn process_error(error:&str)->Value{json!({"schema":"kelft.process-result/1","status":"rejected","error":error,"exit":null,"signal":null,"stdoutHex":"","stderrHex":""})}
pub fn hex(bytes:&[u8])->String {use std::fmt::Write;let mut out=String::with_capacity(bytes.len()*2);for byte in bytes{let _=write!(out,"{byte:02x}");}out}
pub fn unhex(input:&str)->Vec<u8>{input.as_bytes().chunks_exact(2).map(|p|{let digit=|v:u8|if v<=b'9'{v-b'0'}else{v-b'a'+10};digit(p[0])*16+digit(p[1])}).collect()}

/// serde_json::Value normally replaces duplicate object keys. Reject them at
/// every depth before decoding a capability-bearing request.
pub fn decode(raw:&str)->Result<Envelope,serde_json::Error>{
 struct Strict(Value);
 impl<'de> Deserialize<'de> for Strict {
  fn deserialize<D:serde::Deserializer<'de>>(d:D)->Result<Self,D::Error>{
   struct Visitor;impl<'de> serde::de::Visitor<'de> for Visitor{type Value=Strict;fn expecting(&self,f:&mut std::fmt::Formatter)->std::fmt::Result{f.write_str("unique-key JSON")}
    fn visit_bool<E:serde::de::Error>(self,v:bool)->Result<Strict,E>{Ok(Strict(Value::Bool(v)))}
    fn visit_i64<E:serde::de::Error>(self,v:i64)->Result<Strict,E>{Ok(Strict(v.into()))}
    fn visit_u64<E:serde::de::Error>(self,v:u64)->Result<Strict,E>{Ok(Strict(v.into()))}
    fn visit_str<E:serde::de::Error>(self,v:&str)->Result<Strict,E>{Ok(Strict(v.into()))}
    fn visit_unit<E:serde::de::Error>(self)->Result<Strict,E>{Ok(Strict(Value::Null))}
    fn visit_seq<A:serde::de::SeqAccess<'de>>(self,mut a:A)->Result<Strict,A::Error>{let mut values=vec![];while let Some(Strict(v))=a.next_element()?{values.push(v);}Ok(Strict(Value::Array(values)))}
    fn visit_map<A:serde::de::MapAccess<'de>>(self,mut a:A)->Result<Strict,A::Error>{let mut values=serde_json::Map::new();while let Some((k,Strict(v)))=a.next_entry::<String,Strict>()?{if values.insert(k,v).is_some(){return Err(serde::de::Error::custom("duplicate host field"));}}Ok(Strict(Value::Object(values)))}
   }d.deserialize_any(Visitor)
  }
 }
 let Strict(value)=serde_json::from_str::<Strict>(raw)?;serde_json::from_value(value)
}
#[cfg(test)]mod tests{use super::*;
 #[test]fn malformed_envelopes_and_duplicates_are_rejected(){for raw in ["{}","{\"schema\":\"a\",\"schema\":\"b\"}","{\"maximum\":{\"read\":[],\"read\":[]}}","{\"request\":{\"limits\":{\"timeoutMs\":1.5}}}"]{assert!(decode(raw).is_err());}}
 #[test]fn paths_preserve_component_boundaries(){for p in ["/project/../secret","/project//a","relative","C:/a\\b","C:relative"]{assert!(!normal(p));}assert!(normal("C:/hé space"));assert!(!within("/projectSibling","/project"));assert!(within("/project/a","/project"));}
}
