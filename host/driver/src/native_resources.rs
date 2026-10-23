//! Compiled-in contracts. Selection is separate from native enforcement evidence
//! and certification. Optional engines require separately reviewed profiles.
use crate::native_target::Target;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, io};

const REGISTRY: &str = include_str!("../../native/resource-contracts.json");
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Compiler { pub language_heap_bytes: u64, pub wall_ms: u64 }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Memory {
    pub quantity: String, pub scope: String, pub ceiling_bytes: u64,
    pub mechanism: String, pub stack_mechanism: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Registry {
    schema: String, roles: Vec<String>, compiler: Compiler,
    initial_stack_bytes: u64, profiles: BTreeMap<String, Memory>,
}
#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Contract {
    pub schema: &'static str,
    #[serde(rename = "registrySHA256")]
    pub registry_sha256: String,
    pub target: &'static str, pub role: String, pub memory: Memory,
    pub initial_stack_bytes: u64, pub compiler: Compiler,
}
impl Contract {
    pub fn for_role(target: Target, role: &str) -> io::Result<Self> {
        let registry: Registry = serde_json::from_str(REGISTRY).map_err(io::Error::other)?;
        if registry.schema != "kelft-native-resource-registry/2"
            || !registry.roles.iter().any(|r| r == role) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "unreviewed native resource role"));
        }
        let memory = registry.profiles.get(target.id()).ok_or_else(||
            io::Error::new(io::ErrorKind::InvalidInput, "unreviewed native resource target"))?.clone();
        Ok(Self { schema: "kelft-native-resource-contract/2",
            registry_sha256: format!("sha256:{:x}", Sha256::digest(REGISTRY.as_bytes())),
            target: target.id(), role: role.into(), memory,
            initial_stack_bytes: registry.initial_stack_bytes, compiler: registry.compiler })
    }
}
#[derive(Debug,Serialize)]#[serde(rename_all="camelCase")]
pub struct EngineContract{
 pub schema:&'static str,pub target:&'static str,pub engine:String,#[serde(rename="registrySHA256")]pub registry_sha256:String,
 pub memory:Memory,pub language_memory_quantity:&'static str,pub language_memory_ceiling_bytes:u64,
 pub wall_ms:u64,pub stack_ceiling_bytes:u64,
}
impl EngineContract{pub fn for_engine(target:Target,engine:&str)->io::Result<Self>{
 if !matches!(target,Target::WindowsX64|Target::WindowsArm64|Target::MacosX64|Target::MacosArm64)||!matches!(engine,"javascript"|"wasm"){return Err(io::Error::other("unreviewed optional engine profile"));}
 let platform=Contract::for_role(target,"candidate")?;Ok(Self{schema:"kelft-optional-engine-resource-contract/1",target:target.id(),engine:engine.into(),registry_sha256:platform.registry_sha256,memory:platform.memory,language_memory_quantity:if engine=="javascript"{"v8-old-space-bytes"}else{"wasm-linear-memory-bytes"},language_memory_ceiling_bytes:256<<20,wall_ms:600000,stack_ceiling_bytes:16<<20})
}}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn quantities_and_scope_cannot_be_interchanged() {
        for target in Target::ALL {
            let c = Contract::for_role(target, "compiler").unwrap();
            assert_eq!(c.compiler.language_heap_bytes, 256 << 20);
            assert_eq!(c.compiler.wall_ms, 600000);
            assert_eq!(c.initial_stack_bytes, 16 << 20);
            match target {
                Target::WindowsX64 | Target::WindowsArm64 => {
                    assert_eq!(c.memory.quantity, "committed-bytes");
                    assert_eq!(c.memory.scope, "job");
                    assert_eq!(c.memory.ceiling_bytes, 1 << 30);
                }
                _ => {
                    assert_eq!(c.memory.quantity, "virtual-address-bytes");
                    assert_eq!(c.memory.scope, "process");
                    assert_eq!(c.memory.ceiling_bytes, match target {
                        Target::MacosX64 => 64 << 30,
                        Target::MacosArm64 => 512 << 30,
                        _ => 1 << 30,
                    });
                }
            }
            assert!(Contract::for_role(target, "javascript").is_err());
            assert!(Contract::for_role(target, "wasm").is_err());
        }
    }
}
