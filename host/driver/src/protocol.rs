use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Limits {
    pub timeout_ms: u64,
    pub memory_bytes: usize,
    pub stdout_bytes: usize,
    pub stderr_bytes: usize,
}
impl Limits {
    pub fn fixture() -> Self {
        Self {
            timeout_ms: 30_000,
            memory_bytes: 1 << 30,
            stdout_bytes: 1 << 20,
            stderr_bytes: 1 << 20,
        }
    }
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.timeout_ms == 0
            || self.timeout_ms > 3_600_000
            || self.memory_bytes == 0
            || self.memory_bytes > 1 << 30
            || self.stdout_bytes > 64 << 20
            || self.stderr_bytes > 64 << 20
        {
            return Err("invalid execution limits");
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Mount {
    pub host: PathBuf,
    pub guest: String,
    #[serde(default = "default_mount_read")]
    pub read: bool,
    pub write: bool,
}
fn default_mount_read() -> bool { true }
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkerRequest {
    pub schema_version: String,
    pub module: PathBuf,
    pub artifact_hash: String,
    pub args: Vec<String>,
    pub mounts: Vec<Mount>,
    pub configuration: String,
    pub limits: Limits,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExecutionResult {
    pub status: String,
    pub artifact_hash: String,
    pub exit: Option<i32>,
    pub stdout_hex: String,
    pub stderr_hex: String,
    pub trap: Option<String>,
    pub error: Option<String>,
}
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub fn unhex(text: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if text.len() % 2 != 0
        || !text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("invalid hexadecimal bytes".into());
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(Into::into))
        .collect()
}
pub fn hash(bytes: &[u8]) -> String {
    format!("sha256:{}", hex(&Sha256::digest(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hashes_raw_bytes() {
        assert_eq!(
            hash(b"abc"),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(unhex("00ff").unwrap(), [0, 255]);
        assert!(unhex("f").is_err());
    }
    #[test]
    fn limits_fail_closed() {
        let mut value = Limits::fixture();
        value.timeout_ms = 0;
        assert!(value.validate().is_err());
    }
}
