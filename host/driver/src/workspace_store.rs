//! Bounded workspace file mechanisms. Manifest interpretation, dependency
//! selection, lock contents and update decisions belong to the Kelft policy.
use crate::component_store::{Store, invalid};
use std::{collections::BTreeMap, fs, io::{self, Read}, path::Path};
use sha2::{Digest, Sha256};
use serde_json::{Value, json};

/// Streaming mechanism shared by source and installed-image observations.
pub fn fingerprint(mut file: fs::File, bound: u64) -> io::Result<Value> {
    let before = file.metadata()?;
    if !before.is_file() || before.len() > bound {return Err(invalid("workspace input exceeds bound or is not a regular file"));}
    let mut hash = Sha256::new();let mut count = 0u64;let mut buffer = [0; 65536];
    loop {
        let length = file.read(&mut buffer)?;if length == 0 {break;}
        count += length as u64;if count > bound {return Err(invalid("workspace input exceeds bound"));}
        hash.update(&buffer[..length]);
    }
    let after = file.metadata()?;
    if count != before.len() || before.len() != after.len() || before.modified()? != after.modified()? {return Err(invalid("workspace input changed during observation"));}
    Ok(json!({"size":count,"sha256":format!("sha256:{:x}",hash.finalize())}))
}

pub struct Snapshot {
    store: Store,
    observed: BTreeMap<String, Option<String>>,
    sources: BTreeMap<String, Value>,
    exclusive: Option<fs::File>,
}
impl Snapshot {
    pub fn open(root: &Path) -> io::Result<Self> {
        if root.parent().is_none() { return Err(invalid("workspace cannot be a filesystem root")); }
        Ok(Self {store: Store::open(root)?, observed: BTreeMap::new(), sources: BTreeMap::new(), exclusive: None})
    }
    fn read(&self, name: &str) -> io::Result<Option<String>> {
        let leaf = name.rsplit('/').next().unwrap_or("");
        let bound = match leaf { "kelft.toml" | "kelft-toolchain.toml" => 65536, "kelft.lock" => 1 << 20, _ => return Err(invalid("workspace observation must be a manifest or lockfile")) };
        let mut file = match self.store.workspace_parent(name).and_then(|p| p.open(false)) {
            Ok(f) => f, Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None), Err(e) => return Err(e),
        };
        let before = file.metadata()?;
        if before.len() > bound { return Err(invalid("workspace file exceeds bound")); }
        let mut bytes = vec![];Read::by_ref(&mut file).take(bound + 1).read_to_end(&mut bytes)?;
        let after = file.metadata()?;
        if bytes.len() as u64 != before.len() || after.len() != before.len() || before.modified()? != after.modified()? {
            return Err(invalid("workspace file changed during observation"));
        }
        String::from_utf8(bytes).map(Some).map_err(|_| invalid("workspace file is not UTF-8"))
    }
    pub fn observe(&mut self, name: &str) -> io::Result<Option<String>> {
        if self.observed.len() >= 512 && !self.observed.contains_key(name) { return Err(invalid("workspace observation count")); }
        let text = self.read(name)?;
        self.observed.insert(name.into(), text.clone());
        if self.observed.values().map(|v| v.as_ref().map_or(0, String::len)).sum::<usize>() > 2 << 20 {
            return Err(invalid("workspace observation bytes"));
        }
        Ok(text)
    }
    fn source(&self, name: &str) -> io::Result<Value> {
        if !name.ends_with(".kelft") {return Err(invalid("source observation must name .kelft"));}
        fingerprint(self.store.workspace_parent(name)?.open(false)?, 16 << 20)
    }
    pub fn observe_source(&mut self, name: &str) -> io::Result<Value> {
        if self.sources.len() >= 1024 && !self.sources.contains_key(name) {return Err(invalid("workspace source count"));}
        let value = self.source(name)?;self.sources.insert(name.into(),value.clone());
        if self.sources.values().map(|v|v["size"].as_u64().unwrap_or(u64::MAX)).sum::<u64>() > 64 << 20 {return Err(invalid("workspace source bytes"));}
        Ok(value)
    }
    pub fn unchanged(&self) -> io::Result<()> {
        for (name, expected) in &self.observed {
            if &self.read(name)? != expected { return Err(invalid("workspace changed; retry the command")); }
        }
        for (name, expected) in &self.sources {
            if &self.source(name)? != expected {return Err(invalid("workspace source changed; retry the command"));}
        }
        Ok(())
    }
    pub fn acquire(&mut self) -> io::Result<Option<String>> {
        if self.exclusive.is_some() { return Err(invalid("duplicate workspace maintenance lock")); }
        // Root lock changes by another coordinator are normal while waiting.
        // Manifests and non-root lock observations must remain identical.
        let previous = self.observed.remove("kelft.lock");
        if let Err(e) = self.unchanged() {
            if let Some(value) = previous { self.observed.insert("kelft.lock".into(), value); }
            return Err(e);
        }
        let file = self.store.parent(".kelft-workspace/lock", true)?.open(true)?;
        file.lock()?;
        self.exclusive = Some(file);
        self.unchanged()?;
        // The fixed staging file is never active. Recover a previous interrupted
        // writer only while holding the maintenance lock.
        self.store.parent(".kelft-workspace/stage", false)?.remove()?;
        self.observe("kelft.lock")
    }
    pub fn publish(&mut self, contents: &str) -> io::Result<()> {
        if self.exclusive.is_none() || contents.len() > 1 << 20 { return Err(invalid("workspace publication contract")); }
        self.unchanged()?;
        let stage = self.store.parent(".kelft-workspace/stage", false)?;
        let destination = self.store.parent("kelft.lock", false)?;
        destination.put(&mut contents.as_bytes(), 0o644, &stage)?;
        let actual = self.observe("kelft.lock")?;
        if actual.as_deref() != Some(contents) { return Err(invalid("workspace publication changed")); }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn directory() -> std::path::PathBuf {
        let mut nonce = [0; 16];getrandom::fill(&mut nonce).unwrap();
        let root = std::env::temp_dir().join(format!("kelft-workspace-store-{:x}", u128::from_le_bytes(nonce)));
        fs::create_dir(&root).unwrap();root
    }
    #[test]
    fn snapshots_are_bounded_and_publication_is_fixed_atomic_and_requires_a_lock() {
        let root = directory();
        let mut store = Snapshot::open(&root).unwrap();
        fs::create_dir(root.join("café")).unwrap();
        fs::write(root.join("café/kelft.toml"), "manifest-version = 1").unwrap();
        assert_eq!(store.observe("café/kelft.toml").unwrap().as_deref(), Some("manifest-version = 1"));
        assert!(store.observe("../kelft.toml").is_err());
        assert!(store.observe("unrelated.txt").is_err());
        assert!(store.publish("data").is_err());
        assert_eq!(store.acquire().unwrap(), None);
        store.publish("canonical lock\n").unwrap();store.unchanged().unwrap();
        assert_eq!(fs::read_to_string(root.join("kelft.lock")).unwrap(), "canonical lock\n");
        fs::write(root.join("café/kelft.toml"), "changed").unwrap();
        assert!(store.unchanged().is_err());assert!(store.publish("stale").is_err());
        drop(store);fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn source_hashes_stream_exact_bytes_and_recheck_before_publication() {
        let root = directory();let mut store = Snapshot::open(&root).unwrap();
        let bytes = vec![0x80; 131073];fs::write(root.join("input.kelft"), &bytes).unwrap();
        let expected = format!("sha256:{:x}", Sha256::digest(&bytes));
        assert_eq!(store.observe_source("input.kelft").unwrap(),json!({"size":bytes.len(),"sha256":expected}));
        assert!(store.observe_source("../input.kelft").is_err());assert!(store.observe_source("kelft.lock").is_err());
        fs::write(root.join("kelft-toolchain.toml"),"toolchain-version = 1").unwrap();store.observe("kelft-toolchain.toml").unwrap();
        store.acquire().unwrap();store.unchanged().unwrap();
        fs::write(root.join("input.kelft"),vec![0x81;bytes.len()]).unwrap();assert!(store.publish("stale pins").is_err());
        assert!(!root.join("kelft.lock").exists());
        let oversized = fs::File::create(root.join("large.kelft")).unwrap();oversized.set_len((16 << 20)+1).unwrap();drop(oversized);
        assert!(store.observe_source("large.kelft").is_err());
        drop(store);fs::remove_dir_all(root).unwrap();
    }
    #[cfg(unix)]
    #[test]
    fn links_special_files_and_missing_ancestors_do_not_escape_the_snapshot() {
        use std::os::unix::fs::symlink;
        let root = directory();let outside = directory();
        fs::write(outside.join("kelft.toml"), "outside").unwrap();
        symlink(&outside, root.join("escape")).unwrap();symlink(outside.join("kelft.toml"), root.join("kelft.toml")).unwrap();
        let mut store = Snapshot::open(&root).unwrap();
        assert!(store.observe("escape/kelft.toml").is_err());assert!(store.observe("kelft.toml").is_err());
        fs::write(outside.join("outside.kelft"), "outside").unwrap();symlink(outside.join("outside.kelft"),root.join("linked.kelft")).unwrap();
        assert!(store.observe_source("linked.kelft").is_err());assert!(store.observe_source("escape/outside.kelft").is_err());
        assert_eq!(store.observe("missing/kelft.toml").unwrap(), None);
        drop(store);fs::remove_dir_all(root).unwrap();fs::remove_dir_all(outside).unwrap();
    }
}
