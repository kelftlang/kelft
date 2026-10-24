//! Bounded gzip/tar transport. Names, compatibility, checksums and inventory
//! acceptance are decided by Kelft. No archive name becomes a filesystem path.
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{self, BufReader, Read, Seek, SeekFrom},
    path::Path,
};
fn invalid(s: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, s)
}
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
struct HashReader {
    file: fs::File,
    sha: Sha256,
    count: u64,
}
impl Read for HashReader {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        let n = self.file.read(b)?;
        self.count += n as u64;
        if self.count > 512 << 20 {
            return Err(invalid("compressed archive limit"));
        }
        self.sha.update(&b[..n]);
        Ok(n)
    }
}
fn octal(b: &[u8]) -> io::Result<u64> {
    let mut value = 0u64;
    let mut end = false;
    let mut digits = 0;
    for c in b {
        if *c == 0 || *c == 32 {
            end = true;
        } else {
            if end || !matches!(c, b'0'..=b'7') {
                return Err(invalid("unframeable tar length"));
            }
            value = value
                .checked_mul(8)
                .and_then(|n| n.checked_add((c - b'0') as u64))
                .ok_or_else(|| invalid("tar length overflow"))?;
            digits += 1;
        }
    }
    if digits == 0 || value > 256 << 20 {
        return Err(invalid("tar length bound"));
    }
    Ok(value)
}
pub fn inspect(mut file: fs::File, directory: &Path) -> io::Result<Value> {
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > 512 << 20 {
        return Err(invalid("archive input bound"));
    }
    // Bound gzip framing before entering the library decoder: optional filename
    // and comment fields otherwise permit allocations proportional to the input.
    let mut gzip_header = [0; 10];
    file.read_exact(&mut gzip_header)?;
    if gzip_header[..4] != [31, 139, 8, 0] {
        return Err(invalid("gzip fixed-header framing required"));
    }
    file.seek(SeekFrom::Start(0))?;
    let reader = HashReader {
        file,
        sha: Sha256::new(),
        count: 0,
    };
    let mut decoder = flate2::bufread::GzDecoder::new(BufReader::new(reader));
    let mut rows = vec![];
    let mut total = 0u64;
    let mut first = String::new();
    loop {
        let mut header = [0u8; 512];
        decoder.read_exact(&mut header)?;
        total += 512;
        if header.iter().all(|b| *b == 0) {
            let mut end = [0; 512];
            decoder.read_exact(&mut end)?;
            if end.iter().any(|b| *b != 0) || decoder.read(&mut [0])? != 0 {
                return Err(invalid("tar end or expanded trailing data"));
            }
            break;
        }
        if rows.len() >= 8192 {
            return Err(invalid("archive entry bound"));
        }
        let size = octal(&header[124..136])?;
        total = total
            .checked_add(size + ((512 - size % 512) % 512))
            .ok_or_else(|| invalid("expanded length overflow"))?;
        if total + 1024 > 512 << 20 {
            return Err(invalid("expanded archive limit"));
        }
        let name = directory.join(rows.len().to_string());
        let mut output = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(name)?;
        let mut sha = Sha256::new();
        let mut remaining = size;
        let mut chunk = [0; 65536];
        let mut text = vec![];
        while remaining > 0 {
            let take = (remaining as usize).min(chunk.len());
            decoder.read_exact(&mut chunk[..take])?;
            use std::io::Write;
            output.write_all(&chunk[..take])?;
            sha.update(&chunk[..take]);
            if rows.is_empty() {
                if size > 1 << 20 {
                    return Err(invalid("component metadata bound"));
                }
                text.extend_from_slice(&chunk[..take]);
            }
            remaining -= take as u64;
        }
        output.sync_all()?;
        drop(output);
        if rows.is_empty() {
            first = String::from_utf8(text).map_err(|_| invalid("metadata UTF-8"))?;
        }
        let pad = ((512 - size % 512) % 512) as usize;
        decoder.read_exact(&mut chunk[..pad])?;
        if chunk[..pad].iter().any(|b| *b != 0) {
            return Err(invalid("tar data padding"));
        }
        rows.push(json!({"header":hex(&header),"size":size,"sha256":format!("sha256:{:x}",sha.finalize())}));
    }
    let mut reader = decoder.into_inner();
    let mut trailing = [0; 1];
    if reader.read(&mut trailing)? != 0 {
        return Err(invalid("gzip concatenation or trailing bytes"));
    }
    let reader = reader.into_inner();
    if reader.count != metadata.len() {
        return Err(invalid("archive changed while reading"));
    }
    let after = reader.file.metadata()?;
    if after.len() != metadata.len() || after.modified()? != metadata.modified()? {
        return Err(invalid("archive changed while reading"));
    }
    Ok(
        json!({"entries":rows,"metadata":first,"gzipHeader":hex(&gzip_header),"canonicalEnd":true,"sha256":format!("sha256:{:x}",reader.sha.finalize()),"size":reader.count}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    #[test]
    fn framing_never_interprets_paths_and_bounds_lengths() {
        assert_eq!(octal(b"00000000010\0").unwrap(), 8);
        for b in [b"77777777777\0" as &[u8], b"0000x000000\0", b"           "] {
            assert!(octal(b).is_err());
        }
    }
    #[test]
    fn concatenated_gzip_and_unbounded_members_are_not_accepted() {
        let root = std::env::temp_dir().join(format!("kelft-archive-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let run = || -> io::Result<()> {
            let mut gzip = flate2::write::GzEncoder::new(vec![], flate2::Compression::best());
            gzip.write_all(&[0; 1024])?;
            let bytes = gzip.finish()?;
            let file = root.join("pack");
            fs::write(&file, &bytes)?;
            assert!(
                inspect(fs::File::open(&file)?, &root)?
                    .get("canonicalEnd")
                    .is_some()
            );
            let mut extra = bytes.clone();
            extra.extend_from_slice(&bytes);
            fs::write(&file, &extra)?;
            assert!(inspect(fs::File::open(&file)?, &root).is_err());
            Ok(())
        };
        let result = run();
        fs::remove_dir_all(root).unwrap();
        result.unwrap();
    }
    #[test]
    fn gzip_headers_crc_padding_and_expanded_trailing_data_are_bounded() {
        let root = std::env::temp_dir().join(format!("kelft-framing-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let encode = |tar: &[u8]| {
            let mut gzip = flate2::write::GzEncoder::new(vec![], flate2::Compression::best());
            gzip.write_all(tar).unwrap();
            gzip.finish().unwrap()
        };
        let run = |bytes: &[u8]| {
            let file = root.join("pack");
            fs::write(&file, bytes).unwrap();
            inspect(fs::File::open(&file).unwrap(), &root)
        };
        let valid = encode(&[0; 1024]);
        let mut filename = valid.clone();
        filename[3] = 8;
        assert!(run(&filename).is_err());
        let mut crc = valid.clone();
        let at = crc.len() - 8;
        crc[at] ^= 1;
        assert!(run(&crc).is_err());
        let mut trailing = valid.clone();
        trailing.push(0);
        assert!(run(&trailing).is_err());
        assert!(run(&encode(&[0; 1536])).is_err());
        assert!(run(&valid[..valid.len() - 1]).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
