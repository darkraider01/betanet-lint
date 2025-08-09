use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};

/// Minimal binary metadata
#[derive(Debug, Clone)]
pub struct BinaryMeta {
    pub path: PathBuf,
    /// printable ASCII strings extracted from the binary (min length 4)
    pub strings: Vec<String>,
    /// full-file SHA256 hex
    pub sha256: String,
    /// raw bytes (useful for checks that need raw)
    pub raw: Vec<u8>,
}

impl BinaryMeta {
    pub fn from_path(path: PathBuf) -> Result<Self, String> {
        let raw = fs::read(&path).map_err(|e| format!("read error: {}", e))?;

        // SHA256
        let mut hasher = Sha256::new();
        hasher.update(&raw);
        let sha256 = format!("{:x}", hasher.finalize());

        // strings
        let strings = extract_ascii_strings(&raw, 4);

        Ok(BinaryMeta {
            path,
            strings,
            sha256,
            raw,
        })
    }
}

/// Extract printable ASCII strings (like Unix `strings`).
fn extract_ascii_strings(buf: &[u8], min_len: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = Vec::new();

    for &b in buf {
        if (0x20..=0x7e).contains(&b) {
            cur.push(b);
        } else {
            if cur.len() >= min_len {
                if let Ok(s) = String::from_utf8(cur.clone()) {
                    out.push(s);
                }
            }
            cur.clear();
        }
    }
    if cur.len() >= min_len {
        if let Ok(s) = String::from_utf8(cur.clone()) {
            out.push(s);
        }
    }

    out
}