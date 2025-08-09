use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};
use goblin::{elf::Elf, mach::Mach, pe::PE, Object};

/// Binary format discriminator
#[derive(Debug, Clone)]
pub enum BinFormat { 
    Elf, 
    MachO, 
    PE, 
    Unknown 
}

/// Enhanced binary metadata structure
#[derive(Debug, Clone)]
pub struct BinaryMeta {
    pub path: PathBuf,
    pub format: BinFormat,
    pub size_bytes: u64,
    pub strings: Vec<String>,
    pub sha256: String,
    pub needed_libs: Vec<String>,
    pub raw: Vec<u8>,
}

impl BinaryMeta {
    pub fn from_path(path: PathBuf) -> Result<Self, String> {
        let raw = fs::read(&path).map_err(|e| format!("read error: {}", e))?;
        let size_bytes = raw.len() as u64;

        // SHA256
        let mut hasher = Sha256::new();
        hasher.update(&raw);
        let sha256 = format!("{:x}", hasher.finalize());

        // Extract strings
        let strings = extract_ascii_strings(&raw, 4);

        // Determine format and extract dependencies
        let (format, needed_libs) = match Object::parse(&raw).map_err(|e| e.to_string())? {
            Object::Elf(elf) => {
                let libs = elf.libraries.iter().map(|s| s.to_string()).collect();
                (BinFormat::Elf, libs)
            }
            Object::Mach(Mach::Binary(m)) => {
                let libs = m.libraries.iter().map(|l| l.name.to_string()).collect();
                (BinFormat::MachO, libs)
            }
            Object::PE(pe) => {
                let libs = pe.imports.iter().map(|i| i.name.clone()).collect();
                (BinFormat::PE, libs)
            }
            _ => (BinFormat::Unknown, vec![]),
        };

        Ok(BinaryMeta {
            path,
            format,
            size_bytes,
            strings,
            sha256,
            needed_libs,
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
