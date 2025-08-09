use sha2::{Digest, Sha256};
<<<<<<< HEAD
use std::{fs, path::PathBuf};
use goblin::{mach::Mach, Object};

/// Binary format discriminator
#[derive(Debug, Clone)]
pub enum BinFormat { 
    Elf, 
    MachO, 
    PE, 
    Unknown 
}

/// Enhanced binary metadata structure
=======
use std::path::PathBuf;
use goblin::{mach::Mach};

/// NEW: binary format discriminator
>>>>>>> eed6851 (updated sbom)
#[derive(Debug, Clone)]
pub enum BinFormat { Elf, MachO, PE, Unknown }

#[derive(Debug, Clone)]
#[allow(dead_code)] // TODO: Remove this once `format` and `size_bytes` are used
pub struct BinaryMeta {
    pub path: PathBuf,
<<<<<<< HEAD
    pub format: BinFormat,
    pub size_bytes: u64,
    pub strings: Vec<String>,
    pub sha256: String,
    pub needed_libs: Vec<String>,
=======
    pub format: BinFormat,         // ← NEW
    pub size_bytes: u64,           // ← NEW
    pub sha256: String,
    pub strings: Vec<String>,
    pub needed_libs: Vec<String>,  // ← NEW
>>>>>>> eed6851 (updated sbom)
    pub raw: Vec<u8>,
}

impl BinaryMeta {
    pub fn from_path(path: PathBuf) -> Result<Self, String> {
        let raw = std::fs::read(&path).map_err(|e| e.to_string())?;
        let size_bytes = raw.len() as u64;

        // SHA-256
        let sha256 = {
            let mut h = Sha256::new();
            h.update(&raw);
            format!("{:x}", h.finalize())
        };

<<<<<<< HEAD
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
=======
        // ASCII strings
        let strings = extract_ascii_strings(&raw, 4);

        // Format + imports
        let (format, needed_libs) = match goblin::Object::parse(&raw)
            .map_err(|e| e.to_string())?
        {
            goblin::Object::Elf(elf) => (
                BinFormat::Elf,
                elf.libraries.iter().map(|s| s.to_string()).collect::<Vec<String>>(),
            ),
            goblin::Object::Mach(Mach::Binary(m)) => {
                let libs = m.libs.iter().map(|l| l.to_string()).collect::<Vec<String>>();
                (BinFormat::MachO, libs)
            }
            goblin::Object::PE(pe) => (
                BinFormat::PE,
                pe.imports.iter().map(|i| i.name.to_string()).collect::<Vec<String>>(),
            ),
            _ => (BinFormat::Unknown, vec![]),
        };

        Ok(Self {
            path,
            format,
            size_bytes,
            sha256,
            strings,
>>>>>>> eed6851 (updated sbom)
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
