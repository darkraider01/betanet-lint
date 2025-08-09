use anyhow::Result;
use goblin::Object;
use std::{fs, path::PathBuf};

#[derive(Debug)]
pub struct BinaryMeta {
    pub path: PathBuf,
    pub linked_libs: Vec<String>,
    pub strings: Vec<String>,
}

pub fn parse_binary(path: &PathBuf) -> Result<BinaryMeta> {
    tracing::info!("Parsing binary: {:?}", path);
    let buf = fs::read(path)?;
    let mut linked_libs = Vec::new();

    match Object::parse(&buf)? {
        Object::Elf(elf) => {
            for lib in elf.libraries {
                linked_libs.push(lib.to_string());
            }
            tracing::debug!("ELF linked libraries: {:?}", linked_libs);
        }
        _ => {
            tracing::warn!("Binary is not an ELF, skipping linked library extraction.");
        }
    }

    let strings = extract_strings(&buf);
    tracing::debug!("Extracted strings count: {}", strings.len());
    Ok(BinaryMeta { path: path.clone(), linked_libs, strings })
}

fn extract_strings(buf: &[u8]) -> Vec<String> {
    let mut result = Vec::new();
    let mut current = Vec::new();

    for &b in buf {
        if b.is_ascii_graphic() || b == b' ' {
            current.push(b);
        } else if current.len() >= 4 {
            if let Ok(s) = String::from_utf8(current.clone()) {
                result.push(s);
            } else {
                tracing::warn!("Failed to convert bytes to UTF-8 string: {:?}", current);
            }
            current.clear();
        } else {
            current.clear();
        }
    }
    tracing::debug!("Total strings extracted: {}", result.len());
    result
}
