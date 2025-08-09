use sha2::{Digest, Sha256};
use std::{collections::HashMap, env, fs, path::PathBuf};
use goblin::{mach::Mach, Object};
use serde::{Deserialize, Serialize};

/// Binary format discriminator
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub embedded_files: Vec<EmbeddedFile>,
    pub compiler_info: Option<CompilerInfo>,
    pub build_environment: BuildEnvironment,
    pub crypto_components: Vec<CryptographicComponent>,
    pub static_libraries: Vec<StaticLibrary>,
    pub licenses: Vec<LicenseInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddedFile {
    pub path: String,
    pub hash: String,
    pub size: u64,
    pub file_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompilerInfo {
    pub compiler: String,
    pub version: String,
    pub optimization_level: String,
    pub target_triple: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildEnvironment {
    pub build_tool: Option<String>,
    pub build_version: Option<String>,
    pub build_timestamp: Option<String>,
    pub environment_variables: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptographicComponent {
    pub algorithm: String,
    pub key_length: Option<u32>,
    pub mode: Option<String>,
    pub implementation: String,
    pub quantum_safe: bool,
    pub usage_context: Vec<CryptoUsage>,
    pub compliance_status: ComplianceStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CryptoUsage {
    Encryption,
    Signing,
    KeyExchange,
    Hashing,
    Authentication,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComplianceStatus {
    Approved,
    Deprecated,
    Forbidden,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticLibrary {
    pub name: String,
    pub checksum: String,
    pub size: u64,
    pub objects: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseInfo {
    pub license_id: String,
    pub confidence: f32,
    pub source: LicenseSource,
    pub text_snippet: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LicenseSource {
    HeaderComment,
    EmbeddedText,
    Filename,
    Heuristic,
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
                let libs: Vec<String> = elf.libraries.iter().map(|s| s.to_string()).collect();
                (BinFormat::Elf, libs)
            }
            Object::Mach(Mach::Binary(m)) => {
                let libs: Vec<String> = m.libs.iter().map(|l| l.to_string()).collect();
                (BinFormat::MachO, libs)
            }
            Object::PE(pe) => {
                let libs: Vec<String> = pe.imports.iter().map(|i| i.name.to_string()).collect();
                (BinFormat::PE, libs)
            }
            _ => (BinFormat::Unknown, vec![]),
        };

        // Enhanced analysis
        let embedded_files = detect_embedded_files(&strings);
        let compiler_info = detect_compiler_info(&strings);
        let build_environment = detect_build_environment();
        let crypto_components = detect_crypto_components(&strings, &needed_libs);
        let static_libraries = detect_static_libraries(&raw);
        let licenses = detect_licenses(&strings);

        Ok(BinaryMeta {
            path,
            format,
            size_bytes,
            strings,
            sha256,
            needed_libs,
            raw,
            embedded_files,
            compiler_info,
            build_environment,
            crypto_components,
            static_libraries,
            licenses,
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

fn detect_embedded_files(strings: &[String]) -> Vec<EmbeddedFile> {
    let mut files = Vec::new();
    
    for string in strings {
        if string.contains(".so") || string.contains(".dll") || string.contains(".dylib") {
            files.push(EmbeddedFile {
                path: string.clone(),
                hash: format!("{:x}", md5::compute(string.as_bytes())),
                size: string.len() as u64,
                file_type: detect_file_type(string),
            });
        }
    }
    
    files
}

fn detect_file_type(path: &str) -> String {
    if path.ends_with(".so") || path.contains(".so.") {
        "shared_library".to_string()
    } else if path.ends_with(".dll") {
        "dynamic_library".to_string()
    } else if path.ends_with(".dylib") {
        "dynamic_library".to_string()
    } else {
        "unknown".to_string()
    }
}

fn detect_compiler_info(strings: &[String]) -> Option<CompilerInfo> {
    for string in strings {
        if string.contains("rustc") {
            return Some(CompilerInfo {
                compiler: "rustc".to_string(),
                version: extract_version(string, "rustc").unwrap_or("unknown".to_string()),
                optimization_level: "unknown".to_string(),
                target_triple: "unknown".to_string(),
            });
        } else if string.contains("clang") {
            return Some(CompilerInfo {
                compiler: "clang".to_string(),
                version: extract_version(string, "clang").unwrap_or("unknown".to_string()),
                optimization_level: "unknown".to_string(),
                target_triple: "unknown".to_string(),
            });
        } else if string.contains("gcc") {
            return Some(CompilerInfo {
                compiler: "gcc".to_string(),
                version: extract_version(string, "gcc").unwrap_or("unknown".to_string()),
                optimization_level: "unknown".to_string(),
                target_triple: "unknown".to_string(),
            });
        }
    }
    None
}

fn extract_version(string: &str, tool: &str) -> Option<String> {
    let re = regex::Regex::new(&format!(r"{}\s+(\d+\.\d+\.\d+)", tool)).ok()?;
    re.captures(string)?.get(1).map(|m| m.as_str().to_string())
}

fn detect_build_environment() -> BuildEnvironment {
    let mut env_vars = HashMap::new();
    
    // Capture relevant build environment variables
    if let Ok(val) = env::var("CARGO_PKG_VERSION") {
        env_vars.insert("CARGO_PKG_VERSION".to_string(), val);
    }
    if let Ok(val) = env::var("RUSTC_VERSION") {
        env_vars.insert("RUSTC_VERSION".to_string(), val);
    }
    if let Ok(val) = env::var("TARGET") {
        env_vars.insert("TARGET".to_string(), val);
    }

    BuildEnvironment {
        build_tool: Some("cargo".to_string()),
        build_version: env::var("CARGO_VERSION").ok(),
        build_timestamp: chrono::Utc::now().to_rfc3339().into(),
        environment_variables: env_vars,
    }
}

fn detect_crypto_components(strings: &[String], libs: &[String]) -> Vec<CryptographicComponent> {
    let mut components = Vec::new();
    
    // Crypto algorithm detection from strings
    let crypto_patterns = [
        ("AES", Some(256), Some("GCM"), true),
        ("ChaCha20", Some(256), Some("Poly1305"), true),
        ("Ed25519", Some(255), None, true),
        ("X25519", Some(255), None, true),
        ("Kyber", Some(768), None, true),
        ("RSA", Some(2048), None, false),
        ("SHA256", Some(256), None, true),
        ("SHA3", Some(256), None, true),
    ];
    
    for (algo, key_len, mode, quantum_safe) in crypto_patterns {
        if strings.iter().any(|s| s.to_lowercase().contains(&algo.to_lowercase())) {
            components.push(CryptographicComponent {
                algorithm: algo.to_string(),
                key_length: key_len,
                mode: mode.map(|s| s.to_string()),
                implementation: "detected".to_string(),
                quantum_safe,
                usage_context: vec![CryptoUsage::Encryption],
                compliance_status: if quantum_safe {
                    ComplianceStatus::Approved
                } else {
                    ComplianceStatus::Deprecated
                },
            });
        }
    }
    
    // Library-based crypto detection
    for lib in libs {
        if lib.contains("openssl") {
            components.push(CryptographicComponent {
                algorithm: "OpenSSL".to_string(),
                key_length: None,
                mode: None,
                implementation: lib.clone(),
                quantum_safe: false,
                usage_context: vec![CryptoUsage::Encryption, CryptoUsage::Signing],
                compliance_status: ComplianceStatus::Approved,
            });
        }
    }
    
    components
}

fn detect_static_libraries(raw: &[u8]) -> Vec<StaticLibrary> {
    let mut libraries = Vec::new();
    
    // Simple heuristic - look for .a archive magic
    if raw.starts_with(b"!<arch>") {
        libraries.push(StaticLibrary {
            name: "static_archive".to_string(),
            checksum: format!("{:x}", md5::compute(raw)),
            size: raw.len() as u64,
            objects: vec!["unknown".to_string()],
        });
    }
    
    libraries
}

fn detect_licenses(strings: &[String]) -> Vec<LicenseInfo> {
    let mut licenses = Vec::new();
    
    let license_patterns = [
        ("MIT", "Permission is hereby granted"),
        ("Apache-2.0", "Apache License"),
        ("GPL-3.0", "GNU GENERAL PUBLIC LICENSE"),
        ("BSD-3-Clause", "Redistributions of source code must retain"),
        ("MPL-2.0", "Mozilla Public License"),
    ];
    
    for string in strings {
        for (license_id, pattern) in &license_patterns {
            if string.contains(pattern) {
                licenses.push(LicenseInfo {
                    license_id: license_id.to_string(),
                    confidence: 0.9,
                    source: LicenseSource::EmbeddedText,
                    text_snippet: Some(string.clone()),
                });
            }
        }
    }
    
    licenses
}
