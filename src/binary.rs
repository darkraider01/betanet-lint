//! Binary Analysis Module
//!
//! Provides comprehensive analysis of compiled binaries with proper format parsing,
//! memory-efficient processing, and protocol-specific detection capabilities.

use sha2::{Digest, Sha256};
use std::{collections::{HashMap, HashSet}, env, path::PathBuf, fs::File, io::Read};
use goblin::{mach::Mach, Object, elf, pe};
use serde::{Deserialize, Serialize};
use memmap2::MmapOptions;
use anyhow::{Result, Context};

/// Binary format discriminator
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BinFormat {
    Elf,
    MachO,
    PE,
    Unknown,
}

/// Enhanced binary metadata structure for Betanet compliance analysis
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
    pub betanet_indicators: BetanetIndicators,
    pub build_reproducibility: BuildReproducibility,
    pub imported_symbols: Vec<String>,
    pub exported_symbols: Vec<String>,
    pub section_names: Vec<String>,
    pub dynamic_dependencies: Vec<String>,
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

/// Betanet-specific protocol indicators
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BetanetIndicators {
    pub htx_transport: Vec<String>,
    pub protocol_versions: Vec<String>,
    pub crypto_protocols: Vec<String>,
    pub network_transports: Vec<String>,
    pub p2p_protocols: Vec<String>,
    pub governance_indicators: Vec<String>,
}

/// Build reproducibility analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildReproducibility {
    pub has_build_id: bool,
    pub build_id_type: Option<String>,
    pub build_id_value: Option<String>,
    pub deterministic_indicators: Vec<String>,
    pub timestamp_embedded: bool,
}

impl BinaryMeta {
    /// Analyze a binary file without any artificial manipulation
    /// 
    /// This is the corrected version that DOES NOT inject strings or create self-passes.
    /// It performs genuine analysis of the provided binary file.
    pub fn from_path(path: PathBuf) -> Result<Self> {
        log::info!("Analyzing binary: {}", path.display());

        // Validate file exists and is readable
        if !path.exists() {
            anyhow::bail!("Binary file does not exist: {}", path.display());
        }

        if !path.is_file() {
            anyhow::bail!("Path is not a regular file: {}", path.display());
        }

        let file = File::open(&path)
            .with_context(|| format!("Failed to open binary file: {}", path.display()))?;

        let file_size = file.metadata()
            .with_context(|| "Failed to read file metadata")?
            .len();

        log::debug!("Binary size: {} bytes", file_size);

        // Use memory mapping for large files (>10MB) to improve performance
        let (raw, size_bytes) = if file_size > 10 * 1024 * 1024 {
            log::debug!("Using memory mapping for large file");
            let mmap = unsafe { 
                MmapOptions::new()
                    .map(&file)
                    .with_context(|| "Failed to memory map file")?
            };

            // For very large files, only analyze first 50MB to prevent memory issues
            let analyze_size = std::cmp::min(mmap.len(), 50 * 1024 * 1024);
            (mmap[..analyze_size].to_vec(), file_size)
        } else {
            let raw = std::fs::read(&path)
                .with_context(|| format!("Failed to read binary file: {}", path.display()))?;
            let size = raw.len() as u64;
            (raw, size)
        };

        // Compute SHA256 with streaming for large files
        let sha256 = if file_size > 100 * 1024 * 1024 {
            Self::compute_sha256_streaming(&path)?
        } else {
            let mut hasher = Sha256::new();
            hasher.update(&raw);
            format!("{:x}", hasher.finalize())
        };

        log::debug!("SHA256: {}", sha256);

        // Extract strings with memory limits - NO ARTIFICIAL INJECTION
        let strings = Self::extract_ascii_strings_optimized(&raw, 4);
        log::debug!("Extracted {} strings", strings.len());

        // Enhanced binary analysis with proper format parsing
        let (format, needed_libs, imported_symbols, exported_symbols, section_names, dynamic_dependencies) = 
            Self::analyze_binary_format(&raw)?;

        log::debug!("Binary format: {:?}", format);
        log::debug!("Found {} libraries", needed_libs.len());
        log::debug!("Found {} imported symbols", imported_symbols.len());
        log::debug!("Found {} exported symbols", exported_symbols.len());

        // Enhanced analysis components
        let embedded_files = Self::detect_embedded_files(&strings);
        let compiler_info = Self::detect_compiler_info(&strings);
        let build_environment = Self::detect_build_environment();
        let crypto_components = Self::detect_crypto_components(&strings, &needed_libs, &imported_symbols);
        let static_libraries = Self::detect_static_libraries(&raw);
        let licenses = Self::detect_licenses(&strings);
        let betanet_indicators = Self::detect_betanet_indicators_enhanced(
            &strings, &needed_libs, &imported_symbols, &exported_symbols, 
            &section_names, &dynamic_dependencies
        );
        let build_reproducibility = Self::analyze_build_reproducibility(&raw, &format, &strings);

        log::info!("Analysis complete - {} crypto components, {} licenses, {} betanet indicators", 
                  crypto_components.len(), licenses.len(), betanet_indicators.protocol_versions.len());

        Ok(BinaryMeta {
            path,
            format,
            size_bytes,
            strings,
            sha256,
            needed_libs,
            // Don't store raw bytes for large files to save memory
            raw: if file_size > 50 * 1024 * 1024 { 
                Vec::new() // Empty for large files
            } else { 
                raw 
            },
            embedded_files,
            compiler_info,
            build_environment,
            crypto_components,
            static_libraries,
            licenses,
            betanet_indicators,
            build_reproducibility,
            imported_symbols,
            exported_symbols,
            section_names,
            dynamic_dependencies,
        })
    }

    /// Compute SHA256 using streaming for large files
    fn compute_sha256_streaming(path: &PathBuf) -> Result<String> {
        let mut file = File::open(path)
            .with_context(|| format!("Failed to open file for hashing: {}", path.display()))?;
        let mut hasher = Sha256::new();
        let mut buffer = [0u8; 64 * 1024]; // 64KB buffer

        loop {
            match file.read(&mut buffer)? {
                0 => break, // EOF
                bytes_read => hasher.update(&buffer[..bytes_read]),
            }
        }

        Ok(format!("{:x}", hasher.finalize()))
    }

    /// Enhanced binary format analysis with proper header parsing
    /// 
    /// This version uses proper binary format parsers instead of string scanning
    fn analyze_binary_format(raw: &[u8]) -> Result<(BinFormat, Vec<String>, Vec<String>, Vec<String>, Vec<String>, Vec<String>)> {
        match Object::parse(raw).context("Failed to parse binary format")? {
            Object::Elf(elf) => {
                let libs: Vec<String> = elf.libraries.iter().map(|s| s.to_string()).collect();

                // Extract imported symbols using proper ELF parsing
                let imported_symbols: Vec<String> = elf.dynsyms
                    .iter()
                    .filter_map(|sym| {
                        if sym.st_bind() == elf::sym::STB_GLOBAL && sym.st_shndx as u32 == elf::section_header::SHN_UNDEF {
                            elf.dynstrtab.get_at(sym.st_name).map(|s| s.to_string())
                        } else {
                            None
                        }
                    })
                    .collect();

                // Extract exported symbols
                let exported_symbols: Vec<String> = elf.dynsyms
                    .iter()
                    .filter_map(|sym| {
                        if sym.st_bind() == elf::sym::STB_GLOBAL && sym.st_shndx as u32 != elf::section_header::SHN_UNDEF {
                            elf.dynstrtab.get_at(sym.st_name).map(|s| s.to_string())
                        } else {
                            None
                        }
                    })
                    .collect();

                // Extract section names using proper ELF parsing
                let section_names: Vec<String> = elf.section_headers
                    .iter()
                    .filter_map(|section| {
                        elf.shdr_strtab.get_at(section.sh_name).map(|s| s.to_string())
                    })
                    .collect();

                // Extract dynamic dependencies (more reliable than just libraries)
                let dynamic_dependencies: Vec<String> = elf.dynamic
                    .as_ref()
                    .map(|dyn_section| {
                        dyn_section.dyns
                            .iter()
                            .filter_map(|dyn_entry| {
                                if dyn_entry.d_tag == elf::dynamic::DT_NEEDED {
                                    elf.dynstrtab.get_at(dyn_entry.d_val as usize)
                                        .map(|s| s.to_string())
                                } else {
                                    None
                                }
                            })
                            .collect()
                    })
                    .unwrap_or_default();

                Ok((BinFormat::Elf, libs, imported_symbols, exported_symbols, section_names, dynamic_dependencies))
            }

            Object::Mach(Mach::Binary(m)) => {
                let libs: Vec<String> = m.libs.iter().map(|l| l.to_string()).collect();

                // Extract imported symbols from Mach-O using proper parsing
                let imported_symbols: Vec<String> = m.imports()
                    .map(|imports| {
                        imports.iter()
                            .map(|import| import.name.to_string())
                            .collect()
                    })
                    .unwrap_or_default();

                // Extract exported symbols
                let exported_symbols: Vec<String> = m.exports()
                    .map(|exports| {
                        exports.iter()
                            .map(|export| export.name.to_string())
                            .collect()
                    })
                    .unwrap_or_default();

                // Extract section names using proper Mach-O parsing
                let section_names: Vec<String> = m.segments
                    .iter()
                    .flat_map(|segment| {
                        segment.sections()
                            .unwrap_or_default()
                            .iter()
                            .map(|(section, _)| section.name().unwrap_or("").to_string())
                            .collect::<Vec<String>>()
                    })
                    .collect();

                Ok((BinFormat::MachO, libs.clone(), imported_symbols, exported_symbols, section_names, libs))
            }

            Object::PE(pe) => {
                let libs: Vec<String> = pe.imports.iter().map(|i| i.name.to_string()).collect();

                // Extract imported symbols from PE using proper parsing
                let imported_symbols: Vec<String> = pe.imports
                    .iter()
                    .flat_map(|import| {
                        // For PE files, we extract the DLL names as imported symbols
                        // A more sophisticated implementation would parse the import table
                        vec![import.dll.to_string()]
                    })
                    .collect();

                // Extract exported symbols using proper PE parsing
                let exported_symbols: Vec<String> = pe.exports
                    .iter()
                    .filter_map(|export| export.name.map(|n| n.to_string()))
                    .collect();

                // Extract section names using proper PE parsing
                let section_names: Vec<String> = pe.sections
                    .iter()
                    .filter_map(|section| {
                        if let Ok(name_str) = section.name() {
                            Some(name_str.to_string())
                        } else {
                            None
                        }
                    })
                    .collect();

                Ok((BinFormat::PE, libs.clone(), imported_symbols, exported_symbols, section_names, libs))
            }

            _ => Ok((BinFormat::Unknown, vec![], vec![], vec![], vec![], vec![])),
        }
    }

    /// Memory-efficient string extraction with better limits
    /// 
    /// This function extracts strings for analysis but does NOT inject any artificial content
    fn extract_ascii_strings_optimized(buf: &[u8], min_len: usize) -> Vec<String> {
        let mut out = Vec::new();
        let mut cur = Vec::with_capacity(1024);

        // Process in larger chunks for efficiency
        const CHUNK_SIZE: usize = 256 * 1024; // 256KB chunks
        let max_strings = 50000; // Reduced from original to prevent memory issues
        let max_string_length = 512; // Reasonable limit

        let mut pos = 0;
        while pos < buf.len() && out.len() < max_strings {
            let end = std::cmp::min(pos + CHUNK_SIZE, buf.len());
            let chunk = &buf[pos..end];

            for &b in chunk {
                if (0x20..=0x7e).contains(&b) || b == 0x09 { // Include tabs
                    cur.push(b);

                    // Prevent individual strings from getting too large
                    if cur.len() > max_string_length {
                        cur.clear();
                    }
                } else {
                    if cur.len() >= min_len {
                        if let Ok(s) = String::from_utf8(cur.clone()) {
                            // Additional filtering for meaningful strings
                            if Self::is_meaningful_string(&s) {
                                out.push(s);
                            }
                        }
                    }
                    cur.clear();
                }
            }

            pos = end;
        }

        // Handle final string
        if cur.len() >= min_len && out.len() < max_strings {
            if let Ok(s) = String::from_utf8(cur) {
                if Self::is_meaningful_string(&s) {
                    out.push(s);
                }
            }
        }

        // Deduplicate to save memory
        let unique_strings: HashSet<String> = HashSet::from_iter(out);
        unique_strings.into_iter().collect()
    }

    /// Filter out noise and keep only meaningful strings
    fn is_meaningful_string(s: &str) -> bool {
        // Skip strings that are mostly punctuation or numbers
        let alpha_count = s.chars().filter(|c| c.is_alphabetic()).count();
        let total_chars = s.chars().count();

        if alpha_count < total_chars / 3 {
            return false;
        }

        // Skip very common noise patterns
        let noise_patterns = [
            "................", // repeated dots
            "________________", // repeated underscores
            "@@@@@@@@@@@@@@@@", // repeated symbols
        ];

        for pattern in &noise_patterns {
            if s.contains(pattern) {
                return false;
            }
        }

        true
    }

    fn detect_embedded_files(strings: &[String]) -> Vec<EmbeddedFile> {
        let mut files = Vec::new();

        for string in strings.iter().take(10000) { // Limit processing
            if string.contains(".so") || string.contains(".dll") || string.contains(".dylib") {
                files.push(EmbeddedFile {
                    path: string.clone(),
                    hash: {
                        let mut hasher = Sha256::new();
                        hasher.update(string.as_bytes());
                        format!("{:x}", hasher.finalize())
                    },
                    size: string.len() as u64,
                    file_type: Self::detect_file_type(string),
                });
            }
        }

        files
    }

    fn detect_file_type(path: &str) -> String {
        if path.ends_with(".so") || path.contains(".so.") {
            "shared_library".to_string()
        } else if path.ends_with(".dll") || path.ends_with(".dylib") {
            "dynamic_library".to_string()
        } else {
            "unknown".to_string()
        }
    }

    fn detect_compiler_info(strings: &[String]) -> Option<CompilerInfo> {
        for string in strings.iter().take(1000) { // Limit search
            if string.contains("rustc") {
                return Some(CompilerInfo {
                    compiler: "rustc".to_string(),
                    version: Self::extract_version(string, "rustc").unwrap_or("unknown".to_string()),
                    optimization_level: Self::extract_opt_level(string).unwrap_or("unknown".to_string()),
                    target_triple: Self::extract_target_triple(string).unwrap_or("unknown".to_string()),
                });
            } else if string.contains("clang") {
                return Some(CompilerInfo {
                    compiler: "clang".to_string(),
                    version: Self::extract_version(string, "clang").unwrap_or("unknown".to_string()),
                    optimization_level: "unknown".to_string(),
                    target_triple: "unknown".to_string(),
                });
            } else if string.contains("gcc") {
                return Some(CompilerInfo {
                    compiler: "gcc".to_string(),
                    version: Self::extract_version(string, "gcc").unwrap_or("unknown".to_string()),
                    optimization_level: "unknown".to_string(),
                    target_triple: "unknown".to_string(),
                });
            }
        }
        None
    }

    fn extract_version(string: &str, tool: &str) -> Option<String> {
        let pattern = format!(r"{tool}\s+(\d+\.\d+\.\d+)");
        let re = regex::Regex::new(&pattern).ok()?;
        re.captures(string)?.get(1).map(|m| m.as_str().to_string())
    }

    fn extract_opt_level(string: &str) -> Option<String> {
        if string.contains("-O0") { Some("0".to_string()) }
        else if string.contains("-O1") { Some("1".to_string()) }
        else if string.contains("-O2") { Some("2".to_string()) }
        else if string.contains("-O3") { Some("3".to_string()) }
        else if string.contains("-Os") { Some("s".to_string()) }
        else if string.contains("-Oz") { Some("z".to_string()) }
        else { None }
    }

    fn extract_target_triple(string: &str) -> Option<String> {
        let re = regex::Regex::new(r"([a-z0-9_]+)-([a-z0-9_]+)-([a-z0-9_]+)").ok()?;
        re.captures(string)?.get(0).map(|m| m.as_str().to_string())
    }

    fn detect_build_environment() -> BuildEnvironment {
        let mut env_vars = HashMap::new();

        // Capture relevant build environment variables
        let build_vars = [
            "CARGO_PKG_VERSION", "RUSTC_VERSION", "TARGET", "PROFILE",
            "SOURCE_DATE_EPOCH", "CARGO_CFG_TARGET_ARCH", "CARGO_CFG_TARGET_OS"
        ];

        for var in &build_vars {
            if let Ok(val) = env::var(var) {
                env_vars.insert(var.to_string(), val);
            }
        }

        BuildEnvironment {
            build_tool: Some("cargo".to_string()),
            build_version: env::var("CARGO_VERSION").ok(),
            build_timestamp: env::var("SOURCE_DATE_EPOCH").ok()
                .and_then(|epoch| epoch.parse::<i64>().ok())
                .and_then(|timestamp| chrono::DateTime::from_timestamp(timestamp, 0))
                .map(|dt| dt.to_rfc3339())
                .or_else(|| Some(chrono::Utc::now().to_rfc3339())),
            environment_variables: env_vars,
        }
    }

    fn detect_crypto_components(strings: &[String], libs: &[String], symbols: &[String]) -> Vec<CryptographicComponent> {
        let mut components = Vec::new();

        // Betanet 1.1 approved cryptographic primitives
        let crypto_patterns = [
            ("ChaCha20-Poly1305", Some(256), Some("IETF"), true, ComplianceStatus::Approved),
            ("SHA-256", Some(256), None, true, ComplianceStatus::Approved),
            ("HKDF-SHA256", Some(256), None, true, ComplianceStatus::Approved),
            ("Ed25519", Some(255), None, true, ComplianceStatus::Approved),
            ("X25519", Some(255), None, true, ComplianceStatus::Approved),
            ("Kyber768", Some(768), Some("hybrid"), true, ComplianceStatus::Approved),
            ("AES-256-GCM", Some(256), Some("GCM"), true, ComplianceStatus::Approved),

            // Deprecated/forbidden algorithms
            ("RSA", Some(2048), None, false, ComplianceStatus::Deprecated),
            ("DES", Some(56), None, false, ComplianceStatus::Forbidden),
            ("3DES", Some(168), None, false, ComplianceStatus::Deprecated),
            ("MD5", Some(128), None, false, ComplianceStatus::Forbidden),
            ("SHA-1", Some(160), None, false, ComplianceStatus::Deprecated),
            ("RC4", Some(128), None, false, ComplianceStatus::Forbidden),
        ];

        // Combine all text sources for analysis
        let all_sources: Vec<&str> = strings.iter()
            .chain(libs.iter())
            .chain(symbols.iter())
            .map(|s| s.as_str())
            .collect();

        for (algo, key_len, mode, quantum_safe, status) in crypto_patterns {
            let algo_variants = [
                algo.to_lowercase().replace('-', ""),
                algo.to_lowercase().replace('-', "_"),
                algo.to_uppercase().replace('-', "_"),
                algo.to_string(),
            ];

            let found = all_sources.iter().any(|&source| {
                algo_variants.iter().any(|variant| 
                    source.to_lowercase().contains(&variant.to_lowercase())
                )
            });

            if found {
                components.push(CryptographicComponent {
                    algorithm: algo.to_string(),
                    key_length: key_len,
                    mode: mode.map(|s| s.to_string()),
                    implementation: "detected".to_string(),
                    quantum_safe,
                    usage_context: vec![CryptoUsage::Encryption],
                    compliance_status: status,
                });
            }
        }

        // Library-based crypto detection
        for lib in libs {
            if lib.contains("ring") || lib.contains("rustls") {
                components.push(CryptographicComponent {
                    algorithm: "Rust Crypto Stack".to_string(),
                    key_length: None,
                    mode: None,
                    implementation: lib.clone(),
                    quantum_safe: true,
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
                checksum: {
                    let mut hasher = Sha256::new();
                    hasher.update(raw);
                    format!("{:x}", hasher.finalize())
                },
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

        for string in strings.iter().take(5000) { // Limit processing
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

    /// Enhanced Betanet protocol detection using symbols and sections
    /// 
    /// This function detects actual protocol implementation indicators
    /// rather than just looking for specific strings
    fn detect_betanet_indicators_enhanced(
        strings: &[String], 
        libs: &[String],
        imported_symbols: &[String],
        exported_symbols: &[String],
        section_names: &[String],
        dynamic_deps: &[String]
    ) -> BetanetIndicators {
        let mut htx_transport = Vec::new();
        let mut protocol_versions = Vec::new();
        let mut crypto_protocols = Vec::new();
        let mut network_transports = Vec::new();
        let mut p2p_protocols = Vec::new();
        let mut governance_indicators = Vec::new();

        // Combine all sources for analysis - but don't just do string matching
        let all_sources: Vec<&str> = strings.iter().map(|s| s.as_str())
            .chain(libs.iter().map(|s| s.as_str()))
            .chain(imported_symbols.iter().map(|s| s.as_str()))
            .chain(exported_symbols.iter().map(|s| s.as_str()))
            .chain(section_names.iter().map(|s| s.as_str()))
            .chain(dynamic_deps.iter().map(|s| s.as_str()))
            .collect();

        // Symbol-based protocol detection (more reliable than string scanning)
        let crypto_symbols = [
            "chacha20_poly1305_encrypt", "chacha20_poly1305_decrypt",
            "ed25519_sign", "ed25519_verify", 
            "x25519_scalar_mult", "x25519_base",
            "kyber768_keygen", "kyber768_encaps", "kyber768_decaps"
        ];

        let quic_symbols = [
            "quic_connection_new", "quic_send_packet", "quic_recv_packet",
            "h3_connection_new", "h3_send_request"
        ];

        let libp2p_symbols = [
            "libp2p_new_identity", "libp2p_dial", "libp2p_listen",
            "kad_bootstrap", "bitswap_new"
        ];

        // Check for crypto symbols in imported/exported functions
        for symbol in &crypto_symbols {
            if imported_symbols.iter().any(|s| s.contains(symbol)) ||
               exported_symbols.iter().any(|s| s.contains(symbol)) {
                crypto_protocols.push(format!("Symbol: {}", symbol));
            }
        }

        // Check for QUIC symbols
        for symbol in &quic_symbols {
            if imported_symbols.iter().any(|s| s.contains(symbol)) ||
               exported_symbols.iter().any(|s| s.contains(symbol)) {
                network_transports.push(format!("Symbol: {}", symbol));
            }
        }

        // Check for libp2p symbols
        for symbol in &libp2p_symbols {
            if imported_symbols.iter().any(|s| s.contains(symbol)) ||
               exported_symbols.iter().any(|s| s.contains(symbol)) {
                p2p_protocols.push(format!("Symbol: {}", symbol));
            }
        }

        // Section-based detection (more reliable than string scanning)
        let betanet_sections = [".htx", ".betanet", ".quic", ".noise"];
        for section in &betanet_sections {
            if section_names.iter().any(|s| s.contains(section)) {
                protocol_versions.push(format!("Section: {}", section));
            }
        }

        // Enhanced string analysis with context (but not primary method)
        for source in all_sources.iter().take(10000) {
            let lower = source.to_lowercase();

            // HTX transport indicators with better context
            if (lower.contains("htx") && (lower.contains("transport") || lower.contains("protocol"))) ||
               lower.contains("cover_transport") {
                htx_transport.push(source.to_string());
            }

            // More specific protocol version detection
            if lower.contains("/betanet/") && (lower.contains("/1.1.0") || lower.contains("/1.0.0")) {
                protocol_versions.push(source.to_string());
            }

            // Governance indicators
            if lower.contains("vote_weight") || lower.contains("quorum") ||
               lower.contains("slsa") || lower.contains("provenance") {
                governance_indicators.push(source.to_string());
            }
        }

        BetanetIndicators {
            htx_transport,
            protocol_versions,
            crypto_protocols,
            network_transports,
            p2p_protocols,
            governance_indicators,
        }
    }

    /// Analyze build reproducibility with proper build ID extraction
    fn analyze_build_reproducibility(raw: &[u8], _format: &BinFormat, strings: &[String]) -> BuildReproducibility {
        let mut has_build_id = false;
        let mut build_id_type = None;
        let mut build_id_value = None;
        let mut deterministic_indicators = Vec::new();
        let mut timestamp_embedded = false;

        // Proper build ID extraction using binary format parsers
        match Object::parse(raw) {
            Ok(Object::Elf(elf)) => {
                // Check for GNU build ID in note sections using proper ELF parsing
                if let Some(notes) = elf.iter_note_sections(raw, None) {
                    for note_result in notes {
                        if let Ok(note) = note_result {
                            if note.n_type == 3 && note.name.starts_with("GNU") { // NT_GNU_BUILD_ID
                                has_build_id = true;
                                build_id_type = Some("GNU Build ID".to_string());
                                build_id_value = Some(hex::encode(&note.desc));
                                break;
                            }
                        }
                    }
                }

                // Fallback: check for build ID section using proper section parsing
                if !has_build_id {
                    for section in &elf.section_headers {
                        if let Some(name) = elf.shdr_strtab.get_at(section.sh_name) {
                            if name == ".note.gnu.build-id" {
                                has_build_id = true;
                                build_id_type = Some("GNU Build ID (section)".to_string());

                                // Extract build ID from section data
                                let section_offset = section.sh_offset as usize;
                                let section_size = section.sh_size as usize;
                                if raw.len() >= section_offset + section_size && section_size >= 16 {
                                    let data = &raw[section_offset..section_offset + section_size];
                                    // Skip note header (16 bytes) and get the build ID
                                    let build_id = &data[16..];
                                    build_id_value = Some(hex::encode(build_id));
                                }
                                break;
                            }
                        }
                    }
                }
            }

            Ok(Object::Mach(goblin::mach::Mach::Binary(m))) => {
                // Check for UUID load command in Mach-O using proper parsing
                for lc in &m.load_commands {
                    if let goblin::mach::load_command::CommandVariant::Uuid(uuid_cmd) = &lc.command {
                        has_build_id = true;
                        build_id_type = Some("Mach-O UUID".to_string());
                        build_id_value = Some(hex::encode(&uuid_cmd.uuid));
                        break;
                    }
                }
            }

            Ok(Object::PE(pe)) => {
                // Check timestamp for PE files (simplified approach)
                if pe.header.coff_header.time_date_stamp != 0 {
                    has_build_id = true;
                    build_id_type = Some("PE Timestamp".to_string());
                    build_id_value = Some(format!("{:08x}", pe.header.coff_header.time_date_stamp));
                }
            }

            _ => {}
        }

        // Check for deterministic build indicators
        let timestamp_regex = regex::Regex::new(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")
            .unwrap_or_else(|_| regex::Regex::new("").unwrap());

        for string in strings.iter().take(1000) {
            if string.contains("SOURCE_DATE_EPOCH") {
                deterministic_indicators.push("SOURCE_DATE_EPOCH".to_string());
            }
            if string.contains("reproducible") || string.contains("deterministic") {
                deterministic_indicators.push("reproducible build flag".to_string());
            }
            if string.contains("-frandom-seed") || string.contains("-fdeterministic") {
                deterministic_indicators.push("deterministic compiler flags".to_string());
            }

            // Check for embedded timestamps (bad for reproducibility)
            if timestamp_regex.is_match(string) {
                timestamp_embedded = true;
            }
        }

        BuildReproducibility {
            has_build_id,
            build_id_type,
            build_id_value,
            deterministic_indicators,
            timestamp_embedded,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use std::io::Write;

    #[test]
    fn test_string_extraction_no_injection() {
        let test_data = b"Hello World test ";
        let strings = BinaryMeta::extract_ascii_strings_optimized(test_data, 4);

        // Should contain actual strings from the data
        assert!(strings.contains(&"Hello".to_string()));
        assert!(strings.contains(&"World".to_string()));
        assert!(strings.contains(&"test".to_string()));

        // Should NOT contain any artificially injected strings
        assert!(!strings.iter().any(|s| s.contains("BETANET_SPEC")));
    }

    #[test]
    fn test_meaningful_string_filtering() {
        assert!(BinaryMeta::is_meaningful_string("hello_world"));
        assert!(BinaryMeta::is_meaningful_string("function_name"));
        assert!(!BinaryMeta::is_meaningful_string("1234567890"));
        assert!(!BinaryMeta::is_meaningful_string("................"));
    }

    #[test]
    fn test_binary_analysis_integrity() {
        // Create a temporary test file
        let mut temp_file = NamedTempFile::new().unwrap();
        let test_data = b"ELF test binary data with some strings";
        temp_file.write_all(test_data).unwrap();

        // The analysis should only find what's actually in the file
        let meta = BinaryMeta::from_path(temp_file.path().to_path_buf()).unwrap();

        // Verify no artificial injection occurred
        assert!(!meta.strings.iter().any(|s| s.contains("BETANET_SPEC_v1.0")));
        assert!(meta.strings.iter().any(|s| s.contains("binary") || s.contains("data") || s.contains("strings")));
    }

    #[test]
    fn test_crypto_component_detection() {
        let strings = vec![
            "chacha20_poly1305_encrypt".to_string(),
            "ed25519_sign".to_string(),
            "rsa_encrypt".to_string(), // Should be marked as deprecated
        ];
        let libs = vec!["libring.so".to_string()];
        let symbols = vec!["x25519_scalar_mult".to_string()];

        let components = BinaryMeta::detect_crypto_components(&strings, &libs, &symbols);

        assert!(!components.is_empty());

        // Should detect approved algorithms
        assert!(components.iter().any(|c| c.algorithm.contains("ChaCha20")));
        assert!(components.iter().any(|c| c.algorithm.contains("Ed25519")));

        // Should properly mark RSA as deprecated
        let rsa_component = components.iter().find(|c| c.algorithm.contains("RSA"));
        if let Some(rsa) = rsa_component {
            assert!(!matches!(rsa.compliance_status, ComplianceStatus::Approved));
        }
    }
}
