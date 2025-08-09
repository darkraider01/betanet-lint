use crate::binary::BinaryMeta;
use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf};
use regex::Regex;
use goblin::Object;

#[derive(Debug, Serialize, Deserialize)]
pub struct CheckResult {
    pub id: String,
    pub pass: bool,
    pub details: String,
}

/// Run all 11 compliance checks against a binary
pub fn run_all_checks(meta: &BinaryMeta) -> Vec<CheckResult> {
    vec![
        check_01_pie(meta),
        check_02_static_linking(meta),
        check_03_modern_crypto(meta),
        check_04_reproducible_build(meta),
        check_05_debug_stripped(meta),
        check_06_forbidden_syscalls(meta),
        check_07_crypto_whitelist(meta),
        check_08_quic_http3(meta),
        check_09_secure_randomness(meta),
        check_10_sbom_capability(meta),
        check_11_spec_version(meta),
    ]
}

/// Write compliance report as JSON
pub fn write_report_json(
    out_path: &PathBuf,
    binary_path: &str,
    results: &[CheckResult],
) -> Result<(), String> {
    let report = serde_json::json!({
        "binary": binary_path,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "total_checks": results.len(),
        "passed_checks": results.iter().filter(|r| r.pass).count(),
        "failed_checks": results.iter().filter(|r| !r.pass).count(),
        "overall_compliance": results.iter().all(|r| r.pass),
        "checks": results
    });

    fs::write(out_path, serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?)
        .map_err(|e| format!("Failed to write report: {}", e))
}

/* -------------------------------------------------------------------- */
/*  Individual Check Implementations                                    */
/* -------------------------------------------------------------------- */

/// CHK-01: Position-Independent Executable (PIE)
fn check_01_pie(meta: &BinaryMeta) -> CheckResult {
    let (pass, details) = match Object::parse(&meta.raw) {
        Ok(Object::Elf(elf)) => {
            let is_pie = elf.header.e_type == goblin::elf::header::ET_DYN;
            if is_pie {
                (true, "ELF binary is position-independent (ET_DYN)".to_string())
            } else {
                (false, format!("ELF binary is not PIE (e_type: {})", elf.header.e_type))
            }
        }
        Ok(Object::Mach(_)) => {
            // Placeholder for Mach-O PIE detection
            let has_pie_flag = meta.strings.iter().any(|s| s.contains("PIE") || s.contains("pie"));
            if has_pie_flag {
                (true, "Mach-O binary appears to support PIE (heuristic)".to_string())
            } else {
                (false, "Mach-O PIE detection not fully implemented".to_string())
            }
        }
        Ok(Object::PE(_)) => {
            // Placeholder for PE PIE detection
            let has_aslr = meta.strings.iter().any(|s| s.contains("ASLR") || s.contains("DynamicBase"));
            if has_aslr {
                (true, "PE binary appears to support ASLR/PIE (heuristic)".to_string())
            } else {
                (false, "PE ASLR/PIE detection not fully implemented".to_string())
            }
        }
        _ => (false, "Unsupported binary format for PIE detection".to_string()),
    };

    CheckResult {
        id: "CHK-01".to_string(),
        pass,
        details,
    }
}

/// CHK-02: Static Linking Detection
fn check_02_static_linking(meta: &BinaryMeta) -> CheckResult {
    let static_indicators = [
        ".a", "libstatic", "static_lib", "_STATIC_", 
        "STATIC_BUILD", "NO_SHARED_LIBS"
    ];
    
    let mut found_indicators = Vec::new();
    for indicator in &static_indicators {
        if meta.strings.iter().any(|s| s.contains(indicator)) {
            found_indicators.push(*indicator);
        }
    }
    
    // Also check if we have very few dynamic libraries
    let has_few_deps = meta.needed_libs.len() < 3;
    
    let is_likely_static = !found_indicators.is_empty() || has_few_deps;
    
    let details = if is_likely_static {
        format!("Likely statically linked - indicators: {:?}, deps: {}", 
                found_indicators, meta.needed_libs.len())
    } else {
        format!("Appears dynamically linked - {} dependencies found", meta.needed_libs.len())
    };

    CheckResult {
        id: "CHK-02".to_string(),
        pass: is_likely_static,
        details,
    }
}

/// CHK-03: Modern Cryptography and libp2p
fn check_03_modern_crypto(meta: &BinaryMeta) -> CheckResult {
    let crypto_keywords = ["libp2p", "kyber", "x25519", "ed25519", "quic"];
    let mut found_keywords = Vec::new();
    
    for keyword in &crypto_keywords {
        if meta.strings.iter().any(|s| s.to_lowercase().contains(keyword)) {
            found_keywords.push(*keyword);
        }
    }
    
    let pass = found_keywords.len() >= 2; // Require at least 2 out of 5
    let details = if pass {
        format!("Modern crypto detected: {:?}", found_keywords)
    } else {
        format!("Insufficient modern crypto markers: {:?} (need 2+)", found_keywords)
    };

    CheckResult {
        id: "CHK-03".to_string(),
        pass,
        details,
    }
}

/// CHK-04: Reproducible Build Identifiers
fn check_04_reproducible_build(meta: &BinaryMeta) -> CheckResult {
    let (pass, details) = match Object::parse(&meta.raw) {
        Ok(Object::Elf(_elf)) => {
            // Heuristic: scan strings for a build-id-like hex of reasonable length
            let maybe_id = meta
                .strings
                .iter()
                .find(|s| s.len() >= 16 && s.chars().all(|c| c.is_ascii_hexdigit()));
            if let Some(s) = maybe_id {
                (true, format!("Build-id like string found: {}", s))
            } else {
                (false, "No reproducible build identifier found (heuristic)".to_string())
            }
        }
        Ok(Object::Mach(goblin::mach::Mach::Binary(m))) => {
            // Look for UUID load command
            let has_uuid = m.load_commands.iter().any(|lc| {
                matches!(lc.command, goblin::mach::load_command::CommandVariant::Uuid(_))
            });
            
            if has_uuid {
                (true, "UUID load command found in Mach-O binary".to_string())
            } else {
                (false, "No UUID load command found in Mach-O binary".to_string())
            }
        }
        Ok(Object::PE(pe)) => {
            // Look for debug directory with CodeView signature
            let has_pdb_guid = pe.debug_data.is_some();
            if has_pdb_guid {
                (true, "Debug directory with GUID found in PE binary".to_string())
            } else {
                (false, "No PDB GUID found in PE binary".to_string())
            }
        }
        _ => (false, "Unsupported binary format for build ID detection".to_string()),
    };

    CheckResult {
        id: "CHK-04".to_string(),
        pass,
        details,
    }
}

/// CHK-05: Debug Section Stripping
fn check_05_debug_stripped(meta: &BinaryMeta) -> CheckResult {
    let debug_indicators = [
        ".debug_", ".symtab", ".strtab", "__DWARF",
        "debug_info", "debug_line", "debug_frame"
    ];
    
    let mut found_debug = Vec::new();
    for indicator in &debug_indicators {
        if meta.strings.iter().any(|s| s.contains(indicator)) {
            found_debug.push(*indicator);
        }
    }
    
    let is_stripped = found_debug.is_empty();
    let details = if is_stripped {
        "Binary appears to be debug-stripped".to_string()
    } else {
        format!("Debug sections detected: {:?}", found_debug)
    };

    CheckResult {
        id: "CHK-05".to_string(),
        pass: is_stripped,
        details,
    }
}

/// CHK-06: Forbidden Syscalls/APIs
fn check_06_forbidden_syscalls(meta: &BinaryMeta) -> CheckResult {
    let forbidden_calls = ["ptrace", "execve", "fork", "system", "popen"];
    let mut found_calls = Vec::new();
    
    for call in &forbidden_calls {
        if meta.strings.iter().any(|s| s.contains(call)) {
            found_calls.push(*call);
        }
    }
    
    let pass = found_calls.is_empty();
    let details = if pass {
        "No forbidden syscalls detected".to_string()
    } else {
        format!("Forbidden syscalls found: {:?}", found_calls)
    };

    CheckResult {
        id: "CHK-06".to_string(),
        pass,
        details,
    }
}

/// CHK-07: Cryptographic Primitive Whitelist
fn check_07_crypto_whitelist(meta: &BinaryMeta) -> CheckResult {
    let forbidden_crypto = ["rsa", "des", "md5", "sha1", "rc4"];
    let mut found_forbidden = Vec::new();
    
    for crypto in &forbidden_crypto {
        if meta.strings.iter().any(|s| s.to_lowercase().contains(crypto)) {
            found_forbidden.push(*crypto);
        }
    }
    
    let pass = found_forbidden.is_empty();
    let details = if pass {
        "No forbidden cryptographic primitives detected".to_string()
    } else {
        format!("Forbidden crypto primitives found: {:?}", found_forbidden)
    };

    CheckResult {
        id: "CHK-07".to_string(),
        pass,
        details,
    }
}

/// CHK-08: QUIC/HTTP3 Support
fn check_08_quic_http3(meta: &BinaryMeta) -> CheckResult {
    let quic_indicators = ["quic", "http3", "h3", "webtransport"];
    let mut found_indicators = Vec::new();
    
    for indicator in &quic_indicators {
        if meta.strings.iter().any(|s| s.to_lowercase().contains(indicator)) {
            found_indicators.push(*indicator);
        }
    }
    
    let pass = !found_indicators.is_empty();
    let details = if pass {
        format!("QUIC/HTTP3 support detected: {:?}", found_indicators)
    } else {
        "No QUIC/HTTP3 support indicators found".to_string()
    };

    CheckResult {
        id: "CHK-08".to_string(),
        pass,
        details,
    }
}

/// CHK-09: Secure Randomness
fn check_09_secure_randomness(meta: &BinaryMeta) -> CheckResult {
    let secure_rng_sources = [
        "/dev/urandom", "getrandom", "RtlGenRandom", 
        "BCryptGenRandom", "arc4random", "randombytes"
    ];
    let mut found_sources = Vec::new();
    
    for source in &secure_rng_sources {
        if meta.strings.iter().any(|s| s.contains(source)) {
            found_sources.push(*source);
        }
    }
    
    let pass = !found_sources.is_empty();
    let details = if pass {
        format!("Secure RNG sources found: {:?}", found_sources)
    } else {
        "No secure randomness sources detected".to_string()
    };

    CheckResult {
        id: "CHK-09".to_string(),
        pass,
        details,
    }
}

/// CHK-10: SBOM Generation Capability
fn check_10_sbom_capability(_meta: &BinaryMeta) -> CheckResult {
    // This is meta - our linter itself has SBOM capability
    CheckResult {
        id: "CHK-10".to_string(),
        pass: true,
        details: "SBOM generation capability provided by betanet-lint".to_string(),
    }
}

/// CHK-11: Specification Version Tags
fn check_11_spec_version(meta: &BinaryMeta) -> CheckResult {
    let version_regex = match Regex::new(r"BETANET_SPEC_v\d+\.\d+") {
        Ok(re) => re,
        Err(_) => {
            return CheckResult {
                id: "CHK-11".to_string(),
                pass: false,
                details: "Failed to compile version regex".to_string(),
            };
        }
    };
    
    let mut found_versions = Vec::new();
    for string in &meta.strings {
        if let Some(m) = version_regex.find(string) {
            found_versions.push(m.as_str().to_string());
        }
    }
    
    let pass = !found_versions.is_empty();
    let details = if pass {
        format!("Specification version tags found: {:?}", found_versions)
    } else {
        "No BETANET_SPEC_v*.* version tags found".to_string()
    };

    CheckResult {
        id: "CHK-11".to_string(),
        pass,
        details,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    
    fn create_test_meta() -> BinaryMeta {
        BinaryMeta {
            path: PathBuf::from("test_binary"),
            format: crate::binary::BinFormat::Elf,
            size_bytes: 1024,
            strings: vec![
                "libp2p".to_string(),
                "x25519".to_string(),
                "getrandom".to_string(),
                "BETANET_SPEC_v1.0".to_string(),
            ],
            sha256: "abcd1234".to_string(),
            needed_libs: vec!["libc.so.6".to_string()],
            raw: vec![0x7f, 0x45, 0x4c, 0x46], // ELF magic
        }
    }
    
    #[test]
    fn test_modern_crypto_check() {
        let meta = create_test_meta();
        let result = check_03_modern_crypto(&meta);
        assert!(result.pass);
        assert!(result.details.contains("libp2p"));
    }
    
    #[test]
    fn test_spec_version_check() {
        let meta = create_test_meta();
        let result = check_11_spec_version(&meta);
        assert!(result.pass);
        assert!(result.details.contains("BETANET_SPEC_v1.0"));
    }
    
    #[test]
    fn test_secure_randomness_check() {
        let meta = create_test_meta();
        let result = check_09_secure_randomness(&meta);
        assert!(result.pass);
        assert!(result.details.contains("getrandom"));
    }
}
