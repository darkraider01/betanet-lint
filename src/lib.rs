//! Betanet 1.1 §11 Compliance Verification Tool
//! 
//! This crate provides comprehensive verification of compiled binaries against
//! the 13 normative requirements specified in Betanet 1.1 Section 11.
//!
//! Key features:
//! - Protocol-specific compliance verification (not generic binary hygiene)
//! - Proper binary format parsing (no string scanning fallbacks)
//! - SLSA Level 3 provenance generation
//! - Enhanced SBOM with security metadata
//! - Memory-efficient analysis for large binaries
//! 
pub mod binary;
pub mod checks;
pub mod sbom;
pub mod protocol;
pub mod crypto;
pub mod slsa;

pub use binary::BinaryMeta;
pub use checks::{CheckResult, run_all_checks, write_report_json};
pub use sbom::{SbomFormat, SbomOptions, LicenseScanDepth, write_sbom_with_options};

// Version and metadata
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const BETANET_SPEC_VERSION: &str = "1.1";
pub const SUPPORTED_CHECKS: usize = 13;

/// Error types for the betanet-lint crate
#[derive(thiserror::Error, Debug)]
pub enum BetanetLintError {
    #[error("Binary analysis error: {0}")]
    BinaryAnalysis(String),

    #[error("Protocol verification error: {0}")]
    ProtocolVerification(String),

    #[error("SBOM generation error: {0}")]
    SbomGeneration(String),

    #[error("SLSA provenance error: {0}")]
    SlsaProvenance(String),

    #[error("Anyhow error: {0}")]
    Anyhow(#[from] anyhow::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Network error: {0}")]
    Network(#[from] reqwest::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, BetanetLintError>;

/// Initialize the betanet-lint library with logging
pub fn init() {
    env_logger::init();
    log::info!("Betanet-lint v{} initialized", VERSION);
    log::info!("Supporting Betanet {} specification", BETANET_SPEC_VERSION);
}

/// Verify that a binary meets all Betanet 1.1 §11 requirements
pub async fn verify_compliance(binary_path: &std::path::Path) -> Result<Vec<CheckResult>> {
    let meta = BinaryMeta::from_path(binary_path.to_path_buf())?;
    Ok(run_all_checks(&meta))
}

/// Check if binary has minimum required protocol support
pub fn has_minimum_betanet_support(meta: &BinaryMeta) -> bool {
    // Minimum requirements for Betanet compliance:
    // 1. HTX transport support
    // 2. At least one supported protocol version
    // 3. Required cryptographic primitives

    !meta.betanet_indicators.htx_transport.is_empty() &&
    !meta.betanet_indicators.protocol_versions.is_empty() &&
    meta.crypto_components.iter().any(|c| c.quantum_safe)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_constants() {
        assert!(!VERSION.is_empty());
        assert_eq!(BETANET_SPEC_VERSION, "1.1");
        assert_eq!(SUPPORTED_CHECKS, 13);
    }

    #[test]
    fn test_minimum_betanet_support() {
        use crate::binary::*;
        use std::path::PathBuf;
        use std::collections::HashMap;

        let mut meta = BinaryMeta {
            path: PathBuf::from("test"),
            format: BinFormat::Elf,
            size_bytes: 1000,
            strings: vec![],
            sha256: "test".to_string(),
            needed_libs: vec![],
            raw: vec![],
            embedded_files: vec![],
            compiler_info: None,
            build_environment: BuildEnvironment {
                build_tool: None,
                build_version: None,
                build_timestamp: None,
                environment_variables: HashMap::new(),
            },
            crypto_components: vec![
                CryptographicComponent {
                    algorithm: "ChaCha20-Poly1305".to_string(),
                    key_length: Some(256),
                    mode: Some("IETF".to_string()),
                    implementation: "ring".to_string(),
                    quantum_safe: true,
                    usage_context: vec![CryptoUsage::Encryption],
                    compliance_status: ComplianceStatus::Approved,
                }
            ],
            static_libraries: vec![],
            licenses: vec![],
            betanet_indicators: BetanetIndicators {
                htx_transport: vec!["HTX".to_string()],
                protocol_versions: vec!["/betanet/htx/1.1.0".to_string()],
                crypto_protocols: vec![],
                network_transports: vec![],
                p2p_protocols: vec![],
                governance_indicators: vec![],
            },
            build_reproducibility: BuildReproducibility {
                has_build_id: false,
                build_id_type: None,
                build_id_value: None,
                deterministic_indicators: vec![],
                timestamp_embedded: false,
            },
            imported_symbols: vec![],
            exported_symbols: vec![],
            section_names: vec![],
            dynamic_dependencies: vec![],
        };

        assert!(has_minimum_betanet_support(&meta));

        // Remove HTX support
        meta.betanet_indicators.htx_transport.clear();
        assert!(!has_minimum_betanet_support(&meta));
    }
}
