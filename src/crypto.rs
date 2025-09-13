//! Cryptographic Analysis Module
//!
//! Provides sophisticated cryptographic component analysis for Betanet compliance.
//! Focuses on post-quantum readiness and approved cryptographic primitives.

use crate::binary::{BinaryMeta, CryptographicComponent, ComplianceStatus};
use serde::{Deserialize, Serialize};

pub struct CryptoAnalyzer<'a> {
    meta: &'a BinaryMeta,
}

impl<'a> CryptoAnalyzer<'a> {
    pub fn new(meta: &'a BinaryMeta) -> Self {
        Self { meta }
    }

    pub fn analyze_post_quantum_crypto(&self) -> PostQuantumSupport {
        let mut support = PostQuantumSupport::default();

        // Check for Kyber768 support (required from 2027-01-01)
        support.has_kyber768 = self.detect_kyber_support();

        // Check for other post-quantum algorithms
        support.has_dilithium = self.detect_dilithium_support();
        support.has_falcon = self.detect_falcon_support();

        // Check classical crypto that should be upgraded
        support.classical_algorithms = self.detect_classical_crypto();

        support
    }

    pub fn detect_frost_signatures(&self) -> FROSTSupport {
        let mut support = FROSTSupport::default();

        support.supports_frost_ed25519 = self.has_frost_ed25519();
        support.supports_threshold_sigs = self.has_threshold_signatures();

        support
    }

    pub fn analyze_crypto_compliance(&self) -> CryptoComplianceReport {
        let mut report = CryptoComplianceReport::default();

        // Analyze each crypto component for compliance
        for component in &self.meta.crypto_components {
            match component.compliance_status {
                ComplianceStatus::Approved => report.approved_count += 1,
                ComplianceStatus::Deprecated => {
                    report.deprecated_count += 1;
                    report.deprecated_algorithms.push(component.algorithm.clone());
                }
                ComplianceStatus::Forbidden => {
                    report.forbidden_count += 1;
                    report.forbidden_algorithms.push(component.algorithm.clone());
                }
                ComplianceStatus::Unknown => report.unknown_count += 1,
            }
        }

        report.total_components = self.meta.crypto_components.len();
        report.quantum_safe_count = self.meta.crypto_components.iter()
            .filter(|c| c.quantum_safe)
            .count();

        report
    }

    fn detect_kyber_support(&self) -> bool {
        // Look for Kyber768 in symbols, imports, and crypto components
        self.has_crypto_symbol("kyber") || 
        self.has_crypto_symbol("KYBER") ||
        self.meta.crypto_components.iter().any(|c| c.algorithm.contains("Kyber"))
    }

    fn detect_dilithium_support(&self) -> bool {
        self.has_crypto_symbol("dilithium") || 
        self.has_crypto_symbol("DILITHIUM")
    }

    fn detect_falcon_support(&self) -> bool {
        self.has_crypto_symbol("falcon") || 
        self.has_crypto_symbol("FALCON")
    }

    fn detect_classical_crypto(&self) -> Vec<String> {
        let mut classical = Vec::new();

        let classical_algorithms = [
            ("RSA", vec!["rsa", "RSA"]),
            ("DES", vec!["des", "DES", "3des"]),
            ("MD5", vec!["md5", "MD5"]),
            ("SHA1", vec!["sha1", "SHA1"]),
            ("RC4", vec!["rc4", "RC4"]),
        ];

        for (name, patterns) in &classical_algorithms {
            if patterns.iter().any(|&pattern| self.has_crypto_symbol(pattern)) {
                classical.push(name.to_string());
            }
        }

        classical
    }

    fn has_frost_ed25519(&self) -> bool {
        (self.has_crypto_symbol("frost") || self.has_crypto_symbol("FROST")) &&
        (self.has_crypto_symbol("ed25519") || self.has_crypto_symbol("ED25519"))
    }

    fn has_threshold_signatures(&self) -> bool {
        self.has_crypto_symbol("threshold") || 
        self.has_crypto_symbol("multisig") ||
        self.has_crypto_symbol("shamir")
    }

    fn has_crypto_symbol(&self, pattern: &str) -> bool {
        self.meta.imported_symbols.iter().any(|s| s.contains(pattern)) ||
        self.meta.exported_symbols.iter().any(|s| s.contains(pattern)) ||
        self.meta.strings.iter().any(|s| s.contains(pattern))
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct PostQuantumSupport {
    pub has_kyber768: bool,
    pub has_dilithium: bool,
    pub has_falcon: bool,
    pub classical_algorithms: Vec<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct FROSTSupport {
    pub supports_frost_ed25519: bool,
    pub supports_threshold_sigs: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct CryptoComplianceReport {
    pub total_components: usize,
    pub approved_count: usize,
    pub deprecated_count: usize,
    pub forbidden_count: usize,
    pub unknown_count: usize,
    pub quantum_safe_count: usize,
    pub deprecated_algorithms: Vec<String>,
    pub forbidden_algorithms: Vec<String>,
}

impl CryptoComplianceReport {
    pub fn compliance_percentage(&self) -> f32 {
        if self.total_components == 0 {
            return 100.0;
        }
        (self.approved_count as f32 / self.total_components as f32) * 100.0
    }

    pub fn quantum_safe_percentage(&self) -> f32 {
        if self.total_components == 0 {
            return 0.0;
        }
        (self.quantum_safe_count as f32 / self.total_components as f32) * 100.0
    }

    pub fn is_compliant(&self) -> bool {
        self.forbidden_count == 0 && self.compliance_percentage() >= 80.0
    }
}
